#!/usr/bin/env python3
# send_cli_choice_serrms.py
# Tam birleşik sürüm — senin orijinal kodun + config otomatik oluşturma

import os
import json
import getpass
import sys
import time
import traceback
import datetime
from pathlib import Path
from email.message import EmailMessage
from email.header import Header
from email.utils import formataddr
import smtplib, ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv

# colorama (opsiyonel)
try:
    from colorama import init, Fore, Style
    init()
except Exception:
    class _Fake:
        RESET_ALL = ""
        def __getattr__(self, n): return ""
    Fore = Style = _Fake()
    Fore.GREEN = Fore.RED = Fore.YELLOW = Fore.CYAN = Fore.MAGENTA = ""

BASE = Path(__file__).parent
CFG_PATH = BASE / "config.json"
EXAMPLE_CFG_PATH = BASE / "config.example.json"
LOG_PATH = BASE / "send_log.jsonl"
STATE_PATH = BASE / "send_state.json"
CSV_PATH = BASE / "send_results.csv"

ASCII = r"""
 ____  _____  ____  ____  __  __  _____ 
/ ___|| ____||  _ \|  _ \|  \/  |/ ____|
\___ \|  _|  | |_) | |_) | |\/| | (___  
 ___) | |___ |  _ <|  _ <| |  | |\___ \ 
|____/|_____||_| \_\_| \_\_|  |_|_____) 
"""

# ---------------- SERRMS logging ----------------
def serrms_log(msg, level="INFO"):
    now = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[SERRMS][{level}][{now}] {msg}")

# ---------------- helpers ----------------
def now_iso():
    return datetime.datetime.now().astimezone().isoformat()

def short_exc(e):
    return "".join(traceback.format_exception_only(type(e), e)).strip()

def load_json(path, default):
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return default

def save_json(path, obj):
    try:
        path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass

# ---------------- config & state ----------------
def load_config():
    # Eğer config yoksa örnekten veya yeni oluştur
    if not CFG_PATH.exists():
        if EXAMPLE_CFG_PATH.exists():
            serrms_log(f"config.json bulunamadı, örnek dosya kullanılıyor: {EXAMPLE_CFG_PATH}", "WARN")
            # kopyala ama config.json'unu oluştur (yerelde)
            CFG_PATH.write_text(EXAMPLE_CFG_PATH.read_text(encoding="utf-8"), encoding="utf-8")
        else:
            example = {
                "senders":[
                    # Örnek gönderici tanımı; çalıştırmadan önce gerçek bilgilerle değiştir
                    {"email":"example@gmail.com","name":"Example","smtp":"smtp.gmail.com","port":465}
                ],
                "default_subject":"Test",
                "default_body":"Deneme mesajı",
                "turbo_max_workers":4,
                "max_per_sender_per_hour":50,
                "max_per_target_per_hour":200,
                "allowed_targets":[],
                "require_target_confirm":True,
                "verify_senders_on_start":True,
                "smtp_default_timeout":30,
                "smtp_retries":3,
                "smtp_retry_backoff_base":1.5,
                "debug_smtp":False,
                "save_csv_results":True
            }
            serrms_log("config.json ve örnek bulunamadı; yeni örnek oluşturuluyor.", "WARN")
            CFG_PATH.write_text(json.dumps(example, indent=2, ensure_ascii=False), encoding="utf-8")
            # Ayrıca EXAMPLE_CFG_PATH oluştur (repo için)
            try:
                EXAMPLE_CFG_PATH.write_text(json.dumps(example, indent=2, ensure_ascii=False), encoding="utf-8")
            except Exception:
                pass

    # Okuma
    try:
        cfg = json.loads(CFG_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        serrms_log(f"config.json okunamadı: {e}", "ERR")
        sys.exit(1)

    if not cfg.get("senders"):
        serrms_log("config.json içinde en az 1 sender olmalı.", "ERR")
        sys.exit(1)
    # defaultları set et
    cfg.setdefault("default_subject", "Test")
    cfg.setdefault("default_body", "Deneme mesajı")
    cfg.setdefault("turbo_max_workers", 4)
    cfg.setdefault("max_per_sender_per_hour", 50)
    cfg.setdefault("max_per_target_per_hour", 200)
    cfg.setdefault("allowed_targets", [])
    cfg.setdefault("require_target_confirm", True)
    cfg.setdefault("verify_senders_on_start", True)
    cfg.setdefault("smtp_default_timeout", 30)
    cfg.setdefault("smtp_retries", 3)
    cfg.setdefault("smtp_retry_backoff_base", 1.5)
    cfg.setdefault("debug_smtp", False)
    cfg.setdefault("save_csv_results", True)
    return cfg

STATE = load_json(STATE_PATH, {"recent": []})

def prune_state(hours=24):
    try:
        cutoff = datetime.datetime.now().timestamp() - hours*3600
        STATE["recent"] = [r for r in STATE.get("recent", []) if datetime.datetime.fromisoformat(r["ts"]).timestamp() >= cutoff]
        save_json(STATE_PATH, STATE)
    except Exception:
        pass

prune_state()

def record_send(sender_email, target):
    STATE.setdefault("recent", []).append({"ts": now_iso(), "sender": sender_email, "target": target})
    save_json(STATE_PATH, STATE)

def count_recent(sender=None, target=None, within_hours=1):
    cutoff = datetime.datetime.now().timestamp() - within_hours*3600
    cnt = 0
    for r in STATE.get("recent", []):
        try:
            ts = datetime.datetime.fromisoformat(r["ts"]).timestamp()
        except Exception:
            continue
        if ts < cutoff: continue
        if sender and r.get("sender") != sender: continue
        if target and r.get("target") != target: continue
        cnt += 1
    return cnt

def log_json(entry: dict):
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass

# ---------------- password resolver ----------------
def resolve_sender_password(sender_meta):
    env = sender_meta.get("env_var")
    if env:
        val = os.environ.get(env)
        if val:
            return val
    if sender_meta.get("app_password"):
        return sender_meta.get("app_password")
    try:
        prompt_text = f"Gönderici {sender_meta.get('email')} için parola gir (gösterilmeyecek). Enter boş bırakılırsa iptal edilir: "
        pw = getpass.getpass(prompt_text)
        if pw:
            return pw
    except Exception:
        pass
    return None

# ---------------- smtp utils ----------------
def build_msg(sender_meta, target, subject, body):
    msg = EmailMessage()
    msg["From"] = formataddr((str(Header(sender_meta.get("name",""), "utf-8")), sender_meta["email"]))
    msg["To"] = target
    msg["Subject"] = str(Header(subject, "utf-8"))
    msg.set_content(body, subtype="plain", charset="utf-8")
    return msg

def _open_smtp_connection(smtp_host, port, timeout, use_ssl_hint=False, debug=False):
    ctx = ssl.create_default_context()
    if use_ssl_hint or port == 465:
        s = smtplib.SMTP_SSL(smtp_host, port, context=ctx, timeout=timeout)
    else:
        s = smtplib.SMTP(smtp_host, port, timeout=timeout)
        try:
            s.ehlo()
            s.starttls(context=ctx)
            s.ehlo()
        except Exception:
            pass
    if debug:
        s.set_debuglevel(1)
    return s

def send_email_once(sender_meta, target, subject, body, timeout=30, retries=3, backoff_base=1.5, debug=False):
    email = sender_meta["email"]
    smtp = sender_meta.get("smtp", "smtp.gmail.com")
    port = int(sender_meta.get("port", 465))
    pw = resolve_sender_password(sender_meta)
    if not pw:
        reason = "no password (env/app_password or interactive)"
        log_json({"ts": now_iso(), "sender": email, "target": target, "status": "ERR", "reason": reason})
        serrms_log(f"{email} -> {target} | ERR | {reason}", "ERR")
        return (email, False, reason)
    msg = build_msg(sender_meta, target, subject, body)

    attempt = 0
    last_exc = None
    while attempt < retries:
        attempt += 1
        try:
            with _open_smtp_connection(smtp, port, timeout, use_ssl_hint=sender_meta.get("use_ssl", False), debug=debug) as s:
                s.login(email, pw)
                s.send_message(msg)
            log_json({"ts": now_iso(), "sender": email, "target": target, "status": "OK", "attempt": attempt})
            record_send(email, target)
            serrms_log(f"{email} -> {target} | OK", "OK")
            return (email, True, None)
        except smtplib.SMTPServerDisconnected as e:
            last_exc = e
            reason = short_exc(e)
            wait = backoff_base ** attempt
            log_json({"ts": now_iso(), "sender": email, "target": target, "status": "ERR", "reason": reason, "attempt": attempt, "transient": True})
            serrms_log(f"{email} -> {target} | ERR | {reason}", "ERR")
            if attempt < retries:
                time.sleep(min(wait, 30))
                continue
            return (email, False, reason)
        except smtplib.SMTPAuthenticationError as e:
            reason = short_exc(e)
            log_json({"ts": now_iso(), "sender": email, "target": target, "status": "ERR", "reason": reason, "attempt": attempt, "auth": True})
            serrms_log(f"{email} -> {target} | ERR | {reason}", "ERR")
            return (email, False, reason)
        except Exception as e:
            last_exc = e
            reason = short_exc(e)
            log_json({"ts": now_iso(), "sender": email, "target": target, "status": "ERR", "reason": reason, "attempt": attempt})
            serrms_log(f"{email} -> {target} | ERR | {reason}", "ERR")
            if attempt < retries:
                wait = backoff_base ** attempt
                time.sleep(min(wait, 30))
                continue
            return (email, False, reason)
    return (email, False, short_exc(last_exc) if last_exc else "unknown")

def verify_sender(sender_meta, timeout=10, retries=2, debug=False):
    email = sender_meta["email"]
    smtp = sender_meta.get("smtp", "smtp.gmail.com")
    port = int(sender_meta.get("port", 465))
    pw = resolve_sender_password(sender_meta)
    if not pw:
        return (email, False, "no password found")
    attempt = 0
    last_exc = None
    while attempt < retries:
        attempt += 1
        try:
            with _open_smtp_connection(smtp, port, timeout, use_ssl_hint=sender_meta.get("use_ssl", False), debug=debug) as s:
                s.login(email, pw)
            return (email, True, None)
        except Exception as e:
            last_exc = e
            if attempt < retries:
                time.sleep(1)
                continue
            return (email, False, short_exc(e))
    return (email, False, short_exc(last_exc) if last_exc else "unknown")

# ---------------- runners ----------------
def run_normal(cfg, target, subj, body):
    results = []
    for s in cfg["senders"]:
        if count_recent(sender=s["email"], within_hours=1) >= cfg["max_per_sender_per_hour"]:
            reason = "sender hourly limit reached"
            serrms_log(f"[SKIP] {s['email']} -> {target} : {reason}", "INFO")
            results.append((s["email"], False, reason))
            continue
        if count_recent(target=target, within_hours=1) >= cfg["max_per_target_per_hour"]:
            reason = "target hourly limit reached"
            serrms_log("Target hourly limit reached. Aborting further sends.", "ERR")
            results.append(("*", False, reason))
            break
        res = send_email_once(s, target, subj, body, timeout=cfg.get("smtp_default_timeout",30), retries=cfg.get("smtp_retries",3), backoff_base=cfg.get("smtp_retry_backoff_base",1.5), debug=cfg.get("debug_smtp", False))
        results.append(res)
        time.sleep(1.0)
    return results

def run_turbo_repeat(cfg, target, subj, body, repeat=4):
    results = []
    tasks = []
    for s in cfg["senders"]:
        already = count_recent(sender=s["email"], within_hours=1)
        remaining = max(0, cfg["max_per_sender_per_hour"] - already)
        allowed_repeats = min(repeat, remaining)
        if allowed_repeats <= 0:
            serrms_log(f"[SKIP] {s['email']} (sender hourly limit)", "INFO")
            continue
        for _ in range(allowed_repeats):
            tasks.append(s)
    target_already = count_recent(target=target, within_hours=1)
    if target_already + len(tasks) > cfg["max_per_target_per_hour"]:
        serrms_log("Target hourly limit would be exceeded by this operation. Aborting.", "ERR")
        return [ (s["email"], False, "would exceed target hourly limit") for s in tasks ]
    if not tasks:
        serrms_log("Gönderecek uygun sender yok (limitler veya yok).", "INFO")
        return []
    max_workers = min(cfg.get("turbo_max_workers", 8), len(tasks))
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = { ex.submit(send_email_once, s, target, subj, body, cfg.get("smtp_default_timeout",30), cfg.get("smtp_retries",3), cfg.get("smtp_retry_backoff_base",1.5), cfg.get("debug_smtp", False)): s for s in tasks }
        for fut in as_completed(futures):
            try:
                r = fut.result()
            except Exception as e:
                s = futures[fut]
                r = (s["email"], False, short_exc(e))
            results.append(r)
    return results

# ---------------- CLI helpers ----------------
def prompt_confirm_target(cfg, target):
    if target in cfg.get("allowed_targets", []):
        return True
    if not cfg.get("require_target_confirm", True):
        return True
    serrms_log("[UYARI] Bu hedef izinli listede değil.", "WARN")
    serrms_log("Bu hedefe gerçekten sahipsen veya açık izin verildiyse, 'I_OWN_TARGET' yazıp Enter'a bas.", "WARN")
    v = input("Onay metni: ").strip()
    return v == "I_OWN_TARGET"

def verify_all_senders(cfg):
    serrms_log("Gönderici hesapları test ediliyor...", "SERRMS")
    ok_count = 0
    for s in cfg["senders"]:
        em, ok, reason = verify_sender(s, timeout=cfg.get("smtp_default_timeout",10), retries=cfg.get("smtp_retries",2), debug=cfg.get("debug_smtp", False))
        serrms_log(f"{em} -> {'OK' if ok else reason}", "OK" if ok else "ERR")
        if ok: ok_count += 1
    serrms_log(f"Doğrulanan gönderici sayısı: {ok_count}/{len(cfg.get('senders',[]))}", "SERRMS")
    return ok_count

def save_results_csv(rows):
    try:
        exists = CSV_PATH.exists()
        with open(CSV_PATH, "a", newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            if not exists:
                writer.writerow(["ts","sender","target","status","reason"])
            for r in rows:
                ts = now_iso()
                sender, ok, reason = r
                writer.writerow([ts, sender, target_global, "OK" if ok else "ERR", reason or ""])
    except Exception:
        pass

# ---------------- main / CLI ----------------
def main():
    cfg = load_config()
    # Başlangıçta opsiyonel doğrulama
    if cfg.get("verify_senders_on_start", True):
        # verify_all_senders, ama programı kapatmayacak — sadece raporlayacak
        try:
            verify_all_senders(cfg)
        except Exception as e:
            serrms_log(f"Doğrulama sırasında hata: {e}", "WARN")

    while True:
        print("\n" + ASCII)
        print("1 - Normal Gönderim (birer kez her sender)")
        print("2 - Turbo (her sender tekrar)")
        print("3 - Gönderici test et")
        print("4 - Çıkış")
        choice = input("Seçin: ").strip()
        if choice in ("4","q","exit","çıkış"):
            serrms_log("Çıkılıyor.", "SERRMS")
            break
        if choice not in ("1","2","3"):
            serrms_log("Geçersiz seçim", "WARN"); continue
        if choice == "3":
            verify_all_senders(cfg)
            input("\nAna menüye dönmek için Enter'a bas.")
            continue
        target = input("Hedef e-posta: ").strip()
        if not target:
            serrms_log("Hedef boş olamaz", "ERR"); continue
        if not prompt_confirm_target(cfg, target):
            serrms_log("Hedef onaylanmadı; işlem iptal edildi.", "ERR")
            input("\nAna menüye dönmek için Enter'a bas.")
            continue
        subj = input(f"Konu (Enter=varsayılan '{cfg.get('default_subject')}'): ").strip() or cfg.get("default_subject")
        body = input(f"Mesaj (Enter=varsayılan): ").strip() or cfg.get("default_body")
        global target_global
        target_global = target
        if choice == "1":
            res = run_normal(cfg, target, subj, body)
        else:
            default_repeat = 10000000
            rr = input(f"Tekrar sayısı (her sender kaç defa göndersin) [default {default_repeat}]: ").strip()
            repeat = default_repeat
            if rr.isdigit():
                repeat = max(1, min(1000, int(rr)))
            res = run_turbo_repeat(cfg, target, subj, body, repeat=repeat)
        ok_count = sum(1 for _,ok,_ in res if ok)
        serrms_log("\n--- Özet ---", "SERRMS")
        for email, ok, reason in res:
            serrms_log(f"{email} — {'OK' if ok else 'ERR'}{'' if not reason else ' - ' + str(reason)}", "OK" if ok else "ERR")
        serrms_log(f"Başarılı: {ok_count} / {len(res)}", "SERRMS")
        if cfg.get("save_csv_results", True) and res:
            save_results_csv(res)
            serrms_log(f"Sonuçlar CSV'ye kaydedildi: {CSV_PATH}", "SERRMS")
        input("\nAna menüye dönmek için Enter'a bas.")

if __name__=="__main__":
    try:
        main()
    except KeyboardInterrupt:
        serrms_log("\nÇıkış (CTRL+C).", "SERRMS")
    except Exception as e:
        serrms_log(f"Beklenmeyen hata: {e}", "ERR")
        traceback.print_exc()







































































































