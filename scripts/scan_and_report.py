
#!/usr/bin/env python3
# scripts/scan_and_report.py

import os
import sys
import smtplib
import ssl
import subprocess
from datetime import datetime
from email.mime.text import MIMEText
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import tempfile
import shutil

# ====== 環境変数の取得 ======
EVTX_ROOT       = os.getenv("EVTX_ROOT", "/workspace/evtx")
REPORTS_DIR     = os.getenv("REPORTS_DIR", "/workspace/reports")

CHAINS_MODE     = os.getenv("CHAINS_MODE", "hunt").strip().lower()  # hunt 固定運用
CHAINS_FORMAT   = os.getenv("CHAINS_FORMAT", "csv").strip().lower() # csv|json|log
CHAINS_LEVELS   = [lv.strip() for lv in os.getenv("CHAINS_LEVELS", "").split(",") if lv.strip()]

SIGMA_DIR       = os.getenv("SIGMA_DIR", "").strip()
MAPPING_YML     = os.getenv("MAPPING_YML", "").strip()
CHAINS_RULE_DIR = os.getenv("CHAINS_RULE_DIR", "").strip()  # 未設定でもOK（空ディレクトリを自動生成）

QUIET           = os.getenv("QUIET", "true").strip().lower() == "true"
LOCAL_TIME      = os.getenv("LOCAL_TIME", "true").strip().lower() == "true"
TIMEZONE        = os.getenv("TIMEZONE", "").strip()

FROM            = os.getenv("FROM", "").strip()
TO              = os.getenv("TO", "").strip()

# ディレクトリを渡す場合にのみ使用（今回のファイル単位方式では基本未使用）
EXTENSIONS      = [ext.strip() for ext in os.getenv("EXTENSIONS", ".evtx").split(",") if ext.strip()]

SMTP_HOST       = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT       = int(os.getenv("SMTP_PORT", "587"))
SMTP_TLS        = os.getenv("SMTP_TLS", "true").strip().lower() == "true"
SMTP_USER       = os.getenv("SMTP_USER", "").strip()
SMTP_PASS       = os.getenv("SMTP_PASS", "").strip()
MAIL_FROM       = os.getenv("MAIL_FROM", "").strip()
MAIL_TO         = [addr.strip() for addr in os.getenv("MAIL_TO", "").split(",") if addr.strip()]
MAIL_SUBJECT_PREFIX = os.getenv("MAIL_SUBJECT_PREFIX", "[Chainsaw Detection]").strip()

# ====== 事前チェック ======
def die(msg):
    print(f"[ERROR] {msg}", file=sys.stderr)
    sys.exit(1)

if CHAINS_MODE != "hunt":
    die("このスクリプトは CHAINS_MODE=hunt を前提にしています。search で使う場合はコードを調整してください。")

if not os.path.isdir(EVTX_ROOT):
    die(f"EVTX_ROOT が存在しません: {EVTX_ROOT}")

if not SIGMA_DIR or not os.path.isdir(SIGMA_DIR):
    die(f"SIGMA_DIR が存在しません: {SIGMA_DIR}")

if not MAPPING_YML or not os.path.isfile(MAPPING_YML):
    die(f"MAPPING_YML が存在しません: {MAPPING_YML}")

os.makedirs(REPORTS_DIR, exist_ok=True)

# ====== Chainsaw コマンド組み立て（ファイル単位） ======
def build_hunt_cmd_for_file(evtx_file: str, output_dir: str, rules_dir: str, force_non_quiet: bool = False):
    """
    あなたの chainsaw ビルド仕様:
      Usage: chainsaw hunt --mapping <MAPPING> --output <OUTPUT> --sigma <SIGMA> --csv --local <RULES> [PATH]...

    必須:
      --mapping, --output, --sigma, 出力形式(--csv/--json/--log), --local, <RULES>, [PATH...]
    """
    cmd = ["chainsaw", "hunt",
           "--mapping", MAPPING_YML,
           "--output", output_dir,
           "--sigma", SIGMA_DIR]

    # 出力形式
    if CHAINS_FORMAT == "csv":
        cmd.append("--csv")
    elif CHAINS_FORMAT == "json":
        cmd.append("--json")
    elif CHAINS_FORMAT == "log":
        cmd.append("--log")
    else:
        cmd.append("--csv")

    # レベル指定
    for lv in CHAINS_LEVELS:
        cmd.extend(["--level", lv])

    # ローカル時刻/タイムゾーン
    if LOCAL_TIME:
        cmd.append("--local")
    elif TIMEZONE:
        cmd.extend(["--timezone", TIMEZONE])

    # Chainsaw ネイティブルール（ヘルプにより必須とみなす）
    # 未設定なら空ディレクトリを指す
    cmd.extend(["-r", rules_dir])

    # 期間
    if FROM:
        cmd.extend(["--from", FROM])
    if TO:
        cmd.extend(["--to", TO])

    # quiet 制御
    effective_quiet = (QUIET and not force_non_quiet)
    if effective_quiet:
        cmd.append("-q")

    # 最後に対象ファイル
    cmd.append(evtx_file)

    return cmd


def run_for_host(host_dir: str):
    """
    ホストディレクトリ配下の .evtx をすべて再帰列挙し、
    ファイル単位で chainsaw hunt を実行。chainsaw の --output に同一 out_dir を指定して集約。
    """
    host = os.path.basename(host_dir.rstrip("/"))
    ts = datetime.now().strftime("%Y%m%d%H%M%S")

    # 出力ディレクトリ（chainsaw --output はディレクトリ必須）
    out_dir  = os.path.join(REPORTS_DIR, f"{host}-{ts}")
    os.makedirs(out_dir, exist_ok=True)
    log_path = os.path.join(out_dir, f"{host}-{ts}.log")

    # .evtx を再帰列挙（大小文字対応）
    evtx_files = [str(p.resolve()) for p in Path(host_dir).rglob("*")
                  if p.is_file() and p.suffix.lower() == ".evtx"]

    # RULES_DIR（Chainsaw独自ルール）必須対応：設定が無ければ空ディレクトリを用意
    rules_dir = CHAINS_RULE_DIR
    temp_rules_dir = None
    if not rules_dir:
        temp_rules_dir = tempfile.mkdtemp(prefix="chainsaw_rules_")
        rules_dir = temp_rules_dir  # 空でOK（SigmaのみでもCLI要件を満たすため）

    try:
        if not QUIET:
            # === ログファイル出力（STDOUT/STDERRを結合） ===
            with open(log_path, "w", encoding="utf-8", newline="") as lf:
                # 実行条件ヘッダ
                lf.write(f"# started: {datetime.now().isoformat()}\n")
                lf.write(f"# host_dir: {host_dir}\n")
                lf.write(f"# levels: {','.join(CHAINS_LEVELS) if CHAINS_LEVELS else 'ALL'}\n")
                lf.write(f"# mode: {CHAINS_MODE}, format: {CHAINS_FORMAT}\n")
                lf.write(f"# output_dir: {out_dir}\n")
                lf.write(f"# rules_dir: {rules_dir}\n")
                lf.write("# target files:\n")
                if evtx_files:
                    for f in evtx_files:
                        lf.write(f"#   {f}\n")
                else:
                    lf.write("#   (none found)\n")
                lf.write(f"# target count: {len(evtx_files)}\n\n")

                if not evtx_files:
                    lf.write("# skipped: no .evtx found\n")
                else:
                    # === ファイル単位で Chainsaw を実行し、同一 out_dir に集約 ===
                    for f in evtx_files:
                        cmd = build_hunt_cmd_for_file(f, output_dir=out_dir, rules_dir=rules_dir, force_non_quiet=True)
                        lf.write(f"# cmd: {' '.join(cmd)}\n")
                        subprocess.run(cmd, stdout=lf, stderr=lf, text=True, check=False)

            # === 検出判定 ===
            detected = False
            report_path = None

            if CHAINS_FORMAT == "csv":
                # out_dir 内の CSV のうち、ヘッダー＋1行以上があるファイルがあれば検出あり
                for cf in sorted(Path(out_dir).glob("*.csv")):
                    try:
                        text = Path(cf).read_text(encoding="utf-8", errors="ignore")
                        rows = [ln for ln in text.splitlines() if ln.strip()]
                        if len(rows) > 1:
                            detected = True
                            report_path = str(cf)
                            break
                    except Exception:
                        pass
            elif CHAINS_FORMAT == "json":
                for jf in sorted(Path(out_dir).glob("*.json")):
                    try:
                        if Path(jf).read_text(encoding="utf-8", errors="ignore").strip():
                            detected = True
                            report_path = str(jf)
                            break
                    except Exception:
                        pass
            else:
                # log 形式の場合は自前ログから簡易判定
                try:
                    content = Path(log_path).read_text(encoding="utf-8", errors="ignore")
                    detected = ("DETECTED" in content) or ("Matches:" in content)
                except Exception:
                    detected = False

            status = "DETECTED" if detected else "CLEAN"
            print(f"[{status}] {host} -> {report_path or '(no report file)'} (log: {log_path})")

            return {
                "host": host,
                "report_path": report_path,
                "log_path": log_path,
                "detected": detected,
            }

        else:
            # === QUIET=true：標準出力のみ（ただし --output が必須なので out_dir には出る）。ここでは判定のみ ===
            detected = False
            report_path = None

            # 実行（コマンド出力は抑制）
            if evtx_files:
                for f in evtx_files:
                    cmd = build_hunt_cmd_for_file(f, output_dir=out_dir, rules_dir=rules_dir, force_non_quiet=False)
                    subprocess.run(cmd, capture_output=True, text=True, check=False)

            # 判定ロジックは上と同じ
            if CHAINS_FORMAT == "csv":
                for cf in sorted(Path(out_dir).glob("*.csv")):
                    try:
                        text = Path(cf).read_text(encoding="utf-8", errors="ignore")
                        rows = [ln for ln in text.splitlines() if ln.strip()]
                        if len(rows) > 1:
                            detected = True
                            report_path = str(cf)
                            break
                    except Exception:
                        pass
            elif CHAINS_FORMAT == "json":
                for jf in sorted(Path(out_dir).glob("*.json")):
                    try:
                        if Path(jf).read_text(encoding="utf-8", errors="ignore").strip():
                            detected = True
                            report_path = str(jf)
                            break
                    except Exception:
                        pass
            else:
                detected = False
                report_path = None

            status = "DETECTED" if detected else "CLEAN"
            print(f"[{status}] {host} -> {report_path or '(no report file)'}")
            return {
                "host": host,
                "report_path": report_path,
                "log_path": None if QUIET else log_path,
                "detected": detected,
            }

    except Exception as e:
        print(f"[ERROR] {host}: {e}", file=sys.stderr)
        return {
            "host": host,
            "report_path": None,
            "log_path": None if QUIET else log_path,
            "detected": False,
        }
    finally:
        # 空ルールディレクトリを作った場合は削除
        if temp_rules_dir and os.path.isdir(temp_rules_dir):
            shutil.rmtree(temp_rules_dir, ignore_errors=True)


# ====== メール送信 ======
def send_mail(subject: str, body: str):
    if not (SMTP_HOST and MAIL_FROM and MAIL_TO):
        print("[WARN] SMTP/MAIL の設定が不十分のためメールは送信されません。", file=sys.stderr)
        return

    msg = MIMEText(body, _charset="utf-8")
    msg["Subject"] = subject
    msg["From"]    = MAIL_FROM
    msg["To"]      = ", ".join(MAIL_TO)

    if SMTP_TLS:
        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            if SMTP_USER and SMTP_PASS:
                server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(MAIL_FROM, MAIL_TO, msg.as_string())
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            if SMTP_USER and SMTP_PASS:
                server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(MAIL_FROM, MAIL_TO, msg.as_string())


# ====== メイン ======
def main():
    # evtx/<HOST> のみ対象
    host_dirs = [os.path.join(EVTX_ROOT, d) for d in os.listdir(EVTX_ROOT)
                 if os.path.isdir(os.path.join(EVTX_ROOT, d))]
    if not host_dirs:
        die(f"ホストディレクトリが見つかりません: {EVTX_ROOT}/*")

    results = []
    # 並列数は適宜調整（I/O中心ならやや多めでもOK）
    with ThreadPoolExecutor(max_workers=4) as ex:
        futures = {ex.submit(run_for_host, hd): hd for hd in host_dirs}
        for fut in as_completed(futures):
            res = fut.result()
            results.append(res)
            status = "DETECTED" if res["detected"] else "CLEAN"
            print(f"[{status}] {res['host']} -> {res.get('report_path')}")

    # 検出のあったホストの要約と通知
    detected_hosts = [r for r in results if r["detected"]]
    if detected_hosts:
        lines = []
        lines.append("Chainsaw 検出結果サマリ")
        lines.append(f"対象モード: {CHAINS_MODE}, フォーマット: {CHAINS_FORMAT}")
        if CHAINS_LEVELS:
            lines.append(f"レベルフィルタ: {','.join(CHAINS_LEVELS)}")
        if FROM or TO:
            lines.append(f"期間: {FROM or '-'} ～ {TO or '-'}")
        lines.append("")
        for r in detected_hosts:
            lines.append(f"- {r['host']}: {r['report_path'] or '(report not found)'}")
        body = "\n".join(lines)

        subject = f"{MAIL_SUBJECT_PREFIX} {len(detected_hosts)} host(s) detected"
        send_mail(subject, body)
    else:
        print("[INFO] 検出はありませんでした。メールは送信されません。")


if __name__ == "__main__":
    main()
