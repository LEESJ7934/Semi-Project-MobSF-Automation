#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mass_dynamic_analysis.py (Frida-integrated)
"""
import argparse
import os
import time
import requests
import sys
import tempfile
import shutil
import re
import json
import subprocess
from pathlib import Path
from typing import Optional

# Frida import - required when --use-frida is used
try:
    import frida
except Exception:
    frida = None

DEFAULT_UPLOAD_ENDPOINT = "/api/v1/upload"
DEFAULT_DYNAMIC_ENDPOINT = "/api/v1/scan/"


# -----------------------
# Utility helper
# -----------------------
def run_cmd(cmd, check=True, shell=False, env=None):
    """
    cmd: list or string
    returns stdout (str)
    raises RuntimeError on failure if check=True
    """
    #
    # [수정 1] -----------------------------------------------------------
    # 'cp949' 인코딩 오류를 막기 위해 encoding='utf-8', errors='ignore' 추가
    # ----------------------------------------------------------------------
    if isinstance(cmd, list):
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            env=env,
            shell=False,
        )
    else:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            env=env,
            shell=True,
        )
    out = proc.stdout or ""
    err = proc.stderr or ""
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"Command failed (rc={proc.returncode}): {cmd}\nstdout: {out}\nstderr: {err}"
        )
    return out.strip()


# -----------------------
# MobSF API helpers
# -----------------------
def upload_apk(server: str, api_key: str, apk_path: str, timeout=120) -> Optional[dict]:
    url = f"http://{server.rstrip('/')}{DEFAULT_UPLOAD_ENDPOINT}"
    headers = {"Authorization": api_key}
    resp = None
    try:
        with open(apk_path, "rb") as f:
            files = {
                "file": (
                    os.path.basename(apk_path),
                    f,
                    "application/octet-stream",  # .dex 파일 업로드를 위해 vnd.android.package-archive에서 변경
                )
            }
            resp = requests.post(url, files=files, headers=headers, timeout=timeout)
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        print(f"[ERROR] Upload failed for {apk_path}: {e}")
        if resp is not None:
            try:
                print(f"  Response: {resp.status_code} {resp.text[:400]}")
            except:
                pass
        return None


def request_dynamic_scan(
    server: str, api_key: str, scan_endpoint: str, upload_resp: dict, timeout=120
) -> Optional[dict]:
    url = f"http://{server.rstrip('/')}{scan_endpoint}"
    headers = {"Authorization": api_key, "Content-Type": "application/json"}
    payload = {}
    if not upload_resp:
        print("[ERROR] upload_resp is empty")
        return None
    # find common fields
    for f in ("hash", "sha256", "file", "file_name"):
        if f in upload_resp:
            payload[f] = upload_resp[f]
            break
    if not payload:
        payload.update(upload_resp)
    resp = None
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=timeout)
        resp.raise_for_status()
        try:
            return resp.json()
        except ValueError:
            return {"text": resp.text}
    except Exception as e:
        print(f"[ERROR] Dynamic scan request failed: {e}")
        try:
            if resp is not None:
                print(f"  Response: {resp.status_code} {resp.text[:400]}")
        except:
            pass
        return None


# -----------------------
# ADB / Frida flow
# -----------------------
def adb_push_and_start_frida(
    adb_path, frida_server_local_path, remote_path="/data/local/tmp/frida-server"
):
    print(
        f"[+] Pushing frida-server to device: {frida_server_local_path} -> {remote_path}"
    )
    run_cmd([adb_path, "push", frida_server_local_path, remote_path])
    run_cmd([adb_path, "shell", "chmod", "755", remote_path])
    # start in background; use nohup to detach (works on typical Android shell)
    start_cmd = f"nohup {remote_path} >/data/local/tmp/frida_server.log 2>&1 &"
    try:
        run_cmd([adb_path, "shell", start_cmd], shell=True)
    except RuntimeError as e:
        # some devices don't have nohup; try simple background
        run_cmd([adb_path, "shell", f"{remote_path} &"], shell=True)
    time.sleep(1)
    # check
    try:
        out = run_cmd(
            [adb_path, "shell", "ps -A | grep frida || ps | grep frida"],
            check=False,
            shell=True,
        )
        print("[+] frida-server process check:", out[:400])
    except Exception:
        pass


def get_package_name_from_apk(aapt_path, apk_path):
    out = run_cmd([aapt_path, "dump", "badging", apk_path])
    m = re.search(r"package: name='([^']+)'", out)
    if not m:
        raise RuntimeError("Failed to get package name via aapt")
    return m.group(1)


def install_apk(adb_path, apk_path):
    print(f"[ADB] Installing {apk_path}")
    out = run_cmd([adb_path, "install", "-r", apk_path], shell=False)
    print("[ADB] install output:", out[:400])
    time.sleep(1)


def start_tcpdump_on_device(adb_path, remote_pcap="/sdcard/dynamic_capture.pcap"):
    # assumes tcpdump binary exists on device path or in /system/xbin
    try:
        # try nohup invocation
        cmd = f"nohup tcpdump -i any -w {remote_pcap} >/dev/null 2>&1 &"
        run_cmd([adb_path, "shell", cmd], shell=True)
        time.sleep(1)
        print("[+] tcpdump started on device at", remote_pcap)
        return remote_pcap
    except Exception as e:
        print("[!] tcpdump start failed:", e)
        raise


def pull_file(adb_path, remote_path, local_path):
    run_cmd([adb_path, "pull", remote_path, local_path], shell=False)
    print(f"[+] Pulled {remote_path} -> {local_path}")


def run_monkey(adb_path, package_name, events=500, throttle_ms=200):
    cmd = [
        adb_path,
        "shell",
        "monkey",
        "-p",
        package_name,
        "--throttle",
        str(throttle_ms),
        str(events),
    ]
    print("[+] Running monkey to generate UI events")
    p = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="ignore",
    )
    return p


#
# [수정 2] -----------------------------------------------------------
# 'adb_path'를 인자로 추가하고, 'time.sleep'을 'run_monkey'로 대체
# ----------------------------------------------------------------------
# mass_dynamic_analysis.py 파일의 이 함수를 수정하세요.
def frida_instrument_and_run(package_name, frida_script_path, adb_path, timeout=60):
    if frida is None:
        raise RuntimeError("frida python package not installed (pip install frida)")
    device = None
    try:
        device = frida.get_usb_device(timeout=5)
    except Exception as e:
        # fallback to get_local_device
        device = frida.get_local_device()
    print("[+] Frida device connected:", device)

    pid = device.spawn([package_name])
    session = device.attach(pid)
    print(f"[+] Spawned {package_name} pid={pid}, attached")

    with open(frida_script_path, "r", encoding="utf-8") as f:
        script_src = f.read()

    def on_message(message, data):
        # [FRIDA] 로그가 터미널에 실시간으로 보이도록 수정
        if message.get("type") == "send":
            # DumpDex.js 스크립트의 console.log/warn/error를 터미널에 출력
            payload = message.get("payload", {})
            if isinstance(payload, dict):
                # frida-tools 12.x+ 스타일
                level = payload.get("level", "info")
                text = payload.get("message", str(payload))
                print(f"[FRIDA SCRIPT - {level.upper()}] {text}")
            else:
                # 구형 스타일
                print(f"[FRIDA SCRIPT] {payload}")
        elif message.get("type") == "error":
            print(f"[FRIDA ERROR] {message.get('description')}")
        else:
            print("[FRIDA]", message, data if data else "")

    script = session.create_script(script_src)
    script.on("message", on_message)
    script.load()
    print("[+] Frida script loaded")
    device.resume(pid)
    print("[+] App resumed; instrumentation active")

    try:
        print("[+] Running monkey to generate UI events (while Frida is attached)...")
        monkey_proc = run_monkey(adb_path, package_name, events=500, throttle_ms=200)

        # ⬇️ [핵심 수정!] -----------------------------------------------------------
        # Monkey가 타임아웃되어도 파이프라인이 중단되지 않도록 예외 처리
        # ----------------------------------------------------------------------
        try:
            monkey_proc.wait(timeout=timeout + 30)
            print("[+] Monkey finished.")
        except subprocess.TimeoutExpired:
            monkey_proc.terminate()
            print("[+] Monkey timed out (as expected), terminating Monkey.")

    finally:
        try:
            script.unload()
        except Exception:
            pass
        try:
            session.detach()
        except Exception:
            pass
        print("[+] Frida session ended")


# mass_dynamic_analysis.py 파일의 이 함수를 덮어쓰세요.


def run_dynamic_with_frida(
    apk_path,
    frida_server_local_path,
    frida_script_path,
    aapt_path="aapt",
    adb_path="adb",
    run_timeout=60,
    use_tcpdump=True,
    # [✨ 핵심 수정!] main.py로부터 API 키와 경로 정보 등을 전달받습니다.
    server: str = "",
    api_key: str = "",
    project_root: str = "",
    package_name: str = "",
    remote_dump_dir: str = "",
):
    # sanity checks
    if not Path(apk_path).exists():
        raise FileNotFoundError(apk_path)
    if not Path(frida_server_local_path).exists():
        raise FileNotFoundError(frida_server_local_path)
    if not Path(frida_script_path).exists():
        raise FileNotFoundError(frida_script_path)

    # 1 push & start frida-server
    adb_push_and_start_frida(adb_path, frida_server_local_path)

    # 2 install apk
    install_apk(adb_path, apk_path)

    # 3 get package name (main.py에서 받은 값 사용)
    if not package_name:
        package = get_package_name_from_apk(aapt_path, apk_path)
    else:
        package = package_name
    print("[+] package:", package)

    # 4 start tcpdump (optional)
    remote_pcap = None
    out_dir = Path(tempfile.mkdtemp(prefix="dynamic_out_"))
    if use_tcpdump:
        try:
            remote_pcap = "/sdcard/dynamic_capture.pcap"
            start_tcpdump_on_device(adb_path, remote_pcap)
        except Exception as e:
            print("[!] tcpdump start failed, continuing without pcap:", e)
            remote_pcap = None

    # 5 instrument with frida (spawn+attach+script)
    frida_instrument_and_run(package, frida_script_path, adb_path, timeout=run_timeout)

    # [✨ 6. 덤프된 DEX 수집 및 재분석 (엔진 내부로 이동)]
    # Frida 세션 종료 '즉시' adb pull을 실행하여 앱 자폭/재부팅보다 빠르게 파일을 수집합니다.
    if server and api_key and project_root and remote_dump_dir:
        local_dump_dir = os.path.join(project_root, "dumped_dex_files", package)
        print(
            f"[+] Pulling dumped DEX files from {remote_dump_dir} to {local_dump_dir}"
        )
        try:
            os.makedirs(local_dump_dir, exist_ok=True)
            run_cmd([adb_path, "pull", remote_dump_dir, local_dump_dir], check=True)

            dumped_files = [
                os.path.join(local_dump_dir, f)
                for f in os.listdir(local_dump_dir)
                if f.endswith(".dex")
            ]

            if not dumped_files:
                print("[!] No .dex files were pulled. Dex dump might have failed.")
            else:
                print(
                    f"[+] Found {len(dumped_files)} dumped .dex files. Re-analyzing..."
                )
                for dex_file_path in dumped_files:
                    print(
                        f"[+] Re-uploading {os.path.basename(dex_file_path)} for static analysis..."
                    )
                    re_upload_resp = upload_apk(
                        server, api_key, dex_file_path, timeout=120
                    )
                    if re_upload_resp:
                        print(
                            f"[+] ✅ Successfully Re-Analyzed {os.path.basename(dex_file_path)}. Hash: {re_upload_resp.get('hash')}"
                        )
                    else:
                        print(f"[!] ❌ Failed to re-analyze {dex_file_path}")
        except Exception as e:
            print(f"[!] ❌ Failed to pull or re-analyze dumped DEX files: {e}")
    else:
        print(
            "[WARN] server/api_key not provided to run_dynamic_with_frida. Skipping DEX re-analysis."
        )

    # 7 pull artifacts
    if remote_pcap:
        local_pcap = str(out_dir / "capture.pcap")
        try:
            pull_file(adb_path, remote_pcap, local_pcap)
        except Exception as e:
            print("[!] failed to pull pcap:", e)

    # logs
    local_log = str(out_dir / "logcat.txt")
    try:
        # collect and write logcat to file
        lc = run_cmd([adb_path, "logcat", "-d"], check=False, shell=False)
        with open(local_log, "w", encoding="utf-8") as f:
            f.write(lc)
    except Exception as e:
        print("[!] logcat collect failed:", e)

    print(f"[+] dynamic artifacts saved to {out_dir}")
    return str(out_dir)


# -----------------------
# CLI and main (수정 없음)
# -----------------------
def find_apks_in_dir(directory: str):
    p = Path(directory)
    if not p.exists():
        raise FileNotFoundError(f"APK directory not found: {directory}")
    return sorted([str(x) for x in p.rglob("*.apk")])


def parse_args():
    p = argparse.ArgumentParser(
        description="Mass Dynamic Analysis for MobSF (upload + dynamic scan or frida-run)"
    )
    p.add_argument("-d", "--dir", required=True, help="Directory containing APKs")
    p.add_argument(
        "-s",
        "--server",
        required=True,
        help="MobSF server host:port (e.g. 127.0.0.1:8000)",
    )
    p.add_argument("-k", "--key", required=True, help="MobSF API key")
    p.add_argument(
        "-e",
        "--dynamic-endpoint",
        default=DEFAULT_DYNAMIC_ENDPOINT,
        help="MobSF dynamic scan endpoint path",
    )
    p.add_argument(
        "--wait",
        type=int,
        default=30,
        help="Seconds to wait after triggering dynamic analysis / ADB run",
    )
    p.add_argument("--adb-path", default="adb", help="Optional: path to adb (adb.exe)")
    p.add_argument(
        "--aapt-path", default="aapt", help="Path to aapt (aapt.exe on Windows)"
    )
    p.add_argument(
        "--package-name",
        default=None,
        help="Optional: package name to launch when using adb",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not actually post dynamic scan; just upload and print what would be done",
    )
    p.add_argument(
        "--upload-timeout", type=int, default=120, help="Timeout for upload requests"
    )
    p.add_argument(
        "--scan-timeout",
        type=int,
        default=120,
        help="Timeout for dynamic scan requests",
    )
    # frida-specific
    p.add_argument(
        "--use-frida",
        action="store_true",
        help="Use frida-server + adb local dynamic analysis instead of MobSF dynamic API",
    )
    p.add_argument(
        "--frida-server-path",
        default=None,
        help="Local path to frida-server binary to push to device",
    )
    p.add_argument(
        "--frida-script",
        default=None,
        help="Local path to frida JS script to load into target app",
    )
    p.add_argument(
        "--no-tcpdump", action="store_true", help="Disable tcpdump collection on device"
    )
    return p.parse_args()


def main():
    args = parse_args()
    apk_list = find_apks_in_dir(args.dir)
    if not apk_list:
        print("[!] No APK files found. Exiting.")
        return

    print(f"[+] Found {len(apk_list)} APK(s).")
    for idx, apk in enumerate(apk_list, start=1):
        print(f"\n=== ({idx}/{len(apk_list)}) Processing: {apk} ===")
        upload_resp = upload_apk(
            args.server, args.key, apk, timeout=args.upload_timeout
        )
        if upload_resp is None:
            print("[!] Upload failed — skipping dynamic scan for this APK.")
            continue

        print(f"[+] Upload response keys: {list(upload_resp.keys())}")
        if args.dry_run:
            print(
                "[DRY RUN] Would request dynamic scan with payload derived from upload response."
            )
            continue

        # If use-frida, run local frida orchestration instead of calling dynamic API
        if args.use - frida:
            print("[*] use-frida selected. Running local Frida-based dynamic analysis.")
            if not args.frida_server_path or not args.frida_script:
                print(
                    "[ERROR] --frida-server-path and --frida-script are required when using --use-frida"
                )
            else:
                try:
                    out_dir = run_dynamic_with_frida(
                        apk_path=apk,
                        frida_server_local_path=args.frida_server_path,
                        frida_script_path=args.frida_script,
                        aapt_path=args.aapt_path,
                        adb_path=args.adb_path,
                        run_timeout=args.wait,
                        use_tcpdump=not args.no - tcpdump,
                    )
                    print(f"[+] Frida dynamic run artifacts: {out_dir}")
                except Exception as e:
                    print(f"[!] Frida dynamic run failed: {e}")
        else:
            # optionally install + run via adb
            if args.adb_path:
                print(
                    "[*] ADB integration requested. Attempting to install & run on emulator/device."
                )
                try:
                    install_apk(args.adb_path, apk)
                    if args.package_name:
                        # Basic launch via monkey
                        p = run_monkey(
                            args.adb_path,
                            args.package_name,
                            events=100,
                            throttle_ms=200,
                        )
                        try:
                            p.wait(timeout=args.wait + 10)
                        except subprocess.TimeoutExpired:
                            p.terminate()
                except Exception as e:
                    print("[!] ADB install/run failed:", e)

            # Request dynamic scan via MobSF API (legacy)
            dyn_resp = request_dynamic_scan(
                args.server,
                args.key,
                args.dynamic_endpoint,
                upload_resp,
                timeout=args.scan_timeout,
            )
            if dyn_resp:
                safe_name = Path(apk).stem
                out_dir = Path("dynamic_scan_results")
                out_dir.mkdir(parents=True, exist_ok=True)
                out_path = out_dir / f"{safe_name}_dynamic_response.json"
                try:
                    with open(out_path, "w", encoding="utf-8") as f:
                        json.dump(dyn_resp, f, indent=2, ensure_ascii=False)
                    print(f"[+] Dynamic API response saved to {out_path}")
                except Exception as e:
                    print(f"[WARN] Could not save dynamic response JSON: {e}")
            else:
                print("[!] Dynamic API returned no/invalid response.")

        print(f"[*] Sleeping {args.wait}s before next APK...")
        time.sleep(args.wait)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting.")
        sys.exit(1)
