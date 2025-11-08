import subprocess
import os
import time

# ⬇️ 'run_cmd' is now imported to be used for 'adb pull'
from scripts.mass_dynamic_analysis import (
    upload_apk,
    run_dynamic_with_frida,
    request_dynamic_scan,
    run_cmd,
)

# ----------------------------------------------------------------------
# [핵심 설정] 당신의 환경에 맞게 모든 경로 및 API 키 설정 (S:\jeong\semi2)
# ----------------------------------------------------------------------
PROJECT_ROOT = r"S:\jeong\semi2\Semi-Project-MobSF-Automation"
API_KEY = "6b139f46c4fa179a87438571c83c291e799e1bbb59cf1987d22f1fd634df306b"  # 서버 로그에서 확인된 REST API Key
SERVER_HOST = "127.0.0.1:8000"


# 정적 분석 실행 (수정 없음)
def run_mass_static_analysis():

    apk_dir = os.path.join(PROJECT_ROOT, "data", "apk")
    report_type = 1

    command = [
        "python",
        "scripts/mass_static_analysis.py",
        "-d",
        apk_dir,
        "-s",
        SERVER_HOST,
        "-k",
        API_KEY,
        "-r",
        str(report_type),
    ]

    print(f"[+] Running static analysis...\n{' '.join(command)}\n")
    subprocess.run(command, check=True)
    print("[+] Static analysis completed.\n")


# 동적 분석 실행 (DEX 덤핑 및 재분석 로직 최종 포함)
# main.py의 run_mass_dynamic_analysis 함수를 이걸로 덮어쓰세요.


# main.py 파일의 이 함수를 통째로 복사해서 붙여넣으세요.


def run_mass_dynamic_analysis():
    """난독화 우회 DEX 덤프 기능을 포함한 Frida 기반 동적 분석 실행"""

    # ----------------------------------------------------------------------
    # [1. 환경 설정]
    # ----------------------------------------------------------------------
    apk_dir = os.path.join(PROJECT_ROOT, "data", "apk")

    frida_server_path = os.path.join(
        PROJECT_ROOT, "tools", "frida-server", "frida-server-17.4.4-android-x86"
    )
    frida_script_path = os.path.join(
        PROJECT_ROOT,
        "mobsf",
        "DynamicAnalyzer",
        "tools",
        "frida_scripts",
        "android",
        "others",
        "DumpDex.js",
    )

    adb_path = r"adb"
    aapt_path = r"aapt"
    wait_seconds = 120

    # ----------------------------------------------------------------------
    # [2. APK 파일 검색]
    # ----------------------------------------------------------------------
    apk_files = [
        os.path.join(apk_dir, f) for f in os.listdir(apk_dir) if f.endswith(".apk")
    ]
    if not apk_files:
        print("[!] No APK files found in:", apk_dir)
        return

    print(
        f"[+] Found {len(apk_files)} APK(s). Starting dynamic analysis using Frida...\n"
    )

    for idx, apk_path in enumerate(apk_files, start=1):
        print(f"\n=== ({idx}/{len(apk_files)}) Processing: {apk_path} ===")

        # 1️⃣ MobSF에 APK 업로드 (난독화된 원본)
        upload_resp = upload_apk(SERVER_HOST, API_KEY, apk_path, timeout=120)
        if upload_resp is None:
            print("[!] Upload failed — skipping this APK.")
            continue
        print(f"[+] Original APK Uploaded. Hash: {upload_resp.get('hash')}")

        # ----------------------------------------------------------------------
        # [✨ 2.5. 덤프 폴더 생성 '및' 권한 설정]
        # ----------------------------------------------------------------------
        package_name = "com.ldjSxw.heBbQd"
        remote_dump_dir = f"/data/local/tmp/dex_dumps/"
        print(
            f"[+] Staging: Creating remote dump directory on device: {remote_dump_dir}"
        )
        try:
            # 1. adb shell mkdir -p [경로] (폴더 생성)
            run_cmd([adb_path, "shell", "mkdir", "-p", remote_dump_dir], check=True)

            # 2. [✨ 핵심 수정!] adb shell chmod 777 [경로] (모든 권한 부여)
            run_cmd([adb_path, "shell", "chmod", "777", remote_dump_dir], check=True)

            print(f"[+] Remote directory created and permissions set to 777.")
        except Exception as e:
            print(f"[!] ❌ Failed to create remote directory {remote_dump_dir}: {e}")
            print("[!] This is critical. Aborting run for this APK.")
            continue

        # ----------------------------------------------------------------------
        # [3. 동적 분석 & 4. DEX 덤핑/수집/재분석 (엔진에 모두 위임)]
        # ----------------------------------------------------------------------
        try:
            print(f"[+] Running Frida Dex Dumper (Wait {wait_seconds}s)...")

            out_dir = run_dynamic_with_frida(
                apk_path=apk_path,
                frida_server_local_path=frida_server_path,
                frida_script_path=frida_script_path,
                aapt_path=aapt_path,
                adb_path=adb_path,
                run_timeout=wait_seconds,
                use_tcpdump=False,
                # [✨ 추가된 인자]
                server=SERVER_HOST,
                api_key=API_KEY,
                project_root=PROJECT_ROOT,
                package_name=package_name,
                remote_dump_dir=remote_dump_dir,
            )
            print(
                f"[+] Dynamic (Frida) analysis completed. Artifacts saved to: {out_dir}"
            )
        except Exception as e:
            print(f"[!] Dynamic analysis failed for {apk_path}: {e}")
            continue

        print(f"[*] Sleeping {wait_seconds // 2}s before next APK...")
        time.sleep(wait_seconds // 2)

    print("\n[+] All APKs processed. Automation pipeline completed.\n")


def main():
    """메인 함수: 정적/동적 분석 선택"""
    choice = input("Choose analysis type (Static or Dynamic) [S/D]: ").strip().upper()

    if choice == "S":
        run_mass_static_analysis()
    elif choice == "D":
        run_mass_dynamic_analysis()
    else:
        print("Invalid selection. Please choose 'S' or 'D'.")


if __name__ == "__main__":
    main()
