import subprocess
import os
import time
from scripts.mass_dynamic_analysis import upload_apk, run_dynamic_with_frida, request_dynamic_scan

def run_mass_static_analysis():
    """MobSF 정적 분석 실행"""
    apk_dir = r"C:\Users\Seung Jun\Desktop\Semi-Project\Semi-Project-MobSF-Automation\data\apk"
    server = "127.0.0.1:8000"
    api_key = "3ad5653dd25b1946d5a20a0053d36fd0dbb1817684f2a9b0a1915f7b4505982b"
    report_type = 1  # 1: HTML 리포트, 2: JSON 등 가능

    command = [
        "python",
        "scripts/mass_static_analysis.py",
        "-d", apk_dir,
        "-s", server,
        "-k", api_key,
        "-r", str(report_type)
    ]

    print(f"[+] Running static analysis...\n{' '.join(command)}\n")
    subprocess.run(command, check=True)
    print("[+] Static analysis completed.\n")


def run_mass_dynamic_analysis():
    """Frida 기반 MobSF 동적 분석 실행"""
    # 설정값 (필요에 따라 변경)
    apk_dir = r"C:\Users\Seung Jun\Desktop\Semi-Project\Semi-Project-MobSF-Automation\data\apk"
    server = "127.0.0.1:8000"
    api_key = "3ad5653dd25b1946d5a20a0053d36fd0dbb1817684f2a9b0a1915f7b4505982b"

    # Frida 관련 경로 설정
    frida_server_path = r"C:\Users\Seung Jun\Desktop\Semi-Project\Semi-Project-MobSF-Automation\tools\frida-server\frida-server-17.4.4-android-x86"
    frida_script_path = r"C:\Users\Seung Jun\Desktop\Semi-Project\Semi-Project-MobSF-Automation\mobsf\DynamicAnalyzer\tools\frida_scripts\android\others\ssl-pinning-bypass.js"

    # adb / aapt 경로 설정
    adb_path = r"adb"  # PATH에 등록되어 있다면 그냥 'adb'로 사용 가능
    aapt_path = r"C:\Users\Seung Jun\AppData\Local\Android\Sdk\build-tools\36.1.0\aapt.exe"

    # 대기 시간 (앱 실행 후 모니터링 시간)
    wait_seconds = 60

    # APK 디렉터리 내 모든 APK 찾기
    apk_files = [os.path.join(apk_dir, f) for f in os.listdir(apk_dir) if f.endswith(".apk")]
    if not apk_files:
        print("[!] No APK files found in:", apk_dir)
        return

    print(f"[+] Found {len(apk_files)} APK(s). Starting dynamic analysis using Frida...\n")

    for idx, apk_path in enumerate(apk_files, start=1):
        print(f"\n=== ({idx}/{len(apk_files)}) Processing: {apk_path} ===")

        # 1️⃣ MobSF에 APK 업로드 (trace용)
        upload_resp = upload_apk(server, api_key, apk_path, timeout=120)
        if upload_resp is None:
            print("[!] Upload failed — skipping this APK.")
            continue
        print(f"[+] Upload response keys: {list(upload_resp.keys())}")

        # 2️⃣ Frida 기반 동적 분석 실행
        try:
            out_dir = run_dynamic_with_frida(
                apk_path=apk_path,
                frida_server_local_path=frida_server_path,
                frida_script_path=frida_script_path,
                aapt_path=aapt_path,
                adb_path=adb_path,
                run_timeout=wait_seconds,
                use_tcpdump=True
            )
            print(f"[+] Dynamic (Frida) analysis completed. Artifacts saved to: {out_dir}")
        except Exception as e:
            print(f"[!] Dynamic analysis failed for {apk_path}: {e}")

        # 3️⃣ (선택) MobSF dynamic_scan API 호출 (현재 MobSF 버전에선 404일 수 있음)
        # dyn_resp = request_dynamic_scan(server, api_key, "/api/v1/dynamic_scan/", upload_resp, timeout=120)
        # if dyn_resp:
        #     print("[+] MobSF dynamic API response received.")
        # else:
        #     print("[!] MobSF dynamic API unavailable (404 expected).")

        print(f"[*] Sleeping {wait_seconds}s before next APK...")
        time.sleep(wait_seconds)

    print("\n[+] All APKs processed. Dynamic analysis completed.\n")


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