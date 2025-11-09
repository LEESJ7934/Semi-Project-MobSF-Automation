import requests
import time
import os
import webbrowser

# --- 1. 기본 설정 ---
MOBSF_URL = "http://127.0.0.1:8000"
# 서버 로그에 나온 본인의 API 키로 교체하세요
MOBSF_API_KEY = "6b139f46c4fa179a87438571c83c291e799e1bbb59cf1987d22f1fd634df306b"
# 분석할 APK 파일의 전체 경로
FILE_PATH = r"S:\jeong\semi2\Semi-Project-MobSF-Automation\data\apk\sample.apk"

# API 엔드포인트
UPLOAD_URL = f"{MOBSF_URL}/api/v1/upload"
SCAN_URL = f"{MOBSF_URL}/api/v1/scan"
PDF_URL = f"{MOBSF_URL}/api/v1/download_pdf"
JSON_URL = f"{MOBSF_URL}/api/v1/report_json"
DYNAMIC_START_URL = f"{MOBSF_URL}/api/v1/dynamic/start_analysis"
DYNAMIC_STOP_URL = f"{MOBSF_URL}/api/v1/dynamic/stop_analysis"
DYNAMIC_REPORT_URL = f"{MOBSF_URL}/api/v1/dynamic/report_json"  # 동적 분석 JSON 리포트
INSTRUMENT_URL = f"{MOBSF_URL}/api/v1/frida/instrument"
START_ACTIVITY_URL = f"{MOBSF_URL}/api/v1/android/start_activity"

headers = {"Authorization": MOBSF_API_KEY}


# --- 정적 분석 함수 ---
def run_static_analysis(file_hash):
    print(f"해시 '{file_hash}'에 대한 정적 분석 시작 요청...")
    scan_payload = {"hash": file_hash}
    resp_scan = requests.post(SCAN_URL, headers=headers, data=scan_payload)

    if resp_scan.status_code != 200:
        print(f"스캔 시작 실패: {resp_scan.text}")
        return False

    print("스캔 요청 성공! 분석이 완료될 때까지 대기합니다...")

    # --- 폴링(Polling) + JSON 가져오기 ---
    json_path = "sample_report_auto.json"
    while True:
        time.sleep(5)
        print("스캔 상태 확인 (JSON 리포트 요청 중)...")
        json_payload = {"hash": file_hash}
        resp_json = requests.post(JSON_URL, headers=headers, data=json_payload)

        if resp_json.status_code == 200:
            print("스캔 완료! JSON 리포트 저장 중...")
            with open(json_path, "w", encoding="utf-8") as f:
                f.write(resp_json.text)
            print(f"JSON 리포트 저장 완료: {json_path}")
            break
        elif resp_json.status_code == 404:
            print("아직 분석 중...")
        else:
            print(
                f"리포트 조회 실패 (상태 코드: {resp_json.status_code}): {resp_json.text}"
            )
            return False

    # --- PDF 가져오기 ---
    print("\n--- PDF 리포트 다운로드 ---")
    pdf_payload = {"hash": file_hash}
    resp_pdf = requests.post(PDF_URL, headers=headers, data=pdf_payload, stream=True)

    if resp_pdf.status_code == 200:
        pdf_path = "sample_report_auto.pdf"
        with open(pdf_path, "wb") as f:
            f.write(resp_pdf.content)
        print(f"PDF 리포트 저장 완료: {pdf_path}")
        webbrowser.open(os.path.realpath(pdf_path))
    else:
        print(f"PDF 다운로드 실패: {resp_pdf.text}")

    return True


# --- 동적 분석 함수 (수정됨) ---
def run_dynamic_analysis(file_hash, main_activity):
    print(f"해시 '{file_hash}'에 대한 동적 분석 시작 요청...")

    # 1. '환경 준비' 및 '설치' API 호출
    scan_payload = {"hash": file_hash}
    resp_start = requests.post(DYNAMIC_START_URL, headers=headers, data=scan_payload)
    if resp_start.status_code != 200:
        print(f"동적 분석 시작/설치 실패: {resp_start.text}")
        print(
            "Genymotion 에뮬레이터가 켜져 있고, MobSF 서버 로그에 'Connecting to...' 메시지가 나오는지 확인하세요."
        )
        return False
    print(f"동적 분석 환경 준비 및 '설치' 완료! (서버 로그 확인)")

    # ========== [ 수정된 부분 ] ==========
    # 2. '앱 실행' API 호출 (ADB Monkey 대신 'start_activity' 사용)
    #    이것이 '수동 클릭'을 '자동화'로 대체하는 것입니다.
    print(f"'{main_activity}' 액티비티를 '자동'으로 실행합니다... (Anti-Frida 우회)")
    start_payload = {"hash": file_hash, "activity": main_activity}
    resp_adb = requests.post(START_ACTIVITY_URL, headers=headers, data=start_payload)
    if resp_adb.status_code != 200:
        print(f"액티비티 실행 실패: {resp_adb.text}")
        return False

    print("앱 실행 완료. 3초 후 Frida 'Attach' 시도...")
    time.sleep(3)  # 앱이 로딩될 시간을 줌
    # ====================================

    # 3. 'Frida 접속(Attach)' API 호출
    print("Frida 계측(Attach) 요청...")
    default_hooks = "root_bypass,ssl_pinning_bypass"
    instrument_payload = {
        "hash": file_hash,
        "default_hooks": default_hooks,
        "auxiliary_hooks": "",
        "frida_code": "",
        "frida_action": "session",  # 'Spawn'이 아닌 'Session' (Attach) 모드
    }
    resp_instrument = requests.post(
        INSTRUMENT_URL, headers=headers, data=instrument_payload
    )
    if resp_instrument.status_code != 200:
        print(f"Frida 계측(Attach) 실패: {resp_instrument.text}")
        return False

    print("앱에 성공적으로 'Attach' 되었습니다! (서버 로그 확인)")

    # 4. '수동 테스트' 시간
    print("\n========================================================")
    print(" [수동 조작 필요] - (본 분석)")
    print(" 1. '자동 실행된' 앱을 '마음껏' 조작하며 테스트하세요.")
    print(" 2. 서버 터미널에 [Frida] 로그가 뜨는지 확인하세요.")
    print(" 3. 분석을 완료하고 리포트를 생성하려면 Enter 키를 누르세요...")
    print("========================================================")
    input()  # 사용자가 '테스트'를 마치고 Enter를 칠 때까지 대기

    # ... (5. 분석 중지 / 6. 리포트 생성 - 이전과 동일) ...
    print("동적 분석 중지 및 리포트 생성 요청 중...")
    stop_payload = {"hash": file_hash}
    resp_stop = requests.post(DYNAMIC_STOP_URL, headers=headers, data=stop_payload)
    if resp_stop.status_code != 200:
        print(f"동적 분석 중지 실패: {resp_stop.text}")
        return False
    print("분석 중지 및 데이터 수집 완료.")

    print("동적 분석 JSON 리포트 다운로드 중...")
    json_payload = {"hash": file_hash}
    resp_json = requests.post(DYNAMIC_REPORT_URL, headers=headers, data=json_payload)
    if resp_json.status_code == 200:
        json_path = "dynamic_report_auto.json"
        with open(json_path, "w", encoding="utf-8") as f:
            f.write(resp_json.text)
        print(f"동적 JSON 리포트 저장 완료: {json_path}")
    else:
        print(f"동적 JSON 리포트 다운로드 실패: {resp_json.text}")
    return True


# --- 메인 함수 (수정됨) ---
def main():
    try:
        mode = ""
        while mode not in ["s", "d"]:
            mode = input("분석 타입을 선택하세요 (정적: s, d): ").lower().strip()

        print("\n--- 1. Trigger (트리거) 단계: 파일 업로드 ---")
        print(f"'{FILE_PATH}' 파일 업로드 중...")
        filename = os.path.basename(FILE_PATH)
        with open(FILE_PATH, "rb") as f:
            files = {"file": (filename, f, "application/vnd.android.package-archive")}
            resp_upload = requests.post(UPLOAD_URL, headers=headers, files=files)
        if resp_upload.status_code != 200:
            print(f"파일 업로드 실패: {resp_upload.text}")
            return

        upload_data = resp_upload.json()
        file_hash = upload_data.get("hash")

        # ========== [ 수정된 부분 ] ==========
        # '동적 분석'에 '메인 액티비티' 이름이 필요하므로 'upload' 응답에서 추출
        main_activity = upload_data.get("main_activity")
        if not main_activity:
            # 'main_activity' 키가 없을 경우를 대비
            main_activity = upload_data.get("app_info", {}).get(
                "main_activity", "com.ldjSxw.heBbQd.IntroActivity"
            )
            # [cite_start](우리는 PDF 리포트에서 이미 'IntroActivity'임을 알고 있습니다 [cite: 900])
        # ====================================

        print(f"파일 업로드 성공! 해시(hash): {file_hash}")

        if mode == "s":
            print("\n--- 2. 정적 분석(Static Analysis) 시작 ---")
            run_static_analysis(file_hash)
        elif mode == "d":
            print("\n--- 2. 동적 분석(Dynamic Analysis) 시작 ---")
            # 'main_activity' 이름을 동적 분석 함수로 전달
            run_dynamic_analysis(file_hash, main_activity)

        print("\n모든 작업 완료!")

    except requests.exceptions.ConnectionError:
        print("\n[에러] MobSF 서버에 연결할 수 없습니다.")
        print(f"'{MOBSF_URL}' 주소가 올바른지, MobSF 서버가 실행 중인지 확인하세요.")
    except Exception as e:
        print(f"\n[알 수 없는 에러] {e}")


if __name__ == "__main__":
    main()
