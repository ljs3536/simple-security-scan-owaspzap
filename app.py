import os
import subprocess
import time
import json
from fastapi import FastAPI, Form, File, UploadFile, Response
from fastapi.responses import HTMLResponse
from zapv2 import ZAPv2
# zaproxy/zap-stable:latest images 필요
# docker 에서 OWASP ZAP 실행 명령어 
# docker run -p 8000:8000 -d -e ZAP_JAVA_OPTS="-Xmx2g" zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8000 -config api.disablekey=true -config api.addrs.addr.name=. * -config api.addrs.addr.regex=true
# 
# localhost:8070 -> host.docker.internal:8070
#
# uvicorn app:app --reload --port 9090
app = FastAPI(title="나만의 취약점 점검 포털")

# --- 1. 메인 웹 화면 (HTML 입력 폼) ---
@app.get("/", response_class=HTMLResponse)
async def get_index():
    html_content = """
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <title>통합 취약점 스캐너</title>
        <style>
            body { font-family: sans-serif; padding: 50px; max-width: 800px; margin: auto; }
            .card { border: 1px solid #ddd; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 2px 2px 10px rgba(0,0,0,0.1); }
            input[type="text"], input[type="file"] { width: 80%; padding: 10px; font-size: 16px; margin-bottom: 10px; }
            button { padding: 10px 20px; font-size: 16px; cursor: pointer; background-color: #007bff; color: white; border: none; border-radius: 4px; }
            button:hover { background-color: #0056b3; }
            .loader { display: none; margin-top: 20px; font-weight: bold; color: #d9534f; }
        </style>
    </head>
    <body>
        <h1 style="text-align: center;">🛡️ 통합 취약점 점검 포털</h1>
        
        <div class="card">
            <h2>🔍 소스코드 정적 분석 (SAST)</h2>
            <p>파이썬(.py) 파일을 업로드하여 코드 내 취약점을 분석합니다.</p>
            <form action="/sast" method="post" enctype="multipart/form-data">
                <input type="file" name="file" accept=".py" required><br>
                <button type="submit">코드 취약점 점검 시작</button>
            </form>
        </div>

        <div class="card">
            <h2>🌐 웹 서비스 동적 분석 (DAST)</h2>
            <p>점검할 URL을 입력하세요. (Docker 환경은 host.docker.internal 사용)</p>
            <form action="/dast" method="post" onsubmit="document.getElementById('loading').style.display='block';">
                <input type="text" name="url" value="http://host.docker.internal:8070" required><br>
                <button type="submit">웹 취약점 점검 시작</button>
            </form>
            <div id="loading" class="loader">
                ⏳ ZAP이 해킹 페이로드를 전송 중입니다. 화면을 닫지 마세요... (수 분 소요)
            </div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

# --- 2. SAST (정적 분석) 처리 라우터 ---
@app.post("/sast", response_class=HTMLResponse)
async def run_sast(file: UploadFile = File(...)):
    file_location = f"temp_{file.filename}"
    with open(file_location, "wb") as f:
        f.write(await file.read())

    try:
        # Bandit 실행 (결과를 JSON 형식으로 캡처)
        result = subprocess.run(
            ["bandit", "-f", "json", file_location],
            capture_output=True,
            text=True
        )
        
        # JSON 결과 파싱
        try:
            sast_data = json.loads(result.stdout)
        except json.JSONDecodeError:
            sast_data = {"results": []}

        # 결과를 보기 좋은 HTML 표로 변환
        html_report = f"""
        <!DOCTYPE html>
        <html lang="ko">
        <head><meta charset="UTF-8"><title>SAST 점검 결과</title></head>
        <body style="font-family: sans-serif; padding: 40px; max-width: 900px; margin: auto;">
            <h2>🔍 '{file.filename}' 정적 분석(SAST) 결과</h2>
            <hr>
        """
        
        if not sast_data.get("results"):
            html_report += "<h3 style='color: green;'>✅ 발견된 취약점이 없습니다! 안전한 코드입니다.</h3>"
        else:
            html_report += f"<h3>⚠️ 총 {len(sast_data['results'])}개의 의심되는 코드가 발견되었습니다.</h3>"
            html_report += "<table border='1' cellpadding='10' style='border-collapse: collapse; width: 100%;'>"
            html_report += "<tr style='background-color: #f2f2f2;'><th>위험도</th><th>신뢰도</th><th>취약점 설명</th><th>코드 라인</th></tr>"
            
            for issue in sast_data["results"]:
                # 위험도에 따라 글자 색상 변경
                color = "red" if issue.get('issue_severity') == "HIGH" else ("orange" if issue.get('issue_severity') == "MEDIUM" else "black")
                html_report += f"""
                <tr>
                    <td style='color: {color}; font-weight: bold;'>{issue.get('issue_severity')}</td>
                    <td>{issue.get('issue_confidence')}</td>
                    <td>{issue.get('issue_text')}</td>
                    <td>Line {issue.get('line_number')}</td>
                </tr>
                """
            html_report += "</table>"
            
        html_report += "<br><br><a href='/' style='text-decoration: none; padding: 10px; background: #eee; border-radius: 5px; color: black;'>🔙 메인으로 돌아가기</a>"
        html_report += "</body></html>"
        
        return HTMLResponse(content=html_report)
    
    finally:
        # 검사 완료 후 서버에 남은 임시 파일 삭제
        if os.path.exists(file_location):
            os.remove(file_location)

# --- 3. DAST (동적 분석) 처리 라우터 ---
@app.post("/dast", response_class=HTMLResponse)
async def run_dast(url: str = Form(...)):
    # 수정 전   로컬 환경
    zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8000', 'https': 'http://127.0.0.1:8000'})

    # 수정 후   docker환경
    #zap = ZAPv2(proxies={'http': 'http://zap:8000', 'https': 'http://zap:8000'})
    
    print(f"[{url}] 스파이더링 시작...")
    scan_id = zap.spider.scan(url)
    while int(zap.spider.status(scan_id)) < 100:
        time.sleep(2)
        
    print(f"[{url}] 취약점 점검(Active Scan) 시작...")
    scan_id = zap.ascan.scan(url)
    time.sleep(5)
    
    while True:
        try:
            status = int(zap.ascan.status(scan_id))
            print(f"Active Scan 진행률: {status}%")
            if status >= 100:
                break
        except Exception:
            print("ZAP 응답 지연... 잠시 후 다시 확인합니다.")
        time.sleep(5)
        
    print(f"[{url}] 점검 완료! HTML 리포트 생성 중...")
    report_html = zap.core.htmlreport()
    # 다운로드용 파일명 생성 (예: zap_report_16780000.html)
    filename = f"zap_report_{int(time.time())}.html"
    
    # 브라우저에 띄우지 않고 파일로 다운로드하도록 헤더 설정
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"'
    }
    
    return Response(content=report_html, media_type="text/html", headers=headers)