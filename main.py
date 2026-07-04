from fastapi import FastAPI, File, UploadFile, Form, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import JSONResponse, FileResponse
from dotenv import load_dotenv
from database import create_user, verify_user
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import simpleSplit
import os
import groq
import json
import base64
import requests
import re
from datetime import datetime

load_dotenv()

app = FastAPI()
os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
client = groq.Groq(api_key=os.getenv("GROQ_API_KEY"))
OCR_API_KEY = os.getenv("OCR_API_KEY", "K87430929088957")

HISTORY_FILE = "history.json"
file_store = {}

def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []
    with open(HISTORY_FILE, "r") as f:
        return json.load(f)

def save_history(entry):
    history = load_history()
    history.insert(0, entry)
    history = history[:20]
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f)

def ocr_extract(contents, file_type, file_name):
    try:
        payload = {
            "isOverlayRequired": False,
            "apikey": OCR_API_KEY,
            "language": "eng",
            "isTable": True,
            "scale": True,
            "OCREngine": 2
        }
        files = {"file": (file_name, contents, file_type)}
        response = requests.post(
            "https://api.ocr.space/parse/image",
            files=files,
            data=payload,
            timeout=30
        )
        result = response.json()
        if result.get("IsErroredOnProcessing"):
            return None
        parsed = result.get("ParsedResults", [])
        if parsed:
            text = " ".join([p.get("ParsedText", "") for p in parsed])
            if text.strip():
                return text[:5000]
        return None
    except Exception as e:
        return None

def extract_text(contents, file_type, file_name):
    try:
        # Word document
        if "word" in file_type or file_name.lower().endswith(".docx"):
            try:
                import docx
                import io
                doc = docx.Document(io.BytesIO(contents))
                text = "\n".join([p.text for p in doc.paragraphs])
                if text.strip():
                    return text[:5000]
            except:
                pass

        # Excel
        if "excel" in file_type or file_name.lower().endswith(".xlsx"):
            try:
                import openpyxl
                import io
                wb = openpyxl.load_workbook(io.BytesIO(contents))
                text = ""
                for sheet in wb.sheetnames:
                    ws = wb[sheet]
                    for row in ws.iter_rows(values_only=True):
                        text += " | ".join([str(c) for c in row if c]) + "\n"
                if text.strip():
                    return text[:5000]
            except:
                pass

        # Plain text / CSV / JSON / logs
        try:
            text = contents.decode("utf-8", errors="ignore")
            clean = ''.join(c for c in text if c.isprintable() or c in '\n\t ')
            if clean.strip() and len(clean.strip()) > 50:
                return clean[:5000]
        except:
            pass

        # OCR for PDF and images
        if "pdf" in file_type or "image" in file_type or file_name.lower().endswith(".pdf"):
            ocr_text = ocr_extract(contents, file_type, file_name)
            if ocr_text:
                return ocr_text

        return None

    except Exception as e:
        return None

@app.get("/")
def home(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/dashboard")
def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/register")
async def register(username: str = Form(...), email: str = Form(...), password: str = Form(...)):
    success, message = create_user(username, email, password)
    if success:
        return JSONResponse({"status": "success", "message": message})
    return JSONResponse({"status": "error", "message": message}, status_code=400)

@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    if verify_user(username, password):
        return JSONResponse({"status": "success", "message": "Login successful"})
    return JSONResponse({"status": "error", "message": "Invalid username or password"}, status_code=401)

@app.post("/analyze")
async def analyze_file(file: UploadFile = File(...)):
    contents = await file.read()
    file_type = file.content_type
    file_name = file.filename

    clean_text = extract_text(contents, file_type, file_name)

    file_store["current"] = {
        "name": file_name,
        "type": file_type,
        "content_preview": clean_text or "Binary/encoded file - analysis based on metadata",
    }

    if clean_text:
        prompt = f"""You are a forensic analyst. Analyze this file named '{file_name}' (type: {file_type}).

File content:
{clean_text}

Respond in EXACTLY this format:
RISK_SCORE: [a single number from 0-100, 0=completely safe, 100=highly suspicious]

SUMMARY:
[Brief summary of what the file contains]

FORENSIC BREAKDOWN:
[Detailed forensic analysis including content details, anomalies, patterns]

Be specific and professional. Base the risk score on actual content - normal documents like resumes, reports, notes should score LOW (0-20). Only score high for genuinely suspicious content like malware indicators, illegal content, or security threats."""
    else:
        prompt = f"""You are a forensic analyst. Analyze this file named '{file_name}' (type: {file_type}).
File size: {len(contents)} bytes.

Respond in EXACTLY this format:
RISK_SCORE: [a single number from 0-100, 0=completely safe, 100=highly suspicious]

SUMMARY:
[Based on filename and type, summarize what this file likely contains]

FORENSIC BREAKDOWN:
[Analyze file type, typical structure, potential risks]

Be specific and professional. Base the risk score on file type and name - normal documents should score LOW (0-20) unless there's clear suspicious indication."""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1500
    )

    result = response.choices[0].message.content

    # Extract risk score reliably
    risk_score = 20
    match = re.search(r'RISK_SCORE:\s*(\d+)', result)
    if match:
        risk_score = int(match.group(1))
        risk_score = max(0, min(100, risk_score))

    file_store["current"]["analysis"] = result

    entry = {
        "filename": file_name,
        "filetype": file_type,
        "analysis": result,
        "risk_score": risk_score,
        "date": datetime.now().strftime("%Y-%m-%d %H:%M")
    }
    save_history(entry)

    return JSONResponse({"analysis": result, "filename": file_name, "filetype": file_type, "risk_score": risk_score})

@app.post("/ask")
async def ask_question(request: Request):
    data = await request.json()
    question = data.get("question", "")

    if "current" not in file_store:
        return JSONResponse({"answer": "Please upload and analyze a file first!"})

    current = file_store["current"]

    prompt = f"""You are an AI assistant and forensic analyst. A file named '{current["name"]}' (type: {current["type"]}) was uploaded and analyzed.

FORENSIC ANALYSIS REPORT:
{current.get("analysis", "")}

FILE CONTENT (if available):
{current["content_preview"]}

Answer this question based on the analysis and file content above:
{question}

Rules:
- If the question is about content (skills, projects, data), answer from the file content or analysis
- If content is not readable, use the forensic analysis to give the best possible answer
- Always give a helpful, direct answer
- Never say you cannot help"""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1000
    )

    answer = response.choices[0].message.content
    return JSONResponse({"answer": answer})

@app.get("/history")
def get_history():
    return JSONResponse(load_history())

@app.delete("/history/{index}")
async def delete_history_item(index: int):
    history = load_history()
    if 0 <= index < len(history):
        history.pop(index)
        with open(HISTORY_FILE, "w") as f:
            json.dump(history, f)
        return JSONResponse({"status": "success"})
    return JSONResponse({"status": "error", "message": "Invalid index"}, status_code=400)

@app.get("/history/export-pdf")
async def export_history_pdf():
    history = load_history()
    pdf_path = "ufdr_history_report.pdf"
    c = canvas.Canvas(pdf_path, pagesize=letter)
    width, height = letter

    c.setFillColorRGB(0.04, 0.06, 0.12)
    c.rect(0, 0, width, height, fill=1)
    c.setFillColorRGB(0.38, 0.65, 0.98)
    c.setFont("Helvetica-Bold", 20)
    c.drawString(50, height - 60, "UFDR ANALYSIS HISTORY REPORT")
    c.setFillColorRGB(0.58, 0.64, 0.73)
    c.setFont("Helvetica", 11)
    c.drawString(50, height - 85, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}   |   Total Files: {len(history)}")
    c.setFillColorRGB(0.12, 0.23, 0.54)
    c.rect(50, height - 95, width - 100, 1, fill=1)

    y = height - 120
    for idx, item in enumerate(history):
        if y < 100:
            c.showPage()
            c.setFillColorRGB(0.04, 0.06, 0.12)
            c.rect(0, 0, width, height, fill=1)
            y = height - 60

        c.setFillColorRGB(0.38, 0.65, 0.98)
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, f"{idx + 1}. {item['filename']}")
        y -= 18

        c.setFillColorRGB(0.58, 0.64, 0.73)
        c.setFont("Helvetica", 9)
        risk = item.get("risk_score", "N/A")
        c.drawString(50, y, f"Type: {item['filetype']}   |   Risk Score: {risk}/100   |   Date: {item['date']}")
        y -= 20

        c.setFillColorRGB(0.88, 0.90, 1.0)
        c.setFont("Helvetica", 9)
        analysis_preview = item['analysis'][:300].replace('\n', ' ')
        wrapped = simpleSplit(analysis_preview + "...", "Helvetica", 9, width - 100)
        for wline in wrapped[:4]:
            c.drawString(50, y, wline)
            y -= 14

        y -= 15
        c.setFillColorRGB(0.12, 0.23, 0.54)
        c.rect(50, y, width - 100, 0.5, fill=1)
        y -= 15

    c.save()
    return FileResponse(pdf_path, media_type="application/pdf", filename="UFDR_History_Report.pdf")

@app.post("/download-pdf")
async def download_pdf(request: Request):
    data = await request.json()
    filename = data.get("filename", "unknown")
    analysis = data.get("analysis", "")
    date = datetime.now().strftime("%Y-%m-%d %H:%M")

    pdf_path = "ufdr_report.pdf"
    c = canvas.Canvas(pdf_path, pagesize=letter)
    width, height = letter

    c.setFillColorRGB(0.04, 0.06, 0.12)
    c.rect(0, 0, width, height, fill=1)
    c.setFillColorRGB(0.38, 0.65, 0.98)
    c.setFont("Helvetica-Bold", 20)
    c.drawString(50, height - 60, "UFDR ANALYSIS REPORT")
    c.setFillColorRGB(0.58, 0.64, 0.73)
    c.setFont("Helvetica", 11)
    c.drawString(50, height - 85, f"File: {filename}   |   Date: {date}")
    c.setFillColorRGB(0.12, 0.23, 0.54)
    c.rect(50, height - 95, width - 100, 1, fill=1)
    c.setFillColorRGB(0.88, 0.90, 1.0)
    c.setFont("Helvetica", 10)
    y = height - 120
    lines = analysis.split('\n')
    for line in lines:
        wrapped = simpleSplit(line, "Helvetica", 10, width - 100)
        for wline in wrapped:
            if y < 60:
                c.showPage()
                c.setFillColorRGB(0.04, 0.06, 0.12)
                c.rect(0, 0, width, height, fill=1)
                y = height - 60
            c.setFillColorRGB(0.88, 0.90, 1.0)
            c.setFont("Helvetica", 10)
            c.drawString(50, y, wline)
            y -= 16
    c.save()
    return FileResponse(pdf_path, media_type="application/pdf", filename="UFDR_Report.pdf")
