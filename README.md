# 🔍 AI-Based UFDR Analysis Tool

An AI-powered **Unified Forensic Data Report (UFDR)** analysis tool built for students and cybersecurity professionals to analyze files and generate forensic reports.

## ✨ Features
- 🔐 **User Authentication** — Secure Login & Register (MongoDB)
- 🔬 **AI File Analysis** — Analyze any file type (PDF, DOCX, XLSX, CSV, Images, TXT)
- ⚠️ **Risk Scoring** — Accurate 0-100 forensic risk score
- 💬 **Ask AI** — Chat with AI about your file contents
- 🎤 **Voice Input** — Speak your questions
- 🔊 **Voice Reader** — AI reads analysis aloud
- 📄 **PDF Report** — Download professional forensic report
- 📋 **History** — View, export, and delete analysis history
- 🌙 **Dark/Light Theme** — Toggle between themes

## 🛠️ Tech Stack
- **Backend:** FastAPI (Python)
- **AI:** Groq LLaMA 3.3 70B
- **Database:** MongoDB Atlas
- **Frontend:** HTML, CSS, JavaScript
- **Deployment:** Render (Free Tier)

## 📁 Project Structure

UFDR-Analysis-Tool/
├── main.py          # FastAPI backend
├── database.py      # MongoDB user auth
├── requirements.txt # Dependencies
├── .env             # API keys (not committed)
├── templates/
│   ├── index.html   # Dashboard
│   └── login.html   # Login/Register
└── static/          # Static files
## ⚙️ Setup Locally

```bash
git clone https://github.com/rnithish18/UFDR-Analysis-Tool.git
cd UFDR-Analysis-Tool
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Create `.env` file:

GROQ_API_KEY=XXXXXXXXXXX
MONGO_URL=XXXXXXXXXXX
OCR_API_KEY=XXXXXXXXXX
Run:
```bash
uvicorn main:app --reload
```

## 👨‍💻 Developer
**Loahith** · Software Engineer
Built with ❤️ using FastAPI + Groq AI + MongoDB

## 📄 License
MIT License
