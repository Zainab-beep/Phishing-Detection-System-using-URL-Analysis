# Phishing-Detection-System-using-URL-Analysis
Phishing Detection System using URL Analysis

 Overview
A cybersecurity-focused web application that detects phishing websites by analysing URL characteristics and domain information in real time.
This project was developed as part of a Summer Internship in Ethical Hacking, demonstrating practical implementation of phishing detection techniques.


 Key Highlights
🔍 Analyses URLs to detect phishing attempts

⚡ Real-time risk scoring system

🌐 WHOIS-based domain age verification

🔐 Security-focused feature extraction

📊 Generates clear verdict: Safe / Suspicious / Phishing

🧩 Robust backend with error handling


Tech Stack
Frontend: HTML, CSS, JavaScript
Backend: Python (Flask)
Libraries: whois, datetime, re


 How It Works
The system evaluates multiple parameters:
URL length and structure
Presence of HTTPS
Suspicious keywords in URL
Domain age (via WHOIS lookup)
Special character usage
Each parameter contributes to a risk score, which determines the final verdict.


📂 Project Structure

phishing-detector/
│── static/
│   ├── style.css
│   └── script.js
│── templates/
│   └── index.html
│── app.py
│── utils.py
│── requirements.txt


 Run Locally
git clone https://github.com/your-username/phishing-detector.git
cd phishing-detector
pip install -r requirements.txt
python app.py

Open in browser:
http://127.0.0.1:5000/


Sample Input

https://google.com

Output Includes:
Risk Score
Verdict (Safe / Suspicious / Phishing)
Detailed Analysis


Internship Experience
This project was developed during a Cybersecurity Internship (Ethical Hacking) at Remark Skill Education.
 Duration: April 2025 – May 2025
 Work Done:
Implemented phishing detection logic using URL-based features
Applied cybersecurity concepts in a real-world project
Built a complete full-stack application
Analysed vulnerabilities and improved detection reliability


 Certification
Awarded an Internship Appreciation Letter for successfully completing the project:
> "Phishing Detection System using URL Analysis"



 OUTPUT:
 for safe url:
 <img width="1642" height="1079" alt="Screenshot 2026-04-11 002242" src="https://github.com/user-attachments/assets/7e512309-ce0e-49ca-8b9d-e9a1d9d13175" />


 for phishing url:
<img width="1473" height="1072" alt="Screenshot 2026-04-11 002650" src="https://github.com/user-attachments/assets/39edf216-4523-437f-8608-369c8b0fcd2d" />
