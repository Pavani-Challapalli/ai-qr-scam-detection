# AI-Based QR Code Scam Detection System

Welcome to the **AI-Based QR Code Scam Detection System**! This application is designed to scan and classify QR codes as **Safe**, **Suspicious**, or **Fraud** using an ensemble of a **Scikit-Learn Machine Learning Classifier** and **OpenCV Computer Vision Core**, served via a responsive **Flask Web Application Dashboard**.

The system utilizes an advanced client-side camera stream to decode QR codes in real-time, extracts structural cyber heuristics from the underlying URLs, feeds them to a trained Random Forest model, and renders a visually stunning cyberpunk security report. It also includes an educational **Quishing (QR Phishing) Defense Simulator** mini-game and a secure **Verified QR Generator**.

---

## 🛠️ Technology Stack
1. **Frontend**: HTML5, CSS3 (Glassmorphism design, keyframe scanner animations), and JavaScript (WebRTC webcam stream, local storage history ledger, and interactive simulator mechanics).
2. **Backend**: Flask Web Framework.
3. **Computer Vision**: OpenCV (`cv2.QRCodeDetector`) for target square detection and payload extraction.
4. **Machine Learning**: Scikit-Learn (`RandomForestClassifier`) for multi-class threat classification based on URL feature extraction.

---

## 📂 Project Structure
```txt
ai-qr-scam-detector/
│
├── app.py                     # Flask web server & heuristic scanner
├── train_model.py             # Dataset generator & Scikit-Learn ML trainer
├── requirements.txt           # Python library dependencies
├── README.md                  # Setup & execution guide
│
├── templates/
│   └── index.html             # High-fidelity dashboard interface
│
└── static/
    ├── css/
    │   └── styles.css         # Dark cyberpunk theme & glowing lasers CSS
    └── js/
        └── main.js            # WebRTC camera capture & state machine JS
```

---

## 🚀 Setup & Execution in VS Code (Windows)

Follow these simple steps to launch the application inside VS Code:

### Step 1: Open Project in VS Code
1. Open **VS Code**.
2. Go to `File` -> `Open Folder...` and select `D:\ai-qr-scam-detector`.

### Step 2: Initialize a Python Virtual Environment
1. Open a new terminal in VS Code (`Ctrl + ~` or Terminal -> `New Terminal`).
2. Run the following command to create a virtual environment:
   ```powershell
   python -m venv venv
   ```
3. Activate the virtual environment:
   ```powershell
   .\venv\Scripts\Activate.ps1
   ```
   *(Note: If you get a script execution policy restriction, you can bypass it with: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` and then run activation again).*

### Step 3: Install Required Dependencies
Run the package manager to install Flask, OpenCV-headless, and Scikit-Learn:
```powershell
pip install -r requirements.txt
```

### Step 4: Train the Scikit-Learn AI Model
Before launching the server, train the machine learning classifier so it can evaluate threat signatures. This creates the serialized model file `scam_detector_model.pkl`:
```powershell
python train_model.py
```
*You will see the model accuracy evaluation (achieving ~98.7% accuracy) and feature importances printed directly to the terminal!*

### Step 5: Start the Flask Web Server
Run the backend server application:
```powershell
python app.py
```

### Step 6: Explore the Dashboard
1. Once the server prints that it is running, click the URL: **[http://127.0.0.1:5000](http://127.0.0.1:5000)** in your browser.
2. **Start Camera Stream** to test real-time camera scanning, or **Browse Files** to upload a QR code image.
3. Test out the **Quishing Defense Simulator** to learn security tactics and achieve high ranks!
4. Generate safe QR codes with customizable targets using the **Verified QR Generator**.

---

## 🔒 Security Signals Evaluated by the AI Core
The system extracts **12 active feature points** to build the security profile:
- **URL Structure**: Total length, number of periods (`.`), hyphens (`-`), and directories (`/`).
- **Shortener Masking**: Detects hidden redirects via services like `bit.ly`, `tinyurl.com`, `t.co`, etc.
- **Top-Level Domain Safety**: Compares against a high-risk TLD index (e.g. `.xyz`, `.top`, `.zip`, `.link`).
- **Hostname Reputation**: Flags direct IPv4 routing and credential concealment symbols (`@`).
- **Brand Typosquatting**: Recognizes lookalike brand attempts hijacking labels from entities like PayPal, Chase, Amazon, Netflix, etc. (e.g. `paypa1-security.xyz`).
- **Social Engineering Words**: Checks for urgent terms (e.g. `login`, `verify`, `billing`, `gift`, `claim`).
