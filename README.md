# SecureScan

SecureScan is a lightweight, self‑contained security assessment web application built with **Flask**, **Python**, and vanilla **HTML/CSS/JS**. It performs network scans, aggregates findings, and generates polished PDF/HTML reports that highlight critical and high‑severity issues along with their business impact.

---

## ✨ Features

- **Interactive dashboard** – view scan history, explore findings, and filter by severity.
- **Report Editor** – edit the Executive Summary and Assessment Methodology directly in the UI; changes are persisted and reflected in generated PDFs/HTML.
- **One‑click PDF/HTML export** – generate professional reports with custom executive summary and methodology.
- **Embedded Report Viewer** – view generated reports inside the application without leaving the SPA.
- **Customizable alerts** – highlight critical findings with business‑impact text.
- **Responsive design** – modern glass‑morphism UI that works on desktop browsers.

---

## 📦 Prerequisites

- **Python 3.9+** (tested on 3.11)
- **pip** (comes with Python)
- **Git** (optional, for cloning the repo)

---

## 🔧 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/securescan.git
   cd securescan
   ```

2. **Create a virtual environment** (recommended)
   ```bash
   python -m venv venv
   # Windows
   .\venv\Scripts\activate
   # macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```
   The main dependencies are:
   - Flask
   - reportlab (PDF generation)
   - python‑dotenv (optional configuration)

4. **Run the application**
   ```bash
   python app.py
   ```
   By default the server starts on **http://127.0.0.1:5000**.

---

## 🚀 Usage

1. Open a browser and navigate to `http://127.0.0.1:5000`.
2. Use the **Scan** page to start a new security assessment (you can specify a target IP/hostname).
3. After the scan finishes, go to the **Reports** tab. You’ll see a list of recent scans.
4. **Edit** – click the pencil icon to modify the Executive Summary or Methodology. Save changes.
5. **View** – click the eye icon to open the report in the embedded viewer.
6. **Export** – use the PDF or HTML buttons to download the report.

---

## 🗂️ Project Structure

```
securescan/
│
├─ app.py                 # Flask entry point + API routes
├─ report_gen.py          # PDF/HTML report generation logic
├─ static/
│   └─ js/visualize.js   # Front‑end logic (dashboard, editor, viewer)
├─ templates/
│   └─ index.html        # Main SPA layout
├─ scans.db               # SQLite DB (auto‑created on first run)
├─ requirements.txt       # Python dependencies
└─ README.md              # <‑‑ you are reading this!
```

---

## 🧩 Extending / Customising

- **Add new scan modules** – create a Python module that performs the desired enumeration and store results under `data['<module_name>']`. The front‑end will automatically pick it up.
- **Theme tweaks** – edit `static/css/style.css` (or inject inline styles) to change colours, fonts, or glass‑morphism effects.
- **Deploy** – the app can be containerised with Docker or served behind a production WSGI server (Gunicorn, uWSGI, etc.).

---

## 📚 License

This project is licensed under the **MIT License** – feel free to fork, modify, and use it in both personal and commercial projects.

---

## 🙋‍♂️ Support & Contributions

If you encounter bugs or have suggestions, please open an issue or submit a pull request. Contributions are welcome!

---

*Happy scanning!*
