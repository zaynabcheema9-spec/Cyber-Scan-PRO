from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO
import time

from database import init_db, save_scan, get_all_scans
from flask import send_file
import io
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize DB
init_db()


# =========================
# DASHBOARD UI
# =========================
@app.route("/")
def dashboard():
    return render_template("index.html")


# =========================
# LIVE SCAN ENDPOINT
# =========================
@app.route("/scan", methods=["POST"])
def scan():
    data = request.json

    target = data.get("target")
    ip = data.get("ip", "Unknown")
    open_ports = data.get("open_ports", [])
    vulnerabilities = data.get("vulnerabilities", [])
    risk_score = data.get("risk_score", 0)

    if not target:
        return jsonify({"error": "Target required"}), 400

    # Simulated scan steps (REAL-TIME UI)
    steps = [
        "Initializing scanner...",
        "Resolving target...",
        "Scanning ports...",
        "Detecting services...",
        "Checking vulnerabilities...",
        "Analyzing risk score...",
        "Finalizing report..."
    ]

    total = len(steps)

    for i, step in enumerate(steps):
        socketio.emit("scan_update", {
            "progress": int(((i + 1) / total) * 100),
            "status": step
        })
        time.sleep(1)  # simulate scanning delay

    # Save scan result
    save_scan(target, ip, open_ports, vulnerabilities, risk_score)

    socketio.emit("scan_complete", {
        "message": "Scan completed successfully"
    })

    return jsonify({"message": "Scan finished and saved"})


# =========================
# HISTORY API
# =========================
@app.route("/history")
def history():
    scans = get_all_scans()

    return jsonify([
        {
            "id": s[0],
            "target": s[1],
            "ip": s[2],
            "open_ports": s[3],
            "vulnerabilities": s[4],
            "risk_score": s[5],
            "timestamp": s[6]
        }
        for s in scans
    ])
def generate_pdf(scan):
    buffer = io.BytesIO()

    doc = SimpleDocTemplate(buffer)
    elements = []

    styles = getSampleStyleSheet()
    title = Paragraph("CyberScan Pro - Security Report", styles["Title"])
    elements.append(title)
    elements.append(Spacer(1, 12))

    data = [
        ["Field", "Value"],
        ["ID", str(scan[0])],
        ["Target", scan[1]],
        ["IP", scan[2]],
        ["Open Ports", scan[3]],
        ["Vulnerabilities", scan[4]],
        ["Risk Score", str(scan[5])],
        ["Timestamp", scan[6]],
    ]

    table = Table(data)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.grey),
        ("TEXTCOLOR", (0,0), (-1,0), colors.whitesmoke),
        ("GRID", (0,0), (-1,-1), 0.5, colors.black),
        ("BACKGROUND", (0,1), (-1,-1), colors.beige),
    ]))

    elements.append(table)
    doc.build(elements)

    buffer.seek(0)
    return buffer
@app.route("/report/<int:scan_id>")
def report(scan_id):
    scan = get_scan_by_id(scan_id)

    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    pdf = generate_pdf(scan)

    return send_file(
        pdf,
        download_name=f"scan_report_{scan_id}.pdf",
        as_attachment=True
    )
# =========================
# RUN SERVER
# =========================
if __name__ == "__main__":
    socketio.run(app, debug=True)