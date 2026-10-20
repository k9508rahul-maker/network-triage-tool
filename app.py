import csv
import io
import json
import os
import uuid
from xml.sax.saxutils import escape

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    Response,
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename

# ReportLab PDF imports
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from analyzer.traffic_analyzer import analyze_pcap

# Database imports
from database.db_manager import (
    init_db,
    init_alert_status,
    save_analysis,
    get_history,
    get_dashboard_stats,
    get_analysis,
    get_connection,
    get_protocol_totals,
    get_recent_analyses,
    get_traffic_chart_data,
    get_severity_summary,
    update_finding_status,
)


# --------------------------------------------------
# Flask configuration and CSRF protection
# --------------------------------------------------

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "FLASK_SECRET_KEY",
    "local-development-only",
)

csrf = CSRFProtect(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_DIR
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}


# --------------------------------------------------
# Step 17.4: PCAP extension validation helper
# --------------------------------------------------

def is_allowed_pcap(filename):
    if not filename or "." not in filename:
        return False

    extension = os.path.splitext(filename)[1].lower()
    return extension in {".pcap", ".pcapng"}


# Initialize database and alert statuses
init_db()
init_alert_status()


# --------------------------------------------------
# Dashboard
# --------------------------------------------------

@app.route("/")
def dashboard():
    stats = get_dashboard_stats()
    protocol_totals = get_protocol_totals()
    recent_analyses = get_recent_analyses()

    traffic_chart_data = get_traffic_chart_data()
    severity_summary = get_severity_summary()

    return render_template(
        "dashboard.html",
        stats=stats,
        protocol_totals=protocol_totals,
        recent_analyses=recent_analyses,
        traffic_chart_data=traffic_chart_data,
        severity_summary=severity_summary,
    )


# --------------------------------------------------
# Traffic Analyzer
# --------------------------------------------------

@app.route("/analyzer", methods=["GET", "POST"])
def analyzer():
    result = None

    if request.method == "POST":
        uploaded_file = request.files.get("pcap_file")

        # Validate that a file was selected
        if not uploaded_file or not uploaded_file.filename:
            flash("Please select a PCAP file.", "error")
            return redirect(url_for("analyzer"))

        # Step 17.4: Validate the original filename extension
        if not is_allowed_pcap(uploaded_file.filename):
            flash(
                "Only .pcap and .pcapng files are allowed.",
                "error",
            )
            return redirect(url_for("analyzer"))

        # Keep filename sanitization
        original_name = secure_filename(uploaded_file.filename)

        if not original_name or not is_allowed_pcap(original_name):
            flash("Please upload a valid PCAP filename.", "error")
            return redirect(url_for("analyzer"))

        extension = os.path.splitext(original_name)[1].lower()

        # Keep the random UUID filename to avoid filename collisions
        file_path = os.path.join(
            UPLOAD_DIR,
            f"{uuid.uuid4().hex}{extension}",
        )

        try:
            uploaded_file.save(file_path)

            # Parsing errors are handled by the exception handler below
            result = analyze_pcap(file_path)
            result["filename"] = original_name

            # Save the successful analysis
            analysis_id = save_analysis(original_name, result)
            result["analysis_id"] = analysis_id

            flash("PCAP analysis completed successfully.", "success")

        except Exception:
            app.logger.exception("Traffic analysis failed")
            flash(
                "Analysis failed. The file may be invalid or "
                "unreadable. Check the server logs.",
                "error",
            )
            result = None

        finally:
            # Remove the temporary uploaded file
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except OSError:
                    app.logger.exception(
                        "Could not remove temporary upload"
                    )

    return render_template("analyzer.html", result=result)


# --------------------------------------------------
# Investigation History
# --------------------------------------------------

@app.route("/history")
def history():
    records = get_history()
    return render_template("history.html", records=records)


# --------------------------------------------------
# Investigation Detail
# --------------------------------------------------

@app.route("/analysis/<int:analysis_id>")
def analysis_detail(analysis_id):
    analysis, events = get_analysis(analysis_id)

    if analysis is None:
        return "Analysis not found", 404

    try:
        protocols = json.loads(analysis["protocols_json"])
        if not isinstance(protocols, dict):
            protocols = {}
    except (ValueError, TypeError):
        protocols = {}

    return render_template(
        "analysis_detail.html",
        analysis=analysis,
        events=events,
        protocols=protocols,
    )


# --------------------------------------------------
# CSV Report Export
# --------------------------------------------------

@app.route("/reports/<int:analysis_id>/csv")
def export_csv(analysis_id):
    analysis, events = get_analysis(analysis_id)

    if analysis is None:
        return "Analysis not found", 404

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["Network Triage Investigation Report"])
    writer.writerow(["Analysis ID", analysis["id"]])
    writer.writerow(["Filename", analysis["filename"]])
    writer.writerow(["Analyzed At (UTC)", analysis["analyzed_at"]])
    writer.writerow(["Total Packets", analysis["total_packets"]])
    writer.writerow(["Unique IPs", analysis["unique_ips"]])
    writer.writerow([])

    writer.writerow([
        "Source IP",
        "Finding",
        "Severity",
        "Count",
        "Evidence",
    ])

    for event in events:
        writer.writerow([
            event["source_ip"],
            event["finding"],
            event["severity"],
            event["event_count"],
            event["evidence"],
        ])

    return Response(
        "\ufeff" + output.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={
            "Content-Disposition":
                f'attachment; filename="triage-report-{analysis_id}.csv"'
        },
    )


# --------------------------------------------------
# PDF Report Export
# --------------------------------------------------

@app.route("/reports/<int:analysis_id>/pdf")
def export_pdf(analysis_id):
    analysis, events = get_analysis(analysis_id)

    if analysis is None:
        return "Analysis not found", 404

    buffer = io.BytesIO()

    pdf = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title=f"Network Triage Report - {analysis_id}",
    )

    styles = getSampleStyleSheet()
    story = []

    story.append(
        Paragraph(
            "Network Triage Investigation Report",
            styles["Title"],
        )
    )
    story.append(Spacer(1, 5 * mm))

    # Analysis summary
    story.append(
        Paragraph("Analysis Summary", styles["Heading2"])
    )

    summary_data = [
        ["Field", "Value"],
        ["Analysis ID", str(analysis["id"])],
        ["Filename", str(analysis["filename"])],
        ["Analyzed At (UTC)", str(analysis["analyzed_at"])],
        ["Total Packets", str(analysis["total_packets"])],
        ["Unique IPs", str(analysis["unique_ips"])],
    ]

    summary_table = Table(
        summary_data,
        colWidths=[55 * mm, 115 * mm],
        repeatRows=1,
    )

    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#243247")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))

    story.append(summary_table)
    story.append(Spacer(1, 6 * mm))

    # Protocol statistics
    story.append(
        Paragraph("Protocol Statistics", styles["Heading2"])
    )

    try:
        protocols = json.loads(analysis["protocols_json"])
        if not isinstance(protocols, dict):
            protocols = {}
    except (ValueError, TypeError):
        protocols = {}

    protocol_data = [["Protocol", "Count"]]

    for protocol, count in protocols.items():
        protocol_data.append([
            Paragraph(escape(str(protocol)), styles["BodyText"]),
            str(count),
        ])

    if len(protocol_data) == 1:
        protocol_data.append(["No data", "0"])

    protocol_table = Table(
        protocol_data,
        colWidths=[65 * mm, 85 * mm],
        repeatRows=1,
    )

    protocol_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#243247")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))

    story.append(protocol_table)
    story.append(Spacer(1, 6 * mm))

    # Security findings
    story.append(
        Paragraph("Security Findings", styles["Heading2"])
    )

    finding_data = [
        ["Source IP", "Finding", "Severity", "Count"]
    ]

    for event in events:
        finding_data.append([
            Paragraph(
                escape(str(event["source_ip"])),
                styles["BodyText"],
            ),
            Paragraph(
                escape(str(event["finding"])),
                styles["BodyText"],
            ),
            Paragraph(
                escape(str(event["severity"])),
                styles["BodyText"],
            ),
            str(event["event_count"]),
        ])

    if len(finding_data) == 1:
        finding_data.append([
            "-", "No findings recorded", "-", "0"
        ])

    finding_table = Table(
        finding_data,
        colWidths=[32 * mm, 75 * mm, 25 * mm, 20 * mm],
        repeatRows=1,
    )

    finding_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#243247")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))

    story.append(finding_table)
    story.append(Spacer(1, 6 * mm))

    story.append(
        Paragraph(
            "Note: Findings are heuristic indicators for investigation, "
            "not proof of malicious activity.",
            styles["Italic"],
        )
    )

    pdf.build(story)
    buffer.seek(0)

    return Response(
        buffer.getvalue(),
        mimetype="application/pdf",
        headers={
            "Content-Disposition":
                f'attachment; filename="triage-report-{analysis_id}.pdf"'
        },
    )


# --------------------------------------------------
# Security Alerts: Search, Filters and Status Updates
# --------------------------------------------------

@app.route("/alerts", methods=["GET", "POST"])
def alerts():
    # Handle the POST status-update form
    if request.method == "POST":
        finding_id = request.form.get("finding_id", type=int)
        new_status = request.form.get("status", "")

        allowed_statuses = {
            "Open",
            "Investigating",
            "Resolved",
        }

        if finding_id is None:
            flash("Invalid finding ID.", "error")

        elif new_status not in allowed_statuses:
            flash("Invalid alert status.", "error")

        else:
            try:
                updated = update_finding_status(
                    finding_id,
                    new_status,
                )

                if updated:
                    flash("Alert status updated successfully.", "success")
                else:
                    flash("Finding not found or not updated.", "error")

            except Exception:
                app.logger.exception("Alert status update failed")
                flash("Could not update alert status.", "error")

        return redirect(url_for("alerts"))

    # Handle GET search and filters
    search = request.args.get("search", "").strip()
    severity = request.args.get("severity", "")
    status = request.args.get("status", "")

    allowed_severities = {"High", "Medium", "Low"}
    allowed_statuses = {"Open", "Investigating", "Resolved"}

    if severity not in allowed_severities:
        severity = ""

    if status not in allowed_statuses:
        status = ""

    sql = """
        SELECT
            f.id,
            f.source_ip,
            f.finding,
            f.severity,
            f.event_count,
            f.evidence,
            f.status,
            a.filename,
            a.analyzed_at
        FROM findings f
        JOIN analyses a ON a.id = f.analysis_id
        WHERE 1=1
    """

    params = []

    if search:
        sql += """
            AND (
                f.source_ip LIKE ?
                OR f.finding LIKE ?
                OR a.filename LIKE ?
            )
        """
        term = f"%{search}%"
        params.extend([term, term, term])

    if severity:
        sql += " AND f.severity = ?"
        params.append(severity)

    if status:
        sql += " AND f.status = ?"
        params.append(status)

    sql += " ORDER BY f.id DESC LIMIT 200"

    with get_connection() as conn:
        events = conn.execute(sql, params).fetchall()

    return render_template(
        "alerts.html",
        events=events,
        search=search,
        severity=severity,
        status=status,
    )


# --------------------------------------------------
# IP Investigation with Search
# --------------------------------------------------

@app.route("/ip-investigation")
def ip_investigation():
    search = request.args.get("search", "").strip()

    with get_connection() as conn:
        if search:
            rows = conn.execute("""
                SELECT
                    ip_observations.*,
                    analyses.filename,
                    analyses.analyzed_at
                FROM ip_observations
                JOIN analyses
                    ON analyses.id = ip_observations.analysis_id
                WHERE ip_observations.ip_address LIKE ?
                ORDER BY ip_observations.packet_count DESC
                LIMIT 200
            """, (f"%{search}%",)).fetchall()
        else:
            rows = conn.execute("""
                SELECT
                    ip_observations.*,
                    analyses.filename,
                    analyses.analyzed_at
                FROM ip_observations
                JOIN analyses
                    ON analyses.id = ip_observations.analysis_id
                ORDER BY ip_observations.packet_count DESC
                LIMIT 200
            """).fetchall()

    return render_template(
        "ip_investigation.html",
        observations=rows,
        search=search,
    )


# --------------------------------------------------
# Upload Error Handler
# --------------------------------------------------

@app.errorhandler(413)
def file_too_large(error):
    flash("File exceeds the 10 MB upload limit.", "error")
    return redirect(url_for("analyzer"))


# --------------------------------------------------
# Run Application
# --------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)
