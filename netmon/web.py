"""The dashboard web server: the page, its JSON API and the AI analyst endpoints.

Security for a dashboard that runs on your own computer:
- Only requests addressed to this computer's own names (127.0.0.1, localhost) are answered. This blocks "DNS
  rebinding", where a malicious website tricks the browser into talking to local services.
- Every request that changes something (POST) must carry the header X-Netmon: 1. Browsers do not let other
  websites add custom headers to requests to this server, so a web page you visit cannot change settings,
  approve responses or upload files behind your back (cross-site request forgery).
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

from flask import Flask, Response, abort, jsonify, render_template, request

from .agent import SecurityAnalystAgent, Toolbox
from .analyzer import Analyzer
from .monitor import Monitor
from .responder import PLATFORMS

ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}
UPLOAD_SUFFIXES = {".pcap", ".pcapng", ".cap"}
EXPORT_FIELDS = ["id", "time", "severity", "kind", "source", "target", "message", "mitre", "acked", "ack_note"]


def create_app(analyzer: Analyzer | None = None, source: str = "", agent: SecurityAnalystAgent | None = None,
               monitor: Monitor | None = None) -> Flask:
    monitor = monitor or Monitor(source, analyzer=analyzer, agent=agent, ml_learn=None)
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # uploads up to 200 MB
    app.monitor = monitor
    allowed = ALLOWED_HOSTS | {h.strip() for h in os.environ.get("NETMON_ALLOWED_HOSTS", "").split(",") if h.strip()}

    @app.before_request
    def protect():
        host = request.host.rsplit(":", 1)[0] if not request.host.startswith("[") else request.host.split("]")[0] + "]"
        if host not in allowed:
            abort(403, "This dashboard only answers requests to 127.0.0.1 or localhost.")
        if request.method == "POST" and request.headers.get("X-Netmon") != "1":
            abort(403, "Missing X-Netmon header.")

    def body() -> dict:
        return request.get_json(silent=True) or {}

    # ------------------------------------------------------------------ page and live data

    @app.get("/")
    def index():
        return render_template("index.html", source=monitor.source, agent_mode=monitor.agent.mode,
                               agent_label=monitor.agent.label)

    @app.get("/api/snapshot")
    def snapshot():
        monitor.save_devices()
        snap = monitor.analyzer.snapshot()
        snap["status"] = monitor.status()
        return jsonify(snap)

    @app.post("/api/devices/<mac>/label")
    def label_device(mac):
        if not re.fullmatch(r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}", mac):
            return jsonify({"error": "Not a hardware (MAC) address."}), 400
        monitor.set_label(mac, str(body().get("label", "")))
        return jsonify({"ok": True})

    @app.post("/api/discover")
    def discover():
        result = monitor.discover()
        return (jsonify(result), 400) if "error" in result else jsonify(result)

    @app.get("/api/privacy")
    def privacy():
        return jsonify(monitor.analyzer.privacy.report())

    @app.get("/api/story")
    def story():
        return jsonify(monitor.story())

    @app.get("/api/health")
    def health():
        return jsonify(monitor.health())

    @app.post("/api/selftest")
    def selftest():
        return jsonify(monitor.run_self_test())

    # ------------------------------------------------------------------ AI analyst

    @app.post("/api/agent/investigate")
    def investigate():
        return jsonify(asdict(monitor.agent.investigate()))

    @app.get("/api/agent/progress")
    def progress():
        p = dict(monitor.agent.progress)
        p["elapsed"] = round(time.time() - p["started"]) if p.get("started") else 0
        return jsonify(p)

    @app.post("/api/agent/ask")
    def ask():
        question = body().get("question", "").strip()
        if not question:
            return jsonify({"error": "Type a question first."}), 400
        return jsonify(asdict(monitor.agent.ask(question)))

    @app.post("/api/tools/<name>")
    def tool(name):
        """The analyst's read-only tools, for the MCP server and other programs."""
        return jsonify(Toolbox(monitor.analyzer, monitor.responder).run(name, body()))

    # ------------------------------------------------------------------ alerts, history and export

    @app.post("/api/alerts/<alert_id>/ack")
    def acknowledge(alert_id):
        data = body()
        ok = monitor.acknowledge(alert_id, str(data.get("note", "")), bool(data.get("acked", True)))
        return (jsonify({"ok": True}) if ok else (jsonify({"error": "No such alert."}), 404))

    @app.get("/api/history")
    def history():
        if not monitor.store:
            return jsonify({"enabled": False, "alerts": []})
        args = request.args
        alerts = monitor.store.history(limit=args.get("limit", 200, type=int), severity=args.get("severity") or None,
                                       kind=args.get("kind") or None, query=args.get("q") or None,
                                       include_acked=args.get("open") != "1")
        return jsonify({"enabled": True, "stats": monitor.store.stats(), "alerts": alerts})

    def export_rows():
        if request.args.get("history") == "1" and monitor.store:
            alerts = monitor.store.history(limit=5000)
        else:
            alerts = monitor.analyzer.snapshot()["alerts"]
        for a in alerts:
            yield {**{k: a.get(k, "") for k in EXPORT_FIELDS},
                   "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a["ts"])),
                   "mitre": ";".join(m["id"] for m in a.get("mitre", []))}

    @app.get("/api/export/alerts.csv")
    def export_csv():
        out = io.StringIO()
        writer = csv.DictWriter(out, fieldnames=EXPORT_FIELDS)
        writer.writeheader()
        for row in export_rows():
            # Protect spreadsheet users from formula injection through attacker-controlled text.
            writer.writerow({k: ("'" + v if isinstance(v, str) and v[:1] in "=+-@" else v) for k, v in row.items()})
        return Response(out.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=netmon-alerts.csv"})

    @app.get("/api/export/alerts.json")
    def export_json():
        return Response(json.dumps(list(export_rows()), indent=2), mimetype="application/json",
                        headers={"Content-Disposition": "attachment; filename=netmon-alerts.json"})

    @app.get("/api/report.pdf")
    def report_pdf():
        from .agent import OfflineAnalyst
        from .report import build_pdf

        last = monitor.agent.last_result
        analysis = ({"report": last.report, "by": monitor.agent.label if last.mode == "ai" else "offline analyst"}
                    if last else {"report": OfflineAnalyst(monitor.analyzer).answer("Investigate").report,
                                  "by": "offline analyst"})
        pdf = build_pdf(monitor.analyzer.snapshot(), analysis, monitor.responder.propose(monitor.analyzer),
                        monitor.source)
        return Response(pdf, mimetype="application/pdf",
                        headers={"Content-Disposition": "attachment; filename=netmon-incident-report.pdf"})

    # ------------------------------------------------------------------ settings

    @app.get("/api/config")
    def get_config():
        return jsonify(asdict(monitor.analyzer.config))

    @app.post("/api/config")
    def set_config():
        result = monitor.analyzer.update_config(body())
        return jsonify({**result, "config": asdict(monitor.analyzer.config)}), (400 if result["errors"] else 200)

    @app.post("/api/notify/test")
    def notify_test():
        if not monitor.notifier or not monitor.notifier.channels:
            return jsonify({"error": "No notification channels are set up (see README)."}), 400
        return jsonify(monitor.notifier.test())

    # ------------------------------------------------------------------ responder

    @app.get("/api/responses")
    def responses():
        return jsonify({"responses": monitor.responder.propose(monitor.analyzer), "platforms": PLATFORMS})

    @app.post("/api/responses/<action_id>")
    def decide(action_id):
        if not monitor.responder.decide(action_id, body().get("status", "")):
            return jsonify({"error": "status must be approved, dismissed or proposed"}), 400
        return jsonify({"ok": True})

    @app.get("/api/responses/script")
    def response_script():
        platform = request.args.get("platform", "pf")
        if platform not in PLATFORMS:
            return jsonify({"error": "unknown platform"}), 400
        name = {"pf": "netmon.pf.conf", "iptables": "netmon-iptables.sh", "powershell": "netmon-firewall.ps1",
                "router": "netmon-router-steps.txt"}[platform]
        return Response(monitor.responder.script(monitor.analyzer, platform), mimetype="text/plain",
                        headers={"Content-Disposition": f"attachment; filename={name}"})

    # ------------------------------------------------------------------ upload a capture

    @app.post("/api/upload")
    def upload():
        file = request.files.get("file")
        if not file or not file.filename:
            return jsonify({"error": "Choose a .pcap or .pcapng file."}), 400
        name = Path(file.filename).name
        if Path(name).suffix.lower() not in UPLOAD_SUFFIXES:
            return jsonify({"error": "Only .pcap, .pcapng and .cap files are supported."}), 400
        folder = Path(tempfile.mkdtemp(prefix="netmon-upload-"))
        path = folder / ("capture" + Path(name).suffix.lower())  # never use the uploaded name as a path
        file.save(path)
        monitor.analyze_file(str(path), name)
        return jsonify({"ok": True, "source": monitor.source})

    @app.errorhandler(413)
    def too_big(_):
        return jsonify({"error": "That file is larger than 200 MB."}), 413

    return app
