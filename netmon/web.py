"""The dashboard: one page, a JSON endpoint it polls every two seconds, and the AI analyst endpoints."""

from dataclasses import asdict

from flask import Flask, jsonify, render_template, request

from .agent import SecurityAnalystAgent
from .analyzer import Analyzer


def create_app(analyzer: Analyzer, source: str, agent: SecurityAnalystAgent | None = None) -> Flask:
    app = Flask(__name__)
    agent = agent or SecurityAnalystAgent(analyzer)

    @app.get("/")
    def index():
        return render_template("index.html", source=source, agent_mode=agent.mode, agent_label=agent.label)

    @app.get("/api/snapshot")
    def snapshot():
        return jsonify(analyzer.snapshot())

    @app.post("/api/agent/investigate")
    def investigate():
        return jsonify(asdict(agent.investigate()))

    @app.post("/api/agent/ask")
    def ask():
        question = (request.get_json(silent=True) or {}).get("question", "").strip()
        if not question:
            return jsonify({"error": "Type a question first."}), 400
        return jsonify(asdict(agent.ask(question)))

    return app
