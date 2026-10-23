"""The dashboard: one page plus a JSON endpoint it polls every two seconds."""

from flask import Flask, jsonify, render_template

from .analyzer import Analyzer


def create_app(analyzer: Analyzer, source: str) -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def index():
        return render_template("index.html", source=source)

    @app.get("/api/snapshot")
    def snapshot():
        return jsonify(analyzer.snapshot())

    return app
