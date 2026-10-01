"""`phishing-url-detector serve`: a small web page and JSON API for checking URLs.

URLs are only parsed and scored. The server never fetches or opens them, and
the page shows them as text, not links.
"""

from __future__ import annotations

from flask import Flask, jsonify, render_template, request

from .check import check
from .model import load

MAX_URLS = 200


def create_app(models: str = "models") -> Flask:
    app = Flask(__name__)
    det = load(models)

    @app.get("/")
    def index():
        return render_template("index.html", results=None, text="", meta=det.meta)

    @app.post("/")
    def form():
        text = request.form.get("urls", "")
        urls = [u for u in text.splitlines() if u.strip()][:MAX_URLS]
        return render_template("index.html", results=check(urls, det), text=text, meta=det.meta)

    @app.route("/api/check", methods=["GET", "POST"])
    def api():
        if request.method == "GET":
            urls = request.args.getlist("url")
        else:
            body = request.get_json(silent=True) or {}
            urls = body.get("urls") or ([body["url"]] if body.get("url") else [])
        if not urls or not all(isinstance(u, str) for u in urls):
            return jsonify(error='send ?url=... or a JSON body {"urls": [...]}'), 400
        if len(urls) > MAX_URLS:
            return jsonify(error=f"at most {MAX_URLS} URLs per request"), 400
        return jsonify(model=det.meta["model"], threshold=det.threshold, results=[r.to_dict() for r in check(urls, det)])

    return app
