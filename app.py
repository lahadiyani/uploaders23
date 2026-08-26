import os
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# Konfigurasi dari Environment Variables Vercel
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO_OWNER = os.getenv("REPO_OWNER")
REPO_NAME = os.getenv("REPO_NAME")
BRANCH = os.getenv("GITHUB_BRANCH", "main")
UPLOAD_SECRET_KEY = os.getenv("UPLOAD_SECRET_KEY")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/config", methods=["POST"])
def get_config():
    # 1. Cek Kunci Akses (Passcode)
    user_key = request.headers.get("X-Access-Key") or request.json.get("access_key")
    
    if not UPLOAD_SECRET_KEY:
        return jsonify({"error": "UPLOAD_SECRET_KEY belum diatur di Vercel"}), 500

    if not user_key or user_key != UPLOAD_SECRET_KEY:
        return jsonify({"error": "Kunci Akses Salah!"}), 401

    if not GITHUB_TOKEN or not REPO_OWNER or not REPO_NAME:
        return jsonify({"error": "Environment Variables GitHub belum lengkap!"}), 500

    # 2. Kirim kredensial ke Frontend untuk Direct Upload ke GitHub
    return jsonify({
        "success": True,
        "token": GITHUB_TOKEN,
        "owner": REPO_OWNER,
        "repo": REPO_NAME,
        "branch": BRANCH
    }), 200

if __name__ == "__main__":
    app.run(debug=True)
