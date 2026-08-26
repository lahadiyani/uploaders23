import os
import base64
import requests
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# Environment Variables
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO_OWNER = os.getenv("REPO_OWNER")
REPO_NAME = os.getenv("REPO_NAME")
BRANCH = os.getenv("GITHUB_BRANCH", "main")
# Secret key internal aplikasi untuk otorisasi upload
UPLOAD_SECRET_KEY = os.getenv("UPLOAD_SECRET_KEY")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/upload", methods=["POST"])
def upload():
    # 1. Validasi Kunci Akses Pengguna
    user_key = request.headers.get("X-Access-Key") or request.form.get("access_key")
    
    if not UPLOAD_SECRET_KEY:
        return jsonify({"error": "UPLOAD_SECRET_KEY belum diatur di server"}), 500

    if not user_key or user_key != UPLOAD_SECRET_KEY:
        return jsonify({"error": "Kunci Akses Salah atau Tidak Valid!"}), 401

    # 2. Validasi File
    if "file" not in request.files:
        return jsonify({"error": "File tidak ditemukan dalam request"}), 400
    
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Nama file kosong"}), 400

    if not GITHUB_TOKEN or not REPO_OWNER or not REPO_NAME:
        return jsonify({"error": "Environment variables GitHub belum dikonfigurasi"}), 500

    try:
        # Encode file ke Base64
        file_content = file.read()
        content_b64 = base64.b64encode(file_content).decode("utf-8")

        # Path penyimpanan di repo
        target_path = f"uploads/{file.filename}"

        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{target_path}"

        headers = {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Flask-Vercel-Uploader"
        }

        payload = {
            "message": f"upload: add {file.filename} via Vercel Uploader",
            "content": content_b64,
            "branch": BRANCH
        }

        response = requests.put(url, json=payload, headers=headers)
        res_data = response.json()

        if response.status_code in [200, 201]:
            return jsonify({
                "success": True,
                "filename": file.filename,
                "download_url": res_data["content"].get("download_url"),
                "html_url": res_data["content"].get("html_url")
            }), 200
        else:
            return jsonify({
                "error": res_data.get("message", "Gagal mengunggah ke GitHub"),
                "details": res_data
            }), response.status_code

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
