from flask import Flask, render_template, request, jsonify
from utils import check_url

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/check", methods=["POST"])
def check():
    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "No URL provided"}), 400

    url = data["url"].strip()

    if not url:
        return jsonify({"error": "URL is empty"}), 400

    score, verdict, results = check_url(url)

    return jsonify({
        "score": score,
        "verdict": verdict,
        "details": results
    })


if __name__ == "__main__":
    app.run(debug=True)
