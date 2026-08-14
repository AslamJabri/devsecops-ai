from flask import Flask, jsonify

app = Flask(__name__)

@app.after_request
def set_security_headers(response):
    response.headers["Cache-Control"] = "no-store"
    return response

@app.get("/")
def index():
    return jsonify(service="sentinelforge-demo-app", environment="local-lab", data="safe dummy data only")


@app.get("/health")
def health():
    return jsonify(status="ok")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
