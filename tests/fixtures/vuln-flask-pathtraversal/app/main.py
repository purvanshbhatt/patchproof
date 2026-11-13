import os

from flask import Flask, Response, request

app = Flask(__name__)
BASE = os.path.dirname(os.path.abspath(__file__))


@app.get("/read")
def read():
    # VULNERABLE: user-controlled filename joined without sanitization.
    name = request.args.get("file", "readme.txt")
    path = os.path.join(BASE, name)
    try:
        with open(path) as f:
            return Response(f.read(), mimetype="text/plain")
    except OSError:
        return Response("not found", status=404)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
