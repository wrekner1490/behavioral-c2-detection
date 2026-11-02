from flask import Flask, request
import logging
import time

app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def catch_all(path):
    print(f"[{time.strftime('%H:%M:%S')}] [SERVER] Received {request.method} request to /{path} from {request.remote_addr}")
    return "OK", 200

if __name__ == '__main__':
    print("[SERVER] Starting lightweight C2 server on port 8080...")
    app.run(host='0.0.0.0', port=8080)
