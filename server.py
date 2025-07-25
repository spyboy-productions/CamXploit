from flask import Flask, render_template, request, Response
from werkzeug.utils import secure_filename
import subprocess
import ipaddress
import os
import base64

app = Flask(__name__)

def is_valid_ip(ip_str):
    try:
        ipaddress.ip_network(ip_str)
        return True
    except ValueError:
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    ip_input = request.json.get('ip')

    if not ip_input or not is_valid_ip(ip_input):
        return Response("Invalid or missing IP address or CIDR.", status=400)

    def generate_output():
        try:
            network = ipaddress.ip_network(ip_input)
            for ip in network.hosts():
                safe_ip = secure_filename(str(ip))
                yield f"data: --- Scanning {safe_ip} ---\\n\\n"
                command = ['stdbuf', '-o0', 'python3', 'CamXploit.py']
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1
                )

                process.stdin.write(safe_ip + '\n')
                process.stdin.flush()

                for line in iter(process.stdout.readline, ''):
                    yield f"data: [{safe_ip}] {line}\\n\\n"
                process.stdout.close()
                process.wait()
        except ValueError:
            safe_ip = secure_filename(ip_input)
            command = ['stdbuf', '-o0', 'python3', 'CamXploit.py']
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            process.stdin.write(safe_ip + '\n')
            process.stdin.flush()

            for line in iter(process.stdout.readline, ''):
                yield f"data: {line}\\n\\n"
            process.stdout.close()
            process.wait()


    return Response(generate_output(), mimetype='text/event-stream')


@app.route('/stream/<path:stream_url_b64>')
def stream(stream_url_b64):
    try:
        stream_url = base64.urlsafe_b64decode(stream_url_b64).decode('utf-8')
    except:
        return "Invalid stream URL format.", 400

    def generate_ffmpeg_stream():
        ffmpeg_command = [
            'ffmpeg',
            '-i', stream_url,
            '-c:v', 'libx264',
            '-c:a', 'aac',
            '-f', 'hls',
            '-hls_time', '2',
            '-hls_list_size', '5',
            '-hls_flags', 'delete_segments',
            '-preset', 'ultrafast',
            '-tune', 'zerolatency',
            'pipe:1'
        ]

        process = subprocess.Popen(ffmpeg_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        try:
            while True:
                chunk = process.stdout.read(4096)
                if not chunk:
                    break
                yield chunk
        finally:
            process.terminate()

    return Response(generate_ffmpeg_stream(), mimetype='application/vnd.apple.mpegurl')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
