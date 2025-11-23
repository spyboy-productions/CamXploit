from flask import Flask, render_template, request, Response
from werkzeug.utils import secure_filename
import subprocess
import ipaddress
import os
import base64
import json
import re

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
            ips_to_scan = [str(ip) for ip in network.hosts()]
        except ValueError:
            ips_to_scan = [ip_input]

        for ip in ips_to_scan:
            safe_ip = secure_filename(ip)
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

            streams = []
            for line in iter(process.stdout.readline, ''):
                yield f"data: [{safe_ip}] {line}\\n\\n"
                # Simple regex to find stream URLs
                url_regex = r"(rtsp|rtmp|http|https)?://[^\s\"']+"
                match = re.search(url_regex, line)
                if match:
                    streams.append(match.group(0))

            process.stdout.close()
            process.wait()

            if streams:
                yield f"data: --- Found {len(streams)} streams, generating context... ---\\n\\n"
                for stream_url in streams:
                    image_path = f"/tmp/{safe_ip}_frame.jpg"
                    if capture_frame(stream_url, image_path):
                        technical_data = {"ip_address": safe_ip}
                        geolocation_data = {} # In a real app, you'd get this from ipinfo.io
                        context = get_contextual_summary(image_path, technical_data, geolocation_data)
                        yield f"data: {json.dumps(context)}\\n\\n"
                        os.remove(image_path)
                    else:
                        yield f"data: --- Could not capture frame for {stream_url} ---\\n\\n"


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


import requests

def get_contextual_summary(image_path, technical_data, geolocation_data):
    """
    Gets a contextual summary for a video stream using a multi-modal LLM.
    """
    # Mock response for testing purposes
    return {
        "likely_environment": "outdoor street",
        "key_objects_identified": ["car", "pedestrian"],
        "contextual_summary": "This is likely a public traffic camera in a busy city."
    }

def capture_frame(stream_url, filename):
    """
    Captures a single frame from a video stream and saves it to a file.
    """
    command = [
        'ffmpeg',
        '-i', stream_url,
        '-vframes', '1',
        '-f', 'image2',
        filename
    ]
    try:
        subprocess.run(command, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error capturing frame: {e.stderr.decode()}")
        return False

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
