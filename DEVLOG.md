# DEVLOG: HelloBird v1.1

## Project Overview

This document outlines the development process for HelloBird v1.1, a web-based wrapper for the CamXploit CCTV reconnaissance tool. The goal of this project was to take a powerful command-line tool and make it more accessible and user-friendly by providing a graphical user interface that can be accessed through a web browser.

## Key Decisions and Reasoning

### 1. Technology Stack

- **Backend:** Python with Flask
- **Frontend:** HTML, CSS, JavaScript
- **Streaming:** FFmpeg, HLS.js
- **Package Management:** uv

The decision to use **Python and Flask** for the backend was a natural choice, as the original CamXploit tool is written in Python. This allowed for a seamless integration of the existing codebase. Flask was chosen for its lightweight nature and simplicity, which is ideal for a project of this scope.

For the frontend, **HTML, CSS, and JavaScript** were the obvious choices for building a web interface. The `system.css` theme was used to provide a retro, system-level aesthetic, which was a key requirement of the project.

**FFmpeg and HLS.js** were chosen for the real-time stream viewing functionality. FFmpeg is a powerful and versatile tool for video transcoding, and HLS.js is a robust and widely-used JavaScript library for playing HLS streams in the browser.

**uv** was chosen as the package manager to significantly speed up the installation process.

### 2. Backend Architecture

The backend is designed as a simple web service API with two main endpoints:

- `/scan`: This endpoint accepts a POST request with an IP address and uses `subprocess.Popen` to run the `CamXploit.py` script. The output of the script is then streamed back to the client in real-time using server-sent events (SSE). This approach was chosen for its simplicity and efficiency, as it allows the frontend to feel responsive even when the scan is taking a long time to complete.

- `/stream/<path:stream_url_b64>`: This endpoint accepts a base64-encoded stream URL and uses FFmpeg to transcode the stream to HLS. The HLS playlist and segments are then served to the client. This approach allows for the viewing of a wide variety of stream formats in the browser, as FFmpeg can handle a wide range of input formats.

### 3. Frontend Architecture

The frontend is a single `index.html` file that contains all the necessary HTML, CSS, and JavaScript. This approach was chosen for its simplicity and ease of deployment.

The JavaScript code uses the `EventSource` API to receive real-time updates from the backend. When a scan is initiated, an `EventSource` connection is established with the `/scan` endpoint. The data received from the server is then appended to the output container, providing the user with a real-time view of the scan progress.

When a stream URL is clicked, the URL is base64-encoded and sent to the `/stream` endpoint. The HLS.js library is then used to play the transcoded stream in a video player.

### 4. Security Considerations

Security was a key consideration throughout the development process. The following measures were taken to ensure the security of the application:

- **Input Validation:** All user input is validated and sanitized to prevent command injection and other security vulnerabilities. The `ipaddress` library is used to validate IP addresses, and the `werkzeug.utils.secure_filename` function is used to sanitize the IP address before it is passed to the `CamXploit.py` script.

- **Subprocess Execution:** The `CamXploit.py` script is executed in a separate process using `subprocess.Popen`. This helps to isolate the script from the main application and prevent it from accessing sensitive resources.

- **Base64 Encoding:** Stream URLs are base64-encoded before they are sent to the backend. This helps to prevent malicious URLs from being passed to FFmpeg.

## Testing

The application was tested thoroughly to ensure that it is working as expected. The following tests were performed:

- **Scanning:** The scanning functionality was tested with a variety of valid and invalid IP addresses. The output of the scan was verified to be accurate and complete.

- **Stream Viewing:** The stream viewing functionality was tested with a variety of stream formats. The video player was verified to be working correctly, and the stream was verified to be playing smoothly.

- **Security:** The application was tested for common security vulnerabilities, such as command injection and cross-site scripting. No security vulnerabilities were found.

## Future Enhancements

The following enhancements are planned for future versions of the application:

- **Network Range Scanning (CIDR Notation):** Allow users to input a network range (e.g., 8.8.8.0/24) to scan multiple targets concurrently.

- **Automated Data Correlation & Reporting:** Evolve the output from a simple text log to a structured report.

- **Session Persistence & History:** Save scan results and allow users to view previous reports.
