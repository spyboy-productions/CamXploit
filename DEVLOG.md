# DEVLOG: HelloBird v1.1

## Project Overview

This document outlines the development process for HelloBird v1.1, a web-based wrapper for the CamXploit CCTV reconnaissance tool. The goal of this project was to take a powerful command-line tool and make it more accessible and user-friendly by providing a graphical user interface that can be accessed through a web browser.

This project is designed to be developed in a fork of the original [CamXploit repository](https://github.com/spyboy-productions/CamXploit). This allows for a clean separation between the original tool and the web-based wrapper, and it gives the user full ownership and control over their own version of the application.

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

## AI-Powered Contextual Analysis

The latest version of HelloBird includes AI-powered contextual analysis of video streams. This feature uses a multi-modal LLM to analyze a snapshot from each video stream and provide a contextual summary of what the camera is likely seeing.

### Implementation Details

1.  **Image Snapshot:** For each video stream that is found, a single frame is captured using FFmpeg and saved as a temporary file.

2.  **Multi-Modal Inference Request:** The captured frame, along with technical and geolocation data, is sent to a multi-modal LLM. The request is structured as a JSON object to ensure consistency and to preserve tokens.

3.  **Contextual Summary:** The LLM returns a JSON object containing a contextual summary of the video stream, including the likely environment, key objects identified, and a one-sentence summary.

4.  **Frontend Display:** The frontend is updated to display the contextual summary in a clear and organized way.

### Security Considerations

The implementation of this feature has been done with security in mind. The following measures have been taken to ensure the security of the application:

-   **Temporary Files:** The captured frames are saved as temporary files and are deleted after they have been processed.

-   **API Key:** The Hugging Face API key is stored as an environment variable and is not hard-coded into the application.

-   **Input Validation:** All user input is validated and sanitized to prevent command injection and other security vulnerabilities.

## Plan for Remaining Features

This section outlines the plan for implementing the remaining features from the original CamXploit `README.md`.

### Implement Logging Feature

-   **Justification:** A logging feature is essential for debugging and for keeping a record of the application's activity.
-   **Implementation:** I will use Python's built-in `logging` module to implement a comprehensive logging feature. The application will log all important events, including scan initiations, errors, and successful stream connections. The log file will be stored in a `logs` directory, and it will be rotated daily to prevent it from growing too large.

    ```python
    import logging
    from logging.handlers import TimedRotatingFileHandler

    # Create a logs directory if it doesn't already exist
    if not os.path.exists('logs'):
        os.makedirs('logs')

    # Create a logger
    logger = logging.getLogger('HelloBird')
    logger.setLevel(logging.INFO)

    # Create a rotating file handler
    handler = TimedRotatingFileHandler('logs/hellobird.log', when='d', interval=1, backupCount=7)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

    # Add the handler to the logger
    logger.addHandler(handler)
    ```

### Add Screenshot Capture Functionality

-   **Justification:** The ability to capture screenshots from video streams would be a valuable feature for reconnaissance and documentation.
-   **Implementation:** I will extend the existing `capture_frame` function to allow for capturing multiple screenshots. The frontend will be updated to include a "Capture Screenshot" button, which will send a request to the backend to capture a screenshot from the current video stream. The captured screenshots will be stored in a `screenshots` directory, and they will be displayed to the user in the frontend.

### Implement Report Generation

-   **Justification:** The ability to generate reports of scan results would be a useful feature for sharing and for further analysis.
-   **Implementation:** I will create a new endpoint, `/report`, that will generate a PDF report of the scan results for a given IP address or CIDR range. The report will include all the information from the scan, including the AI-powered contextual summary. I will use a library such as `ReportLab` or `WeasyPrint` to generate the PDF report.

### Implement MAC Address Lookup

-   **Justification:** The ability to look up the MAC address of a device can provide valuable information about the manufacturer of the device.
-   **Implementation:** I will use a library such as `scapy` to send ARP requests to the target device and to get its MAC address. The MAC address will then be used to look up the manufacturer of the device using an online API. The manufacturer information will be added to the scan report.
