<h4 align="center"> If you find this GitHub repo useful, please consider giving it a star! ⭐️ </h4> 
<p align="center">
    <a href="https://spyboy.in/twitter">
      <img src="https://img.shields.io/badge/-TWITTER-black?logo=twitter&style=for-the-badge">
    </a>
    &nbsp;
    <a href="https://spyboy.in/">
      <img src="https://img.shields.io/badge/-spyboy.in-black?logo=google&style=for-the-badge">
    </a>
    &nbsp;
    <a href="https://spyboy.blog/">
      <img src="https://img.shields.io/badge/-spyboy.blog-black?logo=wordpress&style=for-the-badge">
    </a>
    &nbsp;
    <a href="https://spyboy.in/Discord">
      <img src="https://img.shields.io/badge/-Discord-black?logo=discord&style=for-the-badge">
    </a>
  
</p>

<p align="center">
  <img width="20%" src="https://github.com/spyboy-productions/CamXploit/blob/main/CCTV recon.jpg" />
</p>



CamXploit is a reconnaissance tool designed to help researchers and security enthusiasts check if an IP address is hosting an exposed CCTV camera. It scans common camera ports, checks for login pages, tests default credentials, and provides useful search links for further investigation.  

⚠️ **Disclaimer:** This tool is intended for educational and security research purposes **only**. Unauthorized scanning of systems you do not own is illegal. Use responsibly.  

### ☁️ Run It Instantly on Google Colab (No Installation Needed)

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/spyboy-productions/CamXploit/blob/main/CamXploit.ipynb)

---

## 🆕 What's New in v2.0.1
- Massive port scan: Now scans 1000+ ports, including custom and high camera ports
- CP Plus (CP-UVR-0401E1-IC2) and DVR/NVR detection
- Enhanced live stream detection (RTSP/HTTP/RTMP/MMS, with real stream validation)
- Multi-threaded authentication and password brute-force (much faster)
- Improved camera indicator analysis (brand, model, login forms, titles)
- Comprehensive IP/location info with Google Maps/Earth links
- Improved error handling and progress reporting

---

## 🚀 **Features**  

✔️ **Scans all common CCTV ports**  
✔️ **Detects exposed camera login pages**  
✔️ **Checks if the device is a camera stream**  
✔️ **Identifies camera brands & known vulnerabilities**  
✔️ **Tests for default credentials on login pages**  
✔️ **Provides manual search links (Shodan, Censys, Zoomeye, Google Dorking)**  
✔️ **Google Dorking suggestions for deeper recon**  
✔️ **Enhanced Camera Detection** with detailed port analysis and brand identification  
✔️ **Live Stream Detection** for RTSP, RTMP, HTTP, and MMS protocols  
✔️ **Comprehensive IP & Location Information** with Google Maps/Earth links  
✔️ **Multi-threaded Port Scanning** for faster results  
✔️ **Enhanced Error Handling** and SSL support  
✔️ **Detailed Camera Brand Detection** (Hikvision, Dahua, Axis, Sony, Bosch, Samsung, Panasonic, Vivotek, CP Plus)  
✔️ **ONVIF Protocol Support** for standardized camera communication  
✔️ **Smart Brute-force Protection** with rate limiting  
✔️ **Detailed Port Analysis** showing server information and authentication types  

---

## 📚 Supported Brands & Devices
- Hikvision, Dahua, Axis, Sony, Bosch, Samsung, Panasonic, Vivotek, CP Plus, and most generic DVR/NVRs
- CP Plus DVRs (e.g., CP-UVR-0401E1-IC2) with custom ports
- Any device exposing RTSP, HTTP, RTMP, or MMS video streams

---

## 🚀 **Deployment**

This application is designed to be deployed as a Hugging Face Space.

### **1️⃣ Create a Hugging Face Space**

1.  Go to [huggingface.co/spaces](https://huggingface.co/spaces) and click on "New Space".
2.  Give your Space a name and select "Docker" as the Space SDK.
3.  Choose "Create Space".

### **2️⃣ Upload the Code**

1.  Clone the repository to your local machine:
    ```bash
    git clone https://github.com/spyboy-productions/CamXploit.git
    ```
2.  Navigate to the cloned repository:
    ```bash
    cd CamXploit
    ```
3.  Add the Hugging Face Space as a remote:
    ```bash
    git remote add space https://huggingface.co/spaces/<your-username>/<your-space-name>
    ```
4.  Push the code to the Space:
    ```bash
    git push --force space main
    ```

The Space will then build the Docker image and start the application. You can view the application by clicking on the "App" tab in your Space.

---

### **🔍 What It Does:**  
1️⃣ **Scans open ports** (Common CCTV ports)  
2️⃣ **Checks if a camera is present**  
3️⃣ If a camera is found, it:  
   - Searches for **login pages**  
   - Checks **default credentials**  
   - Identifies **camera brand & vulnerabilities**  
   - Detects **live streams** (RTSP, RTMP, HTTP, MMS)  
   - Provides **location information** with maps  
   - Shows **server details** and authentication types  
4️⃣ Provides **manual search URLs** for deeper investigation  

---

## Roadmap

The future development plans for this project are outlined in the [ROADMAP.md](ROADMAP.md) file.

## 📚 Troubleshooting
- If no open ports are found, ensure the target is online and not behind a strict firewall.
- If live streams are not detected, try accessing the URLs manually in VLC or a browser.
- For best detection, ensure your Python version is 3.6+ and all dependencies are installed.

---

## 📸 **Example Output**  

<img width="100%" align="centre" src="https://github.com/spyboy-productions/CamXploit/blob/main/demo.png" />

---


## 🤖 **To-Do & Future Features**  
- [x] Add multi-threaded scanning for speed  
- [x] Expand camera brand detection  
- [ ] Implement logging feature  
- [ ] Add screenshot capture functionality  
- [ ] Implement report generation  
- [ ] Add network range scanning  
- [ ] Implement MAC address lookup  

---
## 🙌 **Contributions**  
Feel free to submit issues, suggestions, or pull requests!  

<h4 align="center"> If you find this GitHub repo useful, please consider giving it a star! ⭐️ </h4> 
