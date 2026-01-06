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



CamXploit is a security reconnaissance tool designed to help researchers and defenders assess whether an IP address is hosting a **potentially exposed IP camera or CCTV service**.

The tool performs **non-intrusive checks** such as scanning commonly used camera ports, identifying accessible web interfaces, and highlighting common configuration weaknesses (e.g., default setups or publicly accessible services). It also provides contextual search links to assist further **manual investigation and verification**.

CamXploit is intended for **security research, awareness, and authorized testing**, helping organizations and individuals identify misconfigurations and reduce the risk of unauthorized access to camera infrastructure.
  

> [!IMPORTANT]
> CamXploit performs reconnaissance and configuration analysis only and must be used **strictly on systems you own or have explicit authorization to test**.

### ☁️ Run It Instantly on Google Colab (No Installation Needed)

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/spyboy-productions/CamXploit/blob/main/CamXploit.ipynb)

---

## 🆕 What's New in v2.0.2
- **RTSP Detection & Testing**: Actively probes ports for RTSP (not just port 554), detects RTSP on non-standard ports (e.g., 443, 8000)
- **Service Name Display**: Shows service names for each open port (e.g., `[OPEN] 8080/tcp HTTP-Alt (Web Interface)`)
- **RTSP Credential Testing**: Tests RTSP Basic Auth credentials on RTSP ports (prioritized over HTTP)
- **Smart Brand Detection**: Automatically suggests RTSP URLs for known camera brands (Axis, Hikvision, Dahua) even if RTSP not detected
- **Enhanced Credential Testing**: Priority-based testing (most common credentials first), faster timeouts, progress indicators
- **Expanded Credential Database**: 100+ default credentials across multiple camera brands
- **Better Stream Detection**: Clear VLC vs browser guidance, multipart stream detection
- **Performance Improvements**: Automatic port deduplication, better timeout handling, prevents hanging
- **IP:PORT Format Support**: Accept IP:PORT format (e.g., `192.168.1.1:85`) to scan specific ports or ensure custom ports are checked
- **Expanded Port Coverage**: Added common alternative ports (81-89, 21-23, 1024-1030, etc.) for better camera detection

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
✔️ **RTSP Detection on Any Port** - Actively probes ports for RTSP, not just standard port 554  
✔️ **Service Name Identification** - Shows what service is running on each open port  
✔️ **RTSP Credential Testing** - Tests RTSP Basic Auth (most important for CCTV cameras!)  
✔️ **Smart RTSP Suggestions** - Automatically suggests RTSP URLs for detected camera brands  
✔️ **Priority Credential Testing** - Tests most common credentials first (admin:admin, admin:1234, etc.)  
✔️ **Expanded Credential Database** - 100+ default credentials across all major CCTV brands  
✔️ **VLC Integration Guide** - Clear instructions for viewing RTSP streams in VLC Media Player  
✔️ **Multipart Stream Detection** - Detects MJPEG streams (multipart/x-mixed-replace)  
✔️ **IP:PORT Format Support** - Accept IP:PORT input to scan specific ports or ensure custom ports are checked  

---

## 📚 Supported Brands & Devices
- Hikvision, Dahua, Axis, Sony, Bosch, Samsung, Panasonic, Vivotek, CP Plus, and most generic DVR/NVRs
- CP Plus DVRs (e.g., CP-UVR-0401E1-IC2) with custom ports
- Any device exposing RTSP, HTTP, RTMP, or MMS video streams

---

## 🛠️ **Installation**  

### **1️⃣ Clone the Repository**  
```bash
git clone https://github.com/spyboy-productions/CamXploit.git
```
```
cd CamXploit
```  
```bash
pip install -r requirements.txt
```
---
```
python CamXploit.py
```
Enter the **public IP address** (or `IP:PORT` format) of the target device when prompted.

**Input Formats:**
- `192.168.1.1` - Scans all common CCTV ports
- `192.168.1.1:85` - Scans all ports + ensures port 85 is checked (useful for custom ports)
- `192.168.1.1:9000` - Scans all ports + ensures port 9000 is checked  

### **🔍 What It Does:**  
1️⃣ **Scans open ports** (Common CCTV ports) with service name identification  
2️⃣ **Checks if a camera is present**  
3️⃣ If a camera is found, it:  
   - Searches for **login pages**  
   - Tests **RTSP credentials** (prioritized) and **HTTP credentials**  
   - Identifies **camera brand & vulnerabilities**  
   - **Suggests RTSP URLs** for detected brands  
   - Detects **live streams** (RTSP, RTMP, HTTP, MMS) with viewing instructions  
   - Provides **location information** with maps  
   - Shows **service names** and authentication types  
4️⃣ Provides **manual search URLs** for deeper investigation  

---

## ⚡ Usage Tips
- Scanning all ports (1000+) may take several minutes, depending on your network and target.
- The tool uses multi-threading for port, login, and password checks for speed.
- If you see "No camera found" but you know a camera is present, check the open ports and look for custom ports in the output.
- For best results, run as administrator/root to avoid local firewall issues.
- **RTSP ports are prioritized for credential testing** (most important for CCTV cameras)
- **RTSP links are shown prominently** - use VLC Media Player to test them
- **HTTP/HTTPS streams can be opened directly** in your web browser
- **Credential testing has a 2-minute timeout** to prevent hanging
- **Service names help identify** what's running on each port
- **Use IP:PORT format** if you know a specific port (e.g., `192.168.1.1:85`) - ensures that port is scanned even if not in common ports list
- **Custom ports are automatically included** when using IP:PORT format

---

## 📚 Troubleshooting
- If no open ports are found, ensure the target is online and not behind a strict firewall.
- If live streams are not detected, try accessing the URLs manually in VLC or a browser.
- For best detection, ensure your Python version is 3.6+ and all dependencies are installed.
- **RTSP streams require VLC Media Player** - HTTP streams work in browser
- **If RTSP not detected on standard port 554**, check other ports (443, 8000, etc.)
- **Brand detection helps suggest RTSP URLs** even if RTSP probe fails
- **If a port is being missed**, use IP:PORT format (e.g., `192.168.1.1:85`) to ensure that specific port is scanned
- **Custom/non-standard ports** can be scanned by using IP:PORT format - the tool will include them in the scan

---

## 📸 **Example Output**  

<img width="100%" align="centre" src="https://github.com/spyboy-productions/CamXploit/blob/main/demo.png" />

---


## 🤖 **To-Do & Future Features**  
- [x] Add multi-threaded scanning for speed  
- [x] Expand camera brand detection  
- [x] RTSP detection and credential testing
- [x] Service name display for ports
- [x] Enhanced credential database
- [ ] Implement logging feature  
- [ ] Add screenshot capture functionality  
- [ ] Implement report generation  
- [ ] Add network range scanning  
- [ ] Implement MAC address lookup  

---
## 🙌 **Contributions**  
Feel free to submit issues, suggestions, or pull requests!  

<h4 align="center"> If you find this GitHub repo useful, please consider giving it a star! ⭐️ </h4> 
