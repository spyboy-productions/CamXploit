## 📌 **About**  
CamXploit is a reconnaissance tool designed to help researchers and security enthusiasts check if an IP address is hosting an exposed CCTV camera. It scans common camera ports, checks for login pages, tests default credentials, and provides useful search links for further investigation.  

⚠️ **Disclaimer:** This tool is intended for educational and security research purposes **only**. Unauthorized scanning of systems you do not own is illegal. Use responsibly.  

---

## 🚀 **Features**  
✔️ **Scans common CCTV ports** (80, 443, 554, 8080, 8443)  
✔️ **Detects exposed camera login pages**  
✔️ **Checks if the device is a camera stream**  
✔️ **Identifies camera brands & known vulnerabilities**  
✔️ **Tests for default credentials on login pages**  
✔️ **Provides manual search links (Shodan, Censys, Zoomeye, Google Dorking)**  
✔️ **Google Dorking suggestions for deeper recon**  

---

## 🛠️ **Installation**  

### **1️⃣ Clone the Repository**  
```bash
git clone https://github.com/yourusername/CamXploit.git
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
Enter the **public IP address** of the target device when prompted.  

### **🔍 What It Does:**  
1️⃣ **Scans open ports** (Common CCTV ports)  
2️⃣ **Checks if a camera is present**  
3️⃣ If a camera is found, it:  
   - Searches for **login pages**  
   - Checks **default credentials**  
   - Identifies **camera brand & vulnerabilities**  
4️⃣ Provides **manual search URLs** for deeper investigation  

---

## 📸 **Example Output**  

```
Enter Public IP of the Camera: 62.210.140.38

[🌍] Use these URLs to check the camera exposure manually:
  🔹 Shodan: https://www.shodan.io/search?query=62.210.140.38
  🔹 Censys: https://search.censys.io/hosts/62.210.140.38
  🔹 Zoomeye: https://www.zoomeye.org/searchResult?q=62.210.140.38
  🔹 Google Dorking: https://www.google.com/search?q=site:62.210.140.38+inurl:view/view.shtml+OR+inurl:admin.html+OR+inurl:login

[🌐] Checking Public IP Information:
  IP: 62.210.140.38
  City: Paris
  Region: Île-de-France
  Country: FR
  ISP: AS12876 SCALEWAY S.A.S.

[🔍] Scanning common CCTV ports:
  ✅ Port 80 is OPEN!
  ✅ Port 443 is OPEN!
  ❌ Port 554 is CLOSED
  ✅ Port 8080 is OPEN!
  ✅ Port 8443 is OPEN!

[📷] Checking if the device is a CAMERA:
  ❌ No camera streams detected.

[❌] No camera detected. Skipping login page, password, and vulnerability checks.

[✅] Scan Completed!
```

---

## 🤖 **To-Do & Future Features**  
- [ ] Add screenshot capture for login pages (optional)  
- [ ] Add multi-threaded scanning for speed  
- [ ] Expand camera brand detection  
- [ ] Implement logging feature  

---

## 📜 **License**  
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.  

---

## 🙌 **Contributions**  
Feel free to submit issues, suggestions, or pull requests!  

---

Let me know if you need any edits! 🚀
