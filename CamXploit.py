import requests
import socket

# ========== COMMON CCTV PORTS & PATHS ==========
COMMON_PORTS = [80, 443, 554, 8080, 8443]  # Standard IP Camera Ports
COMMON_PATHS = ["/", "/admin", "/login", "/viewer", "/webadmin", "/video", "/stream"]  # Camera Admin Pages

# Default passwords for common cameras
DEFAULT_CREDENTIALS = {
    "admin": ["admin", "1234", "password", "12345", "123456", "admin123"],
    "root": ["root", "pass", "toor"],
    "user": ["user", "user"],
}


# ========== PRINT SEARCH URLS ==========
def print_search_urls(ip):
    print("\n[🌍] Use these URLs to check the camera exposure manually:")
    print(f"  🔹 Shodan: https://www.shodan.io/search?query={ip}")
    print(f"  🔹 Censys: https://search.censys.io/hosts/{ip}")
    print(f"  🔹 Zoomeye: https://www.zoomeye.org/searchResult?q={ip}")
    print(f"  🔹 Google Dorking (Quick Search): https://www.google.com/search?q=site:{ip}+inurl:view/view.shtml+OR+inurl:admin.html+OR+inurl:login")


# ========== GOOGLE DORKING SUGGESTIONS ==========
def google_dork_search(ip):
    print("\n[🔎] Google Dorking Suggestions:")
    queries = [
        f"site:{ip} inurl:view/view.shtml",
        f"site:{ip} inurl:admin.html",
        f"site:{ip} inurl:login",
        f"intitle:'webcam' inurl:{ip}",
    ]

    for q in queries:
        print(f"  🔍 Google Dork: https://www.google.com/search?q={q.replace(' ', '+')}")


# ========== CHECK PUBLIC IP INFORMATION ==========
def check_ipinfo(ip):
    print("\n[🌐] Checking Public IP Information (ipinfo.io):")
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            data = response.json()
            print(f"  IP: {data['ip']}")
            print(f"  City: {data.get('city', 'N/A')}")
            print(f"  Region: {data.get('region', 'N/A')}")
            print(f"  Country: {data.get('country', 'N/A')}")
            print(f"  ISP: {data.get('org', 'N/A')}")
        else:
            print("[❌] Failed to fetch IP information.")
    except Exception as e:
        print(f"[❌] IP Info Error: {e}")


# ========== PORT SCANNER ==========
def check_ports(ip):
    print("\n[🔍] Scanning common CCTV ports on IP:", ip)
    open_ports = []

    for port in COMMON_PORTS:
        print(f"  🔄 Checking Port {port}...", end=" ")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        if sock.connect_ex((ip, port)) == 0:
            print(f"✅ OPEN!")
            open_ports.append(port)
        else:
            print(f"❌ CLOSED")

        sock.close()

    return open_ports


# ========== CHECK IF DEVICE IS A CAMERA ==========
def check_if_camera(ip, open_ports):
    print("\n[📷] Checking if the device is a CAMERA:")

    found_camera = False
    for port in open_ports:
        url = f"http://{ip}:{port}"
        print(f"  🔄 Testing {url}...", end=" ")

        try:
            response = requests.get(url, timeout=3)
            content_type = response.headers.get("Content-Type", "")

            if "image" in content_type or "video" in content_type:
                print(f"✅ Camera Stream Found!")
                found_camera = True
            elif response.status_code == 200:
                print(f"❌ Not a Camera")
            else:
                print(f"❌ No Response")
        except:
            print(f"❌ No Response")

    if not found_camera:
        print("  ❌ No camera streams detected.")

    return found_camera


# ========== CHECK FOR CAMERA LOGIN PAGE ==========
def check_login_pages(ip, open_ports):
    print("\n[🔍] Checking for Camera Login Pages:")
    possible_cameras = []

    for port in open_ports:
        for path in COMMON_PATHS:
            url = f"http://{ip}:{port}{path}"
            print(f"  🔄 Trying {url}...", end=" ")

            try:
                response = requests.get(url, timeout=3)
                if response.status_code == 200:
                    print(f"✅ Found!")
                    possible_cameras.append(url)
                else:
                    print(f"❌ Not Found")
            except requests.exceptions.RequestException:
                print(f"❌ No Response")

    if not possible_cameras:
        print("  ❌ No camera login pages detected.")


# ========== CHECK FOR CAMERA FIRMWARE & VULNERABILITIES ==========
def check_camera_firmware(ip, open_ports):
    print("\n[📡] Checking for Camera Type & Known Vulnerabilities:")

    for port in open_ports:
        url = f"http://{ip}:{port}"
        print(f"  🔄 Scanning {url}...", end=" ")

        try:
            response = requests.get(url, timeout=3)
            headers = response.headers

            if "server" in headers:
                server_header = headers["server"].lower()
                if "hikvision" in server_header:
                    print(f"🔥 Hikvision Camera Detected!")
                elif "dahua" in server_header:
                    print(f"🔥 Dahua Camera Detected!")
                elif "axis" in server_header:
                    print(f"🔥 Axis Camera Detected!")
                else:
                    print(f"❌ Unknown Camera Type")
            else:
                print(f"❌ No Camera Signature Found")

        except:
            print(f"❌ No Response")


# ========== TRY DEFAULT CAMERA PASSWORDS ==========
def test_default_passwords(ip, open_ports):
    print("\n[🔑] Testing Default Camera Passwords:")

    for port in open_ports:
        url = f"http://{ip}:{port}/login"
        print(f"  🔄 Testing {url}...", end=" ")

        for username, passwords in DEFAULT_CREDENTIALS.items():
            for password in passwords:
                try:
                    response = requests.post(url, data={"username": username, "password": password}, timeout=3)

                    if response.status_code == 200:
                        print(f"🔥 Vulnerable! Default Login: {username}/{password}")
                        return
                except:
                    pass  # Ignore errors

        print(f"❌ No Default Credentials Found")


# ========== MAIN FUNCTION ==========
def main():
    target_ip = input("Enter Public IP of the Camera: ").strip()

    # Manual Search URLs
    print_search_urls(target_ip)

    # Detailed Google Dorking Suggestions
    google_dork_search(target_ip)

    # Public IP Info
    check_ipinfo(target_ip)

    # Local Port Scan
    open_ports = check_ports(target_ip)

    if open_ports:
        # Check if it's a camera
        camera_found = check_if_camera(target_ip, open_ports)

        if not camera_found:
            choice = input(
                "\n[❓] No camera found. Do you still want to check login pages, vulnerabilities, and passwords? [y/N]: ").strip().lower()
            if choice != "y":
                print("\n[✅] Scan Completed! No camera found.")
                return

        # Check for login pages
        check_login_pages(target_ip, open_ports)

        # Fingerprint Camera Type
        check_camera_firmware(target_ip, open_ports)

        # Test Default Credentials
        test_default_passwords(target_ip, open_ports)

    else:
        print("\n[❌] No open ports found. Likely no camera here.")

    print("\n[✅] Scan Completed!")


if __name__ == "__main__":
    main()
