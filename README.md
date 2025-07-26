# HelloBird

HelloBird is a web-based wrapper for the CamXploit CCTV reconnaissance tool. It provides a user-friendly interface for scanning for exposed CCTV cameras and viewing their streams.

## 🚀 **Features**

-   **Web-based UI:** A clean and intuitive web-based user interface for interacting with the CamXploit tool.
-   **Real-time Scanning:** Real-time output of the scanning process, so you can see the results as they come in.
-   **Stream Viewing:** View the streams of discovered cameras directly in your browser.
-   **CIDR Network Range Scanning:** Scan a range of IP addresses using CIDR notation.
-   **AI-Powered Contextual Analysis:** Get an AI-powered contextual summary of what each camera is likely seeing.

## 🚀 **Deployment**

This application is designed to be deployed as a Hugging Face Space.

### **1️⃣ Fork the Repository**

First, you will need to fork the [CamXploit repository](https://github.com/spyboy-productions/CamXploit) to your own GitHub account.

### **2️⃣ Create a Hugging Face Space**

1.  Go to [huggingface.co/spaces](https://huggingface.co/spaces) and click on "New Space".
2.  Give your Space a name and select "Docker" as the Space SDK.
3.  Choose "Create Space".

### **3️⃣ Upload the Code**

1.  Clone your forked repository to your local machine:
    ```bash
    git clone https://github.com/<your-username>/CamXploit.git
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

## Roadmap

The future development plans for this project are outlined in the [ROADMAP.md](ROADMAP.md) file.
