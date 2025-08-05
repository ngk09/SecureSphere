# Install required packages
!pip install -q beautifulsoup4 requests cryptography opencv-python pillow

# Imports
from IPython.display import display, clear_output, HTML, FileLink
import ipywidgets as widgets
import requests
from bs4 import BeautifulSoup
import ssl, socket, time, os
from cryptography.fernet import Fernet
from google.colab import files

# Generate encryption key
key = Fernet.generate_key()
cipher = Fernet(key)

# Global variable to store uploaded file path
uploaded_file_path = None

# UI Elements (Colab Interactive Widgets)
url_input = widgets.Text(
    value='https://example.com',
    placeholder='Enter a website URL',
    description='Website:',
    style={'description_width': 'initial'},
    layout=widgets.Layout(width='500px')
)

scan_button = widgets.Button(description="Scan Website", button_style='primary')
upload_button = widgets.Button(description="Upload File", button_style='info')
encrypt_button = widgets.Button(description="Encrypt File", button_style='success')
decrypt_button = widgets.Button(description="Decrypt File", button_style='warning')

# Website Scan Functions
def detect_phishing(url):
    """
    Detects potential phishing by checking for suspicious keywords and login forms.
    """
    phishing_keywords = ["login", "verify", "account", "update", "bank"]
    suspicious = any(keyword in url.lower() for keyword in phishing_keywords)
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.content, 'html.parser')
        forms = soup.find_all('form')
        has_login = any("password" in str(f).lower() for f in forms)
    except Exception as e:
        print("Phishing Detection Error:", e)
        return

    print("\nPhishing Detection:")
    if suspicious:
        print(f"Suspicious URL pattern detected: {url}")
    if has_login:
        print("Login form found — Possible phishing page.")
    if not suspicious and not has_login:
        print("No phishing signs detected.")

def check_ssl_cert(domain):
    """
    Checks SSL certificate validity using Python's SSL module.
    """
    print("\nSSL Certificate Check:")
    ctx = ssl.create_default_context()
    try:
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            print("SSL Certificate is valid and trusted.")
    except ssl.SSLCertVerificationError:
        print("Invalid or self-signed SSL certificate.")
    except Exception as e:
        print(f"SSL error: {e}")

def detect_malware(url):
    """
    Checks for suspicious JavaScript patterns indicating possible malware.
    """
    print("\nMalware Detection:")
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.content, 'html.parser')
        scripts = soup.find_all('script')

        suspicious_count = sum(
            1 for script in scripts
            if script.string and any(x in script.string for x in ["eval(", "document.write", "setTimeout(", "unescape"])
        )

        if suspicious_count > 0:
            print(f"Detected {suspicious_count} suspicious JavaScript patterns — Potential malware risk.")
        else:
            print("No malware-like scripts found.")
    except Exception as e:
        print("Malware Detection Error:", e)


# File Encryption / Decryption
def encrypt_file(filepath):
    """
    Encrypts the selected file using Fernet encryption.
    """
    print(f"Encrypting file: {filepath}")
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        encrypted_data = cipher.encrypt(data)

        filename = os.path.basename(filepath).replace(" ", "_")
        encrypted_path = f"/content/{filename}.enc"

        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)

        print(f"Encrypted file saved as: {encrypted_path}")
        try:
            files.download(encrypted_path)
        except:
            print("Auto-download failed — use manual link below:")
        display(FileLink(encrypted_path))
    except Exception as e:
        print("Encryption failed:", e)

def decrypt_file(encrypted_path):
    """
    Decrypts a previously encrypted file.
    """
    try:
        with open(encrypted_path, 'rb') as f:
            encrypted = f.read()
        decrypted = cipher.decrypt(encrypted)

        filename = os.path.basename(encrypted_path).replace(" ", "_")
        output_path = f"/content/{filename.replace('.enc', '')}"

        with open(output_path, 'wb') as f:
            f.write(decrypted)
        print(f"Decrypted file saved as: {output_path}")
        try:
            files.download(output_path)
        except:
            print("Auto-download failed — use manual link below:")
        display(FileLink(output_path))
    except Exception as e:
        print("Decryption failed:", e)


# Button Actions
def on_scan_click(b):
    clear_output(wait=True)
    launch_colab_safe_ui()
    print("\nScanning in progress...\n")
    time.sleep(1)
    url = url_input.value.strip()
    if not url.startswith("http"):
        url = "https://" + url
    domain = url.replace("http://", "").replace("https://", "").split("/")[0]
    print(f"Scanning: {url}")
    detect_phishing(url)
    check_ssl_cert(domain)
    detect_malware(url)
    print("\nWebsite Security Scan Complete.")

def on_upload_click(b):
    global uploaded_file_path
    print("Please upload a file:")
    try:
        uploaded = files.upload()
        for fname in uploaded:
            path = f"/content/{fname}"
            with open(path, 'wb') as f:
                f.write(uploaded[fname])
            print(f"File uploaded: {path}")
            uploaded_file_path = path
    except Exception as e:
        print("Upload failed:", e)

def on_encrypt_click(b):
    if uploaded_file_path:
        encrypt_file(uploaded_file_path)
    else:
        print("Please upload a file first using the Upload button.")

def on_decrypt_click(b):
    print("Please upload a .enc file:")
    try:
        uploaded = files.upload()
        for fname in uploaded:
            if fname.endswith(".enc"):
                encrypted_path = f"/content/{fname}"
                with open(encrypted_path, 'wb') as f:
                    f.write(uploaded[fname])
                decrypt_file(encrypted_path)
            else:
                print("Not a valid .enc file.")
    except Exception as e:
        print("Decryption upload failed:", e)


# Display UI in Google Colab
def launch_colab_safe_ui():
    display(widgets.HTML(value="<h2>SecureSphere – Website & File Security Suite</h2>"))
    display(widgets.HBox([url_input, scan_button]))
    display(widgets.HTML(value="<br><b>Upload File for Encryption</b>"))
    display(upload_button)
    display(widgets.HBox([encrypt_button, decrypt_button]))


# Connect buttons to their actions
scan_button.on_click(on_scan_click)
upload_button.on_click(on_upload_click)
encrypt_button.on_click(on_encrypt_click)
decrypt_button.on_click(on_decrypt_click)

# Launch the app in Colab
launch_colab_safe_ui()
