import platform
import subprocess
import json
import re
from datetime import datetime, timezone

def check_disk_encryption():
    system = platform.system()
    if system == "Windows":
        try:
            result = subprocess.run(["powershell", "-command", "(New-Object -ComObject Shell.Application).NameSpace('C:').Self.ExtendedProperty('System.Volume.BitLockerProtection')"], capture_output=True, text=True)
            output = result.stdout.strip()
            if "1" in output:
                return True
            else:
                return False
        except Exception as e:
            print(f"Error checking BitLocker status: {e}")
            return False
    elif system == "Darwin":  # macOS
        try:
            result = subprocess.run(["diskutil", "apfs", "encryptionstatus"], capture_output=True, text=True)
            output = result.stdout
            if "FileVault is On" in output:
                return True
            else:
                return False
        except Exception as e:
            print(f"Error checking FileVault status: {e}")
            return False
    else:
        return None

def check_edr_agent(process_names):
    system = platform.system()
    if system == "Windows":
        try:
            result = subprocess.run(f'tasklist /FI "IMAGENAME eq {process_names['Windows']}"', shell=True, capture_output=True, text=True)
            output = result.stdout.strip()
            if output == "INFO: No tasks are running which match the specified criteria.":
                return False
            else:
                return True
        except Exception as e:
            print(f"Error checking EDR agent status: {e}")
            return False
    if system == "Darwin":
        try:
            result = subprocess.run(["pgrep", "-l", f"{process_names['Windows']}"], capture_output=True, text=True)
            output = result.stdout.strip()
            if output:
                return True
            else:
                return False
        except Exception as e:
            print(f"Error checking EDR agent status: {e}")
            return False

def check_defender_status():
    system = platform.system()
    if system == "Windows": # Windows only
        try:
            for av_check, expected in {'AntivirusEnabled': True, 'AntispywareEnabled': True, 'AMServiceEnabled': True, 'IoavProtectionEnabled': True, 'RealTimeProtectionEnabled': True, 'DefenderSignaturesOutOfDate': False}.items():
                result = subprocess.run(["powershell", "-command", f"(Get-MpComputerStatus).{av_check}"], capture_output=True, text=True)
                output = result.stdout.strip()
                if output != str(expected):
                    return False
            return True
        except Exception as e:
            print(f"Error checking Defender status: {e}")
            return False

def check_firewall_status():
    system = platform.system()
    if system == "Windows":
        try:
            result = subprocess.run(["powershell", "-command", "Get-NetFirewallProfile | Where-Object {$_.Name -eq 'Domain'} | Select-Object Enabled"], capture_output=True, text=True)
            output = result.stdout.strip()
            return "True" in output
        except Exception as e:
            print(f"Error checking Windows Firewall status: {e}")
            return False
    elif system == "Darwin":  # macOS
        try:
            result = subprocess.run(["pfctl", "-s", "rules"], capture_output=True, text=True)
            output = result.stdout
            if "pass" not in output and "block" in output: #Basic check for active rules
                return True
            else:
                return False
        except Exception as e:
            print(f"Error checking macOS Firewall status: {e}")
            return False
    else:
        return None

def check_jailbreak():
  system = platform.system()
  if system == "Darwin": #macOS only
      try:
          result = subprocess.run(["csrutil", "status"], capture_output=True, text=True)
          output = result.stdout
          if  "disabled" in output:
              return True #Indicates potential jailbreak
          else:
              return False
      except Exception as e:
          print(f"Error checking Jailbreak status: {e}")
          return False

def check_password_required():
    system = platform.system()
    if system == "Windows":
        try:
            result = subprocess.run(["powershell", "-command", "(Get-CimInstance -ClassName Win32_UserAccount | Where-Object {$_.Name -eq 'Administrator'}).PasswordRequired"], capture_output=True, text=True)
            output = result.stdout.strip()
            return "True" in output
        except Exception as e:
            print(f"Error checking password status: {e}")
            return False
    elif system == "Darwin": #macOS only
        try:
            result = subprocess.run(["dscl", ".", "-read", "/Users/root", "Password"], capture_output=True, text=True)
            output = result.stdout
            if output != "":
                return True
            else:
                return False
        except Exception as e:
            print(f"Error checking password status: {e}")
            return False

def check_screen_lockout():
    system = platform.system()
    if system == "Windows":
        try:
            result = subprocess.run(["powershell", "-command", "(Get-ItemProperty -Path 'HKCU:/Control Panel/Desktop').ScreenSaveActive"], capture_output=True, text=True)
            output = result.stdout.strip()
            if output == '1':
                result = subprocess.run(["powershell", "-command", "(Get-ItemProperty -Path 'HKCU:/Control Panel/Desktop').DelayLockInterval"], capture_output=True, text=True)
                output = result.stdout.strip()
                return int(output) > 0 #Check if timeout is greater than zero
            else:
                return False # if the screen saver never activates the lockout delay doesn't begin
        except Exception as e:
            print(f"Error checking screen lockout status: {e}")
            return False
    elif system == "Darwin":
        try:
            result = subprocess.run(["defaults", "read", "com.apple.screensaver", "idleTime"], capture_output=True, text=True)
            output = result.stdout.strip()
            return int(output) > 0 #Check if timeout is greater than zero
        except Exception as e:
            print(f"Error checking screen lockout status: {e}")
            return False

def check_device_trust_certificate(cert_subject):
    system = platform.system()
    cert_result = {"present": False, "valid_until": None}
    if system == "Windows":
        # Use certutil to enumerate certificates in My store
        result = subprocess.run(["certutil", "-store", "My"], capture_output=True, text=True)
        output = result.stdout
        # Find block with Subject matching the expected subject
        pattern = re.compile(r"Subject:.*?CN=([^,\n]+)", re.IGNORECASE)
        for line in output.splitlines():
            match = pattern.search(line)
            if match and cert_subject.lower() in match.group(1).lower():
                cert_result["present"] = True
                # Look ahead for NotAfter field
                notafter_match = re.search(r"NotAfter:\s+(.+)", output, re.IGNORECASE)
                if notafter_match:
                    try:
                        dt = datetime.strptime(
                            notafter_match.group(1).strip(),
                            "%b %d %H:%M:%S %Y %Z"
                        )
                        result["valid_until"] = dt.replace(tzinfo=timezone.utc).isoformat()
                    except Exception:
                        pass
                break
    elif system == "Darwin":
        # security find-certificate -c "<subject>"
        result = subprocess.run(["security", "find-certificate", "-c", cert_subject, "-p"], capture_output=True, text=True)
        output = result.stdout
        if output:
            cert_result["present"] = True
            # Extract NotAfter date using openssl
            result = subprocess.run(["openssl", "x509", "-noout", "-enddate"], capture_output=True, text=True)
            cert_out = result.stdout
            match = re.search(r"notAfter=(.+)", cert_out)
            if match:
                try:
                    dt = datetime.strptime(
                        match.group(1).strip(),
                        "%b %d %H:%M:%S %Y %Z"
                    )
                    cert_result["valid_until"] = dt.replace(tzinfo=timezone.utc).isoformat()
                except Exception:
                    pass
    else:
        return None
    return cert_result

if __name__ == "__main__":
    results = {
        "timestamp_utc": datetime.now().replace(tzinfo=timezone.utc).isoformat(),
        "os_type": platform.system(),
        "os_version": platform.version(),
        "hostname": platform.node(),
        "disk_encryption": check_disk_encryption(),
        "edr_agent": check_edr_agent(process_names = {"Windows": 'MsMpEng.exe', "MacOS": 'syspolicyd'}),
        "firewall_status": check_firewall_status(),
        "defender_status": check_defender_status() if platform.system() == "Windows" else None, #Only run on windows
        "jailbreak": check_jailbreak() if platform.system() == "Darwin" else None, #Only run on macOS
        "password_required": check_password_required(),
        "screen_lockout": check_screen_lockout(),
        "device_trust_certificate": check_device_trust_certificate(cert_subject=platform.node()) # default search for subject based on hostname
    }

    print(json.dumps(results, indent=4))
