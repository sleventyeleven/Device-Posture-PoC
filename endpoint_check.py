import platform
import subprocess
import json
import os

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

def check_edr_agent():
    # Mock EDR agent check. Replace "EDRProcessName" with the actual process name.
    process_name = "EDRProcessName"  # Example: "CrowdStrikeAgent.exe" or "carbonblack.pid"
    try:
        result = subprocess.run(["ps", "aux"], capture_output=True, text=True) #For MacOs
        if system == "Windows":
            result = subprocess.run(["tasklist"], capture_output=True, text=True)
        output = result.stdout
        return process_name in output
    except Exception as e:
        print(f"Error checking EDR agent status: {e}")
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
          result = subprocess.run(["ioreg", "-c", "IOPlatformExpert"], capture_output=True, text=True)
          output = result.stdout
          if "SecureBootModel" in output and "Disabled" in output:
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
    elif system == "Darwin": #macOS only
        try:
            result = subprocess.run(["defaults", "read", "com.apple.screensaver", "idleTime"], capture_output=True, text=True)
            output = result.stdout.strip()
            return int(output) > 0 #Check if timeout is greater than zero
        except Exception as e:
            print(f"Error checking screen lockout status: {e}")
            return False

def check_device_trust_certificate():
    # Implement certificate validation logic here.  This will depend on how the certificates are stored and managed.
    # Example: Check for a specific file in a known location.
    cert_path = "/path/to/device_trust_certificate.pem" #Replace with actual path
    return os.path.exists(cert_path)

if __name__ == "__main__":
    system = platform.system()
    print(f"Operating System: {system}")

    results = {
        "disk_encryption": check_disk_encryption(),
        "edr_agent": check_edr_agent(),
        "firewall_status": check_firewall_status(),
        "jailbreak": check_jailbreak() if system == "Darwin" else None, #Only run on macOS
        "password_required": check_password_required(),
        "screen_lockout": check_screen_lockout(),
        "device_trust_certificate": check_device_trust_certificate()
    }

    print(json.dumps(results, indent=4))
