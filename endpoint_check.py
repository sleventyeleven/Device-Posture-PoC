"""
Healthcare Device Security Posture Check Script

This script performs security posture checks on endpoints to determine if they meet
the minimum security requirements for accessing healthcare records. It is designed to
run without elevated privileges and uses only standard Python libraries.

Functions:
    check_disk_encryption: Checks if disk encryption is enabled
    check_edr_agent: Verifies EDR agent presence
    check_defender_status: Validates Windows Defender status (Windows only)
    check_firewall_status: Ensures firewall is enabled
    check_jailbreak: Detects potential jailbreak on macOS
    check_password_required: Confirms password protection requirements
    check_screen_lockout: Verifies screen lock timeout settings
    check_device_trust_certificate: Validates device trust certificate presence

Author: Michael Contino
"""

import platform
import subprocess
import json
import re
from datetime import datetime, timezone

def check_disk_encryption():
    """
       Check if disk encryption is enabled on the device.

       Returns:
           bool: True if encryption is enabled, False otherwise. None for unsupported OS.
       """
    system = platform.system()
    if system == "Windows":
        try:
            # Use PowerShell to check BitLocker status via legacy com object to avoid need for privileges
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
            # Use fdesetup to view overall FileVault status
            result = subprocess.run(["fdesetup", "status"], capture_output=True, text=True)
            output = result.stdout
            if "FileVault is On" in output:
                return True
            else:
                return False
        except Exception as e:
            print(f"Error checking FileVault status: {e}")
            return False
    else:
        # Unsupported operating system
        return None

def check_edr_agent(process_names):
    """
    Check if an Endpoint Detection and Response (EDR) agent is running.

    Args:
        process_names (dict): Dictionary mapping OS to EDR process name

    Returns:
        bool: True if EDR agent is running, False otherwise
    """
    system = platform.system()
    if system == "Windows":
        try:
            # Use tasklist and leverage built in filter to check for Windows EDR process
            result = subprocess.run(f"tasklist /FI \"IMAGENAME eq {process_names['Windows']}\"", shell=True, capture_output=True, text=True)
            output = result.stdout.strip()
            if output == "INFO: No tasks are running which match the specified criteria.":
                return False
            else:
                return True
        except Exception as e:
            print(f"Error checking EDR agent status: {e}")
            return False
    elif system == "Darwin":
        try:
            # Use native pgrep to check for macOS EDR process
            result = subprocess.run(["pgrep", "-l", f"{process_names['MacOS']}"], capture_output=True, text=True)
            output = result.stdout.strip()
            if output:
                return True
            else:
                return False
        except Exception as e:
            print(f"Error checking EDR agent status: {e}")
            return False
    else:
        # Unsupported operating system
        return None

def check_defender_status():
    system = platform.system()
    if system == "Windows": # Windows only
        try:
            # Check each Defender status parameters within the Computer Status summary using Powershell
            checks = {
                'AntivirusEnabled': True,
                'AntispywareEnabled': True,
                'AMServiceEnabled': True,
                'IoavProtectionEnabled': True,
                'RealTimeProtectionEnabled': True,
                'DefenderSignaturesOutOfDate': False
            }

            for av_check, expected in checks.items():
                result = subprocess.run(["powershell", "-command", f"(Get-MpComputerStatus).{av_check}"], capture_output=True, text=True)
                output = result.stdout.strip()
                if output != str(expected):
                    return False
            return True
        except Exception as e:
            print(f"Error checking Defender status: {e}")
            return False
    else:
        # Not applicable for non-Windows systems
        return None

def check_firewall_status():
    """
    Check if the system firewall is enabled.

    Returns:
        bool: True if firewall is enabled, False otherwise. None for unsupported OS.
    """
    system = platform.system()
    if system == "Windows":
        try:
            # Check Windows Firewall status for local domain using powershell
            result = subprocess.run(["powershell", "-command", "Get-NetFirewallProfile | Where-Object {$_.Name -eq 'Domain'} | Select-Object Enabled"], capture_output=True, text=True)
            output = result.stdout.strip()
            return "True" in output
        except Exception as e:
            print(f"Error checking Windows Firewall status: {e}")
            return False
    elif system == "Darwin":  # macOS
        try:
            # Check macOS Application Firewall status using the socketfilterfw app to avoid root privilege
            result = subprocess.run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"], capture_output=True, text=True)
            output = result.stdout
            if "enabled" in output:
                return True
            else:
                return False
        except Exception as e:
            print(f"Error checking macOS Firewall status: {e}")
            return False
    else:
        # Unsupported operating system
        return None

def check_jailbreak():
    """
    Check if the macOS device appears to be jailbroken.

    Returns:
    bool: True if potential jailbreak detected, False otherwise
    """
    system = platform.system()
    if system == "Darwin": #macOS only
        try:
            # Check System Integrity Protection status
            result = subprocess.run(["csrutil", "status"], capture_output=True, text=True)
            output = result.stdout
            if  "disabled" in output:
                return True #Indicates potential jailbreak
            else:
                return False
        except Exception as e:
            print(f"Error checking Jailbreak status: {e}")
            return False
    else:
        # Not applicable for non-macOS systems
        return None

def check_password_required():
    """
    Check if password protection is required on the device.

    Returns:
        bool: True if password is required, False otherwise
    """
    system = platform.system()
    if system == "Windows":
        try:
            # Check Windows password required for current user
            result = subprocess.run(["powershell", "-command", "(Get-CimInstance -ClassName Win32_UserAccount | Where-Object {$_.Name -eq \"$($env:USERNAME)\"}).PasswordRequired"], capture_output=True, text=True)
            output = result.stdout.strip()
            return "True" in output
        except Exception as e:
            print(f"Error checking password status: {e}")
            return False
    elif system == "Darwin": #macOS only
        try:
            # Check macOS if ask for password at the screen saver is enabled to unlock device
            result = subprocess.run(["defaults", "read", "com.apple.screensaver", "askForPasswordDelay"], capture_output=True, text=True)
            output = result.stdout.strip()
            if "does not exist" in result.stderr.strip():
                return True #If no value is set the default is sleep after 15mins and require password after asleep for 5min
            if int(output) > 0:
                return True #Lockout time set and not zero (infinite)
            else:
                return False
        except Exception as e:
            print(f"Error checking password status: {e}")
            return False

    else:
        # Unsupported operating system
        return None

def check_screen_lockout():
    """
    Check if screen lockout settings are properly configured.

    Returns:
        bool: True if screen lockout is configured, False otherwise
    """
    system = platform.system()
    if system == "Windows":
        try:
            # Check Windows screensaver enabled, if not the delay lock will not take effect
            result = subprocess.run(["powershell", "-command", "(Get-ItemProperty -Path 'HKCU:/Control Panel/Desktop').ScreenSaveActive"], capture_output=True, text=True)
            output = result.stdout.strip()
            if output == '1':
                # Check if the delay interval is set or if it's the default
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
            # Check macOS screensaver idle time in current user plist
            result = subprocess.run(["defaults", "read", "com.apple.screensaver", "idleTime"], capture_output=True, text=True)
            output = result.stdout.strip()
            if "does not exist" in result.stderr.strip():
                return True #If no value has been ever set the default is 20 minute lockout
            if int(output) > 0:
                return True #Lockout time set and not zero (infinite)
            else:
                return False
        except Exception as e:
            print(f"Error checking screen lockout status: {e}")
            return False
    else:
        # Unsupported operating system
        return None

def check_device_trust_certificate(cert_subject):
    """
    Check if a device trust certificate exists with the specified subject.

    Args:
        cert_subject (str): The certificate subject to search for

    Returns:
        dict: Dictionary containing 'present' boolean and 'valid_until' datetime
    """
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
        # Unsupported operating system
        return None
    return cert_result

if __name__ == "__main__":
    """
    Main execution block that runs all security checks and outputs results.

    Returns:
        JSON formatted string with all security posture check results
    """
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
