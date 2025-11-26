# Device-Posture-PoC - Endpoint Posture Check Script
Proof of concept python script to preform custom posture checks for a conditional access gateway.


## Purpose

This script performs a basic security posture check on the machine it's run on to determine if it meets minimum security requirements for accessing sensitive systems. It is designed to be part of a lightweight agent or browser-based health check required before granting access to protected resources.

## How to Run

1.  **Python 3.6+:** Ensure Python 3.6 or later is installed on the target machine.
2.  **Dependencies:** No external dependencies are required.
3.  **Execution:** Save the script as `endpoint_check.py` and run it from the command line:

    ```bash
    python endpoint_check.py
    ```

## Checks Performed

The script verifies the following conditions:

*   **Disk Encryption:** Checks if full-disk encryption is enabled (BitLocker for Windows, FileVault for macOS).
*   **EDR Agent:** Checks if a specified security agent process is running. Currently, mocks this by checking for the OS based process name listed in the dictionary. **Important:** Update the process_names dictionary in the script with the actual process name of your Windows and MacOS EDR agent respectively.
*   **Firewall Status:** Checks if the native OS firewall is enabled.
*   **Jailbreak (macOS only):** Detects potential jailbreaking on macOS devices by checking System Integrity Protection (SIP) status.
*   **Defender Status (Windows Only)** Check if each Windows Defender component is enabled and has the latest signatures
*   **Password Required:** Verifies that a password is required for user accounts.
*   **Screen Lockout Time:** Checks if the screen lockout timeout is configured to prevent unauthorized access after inactivity.
*   **Device Trust Certificate:** Checks if a device trust certificate is installed and not expired based on a given subject name (defaults to hostname).

## Output

The script outputs its findings in JSON format to the console:

```json
{
    "timestamp_utc": "2025-11-23T22:31:12.005476+00:00",
    "os_type": "Windows",
    "os_version": "10.0.26200",
    "hostname": "WORKSTATION",
    "disk_encryption": true,
    "edr_agent": true,
    "firewall_status": true,
    "defender_status": true,
    "jailbreak": null,
    "password_required": true,
    "screen_lockout": true,
    "device_trust_certificate": {
        "present": false,
        "valid_until": null
    }
}
