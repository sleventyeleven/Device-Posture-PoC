# Device-Posture-PoC - Endpoint Posture Check Script
Proof of concept python script to preform custom posture checks for a conditional access gateway.


## Purpose

This script performs a basic security posture check on the machine it's run on to determine if it meets minimum security requirements for accessing sensitive systems. It is designed to be part of a lightweight agent or browser-based health check required before granting access to Included Health resources.

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
*   **EDR Agent:** Checks if a specified security agent process is running.  Currently mocks this by checking for a process named "EDRProcessName". **Important:** Replace `"EDRProcessName"` in the script with the actual process name of your EDR agent.
*   **Firewall Status:** Checks if the native OS firewall is enabled.
*   **Jailbreak (macOS only):** Detects potential jailbreaking on macOS devices by checking SecureBootModel status.
*   **Password Required:** Verifies that a password is required for user accounts.
*   **Screen Lockout Time:** Checks if the screen lockout timeout is configured to prevent unauthorized access after inactivity.
*   **Device Trust Certificate:** Checks if a device trust certificate is installed and not expired.

## Output

The script outputs its findings in JSON format to the console:

```json
{
    "disk_encryption": true,
    "edr_agent": false,
    "firewall_status": true,
    "jailbreak": false,
    "password_required": true,
    "screen_lockout": 600,
    "device_trust_certificate": false
}
