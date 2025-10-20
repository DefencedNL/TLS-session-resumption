import subprocess
import re
import sys
import os
import time

"""
This script thoroughly test a server's support for
TLS Session Resumption for both TLS 1.2 and TLS 1.3 protocols.

It provides a reliable way to check resumption capabilities,
circumventing the known issues with the standard OpenSSL s_client -reconnect
command for TLS 1.3 by implementing a robust,
two-step Pre-Shared Key (PSK) ticket exchange verification.

Copyright Defenced B.V.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

# --- Configuration ---
DEFAULT_PORT = 443
TEMP_SESSION_FILE = "/tmp/tls13_session.pem"

# --- Utility Functions ---

def run_openssl_command(command_parts, input_data):
    """Runs an openssl command with the specified input."""

    # Ensure input_data includes a newline for the command to proceed/exit
    if not input_data.endswith('\n'):
        input_data += '\n'

    print(f"  Command: {' '.join(command_parts)}")

    try:
        process = subprocess.run(
            command_parts,
            input=input_data,
            capture_output=True,
            text=True,
            timeout=25,
            check=False
        )
        return process.stdout + process.stderr, process.returncode
    except FileNotFoundError:
        return "Error: 'openssl' command not found. Ensure OpenSSL is installed and in your PATH.", 1
    except subprocess.TimeoutExpired:
        return "Error: Command timed out after 25 seconds. (Possible hang on connection or I/O).", 1

def analyze_reconnect_output(output):
    """Analyzes output from the -reconnect test (used for reliable TLS 1.2 check)."""
    results = {
        "Online": "No",
        "Initial session ID": "N/A",
        "Final session ID": "N/A", 
        "Total New connections": 0,
        "Total Reused connections": 0,
        "New Cipher Detail": "N/A",
        "Reused Cipher Detail": "N/A",
        "Mechanism": "N/A",
        "Ticket": "N/A"
    }
    
    if "CONNECTED" in output and "Verification: OK" in output:
        results["Online"] = "Yes"
    if results["Online"] == "No": return results

    session_ids = re.findall(r'Session-ID:\s*([0-9A-F]+)', output)
    if session_ids:
        results["Initial session ID"] = session_ids[0]
        results["Final session ID"] = session_ids[-1]
        
    new_matches = re.findall(r'(New, TLSv.*)', output)
    reused_matches = re.findall(r'(Reused, TLSv.*)', output)
    
    results["Total New connections"] = len(new_matches)
    results["Total Reused connections"] = len(reused_matches)
    
    if new_matches: results["New Cipher Detail"] = new_matches[0]
    if reused_matches: results["Reused Cipher Detail"] = reused_matches[0]
        
    if re.search(r'Post-Handshake New Session Ticket arrived:', output):
        results["Ticket"] = "Yes (PSK Ticket Sent)"
    elif re.search(r'Session-ID-context', output):
        results["Ticket"] = "Yes (ID Context)"
    else:
        results["Ticket"] = "No/Unknown"

    if results["Total Reused connections"] > 0:
        if results["Initial session ID"] == results["Final session ID"]:
            results["Mechanism"] = "Session ID (Stateful) - Identified by matching Session IDs"
        else:
            results["Mechanism"] = "Session Ticket (Stateless) - Identified by non-matching Session IDs"
    elif results["Total New connections"] > 0 and results["Total Reused connections"] == 0:
        results["Mechanism"] = "Not Supported"
    
    return results

def check_tls13_two_step(host, target):
    """
    Performs the reliable two-step TLS 1.3 PSK resumption check.
    Step 1: Save PSK ticket.
    Step 2: Attempt resumption using the ticket.
    """
    metrics = {
        "Online": "No",
        "Cipher Detail": "N/A",
        "PSK Ticket Sent": False,
        "Resumption Confirmed": False,
        "Resumption Detail": "", 
        "Mechanism": "TLS 1.3 PSK (Test Pending)"
    }
    
    # Clean up the session file at the start (to be safe)
    if os.path.exists(TEMP_SESSION_FILE):
        os.remove(TEMP_SESSION_FILE)

    # --- Step 1: Save Session Ticket (PSK) ---
    print(" [Step 1/2] Saving PSK Ticket")
    
    command_13_save = [
        'openssl', 's_client', '-connect', target, '-servername', host, 
        '-tls1_3', '-sess_out', TEMP_SESSION_FILE
    ]
    # Input: Minimal HTTP GET request to complete the handshake and trigger ticket sending.
    http_request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    output_13_save, return_code_13_save = run_openssl_command(command_13_save, http_request)

    if "CONNECTED" in output_13_save and "Verification: OK" in output_13_save:
        metrics["Online"] = "Yes"
    else:
        return metrics # Exit if connection fails

    if re.search(r'Post-Handshake New Session Ticket arrived:', output_13_save):
        metrics["PSK Ticket Sent"] = True

    new_match = re.search(r'(New, TLSv1.3, Cipher is [^\n]+)', output_13_save)
    if new_match:
        metrics["Cipher Detail"] = new_match.group(1).replace("New, ", "")


    # --- Step 2: Attempt Resumption ---
    print(" [Step 2/2] Attempting Resumption with Saved Ticket")
    
    if not metrics["PSK Ticket Sent"] or not os.path.exists(TEMP_SESSION_FILE):
        metrics["Mechanism"] = "TLS 1.3 PSK (Ticket Not Sent or File Error)"
        if os.path.exists(TEMP_SESSION_FILE): os.remove(TEMP_SESSION_FILE)
        return metrics

    time.sleep(1) 

    command_13_load = [
        'openssl', 's_client', '-connect', target, '-servername', host, 
        '-tls1_3', '-sess_in', TEMP_SESSION_FILE
    ]
    output_13_load, return_code_13_load = run_openssl_command(command_13_load, 'Q')

    # Find the 'Reused, TLSv1.3' line (if it exists)
    reused_match = re.search(r'(Reused, TLSv1.3, Cipher is [^\n]+)', output_13_load)

    # Check for the two reliable indicators: "Reused session-id: Yes" OR "Reused, TLSv1.3"
    if (re.search(r'Reused session-id: Yes', output_13_load) or reused_match):
        
        metrics["Resumption Confirmed"] = True
        metrics["Mechanism"] = "TLS 1.3 PSK Ticket (Resumption Confirmed)"
        # CAPTURE THE DETAIL HERE
        if reused_match:
             metrics["Resumption Detail"] = reused_match.group(1)
        elif re.search(r'Reused session-id: Yes', output_13_load):
             # Fallback: Capture the negotiated cipher if only the session-id flag is set
             cipher_match = re.search(r'Cipher is ([^\n]+)', output_13_load)
             metrics["Resumption Detail"] = f"Reused, TLSv1.3, Cipher is {cipher_match.group(1).strip()}" if cipher_match else "Reused session-id: Yes"
    else:
        metrics["Mechanism"] = "TLS 1.3 PSK Ticket (Ticket Sent, Resumption Failed)"
            
    os.remove(TEMP_SESSION_FILE)

    return metrics


# --- Main Logic ---

def check_single_url(target_url):
    """Performs TLS session resumption checks for both TLS 1.2 and TLS 1.3 on a single URL."""

    # --- Setup and Parsing ---
    try:
        if ':' not in target_url:
            host = target_url
            host_port = DEFAULT_PORT
        else:
            parts = target_url.split(':')
            host = parts[0]
            host_port = int(parts[1])

        target = f"{host}:{host_port}"
    except Exception:
        print(f"Error: Invalid URL format provided. Use format 'hostname:port' or 'hostname'.")
        sys.exit(1)


    # --- 1. Test TLS 1.2 (Reliable Resumption Test using -reconnect) ---
    print("TLS 1.2 Resumption Test (Forced via -no_tls1_3)")
    
    command_12 = [
        'openssl', 's_client',
        '-connect', target,
        '-servername', host,
        '-reconnect',
        '-no_tls1_3' 
    ]

    output_12, return_code_12 = run_openssl_command(command_12, 'R')
    metrics_12 = analyze_reconnect_output(output_12)
    display_results_12(metrics_12, return_code_12)
    
    # --- 2. Test TLS 1.3 (Reliable Two-Step PSK Check) ---
    print("\nTLS 1.3 Two-Step PSK Resumption Check")

    metrics_13 = check_tls13_two_step(host, target)
    display_results_13(metrics_13)


def display_results_12(metrics, return_code):
    """Formats and prints the detailed results for the TLS 1.2 test."""
    
    if return_code != 0 and metrics["Online"] == "No":
         metrics["Online"] = "Error"
    
    if metrics["Online"] == "Yes" and metrics["Total Reused connections"] > 0:
        overall_status = "TLS Session Resumption Supported"
    elif metrics["Online"] == "Yes":
        overall_status = "No TLS Session Resumption"
    else:
        overall_status = metrics["Online"]
    
    new_detail = f" ({metrics['New Cipher Detail']})" if metrics['New Cipher Detail'] != 'N/A' else ""
    reused_detail = f" ({metrics['Reused Cipher Detail']})" if metrics['Reused Cipher Detail'] != 'N/A' else ""

    print(f"  Parsed output for TLS 1.2:")
    print(f"    Online: {metrics['Online']}")
    print(f"    Overall Status: {overall_status}")
    print(f"    Initial Session ID: {metrics['Initial session ID']}")
    print(f"    Final Session ID: {metrics['Final session ID']}") 
    print(f"    Total New Connections: {metrics['Total New connections']}{new_detail}")
    print(f"    Total Reused Connections: {metrics['Total Reused connections']}{reused_detail}")
    print(f"    Resumption Mechanism: {metrics['Mechanism']}")

def display_results_13(metrics):
    """Formats and prints the detailed results for the TLS 1.3 test."""
    
    if metrics["Online"] == "Yes" and metrics["Resumption Confirmed"]:
        overall_status = "TLS 1.3 PSK Ticket Resumption Confirmed"
    elif metrics["Online"] == "Yes" and metrics["PSK Ticket Sent"]:
        overall_status = "TLS 1.3 PSK Ticket Sent (Likely Supported)"
    elif metrics["Online"] == "Yes":
        overall_status = "TLS 1.3 Supported (PSK Ticket Not Observed)"
    else:
        overall_status = metrics["Online"]

    resumption_detail_output = ""
    # Only append the detail if resumption was confirmed
    if metrics["Resumption Confirmed"] and metrics["Resumption Detail"]:
        resumption_detail_output = f" ({metrics['Resumption Detail']})"

    print(f"  Parsed output for TLS 1.3:")
    print(f"    Online: {metrics['Online']}")
    print(f"    Overall Status: {overall_status}")
    print(f"    Negotiated Cipher: {metrics['Cipher Detail']}")
    print(f"    PSK Ticket Sent (Step 1): {metrics['PSK Ticket Sent']}")
    print(f"    Resumption Confirmed (Step 2): {metrics['Resumption Confirmed']}{resumption_detail_output}") 
    print(f"    Resumption Mechanism: {metrics['Mechanism']}")
    
    if metrics['Resumption Confirmed']:
        print("    Conclusion: Server successfully demonstrated support for stateless TLS 1.3 resumption.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 tls_session_resumption.py <hostname[:port]>")
        print("Example: python3 tls_session_resumption.py www.google.com")
        sys.exit(1)
        
    target_url = sys.argv[1]
    check_single_url(target_url)
