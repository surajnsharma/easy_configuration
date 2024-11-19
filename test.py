#!/usr/bin/env python3
# debug_robot_log.py #
import xml.etree.ElementTree as ET
import requests
from io import BytesIO
import sys
import os
from datetime import datetime
import subprocess
import logging
import json
from collections import defaultdict

ORANGE = "\033[93m"
PINK = "\033[95m"
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"

help_message = """
Author: suraj sharma
Description: This script processes XML files or failure summary logs to extract failure messages,
suggest corrective actions, and save them for future reference. It also provides color-coded output
to highlight failures and suggested actions in the terminal.

Usage:
    python test.py <xml file or  directory_path or failure_summary.txt>
    - ** trained data is saved in corrective_actions.json, check the sample in the botton of file *** 

Arguments:
    <file_or_directory_path> : Path to an XML or summary log file, or directory containing XML files to process.

    - If an XML file is provided, the script will parse it to find failures and suggest corrective actions.
    - If a summary file (like robot_failure_summary.txt) is provided, it will read and analyze failures, 
      suggesting corrective actions for each identified failure.


    The script will also save corrective suggestions to 'robot_failure_suggestions.txt'.

Example:
    ./debug_robot_log.py robot_failure_logs/robot_failure_summary.txt  -> to check the failure summary and suggestions
    ./debug_robot_log.py /path/to/log_filename.xml  -> to check the file and lookup for failure  reason 
    ./debug_robot_log.py /log-file directory_path  -> to check the log_filename.xml in directory/sub dir and  lookup for failure reasons 

If no arguments are provided, this help message will be displayed.
"""


def set_python3_path():
    """Check for python3 path and export it to environment if found."""
    try:
        python3_path = subprocess.check_output(["which", "python3"]).decode().strip()
        if python3_path:
            os.environ["PYTHONPATH"] = python3_path
            print(f"Python3 path set to: {python3_path}")
        else:
            print("Python3 is not available. Please install Python 3 to continue.")
            sys.exit(1)
    except subprocess.CalledProcessError:
        print("Error finding python3 path.")
        sys.exit(1)


# Set the Python3 path on script execution
set_python3_path()


def fetch_xml_from_url(url, cookies=None):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36"
    }
    with requests.Session() as session:
        try:
            if cookies:
                session.cookies.update(cookies)
            response = session.get(url, headers=headers)
            response.raise_for_status()
            xml_data = BytesIO(response.content)
            try:
                tree = ET.parse(xml_data)
                return tree
            except ET.ParseError:
                print("The content retrieved from the URL is not a valid XML document.")
                return None
        except requests.exceptions.RequestException as e:
            print(f"Error fetching XML from URL: {e}")
            return None


def parse_robot_xml(file_path=None, tree=None):
    if tree is None:
        try:
            tree = ET.parse(file_path)
        except (ET.ParseError, FileNotFoundError) as e:
            print(f"Error parsing XML file: {e}")
            return {}

    root = tree.getroot()
    failures = {}

    for test in root.iter("test"):
        test_name = test.get("name")
        failure_messages = set()
        teardown_failure_messages = set()
        parent_teardown_failure_messages = set()

        # Capture failures in <status> tags
        for status in test.iter("status"):
            if status.get("status") == "FAIL":
                message = status.text.strip() if status.text else "No detailed message."
                if message:
                    failure_messages.add(message)

        # Capture specific error messages in <msg> tags
        for msg in test.iter("msg"):
            # Check if msg.text is not None to avoid TypeError
            if msg.text and (msg.get("level") == "FAIL" or "AttributeError" in msg.text or "TypeError" in msg.text):
                message = msg.text.strip()
                if "AttributeError" in message:
                    failure_messages.add(f"AttributeError detected: {message}")
                elif "TypeError" in message:
                    failure_messages.add(f"TypeError detected: {message}")
                elif message != "No detailed message.":
                    failure_messages.add(message)

        # Capture teardown and parent teardown failures
        for kw in test.iter("kw"):
            if kw.get("type") == "teardown":
                for status in kw.iter("status"):
                    if status.get("status") == "FAIL":
                        teardown_message = status.text.strip() if status.text else "No detailed message."
                        if teardown_message:
                            teardown_failure_messages.add(teardown_message)
            elif kw.get("type") == "suite" and "teardown" in kw.get("name", "").lower():
                for status in kw.iter("status"):
                    if status.get("status") == "FAIL":
                        parent_teardown_message = status.text.strip() if status.text else "No detailed message."
                        if parent_teardown_message:
                            parent_teardown_failure_messages.add(parent_teardown_message)

        # Add detected failures to the summary
        if failure_messages or teardown_failure_messages or parent_teardown_failure_messages:
            failures[test_name] = {
                "failures": list(failure_messages),
                "teardown_failures": list(teardown_failure_messages),
                "parent_teardown_failures": list(parent_teardown_failure_messages)
            }

    return failures


def log_failures(failures, file_path):
    log_dir = "robot_failure_logs"
    os.makedirs(log_dir, exist_ok=True)

    filename = os.path.basename(file_path)
    log_file_path = os.path.join(log_dir, f"{filename}_failure_log.txt")

    with open(log_file_path, "w") as failure_log:
        for test_name, failure_details in failures.items():
            if failure_details["failures"]:
                log_entry = f"Testcase {test_name} encountered the following failures:\n"
                failure_log.write(log_entry)
                print(log_entry.strip())
                for msg in failure_details["failures"]:
                    log_message = f" - {msg}\n"
                    failure_log.write(log_message)
                    print(log_message.strip())

            # Teardown and parent teardown failures
            unique_teardown_messages = set(failure_details["teardown_failures"])
            if unique_teardown_messages:
                log_entry = f"Teardown failed for testcase {test_name} with the following errors:\n"
                failure_log.write(log_entry)
                print(log_entry.strip())
                for msg in unique_teardown_messages:
                    log_message = f" - {msg}\n"
                    failure_log.write(log_message)
                    print(log_message.strip())

            unique_parent_teardown_messages = set(
                failure_details["parent_teardown_failures"]) - unique_teardown_messages
            if unique_parent_teardown_messages:
                log_entry = f"Parent suite teardown failed for testcase {test_name} with the following errors:\n"
                failure_log.write(log_entry)
                print(log_entry.strip())
                for msg in unique_parent_teardown_messages:
                    log_message = f" - {msg}\n"
                    failure_log.write(log_message)
                    print(log_message.strip())

    print(f"\033[92mFailure logs saved in local directory '{log_file_path}'.\033[0m")

    # Append the log file content to the summary file
    with open("robot_failure_logs/robot_failure_summary.txt", "a") as summary_file:
        summary_file.write(f"\n--- {filename}_failure_log.txt ---\n")
        with open(log_file_path, "r") as failure_log:
            summary_file.write(failure_log.read())

    # print(f"\033[92mSummary report updated in 'robot_failure_logs/robot_failure_summary.txt'.\033[0m")
    # print(f"{ORANGE} run , python3 debug_robot_log.py robot_failure_logs/robot_failure_summary.txt  -> to check the failure summary and suggestions {RESET}")


def process_directory(directory_path):
    """Process each XML file in the specified directory."""
    print(f"\nProcessing directory: {directory_path}")
    for root, _, files in os.walk(directory_path):
        for filename in files:
            if filename.lower().endswith(".xml"):
                file_full_path = os.path.join(root, filename)
                process_file(file_full_path)


def process_file(file_path):
    """Process a single XML file or summary file."""
    print(f"\nProcessing file: {file_path}")
    if file_path.endswith("robot_failure_summary.txt"):
        display_corrective_actions_from_file(file_path)
        return  # Skip XML parsing since this is a text summary file

    try:
        tree = ET.parse(file_path)
        failures = parse_robot_xml(tree=tree)
        if failures:
            log_failures(failures, file_path)
        else:
            print("No failures detected in the file.")
    except (ET.ParseError, FileNotFoundError, IsADirectoryError) as e:
        print(f"Error processing file {file_path}: {e}")


def aggregate_logs(log_dir):
    """Aggregate all individual failure logs into a summary file."""
    summary_file_path = os.path.join(log_dir, "robot_failure_summary.txt")
    # Open the summary file in write mode to create or overwrite it
    with open(summary_file_path, "w") as summary_file:
        found_logs = False  # Track if any logs are found for aggregation
        for root, _, files in os.walk(log_dir):
            for file in files:
                if file.endswith("_failure_log.txt"):
                    found_logs = True  # Mark that we found at least one log file
                    file_path = os.path.join(root, file)
                    summary_file.write(f"\n--- {file} ---\n")
                    with open(file_path, "r") as f:
                        summary_file.write(f.read())

        if not found_logs:
            # If no logs were found, note it in the summary file
            summary_file.write("No failure logs were found for aggregation.\n")

    # print(f"\033[92mSummary report saved in '{log_dir}/{summary_file_path}'.\033[0m")


# Updated corrective actions dictionary
def load_corrective_actions(file_path="corrective_actions.json"):
    try:
        with open(file_path, 'r') as f:
            corrective_actions = json.load(f)
        print("Loaded corrective actions from 'corrective_actions.json' successfully.")
        return corrective_actions
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print("Error loading corrective actions. Please ensure 'corrective_actions.json' is present and correctly formatted.")
        return {}


def suggest_corrective_action(error_message, corrective_actions):
    # Iterate over each group in the corrective actions
    for group_name, patterns in corrective_actions.items():
        # Check if patterns is a dictionary to iterate over its items
        if isinstance(patterns, dict):
            for pattern, suggestion in patterns.items():
                if pattern in error_message:
                    return group_name, suggestion
        # If patterns is not a dictionary, it should be a direct suggestion
        elif isinstance(patterns, str):
            if group_name in error_message:
                return group_name, patterns
    return None, "No specific corrective action available. Please investigate the log for more details."


# Example usage in your error-checking function
def check_errors(error_log, corrective_actions):
    for error in error_log:
        group, action = suggest_corrective_action(error, corrective_actions)
        if group:
            print(f"[{group} Error] {error}")
            print(f"Suggested Action: {action}\n{'-' * 50}")
        else:
            print(f"No corrective action found for error: {error}\n{'-' * 50}")



def is_genuine_error(line):
    """Determine if a line contains a genuine error message based on keywords and filters out test case identifiers."""
    error_keywords = [
        "Error", "Exception", "failed", "failure", "not found", "invalid", "abort",
        "refused", "unreachable", "timeout", "overflow", "corruption", "exceeded",
        "locked", "retry", "disconnect", "down", "missing", "mismatch"
    ]

    # Filter out lines that are not likely to be genuine errors (e.g., test case identifiers or filenames)
    non_error_indicators = ["Testcase", "---", "encountered", "following failures", "output"]

    # Return True only if an error keyword is present and the line does not contain non-error indicators
    return any(keyword.lower() in line.lower() for keyword in error_keywords) and not any(
        indicator in line for indicator in non_error_indicators)


# Updated function to display corrective actions from file
'''def display_corrective_actions_from_file(file_path):
    corrective_actions = load_corrective_actions()
    suggestions_file_path = "robot_failure_suggestions.txt"
    print(f"\nReading failures from: {file_path}")
    print("\nChecking for corrective actions based on logged failures:")

    unmatched_count = 0  # Track if there were any unmatched errors
    try:
        with open(file_path, 'r') as log_file, open(suggestions_file_path, 'w') as suggestions_file:
            failure_log = log_file.readlines()
            for line in failure_log:
                line = line.strip()
                if is_genuine_error(line):
                    group, corrective_action = suggest_corrective_action(line, corrective_actions)
                    if corrective_action:
                        print(f"{ORANGE}Failure:{RESET} {line}")
                        print(f"Group: {PINK}{group}{RESET}")
                        print(f"Suggested Action: {PINK}{corrective_action}{RESET}\n{'-' * 50}")
                        suggestions_file.write(f"Failure: {line}\n")
                        suggestions_file.write(f"Group: {group}\n")
                        suggestions_file.write(f"Suggested Action: {corrective_action}\n")
                        suggestions_file.write(f"{'-' * 50}\n")
                    else:
                        unmatched_count += 1
                        print(f"{RED}No corrective action found for error: {line}{RESET}")
                        suggestions_file.write(f"No corrective action found for error: {line}\n")
                        suggestions_file.write(f"{'-' * 50}\n")

        print(f"{GREEN}Suggestions saved in '{suggestions_file_path}'.{RESET}")

        if unmatched_count > 0:
            print(f"{RED} ==> No specific corrective actions found for {unmatched_count} errors. Training required!{RESET}")

    except FileNotFoundError:
        print(f"File {file_path} not found.")'''

'''def display_corrective_actions_from_file(file_path):
    corrective_actions = load_corrective_actions()
    suggestions_file_path = "robot_failure_suggestions.txt"
    print(f"\nReading failures from: {file_path}")
    print("\nChecking for corrective actions based on logged failures:")

    error_summary = defaultdict(lambda: {"count": 0, "suggestion": ""})
    unmatched_count = 0  # Track if there were any unmatched errors

    try:
        with open(file_path, 'r') as log_file, open(suggestions_file_path, 'w') as suggestions_file:
            failure_log = log_file.readlines()
            for line in failure_log:
                line = line.strip()
                if is_genuine_error(line):
                    group, corrective_action = suggest_corrective_action(line, corrective_actions)
                    if corrective_action:
                        # Update error_summary with group and action
                        error_summary[(group, corrective_action)]["count"] += 1
                        error_summary[(group, corrective_action)]["suggestion"] = corrective_action
                    else:
                        unmatched_count += 1
                        print(f"{RED}No corrective action found for error: {line}{RESET}")
                        suggestions_file.write(f"No corrective action found for error: {line}\n")
                        suggestions_file.write(f"{'-' * 50}\n")

            # Print grouped errors
            for (group, suggestion), details in error_summary.items():
                count = details["count"]
                print(f"{ORANGE}Failure Group: {group}{RESET}")
                print(f"Occurrences: {count}")
                print(f"{PINK}Suggested Action:{RESET} {suggestion}\n{'-' * 50}")
                suggestions_file.write(f"Failure Group: {group}\n")
                suggestions_file.write(f"Occurrences: {count}\n")
                suggestions_file.write(f"Suggested Action: {suggestion}\n")
                suggestions_file.write(f"{'-' * 50}\n")

        print(f"{GREEN}Suggestions saved in '{suggestions_file_path}'.{RESET}")

        if unmatched_count > 0:
            print(f"{RED} ==> No specific corrective actions found for {unmatched_count} errors. Training required!{RESET}")

    except FileNotFoundError:
        print(f"File {file_path} not found.")'''

def display_corrective_actions_from_file(file_path):
    corrective_actions = load_corrective_actions()
    suggestions_file_path = "robot_failure_suggestions.txt"
    print(f"\nReading failures from: {file_path}")
    print("\nChecking for corrective actions based on logged failures:")

    error_summary = defaultdict(lambda: {"count": 0, "messages": [], "suggestion": ""})
    unmatched_count = 0  # Track if there were any unmatched errors

    try:
        with open(file_path, 'r') as log_file, open(suggestions_file_path, 'w') as suggestions_file:
            failure_log = log_file.readlines()
            for line in failure_log:
                line = line.strip()
                if is_genuine_error(line):
                    group, corrective_action = suggest_corrective_action(line, corrective_actions)
                    if corrective_action:
                        # Update error_summary with group and action
                        error_summary[(group, corrective_action)]["count"] += 1
                        if line not in error_summary[(group, corrective_action)]["messages"]:
                            error_summary[(group, corrective_action)]["messages"].append(line)
                        error_summary[(group, corrective_action)]["suggestion"] = corrective_action
                    else:
                        unmatched_count += 1
                        print(f"{RED}No corrective action found for error: {line}{RESET}")
                        suggestions_file.write(f"No corrective action found for error: {line}\n")
                        suggestions_file.write(f"{'-' * 50}\n")

            # Print grouped errors with all associated failure messages
            for (group, suggestion), details in error_summary.items():
                count = details["count"]
                print(f"{ORANGE}Failure Group: {group}{RESET}")
                print(f"Occurrences: {count}")
                print("Failures:")
                for msg in details["messages"]:
                    print(f" - {msg}")
                print(f"{PINK}Suggested Action:{RESET} {suggestion}\n{'-' * 50}")

                suggestions_file.write(f"Failure Group: {group}\n")
                suggestions_file.write(f"Occurrences: {count}\n")
                suggestions_file.write("Failures:\n")
                for msg in details["messages"]:
                    suggestions_file.write(f" - {msg}\n")
                suggestions_file.write(f"Suggested Action: {suggestion}\n")
                suggestions_file.write(f"{'-' * 50}\n")

        print(f"{GREEN}Suggestions saved in '{suggestions_file_path}'.{RESET}")

        if unmatched_count > 0:
            print(
                f"{RED} ==> No specific corrective actions found for {unmatched_count} errors. Training required!{RESET}")

    except FileNotFoundError:
        print(f"File {file_path} not found.")



def process_file(file_path):
    print(f"\nProcessing file: {file_path}")
    if file_path.endswith("robot_failure_summary.txt"):
        display_corrective_actions_from_file(file_path)
        return  # Skip XML parsing since this is a text summary file

    if file_path.startswith("http"):
        tree = fetch_xml_from_url(file_path)
        if tree is None:
            print("Failed to retrieve or parse XML from URL.")
            return
    else:
        try:
            tree = ET.parse(file_path)
        except (ET.ParseError, FileNotFoundError) as e:
            print(f"Error parsing XML file {file_path}: {e}")
            return

    failures = parse_robot_xml(tree=tree)
    if failures:
        log_failures(failures, file_path)
    else:
        print("No failures detected in the file.")


# Main function
def main(paths):
    log_dir = "robot_failure_logs"
    os.makedirs(log_dir, exist_ok=True)

    for path in paths:
        if os.path.isdir(path):
            process_directory(path)
        else:
            process_file(path)

    aggregate_logs(log_dir)
    print("\033[92mSummary report updated in 'robot_failure_logs/robot_failure_summary.txt'.\033[0m")
    print(
        f"{ORANGE}Run, python3 debug_robot_log.py robot_failure_logs/robot_failure_summary.txt -> to check the failure summary and suggestions {RESET}")


# Display usage information if no arguments are provided


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(help_message)
        sys.exit(0)
    else:
        main(sys.argv[1:])

""" *** Trained json data  ****
robot_failure_summary.txt -> Save in corrective_actions.json

{
    "Infra Checks Failed": "Ensure infrastructure prerequisites are met, such as proper connectivity to devices and availability of required resources.",
    "ConnectionRefusedError": "Verify that the server is running and accessible at the specified IP address and port. Check firewall settings to ensure the connection is allowed.",
    "TimeoutError": "The request timed out. Increase the timeout value if necessary and verify network stability.",
    "SocketError": "Check if the target server is reachable and the network interface is active. Verify if the DNS resolution is correct for the target address.",
    "FileNotFoundError": "Ensure the specified file path is correct and the file exists. Check permissions on the file and directory.",
    "PermissionError": "Check file permissions and ensure that the script has the required permissions to access or modify the specified file.",
    "SyntaxError": "Check for syntax errors in your script, such as typos, missing punctuation, or incorrect indentation.",
    "IndentationError": "Check for consistent use of spaces and tabs. Python requires consistent indentation in all blocks.",
    "UnboundLocalError": "A local variable is referenced before being assigned a value. Ensure all variables are initialized before use.",
    "NameError": "This error occurs when a variable or function is not defined. Check for typos or ensure the variable/function is defined before its usage.",
    "ValueError": "Check the values passed to functions, especially with type conversions, to ensure they are within expected ranges.",
    "IndexError": "List index out of range. Ensure the list or array has enough elements before accessing specific indexes.",
    "AssertionError": "Check the expected and actual output to ensure they align with test requirements. Validate test conditions and setup.",
    "KeyError": "Dictionary key not found. Verify that the key exists or use the '.get()' method to avoid errors.",
    "AuthenticationError": "Check the provided credentials and ensure they are correct. Verify that the user has the required permissions.",
    "AuthorizationError": "Ensure the user or application has the correct permissions. Adjust access levels or consult with the administrator.",
    "MemoryError": "The system ran out of memory. Try optimizing your code to use less memory or close unnecessary applications.",
    "ResourceWarning": "Check for excessive resource usage, like file handles or network connections. Ensure all opened resources are properly closed.",
    "ImportError": "Module not found. Ensure the required module is installed in the environment. Use 'pip install <module_name>' to install it if missing.",
    "ModuleNotFoundError": "Check if the module name is correct and the package is installed in the environment. Verify the Python path and virtual environment.",
    "DependencyError": "Check if all required dependencies are installed and compatible. Update or install missing dependencies if necessary.",
    "KeyboardInterrupt": "The script was manually interrupted. Re-run if this was unintentional or add handling to avoid disruptions.",
    "RecursionError": "The maximum recursion depth was exceeded, indicating possible infinite recursion or excessive function calls. Refactor to iterative logic if possible.",
    "Error: Ixia/Spirent Status is not SUCCESS": "Verify the Ixia/Spirent server status and connectivity.",
    "STCSERVER_RET_ERROR": "Reconnect to the Spirent test session or restart the session manager if the session is inactive or terminated.",
    "Oversubscription detected": "Adjust the traffic configuration to avoid oversubscription. Verify inter-frame gap settings.",
    "commit failed": "Review configuration commands, especially routing and interface configurations. Correct invalid next-hop or buffer settings.",
    "VERIFY FAILED": "Review verification steps. Ensure that device interfaces and states align with expected test parameters.",
    "Cannot create request. SAL is not connected": "Check SAL connection status. Reinitialize or reconnect the session if necessary.",
    "Timeout": "Increase timeout settings or check device response times to ensure they are within configured limits.",
    "Device prompt did not return within": "Verify device responsiveness and command prompt patterns. Restart device sessions if they become unresponsive.",
    "Variable not found": "Ensure all referenced variables in the test are correctly defined and initialized.",
    "RunMultipleException": "Check nested or batch operations for errors in dependencies and connection stability.",
    "ZeroDivisionError": "Check calculations to avoid division by zero. Implement checks or exception handling to manage potential zero values.",
    "OverflowError": "The result of a calculation exceeded the maximum limit. Verify input values and consider using larger data types if needed.",
    "FloatingPointError": "A floating-point operation failed. Check for invalid calculations, such as dividing by very small numbers close to zero.",
    "JSONDecodeError": "Ensure the JSON data is correctly formatted and complete. Verify syntax and check for missing or extra commas.",
    "SSLError": "An SSL connection failed. Verify SSL certificates, encryption protocols, and ensure the server supports the required TLS version.",
    "TimeoutException": "An operation took too long to complete. Consider increasing the timeout or optimizing the operation to reduce execution time.",
    "BrokenPipeError": "A process tried to write to a closed pipe. Ensure the receiving end is open and operational before sending data.",
    "ConnectionAbortedError": "The network connection was unexpectedly aborted. Verify network stability and server status.",
    "UnicodeDecodeError": "An error occurred while decoding bytes to a string. Specify the correct encoding (e.g., UTF-8) to avoid this issue.",
    "UnicodeEncodeError": "An error occurred while encoding strings to bytes. Ensure all characters are within the target encoding set.",
    "EOFError": "The end of file was reached unexpectedly. Ensure the file contains sufficient data for reading or reset the file pointer.",
    "RemoteDisconnected": "The remote host disconnected unexpectedly. Check the network connection and the remote server√ï availability.",
    "SSLCertVerificationError": "SSL certificate verification failed. Ensure certificates are valid or use appropriate flags to bypass verification if acceptable.",
    "HTTPError": "The HTTP request failed. Verify the URL, server status, and ensure the correct method (GET, POST, etc.) is used.",
    "URLError": "A URL request failed. Verify that the URL is correct and the network is accessible.",
    "ProtocolError": "A protocol error occurred. Ensure that the correct protocol (e.g., HTTP/HTTPS) is used and the server supports it.",
    "CircularImportError": "A circular dependency was detected during module imports. Refactor the code to avoid circular imports.",
    "InvalidTokenError": "An authentication token is invalid or expired. Re-authenticate or refresh the token as needed.",
    "InvalidSignatureError": "The digital signature of the request is invalid. Verify that signatures are correct and the secret keys match.",
    "FileExistsError": "A file creation operation failed because the file already exists. Check the file path and consider removing or renaming the existing file.",
    "OverflowError: integer": "An integer operation exceeded limits. Ensure calculations stay within the allowable range of integer values.",
    "InvalidCharacterError": "Invalid characters were found in the input. Validate data before processing, especially with special characters.",
    "QuotaExceededError": "A storage or resource quota has been exceeded. Check usage limits and free up resources if necessary.",
    "DatabaseError": "An error occurred with the database. Verify connectivity, database credentials, and query syntax.",
    "IntegrityError": "A database integrity constraint was violated. Check foreign keys, unique constraints, and ensure data consistency.",
    "DataError": "Invalid data was sent to the database. Verify that input values meet expected types and lengths.",
    "OperationalError": "An operational error occurred in the database. Ensure the database is running and accessible, and review resource limits.",
    "ProgrammingError": "A SQL query or command was incorrect. Check the SQL syntax and ensure the database schema matches the query structure.",
    "InvalidStateError": "An operation was attempted in an invalid state. Verify conditions before proceeding, such as network connectivity or authentication.",
    "DeadlockError": "A deadlock occurred, often in databases or multi-threaded environments. Review locking mechanisms or use timeout options.",
    "ConcurrencyError": "A concurrency error occurred, likely due to simultaneous access. Review the code for race conditions or implement locks where necessary.",
    "ProtocolViolation": "A protocol violation occurred. Ensure client and server follow the same protocol rules and version compatibility.",
    "NullPointerException": "Attempted to access a null or undefined object. Check all variables are initialized before usage.",
    "BGPNeighborDown": "Verify the BGP configuration and check connectivity between the router and the neighbor. Ensure both ends are configured correctly and network policies allow BGP traffic.",
    "BGPFlapDetected": "Check for unstable network conditions or configuration changes. Investigate possible causes like route oscillation, interface instability, or MTU mismatch.",
    "OSPFNeighborLoss": "Confirm OSPF settings like area IDs, authentication, and network types. Ensure interfaces are up and reachable and that OSPF Hello and Dead timers are aligned.",
    "RouteNotInstalled": "Check routing protocols (e.g., BGP, OSPF) for advertisements. Verify route filtering, redistribution policies, and administrative distance settings.",
    "RoutingLoopDetected": "Review route advertisements and ensure the proper filtering of routes. Check for overlapping IPs and correct route summarization if needed.",
    "InterfaceDown": "Verify physical connections and interface configurations. Check for issues like mismatched duplex settings, MTU, or cable problems.",
    "LinkFlap": "Investigate physical link quality and check for loose connections, bad cables, or hardware issues. Monitor power levels and signal strength on optical links.",
    "MTUMismatch": "Ensure the MTU settings match on both ends of the connection. Mismatched MTU can cause packet drops and fragmentation issues.",
    "HighCPUUsage": "Check for processes consuming excessive CPU on the router. Possible causes include route recalculations, high traffic volume, or excessive logging.",
    "HighMemoryUsage": "Investigate memory allocation and usage. Clear unused sessions and stale routes or consider adding more memory if usage is consistently high.",
    "PacketLoss": "Analyze the network path for congested links or faulty equipment. Use traceroute and ping to identify the segment experiencing loss.",
    "PacketCorruption": "Verify interface integrity, error counters, and check cabling. Inspect packet capture logs for signs of corruption.",
    "ARPFailure": "Ensure ARP is functioning correctly. Check subnet configurations, ARP timeout values, and address resolution mechanisms.",
    "DHCPFailure": "Ensure the DHCP server is reachable. Verify scope configurations and ensure no IP conflicts exist.",
    "QoSPolicyDrop": "Examine Quality of Service policies and ensure traffic is classified and prioritized correctly. Verify that traffic shaping and policing configurations match the network requirements.",
    "FirewallBlock": "Check firewall rules and ensure that the necessary ports and protocols are allowed. Inspect ACLs and NAT settings if traffic is blocked.",
    "ACLDrop": "Verify Access Control Lists (ACLs) for specific traffic flow. Ensure the ACL is correctly applied and does not inadvertently block desired traffic.",
    "RoutingProtocolNotConverging": "Check for protocol settings consistency and network topology. Adjust timers or clear routing tables to trigger reconvergence.",
    "NATTranslationFailure": "Check NAT rules and ensure address pools are configured correctly. Monitor translation counters and debug for failed NAT sessions.",
    "InterfaceInputErrors": "Check for physical layer issues, such as faulty cables or SFPs. Look at input error counters for CRC errors, alignment errors, or framing issues.",
    "InterfaceOutputDrops": "Verify QoS settings, buffer limits, and congestion handling policies. Increase buffer sizes if necessary to handle peak loads.",
    "MPLSTunnelDown": "Check MPLS configurations, including LDP or RSVP settings. Verify that label distribution and paths are functioning correctly.",
    "LabelSwitchingFailure": "Inspect MPLS label distribution and label-switched paths (LSPs). Ensure that labels are properly advertised and not conflicting.",
    "ISISAdjacencyLost": "Confirm ISIS settings, including area IDs and authentication. Ensure MTU and network type configurations are consistent.",
    "VLANMismatch": "Ensure VLAN IDs match on all trunked interfaces. Check encapsulation settings (dot1q or ISL) and confirm VLAN tagging.",
    "MACAddressFlap": "Investigate for loops or misconfigured network paths. Enable STP or Loop Guard to prevent flapping.",
    "STPTopologyChange": "Check Spanning Tree Protocol (STP) settings. Investigate port roles and root bridge election to avoid unnecessary topology changes.",
    "HSRPFailover": "Verify HSRP configurations and ensure standby routers are reachable. Check priority settings and preemption configurations.",
    "VRRPSwitchover": "Ensure VRRP priority settings are correct and verify that VRRP groups are configured correctly on all participating routers.",
    "NetFlowExportFailure": "Check NetFlow configuration and ensure the NetFlow collector is reachable. Verify export destination IP and port settings.",
    "SNMPPollTimeout": "Ensure the SNMP community or authentication settings are correct. Verify network connectivity to the SNMP agent.",
    "SyslogMessageNotReceived": "Verify syslog server reachability and ensure the correct logging level is set. Check for blocked syslog traffic in firewalls.",
    "RoutingTableFull": "Check for excessive route advertisements. Implement route summarization or filter unnecessary routes to manage table size.",
    "BFDSessionDown": "Ensure BFD timers match on both sides and that routing adjacency is maintained. Check BFD settings if link instability is detected.",
    "No detailed message": "Investigate the failure logs for more context as the error did not provide detailed information. Ensure all expected outputs and prerequisites are defined correctly.",
    "ISSU is failed for upgrade type": "Check the upgrade procedure, especially for the specified applications. Verify that each application is in the correct state before proceeding and that there is sufficient memory and CPU capacity.",
    "kexec and for apps": "Review the ISSU (In-Service Software Upgrade) configurations and ensure applications are compatible with the kexec upgrade type. Check the status of each listed application and its dependencies.",
    "SocketTimeoutException": "A socket timeout occurred. Check network latency and server availability.",
    "HostUnreachable": "The specified host is unreachable. Verify network connectivity and firewall settings.",
    "InvalidConfiguration": "A configuration setting is invalid. Review and correct the configuration file.",
    "ServiceUnavailable": "The requested service is temporarily unavailable. Verify server status or retry later.",
    "DNSResolutionError": "DNS resolution failed. Ensure DNS servers are reachable and configured correctly.",
    "SessionExpired": "The session has expired. Reauthenticate or start a new session.",
    "InvalidCredentials": "Authentication failed due to invalid credentials. Verify username and password.",
    "DiskSpaceError": "Insufficient disk space. Clear space or increase disk capacity to proceed.",
    "AccessDenied": "Access was denied. Check permissions for the user or application.",
    "CertificateError": "An error occurred with the SSL/TLS certificate. Check validity and CA trust.",
    "NetworkErrors": {
        "ConnectionRefused": "The target server refused the connection. Check if the service is up and firewall settings allow access.",
        "HostUnreachable": "The host could not be reached. Ensure the network is configured correctly.",
        "SocketTimeoutException": "The socket connection timed out. Check network stability and server response time.",
        "DNSResolutionError": "Failed to resolve DNS. Verify DNS configuration and availability."
    },
    "AuthenticationErrors": {
        "InvalidCredentials": "Authentication failed. Verify username and password.",
        "AccessDenied": "Access denied. Ensure correct permissions are configured.",
        "SessionExpired": "The session has expired. Please reauthenticate."
    },
    "FileErrors": {
        "FileNotFoundError": "The file specified was not found. Check the file path and try again.",
        "PermissionError": "Permission denied. Ensure the necessary access rights are granted.",
        "FileExistsError": "The file already exists. Use a different name or delete the existing file if needed."
    },
    "TypeErrors": {
        "TypeError: Expected argument 1 to be a list or list-like": "Check for operations between incompatible data types. For example, ensure you are not adding a string to an integer.",
        "TypeError detected: TypeError: Expected argument 1 to be a list or list-like": "Check for operations between incompatible data types. For example, ensure you are not adding a string to an integer."
    },
    "AttributeErrors": {
        "AttributeError: 'NoneType' object has no attribute 'rsplit'": "This error usually occurs when a variable expected to hold a string is None. Verify that the variable is assigned a valid string value before attempting operations like 'rsplit'."
    },
    "GeneralErrors": {
        "No detailed message": "Investigate the failure logs for more context as the error did not provide detailed information."
    },
    "UpgradeErrors": {
        "ISSU is failed for upgrade type : kexec and for apps": "Check the upgrade procedure, especially for the specified applications. Verify that each application is in the correct state before proceeding and that there is sufficient memory and CPU capacity."
    }
    
}

*** END *** """
