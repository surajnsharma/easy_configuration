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
import re


# Color codes for terminal output
ORANGE, YELLOW, PINK, RESET, RED, GREEN, BLUE = "\033[38;5;214m", "\033[93m", "\033[95m", "\033[0m", "\033[91m", "\033[92m", "\033[94m"


# Patterns for error matching
# Patterns for error matching
patterns_to_match = [
    re.compile("subsystem is not running",re.IGNORECASE),
    re.compile("process-not-running",re.IGNORECASE),
    re.compile(r"error\s\d+", re.IGNORECASE),
    #re.compile(r"'?\d+ <= \d+ <= \d+'? should be true", re.IGNORECASE),
    re.compile(r"TypeError:.* list or list-like", re.IGNORECASE),
    re.compile(r"'\".+?\" == \".+?\"' should be true", re.IGNORECASE)

]
exclusion_patterns = [re.compile(r"\bDictionary does not contain key\b", re.IGNORECASE)]



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
            return ET.parse(BytesIO(response.content))
        except (requests.RequestException, ET.ParseError) as e:
            print(f"Error fetching XML from URL: {e}")
            return None


# Updated capture_failures_in_keywords with pattern matching
def capture_failures_in_keywords(element, failure_messages, teardown_failure_messages,
                                 parent_teardown_failure_messages, rpc_reply_matches=patterns_to_match):
    """Capture failure messages with level="FAIL" and <xnm:error> within <rpc-reply> elements."""
    unique_messages = set()
    unique_errors = set()  # Avoid duplicate error messages

    # Define namespace for xnm elements
    namespaces = {'xnm': 'http://xml.juniper.net/xnm/1.1/xnm'}

    for msg in element.iter("msg"):
        timestamp = msg.get("timestamp", "No timestamp")
        msg_text = msg.text.strip() if msg.text else "No detailed message."

        # Capture standard failures
        if msg.get("level") == "FAIL" and timestamp:
            message_identifier = (timestamp, msg_text)
            if message_identifier not in unique_messages:
                unique_messages.add(message_identifier)
                failure_messages.append({"timestamp": timestamp, "message": msg_text})

        # Check for <rpc-reply> content with user-defined patterns
        rpc_reply_match = re.search(r"(<rpc-reply.*?>.*?</rpc-reply>)", msg_text, re.DOTALL)
        if rpc_reply_match:
            rpc_reply_content = rpc_reply_match.group(1)
            rpc_reply_content = re.sub(r"&[a-zA-Z]+;", "", rpc_reply_content)  # Remove escape sequences

            try:
                rpc_reply = ET.fromstring(rpc_reply_content)
                for error in rpc_reply.findall(".//xnm:error", namespaces):
                    error_msg = error.findtext("xnm:message", "No detailed message.", namespaces).strip()

                    # Match against patterns
                    if any(re.search(pattern, error_msg) if isinstance(pattern, re.Pattern) else pattern in error_msg
                           for pattern in rpc_reply_matches):
                        if error_msg not in unique_errors:
                            unique_errors.add(error_msg)
                            failure_messages.append({"timestamp": timestamp, "message": error_msg})
                            #print(f"[Debug] Found <xnm:error> message matching pattern: {error_msg}")
            except ET.ParseError:
                pass
                #print(f"[Warning] Could not parse sanitized <rpc-reply> content in <msg> at {timestamp}")

    # Recursive call for child elements
    for child in element:
        capture_failures_in_keywords(child, failure_messages, teardown_failure_messages,
                                     parent_teardown_failure_messages, rpc_reply_matches)



def extract_structured_error(inner_xml):
    """Extract specific error details from structured XML, e.g., <message> and <reason> elements."""
    errors = {}

    # Parse error message
    message_element = inner_xml.find(".//{http://xml.juniper.net/xnm/1.1/xnm}message")
    if message_element is not None:
        errors["error_message"] = message_element.text.strip()

    # Parse reason for error
    reason_element = inner_xml.find(".//{http://xml.juniper.net/xnm/1.1/xnm}reason")
    if reason_element is not None:
        daemon_element = reason_element.find("{http://xml.juniper.net/xnm/1.1/xnm}daemon")
        if daemon_element is not None:
            errors["reason"] = f"Daemon '{daemon_element.text.strip()}' is not running."

    return errors if errors else None


# Parse XML with specific patterns

def parse_robot_xml(file_path=None, tree=None):
    """Parse XML and capture failures with structured error messages within specific test cases."""

    def is_excluded(message):
        """Check if a message matches any of the exclusion patterns."""
        return any(pattern.search(message) for pattern in exclusion_patterns)
    if tree is None:
        try:
            tree = ET.parse(file_path)
        except (ET.ParseError, FileNotFoundError) as e:
            print(f"Error parsing XML file: {e}")
            return {}

    root = tree.getroot()
    failures = {}

    # Capture general failures
    general_failures = []
    all_general_failures = []
    capture_failures_in_keywords(root, all_general_failures, [], [], rpc_reply_matches=patterns_to_match)
    general_failures = [failure for failure in all_general_failures if not is_excluded(failure["message"])]

    # Capture failures in each test case
    for test in root.iter("test"):
        test_name = test.get("name")
        failure_messages, teardown_failure_messages, parent_teardown_failure_messages = [], [], []

        all_test_failures = []
        capture_failures_in_keywords(test, all_test_failures, teardown_failure_messages, parent_teardown_failure_messages, rpc_reply_matches=patterns_to_match)
        failure_messages = [failure for failure in all_test_failures if not is_excluded(failure["message"])]

        if failure_messages or teardown_failure_messages or parent_teardown_failure_messages:
            failures[test_name] = {
                "failures": failure_messages,
                "teardown_failures": teardown_failure_messages,
                "parent_teardown_failure_messages": parent_teardown_failure_messages
            }

    if general_failures:
        failures["General Failures"] = {
            "failures": general_failures,
            "teardown_failures": [],
            "parent_teardown_failures": []
        }

    return failures


def log_failures(failures, file_path):
    log_dir = "robot_failure_logs"
    os.makedirs(log_dir, exist_ok=True)

    filename = os.path.basename(file_path)
    log_file_path = os.path.join(log_dir, f"{filename}_failure_log.txt")
    print(f"{BLUE} Saving logfile to {log_file_path}{RESET}")
    with open(log_file_path, "w") as failure_log:
        for test_name, failure_details in failures.items():
            log_entry = f"\n=> {test_name} encountered the following failures:\n" if test_name != "General Failures" else "\n**General Failures:\n"
            failure_log.write(log_entry)
            print(log_entry.strip())

            # Track unique entries per test case or general failure group
            unique_entries = set()
            for entry in failure_details["failures"]:
                timestamp = entry.get("timestamp", "No timestamp")
                message = entry.get("message", "No message")
                log_message = f"[{timestamp}] - {message}\n"

                if log_message not in unique_entries:
                    unique_entries.add(log_message)
                    failure_log.write(log_message)
                    print(log_message.strip())

            if failure_details["teardown_failures"]:
                log_entry = f"Teardown failed for {test_name} with the following errors:\n"
                failure_log.write(log_entry)
                print(log_entry.strip())
                unique_entries = set()  # Reset for teardown entries

                for entry in failure_details["teardown_failures"]:
                    timestamp = entry.get("timestamp", "No timestamp")
                    message = entry.get("message", "No message")
                    log_message = f"[{timestamp}] - {message}\n"

                    if log_message not in unique_entries:
                        unique_entries.add(log_message)
                        failure_log.write(log_message)
                        print(log_message.strip())






def aggregate_logs(log_dir):
    summary_file_path = os.path.join(log_dir, "robot_failure_summary.txt")
    with open(summary_file_path, "w") as summary_file:
        for root, _, files in os.walk(log_dir):
            for file in files:
                if file.endswith("_failure_log.txt"):
                    with open(os.path.join(root, file), "r") as f:
                        summary_file.write(f"\n-------- {file} --------\n")
                        summary_file.write(f.read())
        if not any(file.endswith("_failure_log.txt") for file in os.listdir(log_dir)):
            summary_file.write("No failure logs were found for aggregation.\n")
    #print(f"{GREEN}Summary report saved in '{summary_file_path}'.{RESET}")



# Updated corrective actions dictionary
def load_corrective_actions(file_path="corrective_actions.json"):
    try:
        with open(file_path, 'r') as f:
            corrective_actions = json.load(f)
        print("Loaded corrective actions from 'corrective_actions.json' successfully.")
        return corrective_actions
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"{RED}Error loading corrective actions. Please ensure 'corrective_actions.json' is present and correctly formatted.{RESET}")
        sys.exit()


def suggest_corrective_action(error_message, corrective_actions):
    for group_name, patterns in corrective_actions.items():
        if isinstance(patterns, dict):
            for pattern, suggestion in patterns.items():
                if re.search(pattern, error_message, re.IGNORECASE):
                    return group_name, suggestion
        elif isinstance(patterns, str) and re.search(group_name, error_message, re.IGNORECASE):
            return group_name, patterns

    print(f"No match found for error message: {error_message}")
    return None, "No specific corrective action available. Please investigate the log for more details."



def is_genuine_error(line):
    """Determine if a line contains a genuine error message based on keywords and filters out test case identifiers."""
    error_keywords = [
        "Error", "Exception", "failed", "failure", "not found", "invalid", "abort",
        "refused", "unreachable", "timeout", "overflow", "corruption", "exceeded",
        "locked", "retry", "disconnect", "down", "missing", "mismatch","error"
    ]

    # Filter out lines that are not likely to be genuine errors (e.g., test case identifiers or filenames)
    non_error_indicators = ["=> Testcase", "---", "encountered", "following failures", "output"]

    # Return True only if an error keyword is present and the line does not contain non-error indicators
    return any(keyword.lower() in line.lower() for keyword in error_keywords) and not any(
        indicator in line for indicator in non_error_indicators)



'''def display_corrective_actions_from_file(file_path):
    corrective_actions = load_corrective_actions()
    suggestions_file_path = "robot_failure_suggestions.txt"
    print(f"\nReading failures from: {file_path}")
    print("\nChecking for corrective actions based on logged failures:")

    error_summary = defaultdict(lambda: {"count": 0, "messages": [], "suggestion": ""})
    unmatched_count = 0
    unique_messages = set()

    metadata_patterns = [re.compile(r"^--------.*_failure_log\.txt --------$"), re.compile(r"^=> .* encountered the following failures:$"),
                         re.compile(r"^\*\*General Failures:$"), re.compile(r"^$")]

    group_priority = {"ConfigurationErrors": 1, "GeneralFailures": 2, "AttributeErrors": 1, "UpgradeAndConfigurationErrors": 1}

    def is_metadata_line(line):
        return any(pattern.match(line) for pattern in metadata_patterns)

    try:
        with open(file_path, 'r') as log_file, open(suggestions_file_path, 'w') as suggestions_file:
            for line in log_file:
                line = line.strip()
                if is_metadata_line(line) or line in unique_messages:
                    continue

                assigned_group, highest_priority = None, float('inf')
                for group_name, patterns in corrective_actions.items():
                    if isinstance(patterns, dict):
                        for pattern, suggestion in patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                if group_priority.get(group_name, float('inf')) < highest_priority:
                                    assigned_group = (group_name, suggestion)
                                    highest_priority = group_priority.get(group_name)

                if assigned_group:
                    group_name, suggestion = assigned_group
                    error_summary[(group_name, suggestion)]["count"] += 1
                    error_summary[(group_name, suggestion)]["messages"].append(line)
                    error_summary[(group_name, suggestion)]["suggestion"] = suggestion
                    unique_messages.add(line)
                else:
                    unmatched_count += 1
                    print(f"{RED}No corrective action found for error: {line}{RESET}")
                    suggestions_file.write(f"No corrective action found for error: {line}\n")
                    suggestions_file.write(f"{'-' * 50}\n")

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
            print(f"{RED} ==> No specific corrective actions found for {unmatched_count} errors. Training required!{RESET}")

    except FileNotFoundError:
        print(f"File {file_path} not found.")'''


def display_corrective_actions_from_file(file_path):
    corrective_actions = load_corrective_actions()
    suggestions_file_path = "robot_failure_suggestions.txt"
    print(f"\nReading failures from: {file_path}")
    print("\nChecking for corrective actions based on logged failures:")

    error_summary = defaultdict(lambda: {"count": 0, "messages": [], "suggestion": ""})
    unmatched_count = 0
    unique_messages = set()

    metadata_patterns = [
        re.compile(r"^--------.*_failure_log\.txt --------$"),
        re.compile(r"^=> .* encountered the following failures:$"),
        re.compile(r"^\*\*General Failures:$"),
        re.compile(r"^$")
    ]

    def is_metadata_line(line):
        return any(pattern.match(line) for pattern in metadata_patterns)

    try:
        with open(file_path, 'r') as log_file, open(suggestions_file_path, 'w') as suggestions_file:
            for line in log_file:
                line = line.strip()
                if is_metadata_line(line) or line in unique_messages:
                    continue

                # Use suggest_corrective_action for each line
                group_name, suggestion = suggest_corrective_action(line, corrective_actions)

                if group_name:
                    error_summary[(group_name, suggestion)]["count"] += 1
                    error_summary[(group_name, suggestion)]["messages"].append(line)
                    error_summary[(group_name, suggestion)]["suggestion"] = suggestion
                    unique_messages.add(line)
                else:
                    unmatched_count += 1
                    print(f"{RED}No corrective action found for error: {line}{RESET}")
                    suggestions_file.write(f"No corrective action found for error: {line}\n")
                    suggestions_file.write(f"{'-' * 50}\n")

            # Write results for matched errors
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
        print(f"{PINK}(`_`){RESET} .. No failures detected in the file.")



# Main function
def main(paths):
    def process_directory(directory_path):
        """Process each XML file in the specified directory."""
        print(f"\nProcessing directory: {directory_path}")
        for root, _, files in os.walk(directory_path):
            for filename in files:
                if filename.lower().endswith(".xml"):
                    file_full_path = os.path.join(root, filename)
                    process_file(file_full_path)
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