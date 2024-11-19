#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import requests
from io import BytesIO
import sys
import os
import subprocess
import json
from collections import defaultdict
import re
import gzip
import shutil
import argparse


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



patterns_to_match = [
    re.compile(r"\bnot running\b", re.IGNORECASE),  # Matches "not running" in any context
    re.compile(r"process-?\bnot\b-?\brunning", re.IGNORECASE),  # For variations like "process-not-running"
    re.compile(r"error\s\d+", re.IGNORECASE),  # Matches error codes like "error 404"
    re.compile(r"TypeError:.* list or list-like", re.IGNORECASE),  # Specific TypeError
    re.compile(r"'\".+?\" == \".+?\"' should be true", re.IGNORECASE),  # Specific equality check failure
re.compile(r"<doc>.*?Description: (.*?)</doc>", re.DOTALL | re.IGNORECASE),
]



# Skip patterns to filter out irrelevant lines
skip_patterns = [
    re.compile(r"^--------.*_failure_log\.txt --------$"),
    re.compile(r"^=> .* encountered the following failures:$"),  # General case
    #re.compile(r"^=>TC\d+ encountered the following failures:$"),  # Specific for TC<number>
    re.compile(r"^=>.* encountered the following failures:$"),
    re.compile(r"^\*\*\*=>TC\d+ encountered the following failures:$"),
    re.compile(r"^\*\*General Failures:$"),  # Exclude general failures header
    re.compile(r"^$"),  # Exclude empty lines
    re.compile(r"^\[TestCase Description\].*$", re.DOTALL)  # Exclude [TestCase Description]

]
def should_skip_line(line):
    """Check if a line matches any skip patterns."""
    skip_patterns = [
        re.compile(r"^--------.*_failure_log\.txt --------$"),
        re.compile(r"^=> .* encountered the following failures:$"),  # General case
        re.compile(r"^=>TC\d+ encountered the following failures:$"),  # Specific for TC<number>
        re.compile(r"^\*\*\*=>TC\d+ encountered the following failures:$"),
        re.compile(r"^\*\*General Failures:$"),  # Exclude general failures header
        re.compile(r"^$"),  # Exclude empty lines
        re.compile(r"^\[TestCase Description\].*$", re.DOTALL)  # Exclude [TestCase Description]
    ]

    for pattern in skip_patterns:
        if pattern.match(line):
            return True
    return False


exclusion_patterns = [re.compile(r"\bDictionary does not contain key\b", re.IGNORECASE)]


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





def get_patterns_to_match():
    patterns_to_match = [
        re.compile(r"\bnot running\b", re.IGNORECASE),
        re.compile(r"process-?\bnot\b-?\brunning", re.IGNORECASE),
        re.compile(r"error\s\d+", re.IGNORECASE),
        re.compile(r"TypeError:.* list or list-like", re.IGNORECASE),
        re.compile(r"'\".+?\" == \".+?\"' should be true", re.IGNORECASE),
        re.compile(r"<doc[^>]*>.*?Description:\s*(.*?)</doc>", re.DOTALL | re.IGNORECASE)
    ]

    return patterns_to_match




def capture_failures_in_keywords(element, failure_messages=None, general_failures=None):
    """
    Capture failures and matches in <msg> and <rpc-reply> elements.
    Args:
        element: The current XML element being processed.
        failure_messages: A list to store unique failure messages for the current test case.
        general_failures: A list to store failures not associated with specific test cases.
    """
    if failure_messages is None:
        failure_messages = []
    if general_failures is None:
        general_failures = []

    patterns = get_patterns_to_match()
    unique_messages = set()  # Ensure messages are unique within this invocation
    namespaces = {"xnm": "http://xml.juniper.net/xnm/1.1/xnm"}

    for msg in element.iter("msg"):
        timestamp = msg.get("timestamp", "No timestamp")
        msg_text = msg.text.strip() if msg.text else "No detailed message."

        # Ignore messages with level="INFO"
        if msg.get("level") == "INFO":
            continue

        # Check for failures with "level=FAIL"
        if msg.get("level") == "FAIL" and timestamp:
            unique_messages.add((timestamp, msg_text))
        else:
            # Check patterns within the message text for non-FAIL entries
            for pattern in patterns:
                match = re.search(pattern, msg_text)
                if match:
                    unique_messages.add((timestamp, match.group(0)))

    # Add unique messages to failure_messages or general_failures
    for timestamp, message in unique_messages:
        if element.tag == "test":  # Failures under a <test> tag
            if not any(f["message"] == message for f in failure_messages):  # Avoid duplicates
                failure_messages.append({"timestamp": timestamp, "message": message})
        else:
            if not any(f["message"] == message for f in general_failures):  # Avoid duplicates
                general_failures.append({"timestamp": timestamp, "message": message})

    # Recursively process child elements
    for child in element:
        capture_failures_in_keywords(child, failure_messages, general_failures)



def parse_robot_xml(file_path=None, tree=None):
    """
    Parse XML and capture failures with structured error messages within specific test cases.
    Args:
        file_path: Path to the XML file.
        tree: Parsed ElementTree object (if already loaded).
    Returns:
        dict: Structured data containing all captured failures, including <doc> descriptions.
    """

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
    general_failures = []  # Capture failures not associated with any test case

    # Capture general failures
    capture_failures_in_keywords(root, general_failures=general_failures)
    if general_failures:
        failures["General Failures"] = {
            "failures": [
                failure for failure in general_failures if not is_excluded(failure["message"])
            ]
        }

    # Capture failures in each test case
    for test in root.iter("test"):
        test_name = test.get("name")
        failure_messages = []
        capture_failures_in_keywords(test, failure_messages=failure_messages)

        # Extract <doc> content if it exists
        doc_element = test.find("doc")
        doc_description = None
        if doc_element is not None:
            doc_text = ET.tostring(doc_element, encoding="unicode", method="xml")
            description_match = re.search(
                r"<doc[^>]*>\s*(.*?)\s*</doc>", doc_text, re.DOTALL | re.IGNORECASE
            )
            if description_match:
                doc_description = re.sub(r"\s+", " ", description_match.group(1).strip())

        if failure_messages:
            failures[test_name] = {
                "failures": [
                    failure for failure in failure_messages if not is_excluded(failure["message"])
                ],
                "description": doc_description,  # Include <doc> description if available
            }

    return failures






def extract_doc_text(element):
    """
    Extract the content of the <doc> element from the given XML element.

    Args:
        element: XML element to search for <doc>.

    Returns:
        str: Text content of the <doc> element or None if not found.
    """
    doc_element = element.find("doc")
    if doc_element is not None and doc_element.text:
        return doc_element.text.strip()
    return None




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




def display_corrective_actions_from_file(file_path):
    corrective_actions = load_corrective_actions()
    suggestions_file_path = "robot_failure_suggestions.txt"
    print(f"\nReading failures from: {file_path}")
    print("\nChecking for corrective actions based on logged failures:")

    error_summary = defaultdict(lambda: {"count": 0, "suggestion": "", "unique_messages": {}})
    unmatched_count = 0

    try:
        with open(file_path, 'r') as log_file, open(suggestions_file_path, 'w') as suggestions_file:
            for line in log_file:
                line = line.strip()

                # Skip lines matching patterns
                if should_skip_line(line):
                    continue

                # Highlight lines containing "encountered the following failures"
                if "encountered the following failures" in line:
                    print(f"{BLUE}{line}{RESET}")
                    continue

                # Use suggest_corrective_action for each line
                group_name, suggestion = suggest_corrective_action(line, corrective_actions)

                if group_name:
                    # Log matched errors
                    if line not in error_summary[(group_name, suggestion)]["unique_messages"]:
                        error_summary[(group_name, suggestion)]["unique_messages"][line] = 1
                    else:
                        error_summary[(group_name, suggestion)]["unique_messages"][line] += 1
                    error_summary[(group_name, suggestion)]["suggestion"] = suggestion
                else:
                    unmatched_count += 1
                    print(f"{RED}No match found for error message: {line}{RESET}")
                    suggestions_file.write(f"No corrective action found for error: {line}\n")
                    suggestions_file.write(f"{'-' * 50}\n")

            # Write results for matched errors
            for (group, suggestion), details in error_summary.items():
                count = sum(details["unique_messages"].values())
                print(f"{ORANGE}Failure Group: {group}{RESET}")
                print(f"Occurrences: {count}")
                print("Failures:")
                for msg, occurrence in details["unique_messages"].items():
                    print(f" - {msg} (Occurred {occurrence} times)")
                print(f"{PINK}Suggested Action:{RESET} {suggestion}\n{'-' * 50}")

                suggestions_file.write(f"Failure Group: {group}\n")
                suggestions_file.write(f"Occurrences: {count}\n")
                suggestions_file.write("Failures:\n")
                for msg, occurrence in details["unique_messages"].items():
                    suggestions_file.write(f" - {msg} (Occurred {occurrence} times)\n")
                suggestions_file.write(f"Suggested Action: {suggestion}\n")
                suggestions_file.write(f"{'-' * 50}\n")

        print(f"Suggestions saved in '{suggestions_file_path}'.")
        if unmatched_count > 0:
            print(f"{RED} ==> No specific corrective actions found for {unmatched_count} errors. Training required!{RESET}")

    except FileNotFoundError:
        print(f"File {file_path} not found.")

def process_file(file_path, check_corrective_actions=False):
    print(f"\nProcessing file: {file_path}")
    if file_path.endswith("robot_failure_summary.txt"):
        display_corrective_actions_from_file(file_path)
        return
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
    #Process the xml file#
    failures = parse_robot_xml(tree=tree)
    if failures:
        log_failures(failures, file_path, check_corrective_actions=check_corrective_actions)
    else:
        print(f"{PINK}(`_`){RESET} .. No failures detected in the file.")



def log_failures(failures, file_path, check_corrective_actions=False):
    """
    Logs failures to a file, including test case failures and general failures.
    Args:
        failures: Dictionary containing failure data.
        file_path: Path to the original XML file.
        check_corrective_actions: Whether to check for corrective actions.
    """
    log_dir = "robot_failure_logs"
    os.makedirs(log_dir, exist_ok=True)

    filename = os.path.basename(file_path)
    log_file_path = os.path.join(log_dir, f"{filename}_failure_log.txt")
    print(f"{BLUE}Saving logfile to {log_file_path}{RESET}")

    with open(log_file_path, "w") as failure_log:
        for test_name, failure_details in failures.items():
            # Prepare log entry without color for file writing
            if test_name == "General Failures":
                log_entry = "\n**General Failures:\n"
                print(f"\n{BLUE}**General Failures:{RESET}")
            else:
                log_entry = f"\n=>{test_name} encountered the following failures:\n"
                print(f"\n{RED}=>{test_name} encountered the following failures:{RESET}")

            # Check if there are any failures and then include the description
            if failure_details.get("failures"):
                doc_description = failure_details.get("description")
                if doc_description:
                    # Write description only once (plain text for log file)
                    file_description = f"[TestCase Description] - {doc_description}"
                    log_entry += f"{file_description}\n"

                    # Print description to terminal with color
                    print(f"{ORANGE}[TestCase Description]{RESET} - {doc_description}")

            failure_log.write(log_entry)  # Write the accumulated log entry to file

            # Write and print failure messages
            unique_entries = set()
            for entry in failure_details.get("failures", []):  # Safely handle missing "failures" key
                timestamp = entry.get("timestamp", "No timestamp")
                message = entry.get("message", "No message")
                log_message = f"[{timestamp}] - {message}\n"

                if log_message not in unique_entries:
                    unique_entries.add(log_message)
                    failure_log.write(log_message)  # Write plain text to log file
                    print(f"{YELLOW}[{timestamp}]{RESET} - {message}")  # Print colored output

            # Handle teardown failures (if any)
            teardown_failures = failure_details.get("teardown_failures", [])
            if teardown_failures:
                log_entry = f"Teardown failed for {test_name} with the following errors:\n"
                failure_log.write(log_entry)
                print(f"{RED}Teardown failed for {test_name} with the following errors:{RESET}")
                for entry in teardown_failures:
                    timestamp = entry.get("timestamp", "No timestamp")
                    message = entry.get("message", "No message")
                    log_message = f"[{timestamp}] - {message}\n"
                    if log_message not in unique_entries:
                        unique_entries.add(log_message)
                        failure_log.write(log_message)  # Write plain text to log file
                        print(f"{YELLOW}[{timestamp}]{RESET} - {message}")  # Print colored output

    if check_corrective_actions:
        print(f"\n{BLUE}Checking corrective actions for the logged failures...{RESET}")
        display_corrective_actions_from_file(log_file_path)

    return log_file_path


def main(paths, check_corrective_actions=False):
    def process_directory(directory_path):
        """Process each XML or XML.GZ file in the specified directory."""
        print(f"\nProcessing directory: {directory_path}")
        for root, _, files in os.walk(directory_path):
            for filename in files:
                file_full_path = os.path.join(root, filename)
                if filename.lower().endswith(".xml"):
                    print(f"Processing file: {file_full_path}")
                    process_file(file_full_path, check_corrective_actions)
                elif filename.lower().endswith(".xml.gz"):
                    # Unzip the .gz file
                    unzipped_file_path = file_full_path[:-3]  # Remove .gz extension
                    try:
                        with gzip.open(file_full_path, 'rb') as gz_file:
                            with open(unzipped_file_path, 'wb') as xml_file:
                                shutil.copyfileobj(gz_file, xml_file)
                        print(f"Unzipped file: {unzipped_file_path}")
                        process_file(unzipped_file_path, check_corrective_actions)
                    except Exception as e:
                        print(f"Error processing .gz file: {e}")

    log_dir = "robot_failure_logs"
    os.makedirs(log_dir, exist_ok=True)

    # Process each path provided by the user
    for path in paths:
        if os.path.isdir(path):
            process_directory(path)
        else:
            if path.lower().endswith(".xml.gz"):
                unzipped_file_path = path[:-3]
                try:
                    with gzip.open(path, 'rb') as gz_file:
                        with open(unzipped_file_path, 'wb') as xml_file:
                            shutil.copyfileobj(gz_file, xml_file)
                    print(f"Unzipped file: {unzipped_file_path}")
                    process_file(unzipped_file_path, check_corrective_actions)
                except Exception as e:
                    print(f"Error processing .gz file: {e}")
            elif path.lower().endswith(".xml"):
                print(f"Processing file: {path}")
                process_file(path, check_corrective_actions)
            else:
                print(f"{RED}Error: Only directories or XML files (.xml, .xml.gz) are accepted.{RESET}")
                sys.exit(1)

    # Aggregate logs after processing all paths
    aggregate_logs(log_dir)
    print("\033[92mSummary report updated in 'robot_failure_logs/robot_failure_summary.txt'.\033[0m")
    if check_corrective_actions:
        print(f"{ORANGE}Run, python3 debug_robot_log.py -ca robot_failure_logs/robot_failure_summary.txt -> to check the failure summary and suggestions{RESET}")




'''if __name__ == "__main__":
    # Color codes for terminal output
    ORANGE, YELLOW, PINK, RESET, RED, GREEN, BLUE = (
        "\033[38;5;214m",
        "\033[93m",
        "\033[95m",
        "\033[0m",
        "\033[91m",
        "\033[92m",
        "\033[94m",
    )
    # Set the Python3 path on script execution
    set_python3_path()

    parser = argparse.ArgumentParser(
        description="Process XML or failure logs and optionally display corrective actions."
    )
    parser.add_argument("paths", nargs="*", help="File or directory paths to process")
    parser.add_argument(
        "-ca", metavar="xml_file", help="Specify an XML file path to enable corrective actions check"
    )
    parser.add_argument(
        "-cat",
        metavar="log_file_path",
        help="Specify a log file path in txt format for displaying corrective actions only",
    )
    parser.add_argument(
        "-ge",
        "--group-errors",
        action="store_true",
        help="Group errors by failure group to consolidate suggestions",
    )

    args = parser.parse_args()
    # Display help message if no arguments are provided
    if not args.paths and not args.ca and not args.cat:
        parser.print_help()
        sys.exit(0)

    # Check if -ca is used with a non-XML file
    if args.paths:
        for path in args.paths:
            if os.path.isdir(path):
                # Process directory if it's valid
                print(f"{GREEN}Processing directory: {path}{RESET}")
                main([path], check_corrective_actions=args.ca is not None)
            elif path.lower().endswith(".xml") or path.lower().endswith(".xml.gz"):
                # Process XML or compressed XML files
                print(f"{GREEN}Processing file: {path}{RESET}")
                process_file(path, check_corrective_actions=args.ca is not None)
            else:
                # Handle invalid paths or unsupported file types
                print(
                    f"{RED}Error: Only directories or XML files (.xml, .xml.gz) are accepted as arguments.{RESET}"
                )
                sys.exit(1)

    # Check if -cat is used with a non-txt file
    if args.cat and not args.cat.endswith(".txt"):
        print(f"{RED}Error: The -cat option requires a .txt file format.{RESET}")
        sys.exit(1)


    if args.cat:
        # If -cat is provided, directly display corrective actions for the specified log file
        display_corrective_actions_from_file(args.cat)
    elif args.ca:
        # If -ca is provided, process the file and include corrective actions
        print(f"{GREEN}Processing file for corrective actions: {args.ca}{RESET}")
        process_file(args.ca, check_corrective_actions=True)'''


if __name__ == "__main__":
    # Color codes for terminal output
    ORANGE, YELLOW, PINK, RESET, RED, GREEN, BLUE = (
        "\033[38;5;214m",
        "\033[93m",
        "\033[95m",
        "\033[0m",
        "\033[91m",
        "\033[92m",
        "\033[94m",
    )
    # Set the Python3 path on script execution
    set_python3_path()

    parser = argparse.ArgumentParser(
        description="Process XML or failure logs and optionally display corrective actions."
    )
    parser.add_argument("paths", nargs="*", help="File or directory paths to process")
    parser.add_argument(
        "-ca", metavar="xml_file", help="Specify an XML file path or directory to enable corrective actions check"
    )
    parser.add_argument(
        "-cat",
        metavar="log_file_path",
        help="Specify a log file path in txt format for displaying corrective actions only",
    )
    parser.add_argument(
        "-ge",
        "--group-errors",
        action="store_true",
        help="Group errors by failure group to consolidate suggestions",
    )

    args = parser.parse_args()

    # Display help message if no arguments are provided
    if not args.paths and not args.ca and not args.cat:
        parser.print_help()
        sys.exit(0)

    # Check if -cat is used with a non-txt file
    if args.cat and not args.cat.endswith(".txt"):
        print(f"{RED}Error: The -cat option requires a .txt file format.{RESET}")
        sys.exit(1)

    # Handle -cat option
    if args.cat:
        print(f"{GREEN}Displaying corrective actions for: {args.cat}{RESET}")
        display_corrective_actions_from_file(args.cat)
        sys.exit(0)

    # Handle -ca option
    if args.ca:
        print(f"{GREEN}Processing for corrective actions: {args.ca}{RESET}")
        if os.path.isdir(args.ca):
            main([args.ca], check_corrective_actions=True)
        elif args.ca.lower().endswith((".xml", ".xml.gz")):
            process_file(args.ca, check_corrective_actions=True)
        else:
            print(f"{RED}Error: The -ca option requires a valid directory or XML file.{RESET}")
            sys.exit(1)
        sys.exit(0)

    # Handle paths normally if no -ca or -cat is provided
    if args.paths:
        main(args.paths, check_corrective_actions=False)
