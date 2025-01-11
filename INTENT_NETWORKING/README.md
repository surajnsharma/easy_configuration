Intent Networking Automation

    This project automates intent-based networking tasks on multiple devices. 
    The tasks (intents) are defined in a structured JSON file (intents_registry.json) and executed 
    sequentially or iteratively with support for per-intent sleep timers.

Features

    Dynamic execution of networking tasks (intents) based on a registry.
    Support for both device-specific and tag-based device matching.
    Configurable iterations for each intent.
    Sleep timer control between iterations for fine-grained pacing.
    Logging in XML format for detailed audit trails.


File Structure

    project/
    ├── device_creds.yaml        # Device credentials and tags
    ├── intents_registry.json    # Intents definitions and execution sequences
    ├── intent_functions.py      # Functions for executing intents
    ├── test.py                  # Main execution script
    ├── debug.xml                # XML-based execution logs
    ├── README.md                # Documentation


Prerequisites

    Install Python 3.x.
    Install required Python packages:
        pip install -r requirements.txt

    Ensure device_creds.yaml and intents_registry.json are correctly populated.


Intent Networking Automation

This project automates the execution of network intents across multiple devices using a structured configuration and execution pipeline. It validates intents against a registry and device attributes (e.g., tags, types) before execution.
Features

    Intent Validation: Ensures intents are executed only for allowed devices or tags, based on intents_registry.json.
    Parallel Execution: Executes intents across multiple devices concurrently using threading.
    Dynamic Parameterization: Supports custom parameters for each intent.
    Extensible Framework: Easily add new intents by registering them in intents_registry.json.

Configuration Files
intents_registry.json

Defines the list of available intents, their attributes, and execution constraints.
Example:

{
    "intents": {
        "disable_interface": {
            "description": "Disables a network interface on the specified device.",
            "function": "disable_interface",
            "supported_device_types": ["Router", "Switch"],
            "tags": ["leaf"],
            "devices": ["Router1"],
            "parameters": {}
        },
        "enable_interface": {
            "description": "Enables a network interface on the specified device.",
            "function": "enable_interface",
            "supported_device_types": ["Router", "Switch"],
            "tags": ["spine"],
            "devices": [""], ## this will allow devices..
            "parameters": {}
        },
        "generate_alarm": {
            "description": "Generates an alarm by simulating a high power optics insert.",
            "function": "generate_alarm",
            "supported_device_types": ["Router"],
            "tags": ["alarm", "optics", "spine"],
            "devices": [],
            "parameters": {}
        }
    }
}

Key Attributes:

    description: Human-readable description of the intent.
    function: Name of the function in intent_functions.py that implements the intent.
    supported_device_types: Device types (e.g., Router, Switch) where the intent can run.
    tags: Tags to match against devices in device_creds.yaml.
    devices: Specific devices allowed to execute the intent.
    parameters: Default parameters for the intent.

device_creds.yaml

Defines device credentials, types, and tags for intent validation.
Example:

global:
  username: "root"
  password: "Embe1mpls"

devices:
  - name: "Router1"
    host: "svla-q5240-06.englab.juniper.net"
    username: "root"
    password: "Embe1mpls"
    type: "Switch" ## type should match supported_device_types else intent execution will fail
    tags: ["leaf", "bgp-enabled"]

  - name: "Router2"
    host: "svla-q5240-08.englab.juniper.net"
    type: "Switch"
    tags: ["spine", "bgp-enabled"]

Key Attributes:

    global: Default credentials used if device-specific credentials are not provided.
    devices: List of devices with attributes like name, host, type, and tags.

device_intent.yaml

Defines the sequence of intents to be executed for each device.
Example:

#device_intent.yaml
intent_sequence:
  Router1:
    - intent: snapshot_device_state
      iterations: 1
      active: "yes"
      parameters:
        snapshot_type: "pre"
        format: "text"
        save_to_file: true
        output_dir: "./snapshots"
    - intent: disable_interface
      iterations: 2
      active: "yes"
      sleep_timer: 1
      parameters:
        interface_name:
          - "et-0/0/1:0"
          - "et-0/0/1:1"
    - intent: enable_interface
      iterations: 2
      active: "yes"
      sleep_timer: 1
      parameters:
        interface_name:
          - "et-0/0/1:0"
          - "et-0/0/1:1"
    - intent: generate_alarm
      iterations: 1
      active: "yes"
      sleep_timer: 1
      parameters:
        fpc_slot: 0
        pic_slot: 0
        ports: [ 0, 1 ]
    - intent: snapshot_device_state
      iterations: 1
      active: "yes"
      parameters:
        format: "text"
        snapshot_type: "post"
        save_to_file: true
        output_dir: "./snapshots"
    - intent: state_comparison
      iterations: 1
      active: "yes"
      parameters:
        format: "xml"

  Router2:
    - intent: execute_custom_commands
      iterations: 1
      active: "no"
      parameters:
        format: "xml"
        output_dir: "./snapshots"
        snapshot_type: "pre"
        commands:
          - "show chassis hardware"
          - "show interfaces terse et*"
    - intent: snapshot_device_state
      iterations: 1
      active: "yes"
      parameters:
        save_to_file: true
        format: "xml"
        output_dir: "./snapshots"
        snapshot_type: "pre"
    - intent: disable_interface
      iterations: 1
      active: "yes"
      sleep_timer: 2
      parameters:
        fpc_slot: 0
        pic_slot: 0
        ports: [ "20:1" ]
    - intent: enable_interface
      iterations: 1
      active: "yes"
      sleep_timer: 1
      parameters:
        fpc_slot: 0
        pic_slot: 0
        ports: [ "20:1" ]
    - intent: generate_alarm
      iterations: 1
      active: "yes"
      sleep_timer: 0
      parameters:
        fpc_slot: 0
        pic_slot: 0
        ports: [0, 1]
    - intent: snapshot_device_state
      iterations: 1
      active: "yes"
      parameters:
        save_to_file: true
        format: "xml"
        output_dir: "./snapshots"
        snapshot_type: "post"
    - intent: execute_custom_commands
      iterations: 1
      active: "yes"
      parameters:
        format: "xml"
        output_dir: "./snapshots"
        snapshot_type: "post"
        commands:
          - "show chassis hardware"
          - "show interfaces terse et*"
    - intent: state_comparison
      iterations: 1
      active: "yes"
      parameters:
        format: "xml"


Key Attributes:

    intent: Name of the intent (must match an intent in intents_registry.json).
    iterations: Number of times to execute the intent.
    active: Whether the intent is active (yes or no).
    sleep_timer: Delay (in seconds) between intent executions.
    parameters: Custom parameters for the intent.

Execution Workflow

    Validation:
        Validates each intent in device_intent.yaml against intents_registry.json.
        Ensures the intent is allowed based on devices, tags, and supported_device_types.

    Connection:
        Establishes a connection to each device using credentials from device_creds.yaml.

    Intent Execution:
        Executes intents in a round-robin fashion for all devices in device_intent.yaml.
        Logs success/failure status for each intent.

    Summary:
        Outputs a detailed summary of the execution status for each device and intent.

How to Use

    Configure Files:
        Define intents in intents_registry.json.
        Add devices and credentials to device_creds.yaml.
        Specify intent sequences in device_intent.yaml.

    Run the Script:

    python test.py

    Check Logs:
        Logs are saved to debug.log.
        The final summary is printed to the console.

Logs and Debugging

    Logs include details about validation, connection status, intent execution, and errors.
    To debug:
        Check debug.log for detailed error messages.
        Ensure intents, devices, and tags are correctly configured.

Adding New Intents

    Implement the intent function in intent_functions.py. For example:

def my_custom_intent(dev, cu, **kwargs):
    # Intent logic here
    pass

Register the intent in intents_registry.json:

    {
        "my_custom_intent": {
            "description": "Custom intent description.",
            "function": "my_custom_intent",
            "supported_device_types": ["Router"],
            "tags": ["custom"],
            "devices": [],
            "parameters": {}
        }
    }

    Add the intent to device_intent.yaml for specific devices.

Known Issues

    Ensure all intents are properly registered in intents_registry.json.
    Devices or tags not matching will result in the intent being skipped.

