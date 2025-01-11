#!/bin/bash

# Define file paths
input_file="gnmic_telemetry.log"
cleaned_file="cleaned_telemetry.log"

# Step 1: Clean up file and extract JSON data from mixed log lines
echo "[" > "$cleaned_file"
while IFS= read -r line; do
    # Only process lines that look like JSON but ignore those with non-JSON metadata
    if echo "$line" | grep -Eq '^\s*[{"]'; then
        echo "$line" | sed 's/,$//' >> "$cleaned_file"
    fi
done < "$input_file"
echo "]" >> "$cleaned_file"
echo "Cleaned JSON-like data saved to $cleaned_file."

# Step 2: Display header for the table
echo -e "\nTelemetry Data Overview\n"
echo -e "source              | prefix                                                         | Path          | values"
echo -e "--------------------|---------------------------------------------------------------|---------------|-------"

# Step 3: Parse cleaned JSON and handle gRPC-like fields
jq -r '.[] | select(.source and .prefix and .updates) |
"\(.source) | \(.prefix) | \(.updates[].Path) | \(.updates[].values | to_entries | map(.key + \": \" + (.value | tostring)) | join(", "))"' "$cleaned_file" || echo "Parsing error or unexpected structure detected."

echo -e "\nEnd of Telemetry Data"

