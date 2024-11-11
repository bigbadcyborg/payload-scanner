import yara
import os

# Define the path to your YARA rule file
rule_file_path = "malicious_patterns.yar"

# Check if the file exists, otherwise raise an error or handle it as needed
if not os.path.isfile("malicous_patterns.yar"):
    raise FileNotFoundError(f"The file {rule_file_path} does not exist.")

# Read the YARA rules from the file
with open(rule_file_path, 'r') as rule_file:
    rules_source = rule_file.read()

# Compile the YARA rules from the string source
rules = yara.compile(source=rules_source)

def scan_payload(payload):
    matches = rules.match(data=payload)
    if matches:
        return True, list(matches[0].tags)
    else:
        return False, []

# Example payloads to test
payload1 = b"print('Hello, World!')"
payload2 = b"eval('__import__(\"os\").system(\"dir\")')"
payload3 = b"os.system('rm -rf /')"

# Scan each payload
for i, payload in enumerate([payload1, payload2, payload3]):
    is_malicious, tags = scan_payload(payload)
    if is_malicious:
        print(f'Payload {i+1} is malicious. Tags: {tags}')
    else:
        print(f'Payload {i+1} is clean.')