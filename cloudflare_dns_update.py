import http.client
import json
import os

api_token = os.getenv('CF_API_KEY')
if not api_token:
    raise RuntimeError("CF_API_KEY was not defined.")


zone_id = 'd6adb6059ddec321ca4077f1389c50e3'
record_id = 'c067a40a66781f83ed8be14d5902234f'

# Get the current IP address
conn = http.client.HTTPSConnection('icanhazip.com')
conn.request('GET', '/')
response = conn.getresponse()
current_ip = response.read().strip().decode('utf-8')
conn.close()

# Set the new DNS record details
dns_record = {
    'type': 'A',
    'name': 'check',
    'content': current_ip,
    'ttl': 60,
    'proxied': False
}

# Prepare the headers and the JSON payload
headers = {
    'Authorization': f'Bearer {api_token}',
    'Content-Type': 'application/json'
}
json_data = json.dumps(dns_record)

# Make the API request to update the DNS record
conn = http.client.HTTPSConnection('api.cloudflare.com')
url = f'/client/v4/zones/{zone_id}/dns_records/{record_id}'
conn.request('PATCH', url, body=json_data, headers=headers)

# Get and print the response
response = conn.getresponse()
print(response.read().decode('utf-8'))
conn.close()

