#!/usr/bin/python3
import requests
from requests.auth import HTTPBasicAuth
import sys

def upload_to_webdav(local_file, remote_url, username, password):
    try:
        with open(local_file, "rb") as f:
            response = requests.put(
                remote_url, 
                data=f, 
                auth=HTTPBasicAuth(username, password),
                headers={'Content-Type': 'application/octet-stream'}
            )
        
        if response.status_code in [200, 201, 204]:
            print(f"✓ Upload successful: {response.status_code}")
            return True
        else:
            print(f"✗ Upload failed: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python upload.py <local_file> <remote_url> <username> <password>")
        sys.exit(1)
    
    upload_to_webdav(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])