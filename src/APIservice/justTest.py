

import requests
import json


def main():
    url = "http://localhost:4000/jsonrpc"
    headers = {'content-type': 'application/json'}

    # Example echo method
    payload = {
        "method": "echo",
        "params": ["kvakva!"],
        "jsonrpc": "2.0",
        "id": 0,
    }
    response = requests.post(
        url, data=json.dumps(payload), headers=headers).json()

    payload1 = {
        "method": "add",
        "params": [3, 4],
        "jsonrpc": "2.0",
        "id": 0,
    }
    response1 = requests.post(
        url, data=json.dumps(payload1), headers=headers).json()

    assert response["result"] == "echome!"
    assert response["jsonrpc"]
    assert response["id"] == 0

if __name__ == "__main__":
    main()

