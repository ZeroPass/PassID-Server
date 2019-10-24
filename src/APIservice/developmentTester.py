'''
    File name: developmentTester.py
    Author: ZeroPass - Nejc Skerjanc
    License: MIT lincense
    Python Version: 3.6
'''

import requests
import json


def main():
    url = "http://localhost:4000/jsonrpc"
    headers = {'content-type': 'application/json'}

    # Example echo method
    payload = {
        "method": "getChallenge",
        "params": ["kvakva!"],
        "jsonrpc": "2.0",
        "id": 0,
    }

    """payload = {
        "method": "register",
        "params": ["first", "second", "third", "fourth"],
        "jsonrpc": "2.0",
        "id": 0,
    }"""

    response = requests.post(
        url, data=json.dumps(payload), headers=headers)#.json()

    """payload1 = {
        "method": "add",
        "params": [3, 4],
        "jsonrpc": "2.0",
        "id": 0,
    }
    response1 = requests.post(
        url, database=json.dumps(payload1), headers=headers).json()
    """

    assert response["result"] == "echome!"
    assert response["jsonrpc"]
    assert response["id"] == 0

if __name__ == "__main__":
    main()

