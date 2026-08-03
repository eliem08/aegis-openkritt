"""Negative controls for the Aegis-owned Semgrep rules."""

import sqlite3
import subprocess

import requests
from flask import request


APPROVED_SERVICES = {"status": "https://status.example.test/health"}


def bounded_process():
    value = request.args.get("value")
    return subprocess.run(["printf", "%s", value], shell=False, check=False)


def allowlisted_fetch():
    service = request.args.get("service")
    return requests.get(APPROVED_SERVICES[service], timeout=2)


def parameterized_query():
    user_id = request.args.get("user_id")
    connection = sqlite3.connect(":memory:")
    return connection.execute("SELECT * FROM users WHERE id = ?", (user_id,))
