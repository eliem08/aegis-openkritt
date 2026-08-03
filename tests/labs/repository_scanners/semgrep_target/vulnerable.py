"""Synthetic authorized-lab examples; none of these functions are executed."""

import os
import sqlite3

import requests
from flask import request


def command_injection_candidate():
    command = request.args.get("command")
    return os.system(command)


def ssrf_candidate():
    destination = request.form.get("destination")
    return requests.get(destination, timeout=2)


def sql_injection_candidate():
    user_id = request.json.get("user_id")
    connection = sqlite3.connect(":memory:")
    return connection.execute("SELECT * FROM users WHERE id = " + user_id)
