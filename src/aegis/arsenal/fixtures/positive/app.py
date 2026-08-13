import os
import sqlite3


def unsafe(command: str, user_id: str):
    os.system(command)
    return sqlite3.connect(":memory:").execute("SELECT * FROM users WHERE id=" + user_id)
