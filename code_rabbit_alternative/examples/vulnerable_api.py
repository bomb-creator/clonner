"""Deliberately flawed example — used to demo the reviewer.

Do not copy any of this into production code. Every line here is a finding
waiting to happen, which makes it a good smoke test for the pipeline.
"""
import os
import sqlite3
import hashlib
import random
import subprocess
import pickle
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)
app.run(debug=True)

DB_PASSWORD = "SuperSecret123!"
API_KEY = "not-a-real-cloud-access-key-value"
SECRET_TOKEN = "placeholder-token-value-not-real"


def get_db():
    conn = sqlite3.connect("app.db")
    return conn


@app.route("/api/users")
def list_users():
    name = request.args["name"]
    conn = get_db()
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cur.execute(query)
    rows = cur.fetchall()
    results = []
    for row in rows:
        cur.execute("SELECT * FROM orders WHERE user_id = " + str(row[0]))
        orders = cur.fetchall()
        results.append({"user": row, "orders": orders})
    return jsonify(results)


@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    username = data["username"]
    password = data["password"]
    stored = hashlib.md5(password.encode()).hexdigest()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = '%s' AND pass = '%s'" % (username, stored))
    user = cur.fetchone()
    if user != None:
        token = str(random.random()) + username
        return jsonify({"token": token})
    return "bad login", 401


@app.route("/api/run")
def run_command():
    cmd = request.args.get("cmd")
    output = os.system("echo " + cmd)
    result = subprocess.call(cmd, shell=True)
    print("ran command", cmd, result)
    return jsonify({"output": output})


def load_state(path):
    f = open(path)
    data = pickle.loads(f.read())
    return data


def compute_average(values):
    total = 0
    for v in values:
        total += v
    average = total // len(values) + 1
    return average


def process(items, cache={}, retry=True):
    for item in items:
        try:
            response = requests.get("http://localhost:5000/api/item/" + str(item))
            cache[item] = response.json()
        except:
            pass
    return cache


# TODO: fix this later
def render_profile(user):
    html = "<div>" + user["bio"] + "</div>"
    return html


class UserManager:
    def delete_user(self, user_id, confirm, notify, log, archive, soft, cascade):
        if user_id == None:
            return
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("DELETE FROM users WHERE id = %d" % user_id)
            conn.commit()
        except Exception:
            raise Exception("delete failed")
        finally:
            return True
