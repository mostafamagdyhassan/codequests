from flask import Flask, request, jsonify
import psycopg2
import os

app = Flask(__name__)

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "tasksdb")
DB_USER = os.getenv("DB_USER", "myuser")
DB_PASSWORD = os.getenv("DB_PASSWORD", "mypassword")

def get_connection():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )

@app.route("/addTask", methods=["POST"])
def add_task():
    data = request.json
    description = data.get("description")
    if not description:
        return jsonify({"error": "Description required"}), 400

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO tasks (description) VALUES (%s) RETURNING id", (description,))
    task_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"message": "Task added", "id": task_id}), 201

@app.route("/deleteTask/<int:task_id>", methods=["DELETE"])
def delete_task(task_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM tasks WHERE id = %s", (task_id,))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"message": "Task deleted"}), 200

@app.route("/listTasks", methods=["GET"])
def list_tasks():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, description, created_at FROM tasks")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    tasks = [{"id": r[0], "description": r[1], "created_at": r[2].isoformat()} for r in rows]
    return jsonify(tasks)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
