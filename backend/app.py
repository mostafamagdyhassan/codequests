from fastapi import FastAPI, HTTPException
import psycopg2
import os

app = FastAPI()

DB_HOST = os.getenv("DB_HOST", "postgres")
DB_NAME = os.getenv("DB_NAME", "tasksdb")
DB_USER = os.getenv("DB_USER", "admin")
DB_PASS = os.getenv("DB_PASS", "admin")

def get_conn():
    return psycopg2.connect(
        host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASS
    )

@app.on_event("startup")
def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS tasks (id SERIAL PRIMARY KEY, name TEXT);")
    conn.commit()
    cur.close()
    conn.close()

@app.post("/addTask")
def add_task(name: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO tasks (name) VALUES (%s)", (name,))
    conn.commit()
    cur.close()
    conn.close()
    return {"message": "Task added"}

@app.delete("/deleteTask/{task_id}")
def delete_task(task_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM tasks WHERE id=%s", (task_id,))
    conn.commit()
    cur.close()
    conn.close()
    return {"message": "Task deleted"}

@app.get("/listTasks")
def list_tasks():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM tasks")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [{"id": r[0], "name": r[1]} for r in rows]
