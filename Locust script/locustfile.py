import os
import random
from locust import HttpUser, task, between

# Configurable parameters via ENV
API_HOST = os.getenv("API_HOST", "http://localhost:8000")
WAIT_MIN = int(os.getenv("WAIT_MIN", "1"))
WAIT_MAX = int(os.getenv("WAIT_MAX", "3"))

class BackendUser(HttpUser):
    wait_time = between(WAIT_MIN, WAIT_MAX)

    def on_start(self):
        self.client.base_url = API_HOST

    @task(3)
    def list_tasks(self):
        self.client.get("/listTasks")

    @task(2)
    def add_task(self):
        task_name = f"task-{random.randint(1, 100000)}"
        self.client.post("/addTask", json={"task": task_name})

    @task(1)
    def delete_task(self):
        # Simulate deleting a random task ID
        task_id = random.randint(1, 100)
        self.client.delete(f"/deleteTask?id={task_id}")
