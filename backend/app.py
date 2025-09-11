from flask import Flask, request, jsonify
import psycopg2
import os
import time

# Prometheus metrics
from prometheus_client import Counter, Histogram, generate_latest

# OpenTelemetry imports
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor


# ===============================
# Database connection
# ===============================
DB_HOST = os.getenv("DB_HOST", "db")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "tasksdb")
DB_USER = os.getenv("DB_USER", "myuser")
DB_PASSWORD = os.getenv("DB_PASSWORD", "mypassword")

def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
    )

# ===============================
# OpenTelemetry setup
# ===============================
trace.set_tracer_provider(TracerProvider())
tracer = trace.get_tracer(__name__)

OTEL_ENDPOINT = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector.monitoring:4317")

otlp_exporter = OTLPSpanExporter(
    endpoint=OTEL_ENDPOINT,
    insecure=True
)
trace.get_tracer_provider().add_span_processor(BatchSpanProcessor(otlp_exporter))


# ===============================
# Flask app setup
# ===============================
app = Flask(__name__)
FlaskInstrumentor().instrument_app(app)
RequestsInstrumentor().instrument()


# ===============================
# Prometheus metrics
# ===============================
REQUEST_COUNT = Counter("request_count", "Total requests", ["method", "endpoint"])
REQUEST_LATENCY = Histogram("request_latency_seconds", "Request latency", ["endpoint"])


@app.before_request
def before_request():
    request.start_time = time.time()


@app.after_request
def after_request(response):
    latency = time.time() - request.start_time
    REQUEST_COUNT.labels(request.method, request.path).inc()
    REQUEST_LATENCY.labels(request.path).observe(latency)
    return response


@app.route("/metrics")
def metrics():
    return generate_latest(), 200


# ===============================
# Routes
# ===============================
@app.route("/addTask", methods=["POST"])
def add_task():
    data = request.get_json()
    task = data.get("task")
    if not task:
        return jsonify({"error": "Task is required"}), 400

    with tracer.start_as_current_span("db-insert-task"):
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("INSERT INTO tasks (task) VALUES (%s)", (task,))
        conn.commit()
        cur.close()
        conn.close()

    return jsonify({"message": f"Task '{task}' added successfully"}), 201


@app.route("/deleteTask", methods=["DELETE"])
def delete_task():
    data = request.get_json()
    task_id = data.get("id")
    if not task_id:
        return jsonify({"error": "Task ID is required"}), 400

    with tracer.start_as_current_span("db-delete-task"):
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM tasks WHERE id = %s", (task_id,))
        conn.commit()
        cur.close()
        conn.close()

    return jsonify({"message": f"Task ID {task_id} deleted successfully"}), 200


@app.route("/listTasks", methods=["GET"])
def list_tasks():
    with tracer.start_as_current_span("db-list-tasks"):
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, task FROM tasks")
        rows = cur.fetchall()
        cur.close()
        conn.close()

    tasks = [{"id": row[0], "task": row[1]} for row in rows]
    return jsonify(tasks), 200


# ===============================
# Startup
# ===============================
if __name__ == "__main__":
    # Ensure table exists
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS tasks (
            id SERIAL PRIMARY KEY,
            task TEXT NOT NULL
        )
        """
    )
    conn.commit()
    cur.close()
    conn.close()

    app.run(host="0.0.0.0", port=8000)
