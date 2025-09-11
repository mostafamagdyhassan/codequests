from flask import Flask, request, jsonify
import psycopg2, os, time
from prometheus_client import Counter, Histogram, generate_latest

app = Flask(__name__)

# Metrics
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
