from concurrent.futures import ThreadPoolExecutor
from os import environ
from dotenv import load_dotenv
from fastapi import FastAPI

from .auth_utils import generate_random_secret_key_string

load_dotenv()

app = FastAPI(
    title="SentinelProbe - Security Operations Center",
    version="0.1.0",
    servers=[
        {
            "url": "http://localhost:8000",
        }
    ],
)

auth_secret_key = environ.get("AUTH_SECRET_KEY", generate_random_secret_key_string())
task_timeout = 60 * 60  # 3600 s = 1 hour

redis_con = None
task_queue = None

# Graceful Redis connection with fallback to in-memory thread pool
try:
    from redis import Redis
    from rq import Queue
    r_host = environ.get("REDIS_HOST", "localhost")
    r_port = int(environ.get("REDIS_PORT", 6379))
    r = Redis(host=r_host, port=r_port, socket_connect_timeout=0.5)
    r.ping()
    redis_con = r
    task_queue = Queue(name="sentinelprobe_task_queue", connection=redis_con)
except Exception:
    redis_con = None
    task_queue = None

executor = ThreadPoolExecutor(max_workers=4)
in_memory_jobs = {}
