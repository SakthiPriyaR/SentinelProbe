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

AUTH_SECRET_KEY = environ.get("AUTH_SECRET_KEY")
if not AUTH_SECRET_KEY:
    import warnings
    warnings.warn('AUTH_SECRET_KEY not set; generating ephemeral key. This will not work with multiple workers.', stacklevel=2)
    auth_secret_key = generate_random_secret_key_string()
else:
    if 'change_this' in AUTH_SECRET_KEY or len(AUTH_SECRET_KEY) < 16:
        raise RuntimeError(
            'AUTH_SECRET_KEY is the sample placeholder or shorter than 16 characters. '
            'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(48))"'
        )
    auth_secret_key = AUTH_SECRET_KEY
task_timeout = 60 * 60  # 3600 s = 1 hour

redis_con = None
task_queue = None

# Graceful Redis connection with fallback to in-memory thread pool
try:
    from redis import Redis
    from rq import Queue
    r_host = environ.get("REDIS_HOST", "localhost")
    try:
        r_port = int(environ.get("REDIS_PORT", 6379))
    except (ValueError, TypeError):
        r_port = 6379
    REDIS_PORT = r_port
    r = Redis(host=r_host, port=r_port, socket_connect_timeout=0.5)
    r.ping()
    redis_con = r
    task_queue = Queue(name="sentinelprobe_task_queue", connection=redis_con)
except Exception:
    redis_con = None
    task_queue = None

executor = ThreadPoolExecutor(max_workers=4)
in_memory_jobs = {}

# finished in-memory jobs are dropped after this long / beyond this many jobs
JOB_TTL_SECONDS = 60 * 60
MAX_IN_MEMORY_JOBS = 200


def prune_in_memory_jobs(now: float | None = None) -> None:
    """Removes expired finished jobs and trims the oldest ones over the cap."""
    import time

    now = time.time() if now is None else now
    for job_id, job in list(in_memory_jobs.items()):
        done = job['status'] in ('finished', 'failed')
        if done and now - job.get('updated', now) > JOB_TTL_SECONDS:
            in_memory_jobs.pop(job_id, None)
    overflow = len(in_memory_jobs) - MAX_IN_MEMORY_JOBS
    if overflow > 0:
        finished = [j for j, v in in_memory_jobs.items() if v['status'] in ('finished', 'failed')]
        for job_id in finished[:overflow]:
            in_memory_jobs.pop(job_id, None)
