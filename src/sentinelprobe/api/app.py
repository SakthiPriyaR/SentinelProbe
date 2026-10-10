import os
import platform
import uuid
from textwrap import dedent
from pathlib import Path

from fastapi import status, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from sentinelprobe.api.config import (
    app,
    task_queue,
    task_timeout,
    auth_secret_key,
    executor,
    in_memory_jobs,
)
from sentinelprobe.api.jobs import scan_api
from sentinelprobe.api.schema import CreateScanSchema
from sentinelprobe.logger import logger


logger.info("Secret Key: %s", auth_secret_key)

if (
    platform.system() == "Darwin"
    and os.environ.get("OBJC_DISABLE_INITIALIZE_FORK_SAFETY") != "YES"
):
    logger.warning(
        dedent(
            """Mac Users might need to configure OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES in env
    Visit StackOverFlow link for more info:
    https://stackoverflow.com/questions/50168647/multiprocessing-causes-python-to-crash-and-gives-an-error-may-have-been-in-progr
    """
        )
    )


def _get_dashboard_path() -> Path:
    # 1. Check current working directory
    cwd_path = Path.cwd() / "dashboard.html"
    if cwd_path.is_file():
        return cwd_path
    # 2. Check parent or package directory
    pkg_path = Path(__file__).resolve().parent.parent.parent / "dashboard.html"
    if pkg_path.is_file():
        return pkg_path
    # 3. Fallback to report.html template
    template_path = (
        Path(__file__).resolve().parent.parent
        / "report"
        / "templates"
        / "report.html"
    )
    return template_path


@app.get("/", status_code=status.HTTP_200_OK)
async def serve_dashboard():
    dashboard_file = _get_dashboard_path()
    if dashboard_file.is_file():
        return FileResponse(dashboard_file, media_type="text/html")
    return {
        "name": "SentinelProbe Security Operations Center",
        "status": "Running",
        "docs": "/docs",
    }


@app.get("/api/v1/info")
async def api_info():
    return {
        "name": "SentinelProbe API",
        "version": "0.1.0",
        "queue_backend": "redis" if task_queue else "in-memory-threads",
    }


def _run_in_memory_job(job_id: str, scan_data: CreateScanSchema):
    try:
        in_memory_jobs[job_id]["status"] = "in_progress"
        results = scan_api(scan_data)
        in_memory_jobs[job_id]["status"] = "finished"
        in_memory_jobs[job_id]["results"] = results
    except Exception as exc:
        logger.error("Job %s failed: %s", job_id, exc)
        in_memory_jobs[job_id]["status"] = "failed"
        in_memory_jobs[job_id]["error"] = str(exc)


@app.post("/api/v1/scan", status_code=status.HTTP_201_CREATED)
async def add_scan_task(
    scan_data: CreateScanSchema, request: Request, response: Response
):
    client_ip = request.client.host if request.client else "127.0.0.1"
    secret_key = request.headers.get("SECRET-KEY", None)

    # Allow local browser requests or validate secret key
    is_local = client_ip in ("127.0.0.1", "localhost", "::1", "testclient")
    if not is_local and secret_key != auth_secret_key:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        logger.warning("INTRUSION: %s tried to create an unauthorized scan job", client_ip)
        return {"message": "Unauthorized"}

    job_id = str(uuid.uuid4())
    msg = {"msg": "Scan Task Created", "job_id": job_id}

    if task_queue:
        # Enqueue in Redis RQ
        job = task_queue.enqueue(scan_api, scan_data, job_timeout=task_timeout)
        msg["job_id"] = job.id
        logger.info("SUCCESS: %s created Redis scan job - %s", client_ip, job.id)
    else:
        # Enqueue in in-memory executor
        in_memory_jobs[job_id] = {
            "status": "queued",
            "results": None,
            "error": None,
        }
        executor.submit(_run_in_memory_job, job_id, scan_data)
        logger.info("SUCCESS: %s created In-Memory scan job - %s", client_ip, job_id)

    return msg


@app.get("/api/v1/scan/{job_id}/result")
async def get_scan_task_result(job_id: str, request: Request, response: Response):
    client_ip = request.client.host if request.client else "127.0.0.1"
    secret_key = request.headers.get("SECRET-KEY", None)
    is_local = client_ip in ("127.0.0.1", "localhost", "::1", "testclient")

    if not is_local and secret_key != auth_secret_key:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"message": "Unauthorized"}

    # 1. Check in-memory jobs
    if job_id in in_memory_jobs:
        job_info = in_memory_jobs[job_id]
        if job_info["status"] == "finished":
            response.status_code = status.HTTP_200_OK
            return {"msg": "Task Completed", "results": job_info["results"]}
        elif job_info["status"] == "failed":
            response.status_code = status.HTTP_200_OK
            return {
                "msg": f"Task Failed: {job_info.get('error')}",
                "results": None,
            }
        else:
            response.status_code = status.HTTP_202_ACCEPTED
            return {"msg": "Job In Progress", "results": None}

    # 2. Check Redis RQ if active
    if task_queue:
        scan_results_job = task_queue.fetch_job(job_id=job_id)
        if scan_results_job and scan_results_job.is_started:
            response.status_code = status.HTTP_202_ACCEPTED
            return {"msg": "Job In Progress", "results": None}
        elif scan_results_job and scan_results_job.is_finished:
            response.status_code = status.HTTP_200_OK
            return {"msg": "Task Completed", "results": scan_results_job.result}
        elif scan_results_job and scan_results_job.is_failed:
            response.status_code = status.HTTP_200_OK
            return {
                "msg": "Task Failed. Try Creating Task Again.",
                "results": None,
            }

    response.status_code = status.HTTP_404_NOT_FOUND
    return {"msg": "Invalid Job Id or Job Expired", "results": None}
