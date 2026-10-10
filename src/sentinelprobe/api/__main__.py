from uvicorn import run
import os


def start():
    host = os.environ.get("SENTINELPROBE_HOST", "127.0.0.1")
    port = int(os.environ.get("SENTINELPROBE_PORT", 8000))

    print(f"\n=======================================================")
    print(f" SentinelProbe Web Dashboard & API Server Started")
    print(f" Web UI:  http://localhost:{port}")
    print(f" API Docs: http://localhost:{port}/docs")
    print(f"=======================================================\n")

    run(
        app="sentinelprobe.api.app:app",
        host=host,
        port=port,
        workers=1,
        reload=False,
    )


if __name__ == "__main__":
    start()
