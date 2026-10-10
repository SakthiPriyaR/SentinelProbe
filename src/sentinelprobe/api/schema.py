from typing import Optional
from pydantic import BaseModel


class CreateScanSchema(BaseModel):
    mode: Optional[str] = "api"  # "api", "llm", "all"
    openapi: Optional[str] = None
    regex_pattern: Optional[str] = None
    req_headers: Optional[dict] = {"User-Agent": "sentinelprobe-api"}
    rate_limit: Optional[int] = 60
    test_data_config: Optional[dict] = None
    proxies: Optional[list[str]] = None
    capture_failed: Optional[bool] = False
    remove_unused_data: Optional[bool] = True
    # LLM scanning fields
    llm_model_type: Optional[str] = None
    llm_model_name: Optional[str] = None
    llm_probes: Optional[str] = None
    llm_api_key: Optional[str] = None
