from typing import Literal, Optional

from pydantic import BaseModel, Field


class CreateScanSchema(BaseModel):
    mode: Literal['api', 'llm', 'all'] = 'api'
    # URL of a spec, or the spec itself (JSON/YAML). Local file paths are not accepted.
    openapi: Optional[str] = Field(default=None, max_length=5_000_000)
    regex_pattern: Optional[str] = Field(default=None, max_length=200)
    req_headers: Optional[dict] = Field(
        default_factory=lambda: {'User-Agent': 'sentinelprobe-api'}
    )
    rate_limit: Optional[int] = Field(default=60, ge=1, le=10000)
    test_data_config: Optional[dict] = None
    proxies: Optional[list[str]] = None
    capture_failed: Optional[bool] = False
    remove_unused_data: Optional[bool] = True
    ssl_verify: bool = True
    # LLM scanning fields
    llm_model_type: Optional[str] = Field(default=None, max_length=100)
    llm_model_name: Optional[str] = Field(default=None, max_length=200)
    llm_probes: Optional[str] = Field(default=None, max_length=1000)
    llm_api_key: Optional[str] = Field(default=None, max_length=512, repr=False)
