import re

import yaml

from sentinelprobe.api.schema import CreateScanSchema
from sentinelprobe.api.security import assert_target_allowed
from sentinelprobe.logger import logger
from sentinelprobe.parsers import create_parser
from sentinelprobe.tester.handler import generate_and_run_tests
from sentinelprobe.utils import is_valid_url
from urllib.parse import urlparse

# garak generator family -> environment variable garak reads the key from
LLM_KEY_ENV_VARS = {
    'openai': 'OPENAI_API_KEY',
    'gemini': 'GEMINI_API_KEY',
    'huggingface': 'HF_INFERENCE_TOKEN',
    'cohere': 'COHERE_API_KEY',
    'replicate': 'REPLICATE_API_TOKEN',
    'groq': 'GROQ_API_KEY',
    'nim': 'NIM_API_KEY',
}


def _llm_env(model_type: str, api_key: str | None) -> dict[str, str]:
    if not api_key:
        return {}
    env_var = LLM_KEY_ENV_VARS.get(model_type.split('.')[0].lower())
    if not env_var:
        raise ValueError(
            f'llm_api_key is not supported for model type {model_type!r}; '
            'set the provider key in the server environment instead'
        )
    return {env_var: api_key}


def _load_spec(openapi: str) -> tuple[str | None, dict | None]:
    """Returns (url, None) for a URL or (None, spec) for an inline spec.

    Local file paths are deliberately rejected: this runs on the server and a
    caller must not be able to make it read its own files.
    """
    if is_valid_url(openapi):
        assert_target_allowed(urlparse(openapi).hostname)
        return openapi, None
    try:
        spec = yaml.safe_load(openapi)
    except yaml.YAMLError as exc:
        raise ValueError('openapi is not a URL or valid JSON/YAML') from exc
    if not isinstance(spec, dict):
        raise ValueError('openapi must be a URL or an inline JSON/YAML spec')
    return None, spec


def scan_api(body_data: CreateScanSchema, ssl_verify: bool | None = None):
    """Runs the requested scan(s). Raises on failure so queues mark the job failed."""
    mode = body_data.mode
    if ssl_verify is None:
        ssl_verify = body_data.ssl_verify

    api_results = []
    llm_results = None

    if mode in ('api', 'all'):
        if not body_data.openapi:
            raise ValueError('openapi is required when mode is api or all')
        if body_data.regex_pattern:
            try:
                re.compile(body_data.regex_pattern)
            except re.error as exc:
                raise ValueError(f'invalid regex_pattern: {exc}') from exc

        url, spec = _load_spec(body_data.openapi)
        api_parser = create_parser(fpath_or_url=url, spec=spec, ssl_verify=ssl_verify)
        assert_target_allowed(api_parser.host.split(':')[0])

        api_results = generate_and_run_tests(
            api_parser=api_parser,
            regex_pattern=body_data.regex_pattern,
            req_headers=body_data.req_headers,
            rate_limit=body_data.rate_limit,
            test_data_config=body_data.test_data_config,
            proxies=body_data.proxies,
            capture_failed=body_data.capture_failed,
            remove_unused_data=body_data.remove_unused_data,
            ssl_verify=ssl_verify,
        )

    if mode in ('llm', 'all'):
        if not body_data.llm_model_type or not body_data.llm_probes:
            raise ValueError('llm_model_type and llm_probes are required for llm scans')

        from sentinelprobe.llm.handler import run_llm_scan

        llm_results = run_llm_scan(
            model_type=body_data.llm_model_type,
            model_name=body_data.llm_model_name,
            probes=body_data.llm_probes,
            env_overrides=_llm_env(body_data.llm_model_type, body_data.llm_api_key),
            emit_report=False,
        )

    logger.info('Scan job finished (mode=%s)', mode)
    if mode == 'llm':
        return llm_results
    if mode == 'all':
        return {
            'scan_type': 'combined',
            'api_results': api_results,
            'llm_results': llm_results,
        }
    return api_results
