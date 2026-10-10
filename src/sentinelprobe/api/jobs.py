import os
from sys import exc_info
from sentinelprobe.utils import is_valid_url
from sentinelprobe.api.schema import CreateScanSchema
from sentinelprobe.tester.handler import generate_and_run_tests
from sentinelprobe.parsers import create_parser
from sentinelprobe.logger import logger


def scan_api(body_data: CreateScanSchema, ssl_verify: bool = True):
    try:
        mode = getattr(body_data, 'mode', 'api') or 'api'
        api_results = []
        llm_results = None

        # 1. Run API Scan if mode is 'api' or 'all'
        if mode in ('api', 'all') and body_data.openapi:
            url = body_data.openapi if is_valid_url(body_data.openapi) else None
            spec = None if url else body_data.openapi

            api_parser = create_parser(fpath_or_url=url, spec=spec, ssl_verify=ssl_verify)

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

        # 2. Run LLM Scan if mode is 'llm' or 'all'
        if mode in ('llm', 'all') and body_data.llm_model_type and body_data.llm_probes:
            if body_data.llm_api_key:
                os.environ['OPENAI_API_KEY'] = body_data.llm_api_key
                os.environ['GEMINI_API_KEY'] = body_data.llm_api_key

            from sentinelprobe.llm.handler import run_llm_scan
            llm_results = run_llm_scan(
                model_type=body_data.llm_model_type,
                model_name=body_data.llm_model_name,
                probes=body_data.llm_probes,
            )

        if mode == 'llm':
            return llm_results
        elif mode == 'all':
            return {
                'scan_type': 'combined',
                'api_results': api_results,
                'llm_results': llm_results,
            }
        else:
            return api_results

    except Exception as e:
        logger.error('Error occurred while executing scan job: %s', repr(e))
        logger.error('Debug Data:', exc_info=exc_info())
        return [{'error': str(e)}]
