import sys
from argparse import ArgumentParser

from .parsers.openapi import OpenAPIv3Parser
from .parsers.swagger import SwaggerParser
from .config_data_handler import validate_config_file_data
from .tester.handler import generate_and_run_tests
from .parsers import create_parser
from .logger import logger
from .utils import get_package_version, headers_list_to_dict, read_yaml


def banner():
    """Prints SentinelProbe cli banner"""
    print(
        r"""
      _/|       |\_
     /  |       |  \
    |    \     /    |
    |  \ /     \ /  |
    | \  |     |  / |
    | \ _\_/^\_/_ / |
    |    --\//--    |
     \_  \     /  _/
       \__  |  __/
          \ _ /
         _/   \_
        / _/|\_ \
         /  |  \
          / v \
          SentinelProbe
    """
    )


def start():
    """Starts cli tool"""
    banner()

    parser = ArgumentParser(prog='sentinelprobe')
    parser.add_argument(
        '-f',
        '--file',
        dest='fpath',
        type=str,
        help='path or url of openapi/swagger specification file (required for --mode api/all)',
        required=False,
    )
    parser.add_argument(
        '-v', '--version', action='version', version=f"%(prog)s {get_package_version()}"
    )
    parser.add_argument(
        '--http-methods',
        dest='http_methods',
        nargs='+',
        choices=['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'],
        help="Specify one or more HTTP methods to use while scanning. Allowed values: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH",
        default=['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'],
        required=False
    )
    parser.add_argument(
        '-rl',
        '--rate-limit',
        dest='rate_limit',
        help='API requests rate limit per second',
        type=float,
        default=60,
        required=False,
    )
    parser.add_argument(
        '-pr',
        '--path-regex',
        dest='path_regex_pattern',
        type=str,
        help='run tests for paths matching given regex pattern',
        required=False,
        default=None,
    )
    parser.add_argument(
        '-o',
        '--output',
        dest='output_file',
        type=str,
        help='path to store test results',
        required=False,
        default=None,
    )
    parser.add_argument(
        '-of',
        '--format',
        dest='output_format',
        type=str,
        choices=['json', 'yaml', 'html', 'table'],
        help='Data format to save (json, yaml, html, table). Default: table',
        required=False,
        default='table',
    )
    parser.add_argument(
        '-H',
        '--headers',
        dest='headers',
        type=str,
        help='HTTP requests headers that should be sent during testing eg: User-Agent: sentinelprobe',
        required=False,
        default=None,
        action='append',
        nargs='*',
    )
    parser.add_argument(
        '-tdc',
        '--test-data-config',
        dest='test_data_config',
        help='YAML file containing user test data for tests',
        required=False,
        type=str,
    )
    parser.add_argument(
        '-p',
        '--proxy',
        dest='proxies_list',
        help='Proxy server URL to route HTTP requests through (e.g. "http://proxyserver:port")',
        action='append',
        required=False,
        type=str,
        default=None,
    )
    parser.add_argument(
        '-s',
        '--ssl-verify',
        dest='ssl_verify',
        required=False,
        action='store_true',
        help='Enable SSL Verification',
    )
    parser.add_argument(
        '-cf',
        '--capture-failed',
        dest='capture_failed',
        action='store_true',
        help='Captures failed requests due to any exceptions into output file',
    )
    parser.add_argument(
        '--server',
        dest='server_url',
        type=str,
        default=None,
        required=False,
        help='server/host base url to overwrite from OAS/Swagger file',
    )
    parser.add_argument(
        '--mode',
        dest='mode',
        choices=['api', 'llm', 'all'],
        default='api',
        help='scan type: api (OpenAPI/Swagger tests), llm (garak LLM probes) or all. Default: api',
    )
    llm = parser.add_argument_group(
        'LLM scanning (NVIDIA garak; requires `pip install garak`)'
    )
    llm.add_argument(
        '--llm-model-type',
        dest='llm_model_type',
        help='garak generator type, eg: openai, huggingface, ollama, rest',
    )
    llm.add_argument(
        '--llm-model-name',
        dest='llm_model_name',
        help='model name for the generator, eg: gpt-4o-mini',
    )
    llm.add_argument(
        '--llm-probes',
        dest='llm_probes',
        help='comma separated garak probes or probe modules, eg: promptinject,dan.Dan_11_0',
    )
    llm.add_argument(
        '--llm-generations',
        dest='llm_generations',
        type=int,
        help='number of generations per prompt (garak --generations)',
    )
    llm.add_argument(
        '--llm-parallel-attempts',
        dest='llm_parallel_attempts',
        type=int,
        help='number of parallel attempts (garak --parallel_attempts)',
    )
    llm.add_argument(
        '--llm-seed', dest='llm_seed', type=int, help='random seed for garak'
    )
    llm.add_argument(
        '--llm-generator-options',
        dest='llm_generator_options',
        help='path to a garak generator options JSON file (needed for the rest generator)',
    )
    llm.add_argument(
        '--llm-timeout',
        dest='llm_timeout',
        type=int,
        default=3600,
        help='max seconds to let garak run. Default: 3600',
    )
    llm.add_argument(
        '--llm-report-dir',
        dest='llm_report_dir',
        default='sentinelprobe_llm_runs',
        help='directory for the raw garak report. Default: sentinelprobe_llm_runs',
    )
    llm.add_argument(
        '--llm-list-probes',
        dest='llm_list_probes',
        action='store_true',
        help='list available garak probes and exit',
    )
    args = parser.parse_args()


    if args.llm_list_probes:
        from .llm.garak_runner import GarakError, list_probes

        try:
            print(list_probes())
        except GarakError as exc:
            parser.exit(1, f'error: {exc}\n')
        return

    if args.mode in ('api', 'all') and not args.fpath:
        parser.error('-f/--file is required when --mode is api or all')
    if args.mode in ('llm', 'all'):
        if not args.llm_model_type:
            parser.error('--llm-model-type is required when --mode is llm or all')
        if not args.llm_probes:
            parser.error(
                '--llm-probes is required when --mode is llm or all '
                '(garak runs every probe by default, which is slow and can be costly)'
            )

    if args.mode in ('api', 'all'):
        # convert req headers str to dict
        headers_dict: dict = headers_list_to_dict(args.headers)

        # handle rate limiting options
        # TODO: allow user to opt out of rate limit
        rate_limit = args.rate_limit

        # handle test user data config file
        test_data_config = args.test_data_config
        if test_data_config:
            test_data_config = read_yaml(args.test_data_config)
            test_data_config = validate_config_file_data(test_data_config)

        # parse args and run tests
        api_parser: SwaggerParser | OpenAPIv3Parser = create_parser(
            args.fpath, server_url=args.server_url,
            ssl_verify=args.ssl_verify
        )

        generate_and_run_tests(
            api_parser=api_parser,
            http_methods=args.http_methods,
            regex_pattern=args.path_regex_pattern,
            output_file=args.output_file,
            output_file_format=args.output_format,
            req_headers=headers_dict,
            rate_limit=rate_limit,
            test_data_config=test_data_config,
            proxies=args.proxies_list,
            capture_failed=args.capture_failed,
            ssl_verify=args.ssl_verify,
        )

    if args.mode in ('llm', 'all'):
        from .llm.garak_runner import GarakError
        from .llm.handler import run_llm_scan

        try:
            run_llm_scan(
                model_type=args.llm_model_type,
                model_name=args.llm_model_name,
                probes=args.llm_probes,
                generations=args.llm_generations,
                parallel_attempts=args.llm_parallel_attempts,
                seed=args.llm_seed,
                generator_options_file=args.llm_generator_options,
                timeout=args.llm_timeout,
                report_dir=args.llm_report_dir,
                output_file=args.output_file,
                output_format=args.output_format,
                mode=args.mode,
            )
        except (GarakError, ValueError) as exc:
            logger.error('LLM scan failed: %s', exc)
            sys.exit(1)


if __name__ == '__main__':
    start()
