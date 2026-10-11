"""
Report Generator utils
"""
from copy import deepcopy
from html import escape
from json import dumps as json_dumps, loads as json_loads
from os.path import dirname, join as path_join, splitext
from os import makedirs
from rich.table import Table
from yaml import safe_dump as yaml_safe_dump

from .templates.table import TestResultTable
from ..logger import logger, console
from ..report import templates


class ReportGenerator:
    """can generate report in json,yaml,table and html formats"""

    @staticmethod
    def generate_html_report(results: list[dict]):
        """generates html report from SentinelProbe results"""
        html_report_template_file_name = 'report.html'
        html_report_file_path = path_join(
            dirname(templates.__file__), html_report_template_file_name
        )

        with open(html_report_file_path, 'r', encoding='utf-8') as f:
            report_file_content = f.read()

        if not isinstance(results, list):
            raise ValueError('results arg expects a list[dict].')

        # HTML escape data
        escaped_results = []
        escape_keys = [
            'response_body',
            'url',
            'endpoint',
            'test_name',
            'malicious_payload',
            'curl_command',
        ]
        for result_dict in results:
            escaped_result_dict = {}
            for key, value in result_dict.items():
                if key in escape_keys:
                    escaped_value = escape(str(value) if value is not None else '')
                    escaped_result_dict[key] = escaped_value
                else:
                    escaped_result_dict[key] = value

            escaped_results.append(escaped_result_dict)

        # Escape </ to prevent </script> tag breakout when embedding JSON in HTML
        safe_json = json_dumps(escaped_results).replace('</', r'<\/')
        report_file_content = report_file_content.replace(
            '{ results }', safe_json
        )

        return report_file_content

    @staticmethod
    def handle_report_format(
        results: list[dict], report_format: str | None
    ) -> str | Table:
        """returns report in specified format"""
        result = None

        match report_format:
            case 'html':
                logger.warning('HTML output format displays only basic data.')
                result = ReportGenerator.generate_html_report(results=results)
            case 'yaml':
                logger.warning(
                    'YAML output format needs to be sanitized before using it further.'
                )
                # round-trip through json so safe_dump only sees plain types
                result = yaml_safe_dump(
                    json_loads(json_dumps({'results': results}, default=str)),
                    sort_keys=False,
                )
            case 'json':
                report_format = 'json'
                result = json_dumps({'results': results}, default=str)
            case _:  # default: CLI table
                # TODO: filter failed requests first and then create new table for failed requests
                report_format = 'table'
                results_table = TestResultTable().generate_result_table(
                    deepcopy(results)
                )
                result = results_table

        logger.info('Generated %s format report.', report_format.upper())
        return result

    @staticmethod
    def save_report(report_path: str | None, report_file_content: str | Table | None):
        """saves/prints report to console"""
        if report_path != '/' and report_path:
            dir_name = dirname(report_path)
            if dir_name != '' and report_path:
                makedirs(dir_name, exist_ok=True)

        # print to cli if report path and file content as absent else write to file location.
        if (
            report_path
            and report_file_content
            and not isinstance(report_file_content, Table)
        ):
            with open(report_path, 'w', encoding='utf-8') as f:
                logger.info('Writing report to file: %s', report_path)
                f.write(report_file_content)
        else:
            if isinstance(report_file_content, Table) and report_file_content.columns:
                TestResultTable().print_table(report_file_content)
            elif (
                isinstance(report_file_content, Table)
                and not report_file_content.columns
            ):
                logger.warning('No Columns found in Table.')
            else:
                console.print(report_file_content)

    @staticmethod
    def generate_report(
        results: list[dict],
        report_format: str | None,
        report_path: str | None,
        capture_failed: bool = False,
    ):
        """main function used to generate report"""
        if report_path:
            ext = splitext(report_path)[1].lstrip('.').lower()
            if ext in ('json', 'yaml', 'html'):
                report_format = ext
            elif report_format not in ('json', 'yaml', 'html'):
                # unknown extension and no usable format: do not lose the data
                report_format = 'json'

        # do not store errored results if `capture_failed` is False
        if not capture_failed:
            results = list(
                filter(lambda result: result.get('error', True) is False, results)
            )

        formatted_results = ReportGenerator.handle_report_format(
            results=results, report_format=report_format
        )
        ReportGenerator.save_report(
            report_path=report_path, report_file_content=formatted_results
        )
