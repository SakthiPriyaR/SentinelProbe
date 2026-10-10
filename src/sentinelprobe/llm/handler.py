"""
High level entry point for LLM scans: run garak -> parse -> build/save report.
"""
import logging

from .garak_parser import parse_report
from .garak_runner import GarakConfig, run_garak
from .report import derive_output_path, format_report, resolve_format, save_or_print

logger = logging.getLogger('SentinelProbe')


def run_llm_scan(
    model_type: str,
    probes: str,
    model_name: str | None = None,
    generations: int | None = None,
    parallel_attempts: int | None = None,
    seed: int | None = None,
    generator_options_file: str | None = None,
    timeout: int = 3600,
    report_dir: str = 'sentinelprobe_llm_runs',
    output_file: str | None = None,
    output_format: str | None = None,
    mode: str = 'llm',
) -> dict:
    """Runs a garak scan against an LLM and reports the findings.

    Only scan models you own or are explicitly authorized to test. garak sends
    many adversarial prompts, which can incur API costs and trigger provider
    abuse monitoring.

    Returns:
        dict with ``target``, ``summary``, ``results`` and ``garak_report``.
    """
    cfg = GarakConfig(
        model_type=model_type,
        model_name=model_name,
        probes=probes,
        generations=generations,
        parallel_attempts=parallel_attempts,
        seed=seed,
        generator_options_file=generator_options_file,
        timeout=timeout,
        report_dir=report_dir,
    )
    report_path, _stdout = run_garak(cfg)
    parsed = parse_report(report_path)

    result = {
        'mode': 'llm',
        'target': {'model_type': cfg.model_type, 'model_name': cfg.model_name},
        'probes': cfg.probes,
        'summary': parsed['summary'],
        'results': parsed['results'],
        'garak_report': str(report_path),
    }

    out_path = derive_output_path(output_file, mode)
    fmt = resolve_format(out_path, output_format)
    save_or_print(format_report(result, fmt), out_path)
    if out_path:
        logger.info('Wrote LLM scan report to %s', out_path)
    logger.info(
        'LLM scan done: %d/%d probes vulnerable. Raw garak report: %s',
        result['summary']['vulnerable_probes'],
        result['summary']['probes_run'],
        report_path,
    )
    return result
