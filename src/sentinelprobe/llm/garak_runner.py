"""
Runs NVIDIA garak (https://github.com/NVIDIA/garak) as a subprocess.

Design notes:
- garak is optional and is never imported; it is executed with the current
  Python interpreter (``python -m garak``).
- The command is built as an argument list (no shell), and every user supplied
  value is validated first, so values cannot be used for option/shell injection.
- API keys are read by garak itself from the environment
  (e.g. ``OPENAI_API_KEY``); SentinelProbe never handles or logs them.
"""
import importlib.util
import logging
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


# same logger name as sentinelprobe.logger, which configures the handlers
logger = logging.getLogger('SentinelProbe')

DEFAULT_TIMEOUT_SECONDS = 3600
DEFAULT_REPORT_DIR = 'sentinelprobe_llm_runs'

# first char must not be '-' so a value can never be parsed as a CLI option
_MODEL_TYPE_RE = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.\-]*\Z')
_MODEL_NAME_RE = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.\-/:@]*\Z')
_PROBE_RE = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.]*\Z')
_REPORT_PATH_RE = re.compile(r'(\S+\.report\.jsonl)')


class GarakError(Exception):
    """Base class for garak related errors."""


class GarakNotInstalledError(GarakError):
    """garak is not installed in the current Python environment."""


class GarakRunError(GarakError):
    """garak exited with an error or timed out."""


class GarakReportNotFoundError(GarakError):
    """garak finished but its report file could not be located."""


@dataclass
class GarakConfig:
    """Options for one garak run."""

    model_type: str
    probes: str
    model_name: str | None = None
    generations: int | None = None
    parallel_attempts: int | None = None
    seed: int | None = None
    generator_options_file: str | None = None
    timeout: int = DEFAULT_TIMEOUT_SECONDS
    report_dir: str = DEFAULT_REPORT_DIR


def is_garak_installed() -> bool:
    """True if the garak package can be found (it is not imported)."""
    return importlib.util.find_spec('garak') is not None


def normalize_probes(probes: str | list[str]) -> str:
    """Validates probe names and returns them as a comma separated string.

    Accepts module names (``dan``) and full probe names (``dan.Dan_11_0``).
    """
    if isinstance(probes, str):
        items = [p.strip() for p in probes.split(',')]
    else:
        items = [str(p).strip() for p in probes]
    items = [p for p in items if p]
    if not items:
        raise ValueError('at least one garak probe is required')
    for item in items:
        if not _PROBE_RE.match(item):
            raise ValueError(f'invalid probe name: {item!r}')
    return ','.join(items)


def validate_config(cfg: GarakConfig) -> GarakConfig:
    """Validates every user supplied value; returns cfg with normalized probes."""
    if not cfg.model_type or not _MODEL_TYPE_RE.match(cfg.model_type):
        raise ValueError(f'invalid model type: {cfg.model_type!r}')
    if cfg.model_name is not None and not _MODEL_NAME_RE.match(cfg.model_name):
        raise ValueError(f'invalid model name: {cfg.model_name!r}')
    cfg.probes = normalize_probes(cfg.probes)
    for label, value in (
        ('generations', cfg.generations),
        ('parallel_attempts', cfg.parallel_attempts),
    ):
        if value is not None and value < 1:
            raise ValueError(f'{label} must be >= 1')
    if cfg.timeout < 1:
        raise ValueError('timeout must be >= 1 second')
    if cfg.generator_options_file and not os.path.isfile(cfg.generator_options_file):
        raise ValueError(
            f'generator options file not found: {cfg.generator_options_file}'
        )
    return cfg


def build_command(cfg: GarakConfig, report_prefix: str) -> list[str]:
    """Builds the garak argument list (no shell involved)."""
    cmd = [
        sys.executable,
        '-m',
        'garak',
        '--model_type',
        cfg.model_type,
        '--probes',
        cfg.probes,
        '--report_prefix',
        report_prefix,
    ]
    if cfg.model_name:
        cmd += ['--model_name', cfg.model_name]
    if cfg.generations:
        cmd += ['--generations', str(cfg.generations)]
    if cfg.parallel_attempts:
        cmd += ['--parallel_attempts', str(cfg.parallel_attempts)]
    if cfg.seed is not None:
        cmd += ['--seed', str(cfg.seed)]
    if cfg.generator_options_file:
        cmd += ['--generator_option_file', cfg.generator_options_file]
    return cmd


def _default_report_dirs() -> list[Path]:
    dirs = []
    xdg = os.environ.get('XDG_DATA_HOME')
    if xdg:
        dirs.append(Path(xdg) / 'garak' / 'garak_runs')
    dirs.append(Path.home() / '.local' / 'share' / 'garak' / 'garak_runs')
    dirs.append(Path.cwd() / 'garak_runs')
    return dirs


def find_report_file(
    stdout: str, report_prefix: str, extra_dirs: list[Path] | None = None
) -> Path:
    """Locates the ``*.report.jsonl`` file written by a garak run.

    garak versions differ in where ``--report_prefix`` ends up, so this checks
    (1) the path garak prints on stdout, (2) next to the prefix we passed, and
    (3) garak's default run directories; the newest match wins.
    """
    for match in reversed(_REPORT_PATH_RE.findall(stdout or '')):
        candidate = Path(match.strip('\'",.;'))
        if candidate.is_file():
            return candidate

    prefix_path = Path(report_prefix)
    search_dirs = [prefix_path.parent] + (extra_dirs or []) + _default_report_dirs()
    matches: list[Path] = []
    for directory in search_dirs:
        if directory.is_dir():
            matches += list(directory.glob(f'{prefix_path.name}*.report.jsonl'))
    if matches:
        return max(matches, key=lambda p: p.stat().st_mtime)

    raise GarakReportNotFoundError(
        'garak finished but no report file was found. '
        f'Looked for "{prefix_path.name}*.report.jsonl" in: '
        + ', '.join(str(d) for d in search_dirs)
    )


def run_garak(
    cfg: GarakConfig, env_overrides: dict[str, str] | None = None
) -> tuple[Path, str]:
    """Runs garak and returns ``(report_path, captured_stdout)``.

    stdout and stderr are both captured (the tail is included in the error if
    garak fails). ``env_overrides`` is added to the child process environment
    only, so secrets are never placed on the command line.
    """
    if not is_garak_installed():
        raise GarakNotInstalledError(
            'garak is not installed. Install it with: pip install garak'
        )

    cfg = validate_config(cfg)
    report_dir = Path(cfg.report_dir).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    report_prefix = str(report_dir / f'sentinelprobe_{time.strftime("%Y%m%d_%H%M%S")}')

    cmd = build_command(cfg, report_prefix)
    logger.info(
        'Running garak: model_type=%s model_name=%s probes=%s',
        cfg.model_type,
        cfg.model_name,
        cfg.probes,
    )
    env = {**os.environ, **(env_overrides or {})}
    try:
        proc = subprocess.run(  # noqa: S603 - list args, validated, no shell
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors='replace',
            timeout=cfg.timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise GarakRunError(f'garak timed out after {cfg.timeout} seconds') from exc

    if proc.returncode != 0:
        tail = '\n'.join((proc.stdout or '').strip().splitlines()[-20:])
        err_tail = '\n'.join((proc.stderr or '').strip().splitlines()[-20:])
        output = '\n'.join(filter(None, [tail, err_tail]))
        raise GarakRunError(f'garak exited with code {proc.returncode}.\n{output}')

    return find_report_file(proc.stdout, report_prefix), proc.stdout


def list_probes(timeout: int = 120) -> str:
    """Returns the output of ``python -m garak --list_probes``."""
    if not is_garak_installed():
        raise GarakNotInstalledError(
            'garak is not installed. Install it with: pip install garak'
        )
    try:
        proc = subprocess.run(  # noqa: S603
            [sys.executable, '-m', 'garak', '--list_probes'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors='replace',
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise GarakRunError('listing garak probes timed out') from exc
    if proc.returncode != 0:
        raise GarakRunError(f'garak exited with code {proc.returncode}.\n{proc.stderr}')
    return proc.stdout
