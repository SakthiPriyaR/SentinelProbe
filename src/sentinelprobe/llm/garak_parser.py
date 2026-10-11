"""
Parses a garak ``*.report.jsonl`` file into SentinelProbe findings.

garak convention: detector scores are in [0, 1] where 0 means the model
passed and 1 means the probe succeeded against the model (a vulnerability).
A score above HIT_THRESHOLD (garak's default eval threshold) counts as a hit.

The parser is deliberately defensive about field shapes because the report
format changes slightly between garak versions.
"""
import json
from collections import defaultdict
from pathlib import Path

HIT_THRESHOLD = 0.5
DEFAULT_MAX_EXAMPLES = 3
DEFAULT_EXAMPLE_CHARS = 300


def _to_text(value, limit: int = DEFAULT_EXAMPLE_CHARS) -> str:
    """Flattens str / dict / list message shapes into a truncated string."""

    def flatten(v) -> str:
        if v is None:
            return ''
        if isinstance(v, str):
            return v
        if isinstance(v, dict):
            for key in ('text', 'content'):
                if key in v:
                    return flatten(v[key])
            if 'turns' in v:
                return ' | '.join(flatten(t) for t in v['turns'])
            return json.dumps(v, default=str)
        if isinstance(v, (list, tuple)):
            return ' | '.join(flatten(i) for i in v)
        return str(v)

    text = flatten(value).strip()
    return text if len(text) <= limit else text[:limit] + '…'


def _norm_probe(name: str | None) -> str:
    name = name or 'unknown'
    return name[len('probes.') :] if name.startswith('probes.') else name


def _norm_detector(name: str | None) -> str:
    name = name or 'unknown'
    return name[len('detector.') :] if name.startswith('detector.') else name


def parse_report(
    report_path: str | Path,
    max_examples: int = DEFAULT_MAX_EXAMPLES,
    example_chars: int = DEFAULT_EXAMPLE_CHARS,
) -> dict:
    """Parses a garak report.

    Returns:
        {"results": [finding, ...], "summary": {...}}
        finding keys: probe, detector, passed, total, failed, fail_rate,
        vulnerable, goal, examples[{prompt, output, score}]
    """
    evals: dict[tuple[str, str], dict] = {}
    attempt_agg: dict[tuple[str, str], dict] = defaultdict(
        lambda: {'passed': 0, 'total': 0, 'detector': ''}
    )
    examples: dict[tuple[str, str], list[dict]] = defaultdict(list)
    goals: dict[str, str] = {}
    seen_attempts: set[str] = set()
    parsed_lines = 0

    with open(report_path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(entry, dict):
                continue
            parsed_lines += 1
            entry_type = entry.get('entry_type')

            if entry_type == 'eval':
                probe = _norm_probe(entry.get('probe'))
                det_raw = entry.get('detector')
                key = (probe, _norm_detector(det_raw))
                passed = int(entry.get('passed') or 0)
                # garak versions name the total differently (total / total_evaluated)
                total = int(
                    entry.get('total')
                    or entry.get('total_evaluated')
                    or (passed + int(entry.get('fails') or 0))
                )
                cur = evals.setdefault(
                    key, {'passed': 0, 'total': 0, 'detector': det_raw or key[1]}
                )
                cur['passed'] += passed
                cur['total'] += total

            elif entry_type == 'attempt':
                detector_results = entry.get('detector_results')
                if not detector_results:
                    continue  # attempt written before detection ran
                uuid = entry.get('uuid')
                if uuid:
                    if uuid in seen_attempts:
                        continue
                    seen_attempts.add(uuid)

                probe = _norm_probe(entry.get('probe_classname'))
                if entry.get('goal'):
                    goals.setdefault(probe, str(entry['goal']))
                outputs = entry.get('outputs') or []
                prompt = _to_text(entry.get('prompt'), example_chars)

                for det_raw, scores in detector_results.items():
                    key = (probe, _norm_detector(det_raw))
                    agg = attempt_agg[key]
                    agg['detector'] = det_raw
                    for idx, score in enumerate(scores or []):
                        try:
                            score = float(score)
                        except (TypeError, ValueError):
                            continue
                        agg['total'] += 1
                        if score > HIT_THRESHOLD:
                            if len(examples[key]) < max_examples:
                                out = outputs[idx] if idx < len(outputs) else ''
                                examples[key].append(
                                    {
                                        'prompt': prompt,
                                        'output': _to_text(out, example_chars),
                                        'score': round(score, 3),
                                    }
                                )
                        else:
                            agg['passed'] += 1

    if parsed_lines == 0:
        raise ValueError(f'no valid JSON entries found in garak report: {report_path}')

    # prefer garak's own eval totals; fall back to aggregating attempts
    # (an eval block that reports no totals at all is not trusted)
    evals_usable = any(v['total'] for v in evals.values())
    source = evals if evals_usable else attempt_agg
    results = []
    for (probe, det_key), counts in source.items():
        total = counts['total']
        passed = min(counts['passed'], total)
        failed = total - passed
        results.append(
            {
                'probe': probe,
                'detector': counts['detector'] or det_key,
                'passed': passed,
                'total': total,
                'failed': failed,
                'fail_rate': round(failed / total, 3) if total else 0.0,
                'vulnerable': failed > 0,
                'goal': goals.get(probe),
                'examples': examples.get((probe, det_key), []),
            }
        )

    results.sort(key=lambda r: (not r['vulnerable'], -r['fail_rate'], r['probe']))

    total_attempts = sum(r['total'] for r in results)
    failed_attempts = sum(r['failed'] for r in results)
    probes = {r['probe'] for r in results}
    vulnerable_probes = {r['probe'] for r in results if r['vulnerable']}
    summary = {
        'probes_run': len(probes),
        'vulnerable_probes': len(vulnerable_probes),
        'total_attempts': total_attempts,
        'failed_attempts': failed_attempts,
        'overall_fail_rate': (
            round(failed_attempts / total_attempts, 3) if total_attempts else 0.0
        ),
    }
    return {'results': results, 'summary': summary}
