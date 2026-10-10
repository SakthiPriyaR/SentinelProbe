"""
Report output (json / yaml / html / table) for LLM scan results.

All text coming from the model or from garak (prompts, model outputs, probe
names) is untrusted, so every value placed into HTML is escaped.
"""
import json
import os
from html import escape

SUPPORTED_FORMATS = ('json', 'yaml', 'html', 'table')


def resolve_format(output_file: str | None, requested: str | None) -> str:
    """Picks the output format.

    The file extension wins when it is json/yaml/html (same behaviour as the
    API scan report); a table cannot be written to a file, so it becomes json.
    """
    if output_file:
        ext = output_file.rsplit('.', 1)[-1].lower() if '.' in output_file else ''
        if ext in ('json', 'yaml', 'html'):
            return ext
        return requested if requested in ('json', 'yaml', 'html') else 'json'
    return requested if requested in SUPPORTED_FORMATS else 'table'


def derive_output_path(output_file: str | None, mode: str) -> str | None:
    """In ``all`` mode the API report owns ``output_file``; LLM goes beside it."""
    if not output_file or mode != 'all':
        return output_file
    root, ext = os.path.splitext(output_file)
    return f'{root}.llm{ext}'


def to_json(result: dict) -> str:
    return json.dumps(result, indent=2, default=str)


def to_yaml(result: dict) -> str:
    from yaml import safe_dump

    return safe_dump(json.loads(to_json(result)), sort_keys=False)


def to_table(result: dict):
    """Returns a rich Table of the findings."""
    from rich.table import Table

    table = Table(title='SentinelProbe LLM scan (garak)', show_lines=False)
    for col in ('Probe', 'Detector', 'Passed / Total', 'Fail rate', 'Result'):
        table.add_column(col)
    for r in result['results']:
        verdict = '[red]VULNERABLE[/red]' if r['vulnerable'] else '[green]ok[/green]'
        table.add_row(
            # rich markup in names would be interpreted, so escape brackets
            r['probe'].replace('[', '\\['),
            r['detector'].replace('[', '\\['),
            f"{r['passed']} / {r['total']}",
            f"{r['fail_rate'] * 100:.1f}%",
            verdict,
        )
    return table


def to_html(result: dict) -> str:
    esc = lambda v: escape(str(v), quote=True)  # noqa: E731
    target = result.get('target', {})
    summary = result.get('summary', {})

    rows = []
    for r in result['results']:
        cls = 'bad' if r['vulnerable'] else 'good'
        label = 'VULNERABLE' if r['vulnerable'] else 'ok'
        ex_html = ''
        if r['examples']:
            items = ''.join(
                '<li><b>prompt:</b> <code>{}</code><br><b>output:</b> <code>{}</code>'
                ' <i>(score {})</i></li>'.format(
                    esc(e['prompt']), esc(e['output']), esc(e['score'])
                )
                for e in r['examples']
            )
            ex_html = f'<details><summary>examples</summary><ul>{items}</ul></details>'
        rate = '{:.1f}'.format(r['fail_rate'] * 100)
        rows.append(
            '<tr><td>{}</td><td>{}</td><td>{} / {}</td><td>{}%</td>'
            '<td class="{}">{}</td><td>{}</td></tr>'.format(
                esc(r['probe']),
                esc(r['detector']),
                esc(r['passed']),
                esc(r['total']),
                esc(rate),
                cls,
                label,
                ex_html,
            )
        )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>SentinelProbe - LLM scan</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem;color:#1b1f23}}
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #d0d7de;padding:.4rem .6rem;text-align:left;vertical-align:top}}
th{{background:#f6f8fa}} .bad{{color:#b00020;font-weight:700}} .good{{color:#1a7f37}}
code{{background:#f6f8fa;padding:0 .2rem;word-break:break-word}}
</style></head><body>
<h1>SentinelProbe - LLM scan (garak)</h1>
<p>Target: <b>{esc(target.get('model_type', ''))}</b> / <b>{esc(target.get('model_name') or '-')}</b>
&middot; Probes run: {esc(summary.get('probes_run', 0))}
&middot; Vulnerable probes: {esc(summary.get('vulnerable_probes', 0))}
&middot; Failed attempts: {esc(summary.get('failed_attempts', 0))} / {esc(summary.get('total_attempts', 0))}</p>
<table><thead><tr><th>Probe</th><th>Detector</th><th>Passed / Total</th>
<th>Fail rate</th><th>Result</th><th>Examples</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
</body></html>
"""


def format_report(result: dict, fmt: str):
    """Returns the report as str (json/yaml/html) or a rich Table (table)."""
    if fmt == 'json':
        return to_json(result)
    if fmt == 'yaml':
        return to_yaml(result)
    if fmt == 'html':
        return to_html(result)
    return to_table(result)


def save_or_print(content, output_file: str | None) -> None:
    """Writes str content to output_file, otherwise prints to the console."""
    if output_file and isinstance(content, str):
        directory = os.path.dirname(output_file)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(content)
        return

    from ..logger import console

    console.print(content)
