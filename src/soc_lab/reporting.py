from __future__ import annotations

import html
import json


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def render_html(result: dict) -> str:
    findings = result["findings"]
    finding_cards = "".join(
        f"""
        <article class="finding" data-severity="{_escape(item['severity'])}">
          <div class="finding-head">
            <span class="badge {_escape(item['severity'])}">{_escape(item['severity'])}</span>
            <code>{_escape(item['rule_id'])}</code>
          </div>
          <h3>{_escape(item['title'])}</h3>
          <p>{_escape(item['description'])}</p>
          <details>
            <summary>Evidence and response</summary>
            <h4>Evidence</h4>
            <ul>{''.join(f'<li>{_escape(value)}</li>' for value in item['evidence'])}</ul>
            <h4>MITRE ATT&amp;CK</h4>
            <ul>{''.join(f'<li>{_escape(value)}</li>' for value in item['mitre_attack'])}</ul>
            <h4>Recommended actions</h4>
            <ul>{''.join(f'<li>{_escape(value)}</li>' for value in item['recommended_actions'])}</ul>
          </details>
        </article>
        """
        for item in findings
    )
    timeline_rows = "".join(
        f"<tr><td>{_escape(item['timestamp'])}</td><td>{_escape(item['event_id'])}</td>"
        f"<td>{_escape(item['host'])}</td><td>{_escape(item['username'])}</td>"
        f"<td>{_escape(item['summary'])}</td></tr>"
        for item in result["event_timeline"]
    )
    mitre_tags = "".join(f"<span class='technique'>{_escape(item)}</span>" for item in result["mitre_attack"])
    safe_json = json.dumps(result).replace("<", "\\u003c")
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>SOC Investigation | {_escape(result['case_id'])}</title>
  <style>
    :root {{ color-scheme: dark; --bg:#07111f; --panel:#0d1b2d; --line:#20344d; --text:#e7eef7; --muted:#92a5bd; --cyan:#38d9ff; --red:#ff5c7c; --orange:#ffab5c; --green:#58e6a9; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; font-family:Inter,Segoe UI,Arial,sans-serif; background:radial-gradient(circle at 80% 0,#13294a 0,transparent 36%),var(--bg); color:var(--text); }}
    .shell {{ max-width:1180px; margin:auto; padding:42px 24px 70px; }}
    .eyebrow {{ color:var(--cyan); letter-spacing:.16em; text-transform:uppercase; font-size:.76rem; font-weight:800; }}
    h1 {{ font-size:clamp(2rem,5vw,4.3rem); line-height:1; margin:.45rem 0 1rem; max-width:850px; }}
    .lead {{ color:var(--muted); font-size:1.08rem; max-width:760px; line-height:1.6; }}
    .metrics {{ display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin:32px 0; }}
    .metric,.panel,.finding {{ border:1px solid var(--line); background:linear-gradient(145deg,rgba(18,37,61,.96),rgba(8,21,37,.96)); border-radius:16px; box-shadow:0 18px 40px rgba(0,0,0,.2); }}
    .metric {{ padding:20px; }} .metric span {{ color:var(--muted); font-size:.8rem; text-transform:uppercase; letter-spacing:.09em; }} .metric strong {{ display:block; font-size:1.75rem; margin-top:7px; }}
    .score strong {{ color:var(--red); }}
    .panel {{ padding:24px; margin-top:18px; overflow:auto; }}
    .panel h2 {{ margin-top:0; }}
    .controls {{ display:flex; gap:8px; flex-wrap:wrap; margin:16px 0; }}
    button {{ background:#122741; border:1px solid var(--line); color:var(--text); border-radius:999px; padding:9px 14px; cursor:pointer; }} button.active {{ background:var(--cyan); color:#03111d; border-color:var(--cyan); font-weight:800; }}
    .findings {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:16px; }}
    .finding {{ padding:21px; }} .finding h3 {{ margin:.8rem 0 .5rem; }} .finding p,li {{ color:var(--muted); line-height:1.55; }}
    .finding-head {{ display:flex; justify-content:space-between; gap:12px; align-items:center; }}
    .badge {{ text-transform:uppercase; font-size:.72rem; font-weight:900; letter-spacing:.1em; padding:5px 9px; border-radius:999px; }} .critical {{ background:rgba(255,92,124,.15); color:var(--red); }} .high {{ background:rgba(255,171,92,.14); color:var(--orange); }}
    code {{ color:var(--cyan); }} summary {{ color:var(--cyan); cursor:pointer; font-weight:700; }}
    table {{ width:100%; border-collapse:collapse; min-width:850px; }} th,td {{ text-align:left; padding:12px; border-bottom:1px solid var(--line); }} th {{ color:var(--cyan); font-size:.75rem; text-transform:uppercase; letter-spacing:.08em; }} td {{ color:var(--muted); font-size:.9rem; }}
    .techniques {{ display:flex; flex-wrap:wrap; gap:9px; }} .technique {{ border:1px solid var(--line); color:var(--muted); padding:8px 11px; border-radius:8px; }}
    .chain {{ display:flex; align-items:center; gap:8px; overflow:auto; padding:10px 0; }} .chain span {{ white-space:nowrap; padding:10px 12px; border:1px solid var(--line); border-radius:9px; color:var(--muted); }} .chain b {{ color:var(--cyan); }}
    footer {{ color:var(--muted); margin-top:30px; font-size:.82rem; }}
    @media(max-width:760px) {{ .metrics,.findings {{ grid-template-columns:1fr; }} .shell {{ padding:28px 15px 50px; }} }}
  </style>
</head>
<body>
  <main class="shell">
    <div class="eyebrow">Security Operations Portfolio</div>
    <h1>Windows Account Compromise Investigation</h1>
    <p class="lead">A complete analyst view of correlated authentication, execution, network, and sensitive-data telemetry. All evidence in this demonstration is synthetic and safe.</p>
    <section class="metrics">
      <div class="metric score"><span>Risk score</span><strong>{_escape(result['risk_score'])}/100</strong></div>
      <div class="metric"><span>Classification</span><strong>{_escape(result['classification']).replace('_',' ')}</strong></div>
      <div class="metric"><span>Events</span><strong>{_escape(result['event_count'])}</strong></div>
      <div class="metric"><span>Findings</span><strong>{_escape(result['finding_count'])}</strong></div>
    </section>
    <section class="panel">
      <h2>Attack chain</h2>
      <div class="chain"><span>Failed logons</span><b>›</b><span>Valid account</span><b>›</b><span>PowerShell</span><b>›</b><span>External connection</span><b>›</b><span>File access</span><b>›</b><span>Archive staging</span></div>
    </section>
    <section class="panel">
      <h2>Correlated findings</h2>
      <div class="controls"><button class="active" data-filter="all">All</button><button data-filter="critical">Critical</button><button data-filter="high">High</button></div>
      <div class="findings">{finding_cards}</div>
    </section>
    <section class="panel">
      <h2>Event timeline</h2>
      <table><thead><tr><th>UTC timestamp</th><th>Event</th><th>Host</th><th>User</th><th>Analyst summary</th></tr></thead><tbody>{timeline_rows}</tbody></table>
    </section>
    <section class="panel"><h2>MITRE ATT&amp;CK coverage</h2><div class="techniques">{mitre_tags}</div></section>
    <footer>Case {_escape(result['case_id'])} | Synthetic portfolio evidence | Generated by the local SOC analyzer</footer>
  </main>
  <script id="case-data" type="application/json">{safe_json}</script>
  <script>
    const report = JSON.parse(document.getElementById('case-data').textContent);
    document.querySelectorAll('button[data-filter]').forEach(button => button.addEventListener('click', () => {{
      document.querySelectorAll('button[data-filter]').forEach(item => item.classList.remove('active'));
      button.classList.add('active');
      document.querySelectorAll('.finding').forEach(card => {{
        card.hidden = button.dataset.filter !== 'all' && card.dataset.severity !== button.dataset.filter;
      }});
    }}));
    window.socCase = report;
  </script>
</body>
</html>"""
