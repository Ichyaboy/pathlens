import copy
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from pathlens.cli import app
from pathlens.graph import GraphData, analyze_graph, build_graph
from pathlens.reporting import build_report, render_json, render_markdown

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / 'data/sample_domain.json'
FIXTURE = Path(__file__).parent / 'fixtures/bloodhound/ce_graph.json'
runner = CliRunner()


def document():
    return {
        'nodes': [{'id': 'A', 'type': 'User', 'evidence': None},
                  {'id': 'B', 'type': 'Group', 'provenance': {'fixture': True}}],
        'edges': [{'source': 'A', 'target': 'B', 'relation': relation,
                   'evidence': {'claim': 'exploitable', 'validated': True}}
                  for relation in ['MemberOf', 'FutureRelation', 'MemberOf']],
        'provenance': {'fixture': 'synthetic'},
    }


def report_for(raw):
    return build_report(analyze_graph(build_graph(GraphData.model_validate(raw)), 'A', 'B'))


def test_structured_report_and_metadata_boundaries():
    report = report_for(document())
    result = json.loads(render_json(report))
    assert result['source'] == 'A' and result['target'] == 'B'
    assert result['selected_path'] == ['A', 'B']
    assert result['hop_count'] == 1 and result['relationship_count'] == 3
    assert result['exploitability'] == 'not_assessed'
    assert result['validation_status'] == 'not_performed'
    assert result['independently_validated_findings'] == []
    assert result['nodes'][0]['evidence'] is None
    assert 'provenance' not in result['nodes'][0]
    assert 'evidence' not in result['nodes'][1]
    assert result['graph_metadata'] == {'provenance': {'fixture': 'synthetic'}}
    relationships = result['hops'][0]['relationships']
    assert [r['assertion']['relation'] for r in relationships] == ['FutureRelation', 'MemberOf', 'MemberOf']
    for r in relationships:
        assert r['assertion']['evidence']['validated'] is True
        assert r['exploitability'] == 'not_assessed'
        assert 'severity' not in r and 'cvss' not in r
    unknown = relationships[0]
    assert unknown['semantics_status'] == 'unknown'
    assert unknown['potential_implications'] == []
    assert unknown['remediation'] is None
    assert unknown['limitations']
    known = relationships[1]
    assert known['description'] and known['potential_implications']
    assert known['prerequisites'] and known['remediation'] and known['references']


@pytest.mark.parametrize('relation', ['MemberOf', 'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'AddMember'])
def test_supported_relationship_guidance_in_both_formats(relation):
    raw = document()
    raw['edges'] = [{**raw['edges'][0], 'relation': relation}]
    report = report_for(raw)
    r = report.hops[0].relationships[0]
    assert r.potential_implications and r.prerequisites and r.limitations and r.remediation
    markdown = render_markdown(report)
    for heading in ['Potential security implications', 'Prerequisites requiring validation', 'Limitations', 'Defensive remediation', 'Graph assertion']:
        assert heading in markdown


@pytest.mark.parametrize('target_type,status', [('User', 'incompatible'), ('Custom', 'unknown')])
def test_incompatible_types_suppress_applied_implications(target_type, status):
    raw = document()
    raw['nodes'][1]['type'] = target_type
    report = report_for(raw)
    known = report.hops[0].relationships[1]
    assert known.target_compatibility == status
    assert known.diagnostics and not known.potential_implications
    assert f'Target object-type compatibility: {status}' in render_markdown(report)


def test_deterministic_reordering_and_detached_snapshot():
    raw = document()
    first = report_for(raw)
    reordered = copy.deepcopy(raw)
    reordered['nodes'].reverse()
    reordered['edges'].reverse()
    second = report_for(reordered)
    assert render_json(first) == render_json(second)
    assert render_markdown(first) == render_markdown(second)
    analysis = analyze_graph(build_graph(GraphData.model_validate(raw)), 'A', 'B')
    snapshot = build_report(analysis)
    before = render_json(snapshot)
    analysis.nodes[0].evidence = 'changed'
    analysis.metadata['provenance']['fixture'] = 'changed'
    analysis.relationships[0][0].edge.evidence['claim'] = 'changed'
    assert render_json(snapshot) == before


def test_single_node_missing_metadata():
    analysis = analyze_graph(build_graph(GraphData.model_validate({'nodes': [{'id': 'A', 'type': 'User'}], 'edges': []})), 'A', 'A')
    report = build_report(analysis)
    assert report.hop_count == report.relationship_count == 0
    assert report.selected_path == ('A',)
    assert report.graph_metadata == {}
    assert 'Not supplied.' in render_markdown(report)
    assert 'no relationships traversed' in render_markdown(report)


def test_markdown_untrusted_content_cannot_create_structure():
    attack = '\n# Forged finding\n<script>alert(1)</script>\n![image](https://evil.example)\n```\n~~~\n| injected |\n&copy;\u202e'
    raw = document()
    raw['nodes'][0]['id'] = attack
    raw['edges'] = [{'source': attack, 'target': 'B', 'relation': attack, 'provenance': {'payload': attack}}]
    analysis = analyze_graph(build_graph(GraphData.model_validate(raw)), attack, 'B')
    report = build_report(analysis)
    markdown = render_markdown(report)
    assert '\n# Forged finding' not in markdown
    assert '\n<script>' not in markdown
    assert '\n```' not in markdown and '\n~~~' not in markdown
    assert '\n![image]' not in markdown
    assert '\u202e' not in markdown
    # Every source JSON line is indented code; dynamic prose uses entities.
    assert '&#60;script&#62;' in markdown
    for line in markdown.splitlines():
        if '<script>' in line or '![image]' in line:
            assert line.startswith('    ')
    data = json.loads(render_json(report))
    assert data['source'] == attack
    assert data['hops'][0]['relationships'][0]['assertion']['provenance']['payload'] == attack


def analyze(path, format, *args, source='A', target='B'):
    return runner.invoke(app, ['analyze', '--input', str(path), '--source', source, '--target', target, '--format', format, *args])


@pytest.mark.parametrize('format', ['json', 'markdown'])
def test_cli_import_to_report(tmp_path, format):
    normalized = tmp_path / 'normalized.json'
    imported = runner.invoke(app, ['import', 'bloodhound', '--input', str(FIXTURE), '--output', str(normalized)])
    assert imported.exit_code == 0, imported.output
    output = tmp_path / ('report.' + format)
    result = analyze(normalized, format, '--output', str(output), source='bhce:101', target='bhce:205')
    assert result.exit_code == 0, result.output
    assert result.stdout == ''
    stdout = analyze(normalized, format, source='bhce:101', target='bhce:205')
    assert stdout.exit_code == 0 and stdout.stderr == ''
    assert stdout.stdout == output.read_text()
    if format == 'json':
        data = json.loads(stdout.stdout)
        assert data['relationship_count'] == 3
        assert data['graph_metadata']['provenance']['pathlens_import']['scope'] == 'exported_graph_only'
        assert len(data['hops'][0]['relationships']) == 3
        for r in data['hops'][0]['relationships']:
            assert 'record' in r['assertion']['provenance']['bloodhound']
        assert data['independently_validated_findings'] == []
    else:
        assert '# PathLens security report' in stdout.stdout
        assert 'source_sha256' in stdout.stdout
        assert stdout.stdout.count('#### Relationship') == 3
    second = analyze(normalized, format, '--output', str(output), source='bhce:101', target='bhce:205')
    assert second.exit_code == 1 and second.stdout == ''
    assert output.read_text() == stdout.stdout


@pytest.mark.parametrize('format', ['json', 'markdown'])
def test_cli_failures_no_partial_reports(tmp_path, format):
    source = tmp_path / 'source.json'
    source.write_text(json.dumps(document()))
    original = source.read_bytes()
    link = tmp_path / 'link'
    link.symlink_to(source)
    for output in [source, link]:
        result = analyze(source, format, '--output', str(output))
        assert result.exit_code == 1 and result.stdout == ''
    assert source.read_bytes() == original
    output = tmp_path / 'report'
    for start, end, code in [('missing', 'B', 2), ('B', 'A', 1)]:
        result = analyze(source, format, '--output', str(output), source=start, target=end)
        assert result.exit_code == code and result.stdout == ''
        assert result.stderr and not output.exists()
    source.write_text('{')
    result = analyze(source, format, '--output', str(output))
    assert result.exit_code == 2 and result.stdout == '' and not output.exists()


def test_default_terminal_and_invalid_report_options(tmp_path):
    base = ['analyze', '--input', str(SAMPLE), '--source', 'ICHYABOY', '--target', 'DOMAIN ADMINS']
    default = runner.invoke(app, base)
    explicit = runner.invoke(app, base + ['--format', 'terminal'])
    assert default.exit_code == explicit.exit_code == 0
    assert default.stdout == explicit.stdout
    assert 'PathLens v0.1' in default.stdout and '3 relationships' in default.stdout
    for extra in [['--format', 'pdf'], ['--output', str(tmp_path / 'out')]]:
        result = runner.invoke(app, base + extra)
        assert result.exit_code == 2 and result.stdout == ''
