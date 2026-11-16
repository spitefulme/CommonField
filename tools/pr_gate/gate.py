#!/usr/bin/env python3
"""Trusted whole-candidate gate. Install reviewed bytes, never execute from a PR."""
import argparse
import base64
import datetime
import decimal
import fcntl
import hashlib
import io
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
import zipfile

REPO = 'spitefulme/CommonField'
WORKFLOW = '.github/workflows/pr-quality.yml'
CONTEXT = 'SonarQube / whole-candidate'
VERSION = '1'
METRICS = ('coverage', 'duplicated_lines_density', 'reliability_rating', 'security_rating',
           'sqale_rating', 'violations', 'security_hotspots', 'security_hotspots_reviewed')
MAX_ZIP = 20 * 1024 * 1024

# User-approved issue-level disposition, bound to the ENTIRE reviewed Git file.
# Authority is these installed, hash-pinned worker bytes, never PR metadata/config.
CANVAS_PATH = 'src/web/main.tsx'
CANVAS_SHA256 = 'dfe8fa43b17a4315375a984b38f0e512d960da11881c165d413b594e8fb0d086'
CANVAS_FINDINGS = (('typescript:S6847', 1250), ('typescript:S6845', 1255))
CANVAS_RATIONALE = (
    'User-approved false positive for the reviewed Spatial board canvas only. '
    'WAI-ARIA 1.2 application (https://www.w3.org/TR/wai-aria-1.2/#application) '
    'permits focusable custom spatial keyboard/gesture editors; HTML-ARIA '
    '(https://www.w3.org/TR/html-aria/#el-div) permits application on div. '
    'There is no corresponding native widget. This canvas is named and described, '
    'has tabIndex=0, and arrow-pans only when event.target === event.currentTarget, '
    'preserving native child editing. The widget-superclass heuristic flags this '
    'valid application structure. This is not vendor acknowledgment or a claim of '
    'full assistive-technology conformance. Approval applies only to S6847 at line '
    '1250 and S6845 at line 1255, file '+CANVAS_PATH+' SHA-256 '+CANVAS_SHA256+'.'
)


class Reject(Exception):
    """Only locally authored stable codes belong in this exception."""


def evaluate(metrics):
    failures = []
    limits = {'coverage': (80, 100), 'duplicated_lines_density': (0, 3),
              'reliability_rating': (1, 1), 'security_rating': (1, 1),
              'sqale_rating': (1, 1), 'violations': (0, 0), 'security_hotspots': (0, 1e9)}
    for key, (low, high) in limits.items():
        try:
            value = decimal.Decimal(metrics[key])
            if not value.is_finite() or not low <= value <= high:
                failures.append(key)
        except (KeyError, decimal.InvalidOperation, TypeError):
            failures.append(key)
    if metrics.get('security_hotspots') not in ('0', '0.0'):
        try:
            reviewed = decimal.Decimal(metrics['security_hotspots_reviewed'])
            if not reviewed.is_finite() or reviewed != 100:
                failures.append('security_hotspots_reviewed')
        except (KeyError, decimal.InvalidOperation, TypeError):
            failures.append('security_hotspots_reviewed')
    return failures


# JSON reporter alone does NOT report unhandled runtime errors in Vitest 4.
RUNTIME_REPORTER = '''import fs from 'node:fs';
export default class {
  onTestRunEnd(modules, errors, reason) {
    fs.writeFileSync(process.env.PR_GATE_REPORT_DIR + '/runtime.json', JSON.stringify({
      reason, unhandled: errors.length, modules: modules.length
    }));
  }
}
'''
CI_STEPS = ('Checkout', 'Setup Node', 'Install', 'Trusted worker regression suite',
            'Full unit suite and coverage', 'Validate test and coverage results', 'Types', 'Lint',
            'Bind coverage', 'Upload coverage', 'Enforce coverage threshold')


def validate_ci(root, lcov):
    """Classify only complete passing tests + a known Vitest line-threshold exit.

    Called by the reviewed hosted workflow, never executes in the trusted scanner.
    Unknown stderr on a negative exit is deliberately NOT waived.
    """
    try:
        report = json.loads((root/'tests.json').read_text())
        runtime = json.loads((root/'runtime.json').read_text())
        code = (root/'exit').read_text().strip()
        stderr = (root/'stderr').read_text().strip()
        files = report['testResults']
        assertions = [a for f in files for a in f['assertionResults']]
        if (not files or not assertions or report['success'] is not True
                or runtime != {'reason': 'passed', 'unhandled': 0, 'modules': len(files)}
                or report['snapshot']['failure'] is not False
                or any(report[k] != 0 for k in ('numFailedTestSuites', 'numPendingTestSuites',
                                                'numFailedTests', 'numPendingTests', 'numTodoTests'))
                or report['numTotalTests'] != len(assertions)
                or report['numPassedTests'] != len(assertions)
                or not isinstance(report['numTotalTestSuites'], int)
                or report['numTotalTestSuites'] < len(files)
                or report['numPassedTestSuites'] != report['numTotalTestSuites']
                or len({f['name'] for f in files}) != len(files)
                or any(f['status'] != 'passed' or f['message'] for f in files)
                or any(a['status'] != 'passed' or a['failureMessages'] for a in assertions)):
            raise Reject('ci_tests_incomplete_or_failed')
        # Reuse the same strict LCOV/source validator as the trusted worker.
        text = lcov.read_text()
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as z:
            z.writestr('lcov.info', text)
            z.writestr('binding.json', json.dumps({'sha': '0'*40, 'repository': REPO, 'run_id': '0'}))
        coverage(archive.getvalue(), pathlib.Path.cwd(), '0'*40, 0)
        found = sum(int(v) for v in re.findall(r'^LF:([0-9]+)$', text, re.M))
        hit = sum(int(v) for v in re.findall(r'^LH:([0-9]+)$', text, re.M))
        if not found:
            raise Reject('ci_coverage_empty')
        percent = decimal.Decimal(hit * 100) / found
        if code == '0' and percent >= 80 and not stderr:
            return 'success'
        match = re.fullmatch(r'ERROR: Coverage for lines \(([0-9]+(?:\.[0-9]+)?)%\) does not meet global threshold \(80%\)', stderr)
        if (code == '1' and match and percent < 80
                and decimal.Decimal(match[1]) == percent.quantize(decimal.Decimal('.01'), rounding=decimal.ROUND_DOWN)):
            return 'coverage-only'
        raise Reject('ci_unknown_collector_failure')
    except (OSError, ValueError, KeyError, TypeError, decimal.InvalidOperation):
        raise Reject('ci_report_invalid_or_missing') from None


def phases_eligible(run, jobs):
    """Authenticated exact-attempt jobs, not artifact-authored assertions."""
    try:
        if len(jobs) != 1:
            return False
        job = jobs[0]
        if (job['run_id'] != run['id'] or job['run_attempt'] != run['run_attempt']
                or job['head_sha'] != run['head_sha'] or job['status'] != 'completed'
                or job['name'] != 'Tests, types, lint and coverage'
                or job['conclusion'] != run['conclusion']):
            return False
        steps = job['steps']
        required = [s['name'] for s in steps if s['name'] in CI_STEPS]
        if required != list(CI_STEPS) or len({s['name'] for s in steps}) != len(steps):
            return False
        for step in steps:
            expected = run['conclusion'] if step['name'] == CI_STEPS[-1] else 'success'
            # setup-node's pinned action has post-if: success(); a red job skips its cache save.
            if step['name'] == 'Post Setup Node' and run['conclusion'] == 'failure':
                expected = 'skipped'
            if (step['status'] != 'completed' or step['conclusion'] != expected
                    or step['name'] not in (*CI_STEPS, 'Set up job', 'Post Checkout', 'Post Setup Node', 'Complete job')):
                return False
        return run['conclusion'] in ('success', 'failure')
    except (KeyError, TypeError):
        return False


def eligible(pr, run):
    """Identity prefilter only; Worker ALSO requires authenticated phases()."""
    try:
        sha = pr['head']['sha']
        return bool(re.fullmatch('[0-9a-f]{40}', sha) and pr['state'] == 'open'
                    and pr['base']['repo']['full_name'] == REPO and pr['base']['ref'] == 'main'
                    and run['head_sha'] == sha and run['event'] == 'pull_request'
                    and run['head_repository']['full_name'] == pr['head']['repo']['full_name']
                    and run['path'] == WORKFLOW and run['repository']['full_name'] == REPO
                    and run['status'] == 'completed' and run['conclusion'] in ('success', 'failure')
                    and type(run.get('id')) is int and run['id'] > 0
                    and type(run.get('run_attempt')) is int and run['run_attempt'] > 0
                    and any(p['number'] == pr['number'] and p['head']['sha'] == sha
                            for p in run['pull_requests']))
    except (KeyError, TypeError):
        return False


def coverage(blob, root, sha, run_id):
    if len(blob) > MAX_ZIP:
        raise Reject('artifact_compressed_size')
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            infos = z.infolist()
            if (len(infos) != 2 or {i.filename for i in infos} != {'lcov.info', 'binding.json'}
                    or sum(i.file_size for i in infos) > MAX_ZIP
                    or any(stat.S_ISLNK(i.external_attr >> 16) or i.flag_bits & 1 for i in infos)):
                raise Reject('artifact_members')
            binding = json.loads(z.read('binding.json'))
            if binding != {'sha': sha, 'repository': REPO, 'run_id': str(run_id)}:
                raise Reject('artifact_binding')
            text = z.read('lcov.info').decode('utf-8')
    except (ValueError, UnicodeError, zipfile.BadZipFile, RuntimeError):
        raise Reject('artifact_invalid') from None
    records = set()
    current = None
    lines = set()
    hits = set()
    totals = {}
    for item in text.splitlines():
        if item == 'end_of_record':
            if current is None or not lines or totals.get('LF') != len(lines) or totals.get('LH') != len(hits):
                raise Reject('lcov_totals')
            for found, hit in [('FNF', 'FNH'), ('BRF', 'BRH')]:
                if found in totals or hit in totals:
                    if found not in totals or hit not in totals or totals[hit] > totals[found]:
                        raise Reject('lcov_auxiliary_totals')
            current = None
            continue
        key, sep, value = item.partition(':')
        if not sep:
            raise Reject('lcov_syntax')
        if key == 'TN' and current is None:
            continue
        if key == 'SF':
            p = pathlib.PurePosixPath(value)
            if (current is not None or not value.startswith('src/') or '..' in p.parts
                    or str(p) != value or p.suffix not in ('.ts', '.tsx', '.js', '.jsx')
                    or value in records):
                raise Reject('lcov_path')
            target = root / value
            if any(x.is_symlink() for x in [target, *target.parents]) or not target.is_file():
                raise Reject('lcov_source')
            current = len(target.read_bytes().splitlines())
            records.add(value)
            lines, hits, totals = set(), set(), {}
        elif current is None:
            raise Reject('lcov_record')
        elif key == 'DA':
            if not re.fullmatch(r'[1-9][0-9]*,[0-9]+(?:,[a-fA-F0-9]+)?', value):
                raise Reject('lcov_line')
            line, count = map(int, value.split(',')[:2])
            if line > current or line in lines:
                raise Reject('lcov_line_binding')
            lines.add(line)
            if count:
                hits.add(line)
        elif key in ('LF', 'LH', 'FNF', 'FNH', 'BRF', 'BRH'):
            if not value.isdecimal() or key in totals:
                raise Reject('lcov_count')
            totals[key] = int(value)
        elif key in ('FN', 'FNDA'):
            if not re.fullmatch(r'[0-9]+,.+', value):
                raise Reject('lcov_function')
            if key == 'FN' and not 1 <= int(value.split(',')[0]) <= current:
                raise Reject('lcov_function_binding')
        elif key == 'BRDA':
            if not re.fullmatch(r'[1-9][0-9]*,[0-9]+,[0-9]+,(?:-|[0-9]+)', value):
                raise Reject('lcov_branch')
            if int(value.split(',')[0]) > current:
                raise Reject('lcov_branch_binding')
        else:
            raise Reject('lcov_unknown_field')
    if current is not None or not records:
        raise Reject('lcov_incomplete')
    return text


def publish(read_pr, post, state, sha, status, description, url):
    current = read_pr()
    if current['state'] != 'open' or current['head']['sha'] != sha:
        return False
    payload = {'state': status, 'context': CONTEXT, 'description': description[:140]}
    if url:
        payload['target_url'] = url
    if state.get(sha) == payload:
        return False
    post(payload)
    state[sha] = payload
    return True


def sandbox(image, source, config, output):
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
        raise Reject('scanner_image_not_immutable')
    uid, gid = os.getuid(), os.getgid()
    if uid == 0 or gid == 0:
        raise Reject('scanner_operator_must_be_nonroot')
    return ['docker', 'run', '--rm', '--read-only', '--user='+str(uid)+':'+str(gid), '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--pids-limit=256', '--memory=4g', '--cpus=2',
            '--network=host', '--tmpfs=/tmp:rw,exec,nosuid,size=1g,uid='+str(uid)+',gid='+str(gid),
            '--mount=type=bind,src='+source+',dst=/candidate,readonly',
            '--mount=type=bind,src='+config+',dst=/config,readonly',
            '--mount=type=bind,src='+output+',dst=/output', image,
            '--trusted-config']


def diagnostic(root, phase, exc, mutation, context=None):
    root.mkdir(parents=True, exist_ok=True)
    stack = []
    tb = exc.__traceback__
    while tb:
        stack.append({'module': pathlib.Path(tb.tb_frame.f_code.co_filename).name,
                      'function': tb.tb_frame.f_code.co_name, 'line': tb.tb_lineno})
        tb = tb.tb_next
    data = {'version': VERSION, 'run_id': uuid.uuid4().hex, 'phase': phase,
            'exception': type(exc).__name__, 'reason': str(exc) if type(exc) is Reject else 'unexpected_exception',
            'mutation': mutation, 'stack': stack, 'exit_status': 1,
            'context': {k: v for k, v in (context or {}).items()
                        if k in ('project', 'sha', 'run_id') and isinstance(v, (str, int))
                        and re.fullmatch('[A-Za-z0-9_-]{1,120}', str(v))}}
    path = root / (data['run_id'] + '.json')
    with path.open('x') as f:
        os.chmod(path, 0o600)
        json.dump(data, f)
    print('Diagnostic: '+str(path), file=sys.stderr)
    return path


def command(args, timeout=120, data=None, cwd=None):
    p = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=timeout, cwd=cwd)
    if p.returncode:
        raise Reject('command_failed_' + pathlib.Path(args[0]).name + '_exit_' + str(p.returncode))
    return p.stdout


def run_sandbox(args):
    name = 'commonfield-gate-' + uuid.uuid4().hex
    args = args[:2] + ['--name', name] + args[2:]
    try:
        return command(args, timeout=900)
    finally:
        subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        exists = subprocess.run(['docker', 'inspect', name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        if exists.returncode == 0:
            raise Reject('scanner_cleanup_unverified')


def receipt_key(sha, run, version):
    return sha+':'+str(run['id'])+':'+str(run['run_attempt'])+':'+version


def verify_analysis(analyses, analysis_id, sha):
    if not analyses or analyses[0].get('key') != analysis_id or analyses[0].get('revision') != sha:
        raise Reject('analysis_revision_or_id')
    return analyses[0]


def source_suffixes():
    return ('.ts', '.tsx', '.js', '.jsx', '.css', '.html')


def materialize(repo, sha, output):
    if not re.fullmatch('[0-9a-f]{40}', sha):
        raise Reject('invalid_sha')
    entries = command(['git', '-C', str(repo), 'ls-tree', '-rz', sha, '--', 'src']).split(b'\0')
    chosen = []
    size = 0
    for entry in filter(None, entries):
        meta, path = entry.split(b'\t', 1)
        mode, kind, oid = meta.decode('ascii').split()
        name = path.decode('utf-8')
        pure = pathlib.PurePosixPath(name)
        if mode not in ('100644', '100755') or kind != 'blob':
            raise Reject('source_symlink_or_submodule')
        if not name.startswith('src/') or str(pure) != name or '..' in pure.parts or '\n' in name or '\r' in name:
            raise Reject('source_path')
        if pure.suffix not in source_suffixes():
            continue
        length = int(command(['git', '-C', str(repo), 'cat-file', '-s', oid]))
        size += length
        if length > 2*1024*1024 or size > 50*1024*1024 or len(chosen) >= 10000:
            raise Reject('source_size')
        chosen.append((name, oid))
    if not chosen:
        raise Reject('source_empty')
    output.chmod(0o755)
    for name, oid in chosen:
        dest = output/name
        dest.parent.mkdir(parents=True, exist_ok=True)
        for directory in dest.parent.parents:
            if directory == output:
                break
            directory.chmod(0o755)
        dest.parent.chmod(0o755)
        dest.write_bytes(command(['git', '-C', str(repo), 'cat-file', 'blob', oid]))
        dest.chmod(0o444)


class Worker:
    def __init__(self, cfg, root):
        self.cfg, self.root = cfg, root
        self.phase = 'startup'
        self.statefile = root/'state.json'
        self.state = json.loads(self.statefile.read_text()) if self.statefile.exists() else {}
        self.workflow = pathlib.Path(__file__).with_name('pr-quality.yml').read_bytes()
        if hashlib.sha256(self.workflow).hexdigest() != cfg['workflow_sha256']:
            raise Reject('installed_workflow_hash')
        if hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest() != cfg['worker_sha256']:
            raise Reject('installed_worker_hash')
        if not re.fullmatch(r'http://127\.0\.0\.1:[0-9]+', cfg['sonar_url']):
            raise Reject('sonar_url_must_be_loopback')
        self.token = command(['gopass', 'show', cfg['sonar_token_key']]).decode().strip()
        if not self.token or '\n' in self.token:
            raise Reject('credential_unavailable')

    def save(self):
        temp = self.statefile.with_suffix('.tmp')
        temp.write_text(json.dumps(self.state, sort_keys=True))
        temp.chmod(0o600)
        temp.replace(self.statefile)

    def github(self, endpoint, payload=None, binary=False):
        args = ['gh', 'api', 'repos/'+REPO+'/'+endpoint]
        data = None
        if payload is not None:
            args += ['--method', 'POST', '--input', '-']
            data = json.dumps(payload).encode()
        raw = command(args, data=data)
        if len(raw) > MAX_ZIP:
            raise Reject('github_response_size')
        return raw if binary else json.loads(raw)

    def pages(self, endpoint, key=None):
        result = []
        for page in range(1, 101):
            obj = self.github(endpoint + ('&' if '?' in endpoint else '?') + 'per_page=100&page='+str(page))
            rows = obj[key] if key else obj
            result.extend(rows)
            if len(rows) < 100:
                return result
        raise Reject('github_pagination_limit')

    def sonar(self, endpoint, params, post=False):
        encoded = urllib.parse.urlencode(params)
        req = urllib.request.Request(self.cfg['sonar_url']+'/api/'+endpoint + ('' if post else '?'+encoded),
                                     data=encoded.encode() if post else None,
                                     headers={'Authorization': 'Bearer '+self.token})
        with urllib.request.urlopen(req, timeout=40) as response:
            raw = response.read(2*1024*1024+1)
        if len(raw) > 2*1024*1024:
            raise Reject('sonar_response_size')
        return json.loads(raw) if raw else {}

    def pr(self, number):
        return self.github('pulls/'+str(number))

    def runs(self, sha):
        return self.pages('actions/workflows/pr-quality.yml/runs?event=pull_request&head_sha='+sha, 'workflow_runs')

    def status(self, pr, status, description, url=None):
        sha = pr['head']['sha']
        def post(payload):
            self.github('statuses/'+sha, payload)
            observed = self.github('commits/'+sha+'/statuses?per_page=100')
            if not any(all(row.get(k) == v for k, v in payload.items()) for row in observed):
                raise Reject('status_readback_failed')
        changed = publish(lambda: self.pr(pr['number']), post,
                          self.state.setdefault('statuses', {}), sha, status, description, url)
        if changed:
            self.save()

    def source(self, pr, root):
        repo = root/'git'
        command(['git', 'init', '--bare', '-q', str(repo)])
        # Public transport: no GitHub credential is passed to git or PR content.
        env = {'PATH': os.environ['PATH'], 'HOME': str(root), 'GIT_CONFIG_NOSYSTEM': '1',
               'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_GLOBAL': '/dev/null'}
        p = subprocess.run(['git', '-C', str(repo), '-c', 'core.hooksPath=/dev/null',
                            'fetch', '--depth=1', '--no-tags', 'https://github.com/'+REPO+'.git',
                            'refs/pull/'+str(pr['number'])+'/head'], env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
        if p.returncode:
            raise Reject('candidate_fetch')
        sha = command(['git', '-C', str(repo), 'rev-parse', 'FETCH_HEAD']).decode().strip()
        if sha != pr['head']['sha']:
            raise Reject('candidate_changed_during_fetch')
        # Require the installed reviewed workflow, not merely a matching job name.
        actual = command(['git', '-C', str(repo), 'show', sha+':'+WORKFLOW])
        if actual != self.workflow:
            raise Reject('workflow_requires_operator_review')
        validator = command(['git', '-C', str(repo), 'show', sha+':tools/pr_gate/gate.py'])
        if validator != pathlib.Path(__file__).read_bytes():
            raise Reject('ci_validator_requires_operator_review')
        source = root/'candidate'
        source.mkdir()
        materialize(repo, sha, source)
        return source

    def analysis(self, project, analysis_id, sha):
        verify_analysis(self.sonar('project_analyses/search', {'project': project, 'ps': 2})['analyses'],
                        analysis_id, sha)

    def metrics(self, project, analysis_id, sha):
        """Only authoritative overall measures, bracketed by exact analysis/revision."""
        self.analysis(project, analysis_id, sha)
        measures = self.sonar('measures/component', {'component': project, 'metricKeys': ','.join(METRICS)})
        if measures['component']['key'] != project:
            raise Reject('measure_project_binding')
        metrics = {m['metric']: m['value'] for m in measures['component']['measures'] if 'value' in m}
        self.analysis(project, analysis_id, sha)
        return metrics

    def issue(self, expected):
        rows = self.sonar('issues/search', {'issues': expected['key'], 'additionalFields': 'comments', 'ps': 2})
        issues = rows['issues']
        if rows['paging']['total'] != 1 or len(issues) != 1:
            raise Reject('classification_issue_readback')
        issue = issues[0]
        if any(issue.get(k) != expected.get(k) for k in ('key', 'rule', 'component', 'line')):
            raise Reject('classification_issue_identity')
        return issue

    def classify_canvas(self, project, analysis_id, sha, source_hash):
        """Fresh owned analysis only. Never called on cached receipt evidence."""
        if source_hash != CANVAS_SHA256:
            return []
        self.analysis(project, analysis_id, sha)
        issues, total = [], None
        # Collect BEFORE mutating: false-positive transitions change unresolved pagination.
        for page in range(1, 21):
            response = self.sonar('issues/search', {'componentKeys': project, 'resolved': 'false',
                                                   'ps': 500, 'p': page})
            count = response['paging']['total']
            if type(count) is not int or not 0 <= count <= 10000 or (total is not None and count != total):
                raise Reject('classification_issue_total')
            total = count
            issues.extend(response['issues'])
            if len(issues) >= total:
                break
            if not response['issues']:
                raise Reject('classification_issue_incomplete')
        if len(issues) != total or len({i['key'] for i in issues}) != total:
            raise Reject('classification_issue_incomplete')
        selected = [i for i in issues if i.get('component') == project+':'+CANVAS_PATH
                    and (i.get('rule'), i.get('line')) in CANVAS_FINDINGS]
        if len({(i['rule'], i['line']) for i in selected}) != len(selected):
            raise Reject('classification_issue_ambiguous')
        audit = []
        for expected in selected:
            self.analysis(project, analysis_id, sha)
            issue = self.issue(expected)
            if issue.get('resolution') == 'FALSE-POSITIVE' and issue.get('status') == 'RESOLVED':
                continue
            if issue.get('resolution') or issue.get('status') not in ('OPEN', 'CONFIRMED', 'REOPENED'):
                raise Reject('classification_issue_state')
            before = {'status': issue['status'], 'resolution': issue.get('resolution', '')}
            # Verify comments independently; no repeated comment on a partial retry.
            if not any(c.get('markdown') == CANVAS_RATIONALE for c in issue.get('comments', [])):
                self.sonar('issues/add_comment', {'issue': issue['key'], 'text': CANVAS_RATIONALE}, True)
                issue = self.issue(expected)
                if not any(c.get('markdown') == CANVAS_RATIONALE for c in issue.get('comments', [])):
                    raise Reject('classification_comment_readback')
            self.analysis(project, analysis_id, sha)
            self.sonar('issues/do_transition', {'issue': issue['key'], 'transition': 'falsepositive'}, True)
            observed = self.issue(expected)
            if observed.get('resolution') != 'FALSE-POSITIVE' or observed.get('status') != 'RESOLVED':
                raise Reject('classification_transition_readback')
            audit.append({k: observed[k] for k in ('key', 'rule', 'component', 'line', 'status', 'resolution')})
            audit[-1].update(before=before, source_sha256=source_hash, sha=sha, analysis_id=analysis_id,
                             rationale=CANVAS_RATIONALE)
        self.analysis(project, analysis_id, sha)
        return audit

    def scan(self, pr, run, source, lcov, root):
        sha = pr['head']['sha']
        canvas = source/CANVAS_PATH
        source_hash = hashlib.sha256(canvas.read_bytes()).hexdigest() if canvas.is_file() else None
        key = 'commonfield-pr-'+str(pr['number'])+'-'+sha+'-'+uuid.uuid4().hex[:10]
        self.context = {'project': key, 'sha': sha, 'run_id': run['id']}
        self.phase = 'project_create'
        self.sonar('projects/create', {'project': key, 'name': 'Commonfield PR '+str(pr['number'])}, True)
        project = self.sonar('components/show', {'component': key})
        if project['component']['key'] != key:
            raise Reject('project_readback')
        token_name = key+'-scan'
        token = None
        try:
            self.phase = 'project_token'
            obj = self.sonar('user_tokens/generate', {'name': token_name, 'type': 'PROJECT_ANALYSIS_TOKEN',
                              'projectKey': key, 'expirationDate': (datetime.date.today()+datetime.timedelta(days=1)).isoformat()}, True)
            token = obj['token']
            if obj.get('type') != 'PROJECT_ANALYSIS_TOKEN':
                raise Reject('analysis_token_scope')
            config, output = root/'config', root/'output'
            config.mkdir(mode=0o755)
            config.chmod(0o755)
            output.mkdir(mode=0o777)
            output.chmod(0o777)
            (source/'lcov.info').write_text(lcov)
            (source/'lcov.info').chmod(0o444)
            # The candidate contributes no properties, plugins, tsconfig, scripts or executables.
            props = {'sonar.host.url': self.cfg['sonar_url'], 'sonar.token': token,
                     'sonar.projectKey': key, 'sonar.projectName': 'Commonfield',
                     'sonar.projectVersion': sha, 'sonar.scm.revision': sha,
                     'sonar.scm.disabled': 'true', 'sonar.projectBaseDir': '/candidate',
                     'sonar.sources': 'src', 'sonar.exclusions': '',
                     'sonar.javascript.lcov.reportPaths': '/candidate/lcov.info',
                     'sonar.working.directory': '/output/work', 'sonar.scanner.metadataFilePath': '/output/report-task.txt',
                     'sonar.userHome': '/tmp/sonar', 'sonar.javascript.node.maxspace': '2048'}
            (config/'options.json').write_text(json.dumps(props))
            (config/'options.json').chmod(0o444)
            # Parent temp directory is private; scanner UID only traverses explicitly mounted directories.
            self.phase = 'static_scan'
            run_sandbox(sandbox(self.cfg['scanner_image'], str(source), str(config), str(output)))
            report = dict(line.split('=', 1) for line in (output/'report-task.txt').read_text().splitlines() if '=' in line)
            task_id = report.get('ceTaskId', '')
            if not re.fullmatch('[A-Za-z0-9_-]+', task_id) or report.get('projectKey') != key:
                raise Reject('scanner_task_binding')
            self.phase = 'compute_task'
            deadline = time.monotonic()+300
            while True:
                task = self.sonar('ce/task', {'id': task_id})['task']
                if task.get('componentKey') != key or task.get('id') != task_id:
                    raise Reject('compute_task_binding')
                if task['status'] == 'SUCCESS':
                    break
                if task['status'] in ('FAILED', 'CANCELED') or time.monotonic() >= deadline:
                    raise Reject('compute_task_failed_or_timeout')
                time.sleep(3)
            aid = task['analysisId']
            self.analysis(key, aid, sha)
            if (hashlib.sha256(canvas.read_bytes()).hexdigest() if canvas.is_file() else None) != source_hash:
                raise Reject('classification_source_changed')
            self.phase = 'issue_classification'
            classifications = self.classify_canvas(key, aid, sha, source_hash)
            self.phase = 'overall_metrics'
            metrics = self.metrics(key, aid, sha)
            return {'project': key, 'analysis_id': aid, 'task_id': task_id, 'sha': sha,
                    'run_id': run['id'], 'run_attempt': run['run_attempt'], 'metrics': metrics,
                    'source_binding': {'path': CANVAS_PATH, 'sha256': source_hash},
                    'classifications': classifications, 'failures': evaluate(metrics)}
        finally:
            if token:
                self.sonar('user_tokens/revoke', {'name': token_name}, True)
                remaining = self.sonar('user_tokens/search', {})
                if any(t['name'] == token_name for t in remaining.get('userTokens', [])):
                    raise Reject('analysis_token_revoke_readback')

    def artifact(self, run, sha):
        artifacts = self.pages('actions/runs/'+str(run['id'])+'/artifacts', 'artifacts')
        artifacts = [a for a in artifacts if a['name'] == 'coverage-'+sha+'-'+str(run['run_attempt']) and not a['expired']]
        if len(artifacts) != 1 or artifacts[0]['size_in_bytes'] > MAX_ZIP:
            raise Reject('coverage_artifact_missing_or_ambiguous')
        artifact = artifacts[0]
        binding = artifact.get('workflow_run', {})
        if binding.get('id') != run['id'] or binding.get('head_sha') != sha:
            raise Reject('artifact_run_binding')
        if not re.fullmatch('sha256:[a-f0-9]{64}', artifact.get('digest', '')):
            raise Reject('artifact_digest_missing')
        return artifact

    def latest_run(self, sha):
        runs = sorted(self.runs(sha), key=lambda r: (r['id'], r.get('run_attempt', 1)), reverse=True)
        return runs[0] if runs else None

    def phases(self, run):
        jobs = self.pages('actions/runs/'+str(run['id'])+'/attempts/'+str(run['run_attempt'])+'/jobs', 'jobs')
        return phases_eligible(run, jobs)

    def defer_ci(self, pr, run):
        pending = not run or run.get('status') != 'completed'
        if not pending:
            pending = eligible(pr, run) and self.phases(run)
        self.status(pr, 'pending' if pending else 'failure',
                    'Waiting for current exact-head CI analysis' if pending else 'Exact-head CI phases failed validation')

    def terminal_policy(self, pr, run, receipt):
        # An analysis ID is immutable; issue dispositions and overall metrics are not.
        # Refresh BOTH fresh and cached decisions; cached evidence NEVER authorizes writes.
        self.phase = 'terminal_metrics'
        metrics = self.metrics(receipt['project'], receipt['analysis_id'], pr['head']['sha'])
        failures = evaluate(metrics)
        if run['conclusion'] == 'failure':  # authenticated phases proved coverage-only
            failures.append('vitest_lines')
        if receipt.get('metrics') != metrics or receipt.get('failures') != failures:
            if 'previous_measurement' not in receipt and 'metrics' in receipt:
                receipt['previous_measurement'] = {'metrics': receipt['metrics'], 'failures': receipt['failures']}
            receipt.update(metrics=metrics, failures=failures)
            self.save()
        # Recheck after the scan/analysis readback, for BOTH cached and fresh paths.
        # Re-read after the jobs request too: a new attempt can start during that request.
        latest = self.latest_run(pr['head']['sha'])
        if (latest != run or not eligible(pr, latest) or not self.phases(latest)):
            self.defer_ci(pr, latest)
            return
        current = self.latest_run(pr['head']['sha'])
        if current != latest:
            self.defer_ci(pr, current)
            return
        self.status(pr, 'failure' if receipt['failures'] else 'success',
                    'Whole-candidate policy failed' if receipt['failures'] else 'Whole-candidate policy passed')

    def run_pr(self, pr):
        sha = pr['head']['sha']
        self.context = {'sha': sha}
        self.phase = 'ci_lookup'
        run = self.latest_run(sha)
        if not run:
            self.status(pr, 'pending', 'Waiting for exact-head hosted tests and coverage')
            return
        if not eligible(pr, run) or not self.phases(run):
            self.defer_ci(pr, run)
            return
        proof_key = receipt_key(sha, run, self.cfg['worker_sha256'])
        self.phase = 'artifact_lookup'
        artifact = self.artifact(run, sha)
        receipt = self.state.get('receipts', {}).get(proof_key)
        if receipt:
            if receipt['artifact_id'] != artifact['id'] or receipt['artifact_digest'] != artifact['digest']:
                raise Reject('cached_artifact_changed')
            verify_analysis(self.sonar('project_analyses/search', {'project': receipt['project'], 'ps': 2})['analyses'],
                            receipt['analysis_id'], sha)
            self.terminal_policy(pr, run, receipt)
            return
        self.status(pr, 'pending', 'Validating coverage and scanning whole candidate')
        with tempfile.TemporaryDirectory(prefix='commonfield-gate-', dir=self.root) as d:
            root = pathlib.Path(d)
            source = self.source(pr, root)
            self.phase = 'artifact_download'
            blob = self.github('actions/artifacts/'+str(artifact['id'])+'/zip', binary=True)
            if artifact.get('digest') != 'sha256:'+hashlib.sha256(blob).hexdigest():
                raise Reject('artifact_digest')
            lcov = coverage(blob, source, sha, run['id'])
            self.phase = 'scan'
            receipt = self.scan(pr, run, source, lcov, root)
            if run['conclusion'] == 'failure':
                receipt['failures'].append('vitest_lines')
            receipt['artifact_id'] = artifact['id']
            receipt['artifact_digest'] = artifact['digest']
            self.state.setdefault('receipts', {})[proof_key] = receipt
            self.save()
        self.terminal_policy(pr, run, receipt)

    def poll(self):
        failures = 0
        for pr in self.pages('pulls?state=open&base=main'):
            try:
                self.run_pr(pr)
            except Exception as exc:
                diagnostic(self.root/'diagnostics', self.phase, exc, 'uncertain', getattr(self, 'context', {}))
                self.status(pr, 'error', 'Gate infrastructure/validation error; operator diagnostics available')
                failures += 1
        return failures


def main():
    if len(sys.argv) == 2 and sys.argv[1] == 'ci-reporter':
        print(RUNTIME_REPORTER)
        return 0
    if len(sys.argv) == 4 and sys.argv[1] == 'validate-ci':
        try:
            print(validate_ci(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])))
            return 0
        except Exception as exc:
            diagnostic(pathlib.Path(sys.argv[2])/'diagnostics', 'ci_validation', exc, 'not_started')
            return 1
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--state-dir', required=True)
    args = parser.parse_args()
    root = pathlib.Path(args.state_dir).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    with (root/'worker.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        try:
            cfg = json.loads(pathlib.Path(args.config).read_text())
            worker = Worker(cfg, root)
            return 1 if worker.poll() else 0
        except Exception as exc:
            diagnostic(root/'diagnostics', 'worker', exc, 'uncertain')
            return 1


if __name__ == '__main__':
    sys.exit(main())
