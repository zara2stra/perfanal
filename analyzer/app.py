"""
Flask application for the FlamePerf Linux Analyzer.

Routes:
  /                     - Dashboard (list uploads, filter by cluster)
  /upload               - Upload a perf bundle
  /analysis/<id>        - View analysis results + flamegraph
  /api/flamegraph/<id>  - JSON for d3-flame-graph (?pid=, ?process=, ?mode=, ?active_only=)
  /api/processes/<id>   - Thread/service list for filter dropdown
  /api/pids/<id>        - PID list with comm names and sample counts
  /api/analysis/<id>    - Diagnosis JSON
  /api/iostat/<id>      - iostat time-series JSON
  /delete/<id>          - Delete an upload
"""

import hashlib
import os
import json
import logging
import tarfile
import tempfile
import traceback

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, jsonify, abort, send_file,
)

ADMIN_TOKEN_HASH = os.environ.get(
    'ADMIN_TOKEN_HASH',
    '2c0cffec058a0192b269db7e41b34e693b23df047212c7dac64bff412315d9c9',
)

from models import init_db, insert_upload, get_all_uploads, get_cluster_ids, \
    get_uploads_by_cluster, get_upload, delete_upload
from parser import parse_and_process, folded_to_flamegraph_json, parse_top_snapshot, parse_ps_aux, _is_idle_sample, IDLE_FRAME_MARKERS, parse_iostat, parse_iotop
from diagnostics import run_diagnostics, _classify_thread

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'perf-analyzer-secret-change-me')

DATA_DIR = os.environ.get('DATA_DIR', '/app/data')
UPLOAD_DIR = os.path.join(DATA_DIR, 'uploads')
MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500 MB

app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH


@app.before_request
def ensure_dirs():
    os.makedirs(UPLOAD_DIR, exist_ok=True)


@app.route('/')
def dashboard():
    cluster_filter = request.args.get('cluster_id', '').strip()
    cluster_ids = get_cluster_ids()

    if cluster_filter:
        uploads = get_uploads_by_cluster(cluster_filter)
    else:
        uploads = get_all_uploads()

    return render_template('dashboard.html',
                           uploads=uploads,
                           cluster_ids=cluster_ids,
                           selected_cluster=cluster_filter)


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'GET':
        return render_template('upload.html')

    file = request.files.get('bundle')
    if not file or file.filename == '':
        flash('No file selected.', 'error')
        return redirect(url_for('upload'))

    manual_cluster_id = request.form.get('cluster_id', '').strip()

    try:
        result = _process_bundle(file, manual_cluster_id)
        flash(f'Upload processed: {result["total_samples"]} samples from {result["hostname"]}.', 'success')
        return redirect(url_for('analysis', upload_id=result['upload_id']))
    except Exception as e:
        traceback.print_exc()
        flash(f'Error processing bundle: {e}', 'error')
        return redirect(url_for('upload'))


@app.route('/analysis/<int:upload_id>')
def analysis(upload_id):
    record = get_upload(upload_id)
    if record is None:
        abort(404)
    return render_template('analysis.html', record=record)


@app.route('/api/flamegraph/<int:upload_id>')
def api_flamegraph(upload_id):
    record = get_upload(upload_id)
    if record is None:
        abort(404)

    process_filter = request.args.get('process', '').strip()
    pid_filter = request.args.get('pid', '').strip()
    mode = request.args.get('mode', 'thread')
    active_only = request.args.get('active_only', '').strip()

    # When filtering by PID, use the per-PID folded stacks
    if pid_filter:
        pid_folded = record.get('pid_folded_json') or {}
        working = dict(pid_folded.get(pid_filter, {}))
        if active_only == '1':
            working = {
                stack: count for stack, count in working.items()
                if not any(marker in stack for marker in IDLE_FRAME_MARKERS)
            }
        if working:
            return jsonify(folded_to_flamegraph_json(working))
        return jsonify({'name': 'root', 'value': 0, 'children': []})

    folded = record.get('folded_json')
    if not folded:
        return jsonify(record.get('flamegraph_json', {}))

    working = dict(folded)

    if active_only == '1':
        working = {
            stack: count for stack, count in working.items()
            if not any(marker in stack for marker in IDLE_FRAME_MARKERS)
        }

    if process_filter:
        if mode == 'service':
            working = {
                stack: count
                for stack, count in working.items()
                if _classify_thread(stack.split(';')[0]) == process_filter
            }
        else:
            working = {
                stack: count
                for stack, count in working.items()
                if stack.split(';')[0] == process_filter
            }

    if not process_filter and not active_only and not working:
        return jsonify(record.get('flamegraph_json', {}))

    if working:
        return jsonify(folded_to_flamegraph_json(working))
    return jsonify({'name': 'root', 'value': 0, 'children': []})


@app.route('/api/processes/<int:upload_id>')
def api_processes(upload_id):
    """Return process/service list for the filter dropdown.

    ?mode=thread  -> individual thread names (default)
    ?mode=service -> aggregated by Nutanix service
    """
    record = get_upload(upload_id)
    if record is None:
        abort(404)
    folded = record.get('folded_json', {})
    if not folded:
        return jsonify([])

    mode = request.args.get('mode', 'thread')

    if mode == 'service':
        from diagnostics import NUTANIX_SERVICES
        services = {}
        for stack, count in folded.items():
            comm = stack.split(';')[0]
            svc = _classify_thread(comm) or comm
            services[svc] = services.get(svc, 0) + count
        result = sorted(services.items(), key=lambda x: x[1], reverse=True)
        return jsonify([{
            'name': s,
            'samples': c,
            'description': NUTANIX_SERVICES.get(s, ''),
        } for s, c in result])
    else:
        processes = {}
        for stack, count in folded.items():
            proc = stack.split(';')[0]
            processes[proc] = processes.get(proc, 0) + count
        result = sorted(processes.items(), key=lambda x: x[1], reverse=True)
        return jsonify([{'name': p, 'samples': c} for p, c in result])


@app.route('/api/pids/<int:upload_id>')
def api_pids(upload_id):
    """Return merged list of all processes (from ps) and sampled PIDs (from perf).

    Every process from ps_aux.txt is included.  Processes that were
    captured by perf get their sample count filled in; the rest show 0.
    """
    record = get_upload(upload_id)
    if record is None:
        abort(404)
    analysis = record.get('analysis_json') or {}
    pid_map = analysis.get('pid_map', [])
    ps_map = analysis.get('ps_map', {})
    total = record.get('total_samples') or 1

    # Build a lookup of perf sample counts keyed by PID
    perf_by_pid = {}
    for entry in pid_map:
        perf_by_pid[entry['pid']] = entry

    # Start from ps_map (all processes), enrich with perf data
    seen_pids = set()
    result = []

    for pid_str, ps_info in ps_map.items():
        pid = int(pid_str)
        seen_pids.add(pid)
        perf_info = perf_by_pid.get(pid, {})
        comm = perf_info.get('comm', '')
        samples = perf_info.get('samples', 0)

        # Derive comm from the ps command basename if perf didn't capture it
        if not comm and ps_info.get('cmd'):
            cmd_parts = ps_info['cmd'].split()
            if cmd_parts:
                comm = cmd_parts[0].rsplit('/', 1)[-1]

        result.append({
            'pid': pid,
            'ppid': ps_info.get('ppid'),
            'comm': comm,
            'service': _classify_thread(comm) or '' if comm else '',
            'cmd': ps_info.get('cmd', ''),
            'user': ps_info.get('user', ''),
            'samples': samples,
            'pct': round(100.0 * samples / total, 2),
            'sampled': samples > 0,
        })

    # Also include any perf PIDs not found in ps (kernel threads, etc.)
    for entry in pid_map:
        if entry['pid'] not in seen_pids:
            result.append({
                'pid': entry['pid'],
                'ppid': None,
                'comm': entry['comm'],
                'service': _classify_thread(entry['comm']) or '',
                'cmd': '',
                'user': '',
                'samples': entry['samples'],
                'pct': round(100.0 * entry['samples'] / total, 2),
                'sampled': True,
            })

    result.sort(key=lambda x: x['samples'], reverse=True)
    return jsonify(result)


@app.route('/api/analysis/<int:upload_id>')
def api_analysis(upload_id):
    record = get_upload(upload_id)
    if record is None:
        abort(404)
    return jsonify(record.get('analysis_json', {}))


@app.route('/api/iostat/<int:upload_id>')
def api_iostat(upload_id):
    record = get_upload(upload_id)
    if record is None:
        abort(404)
    analysis = record.get('analysis_json') or {}
    iostat = analysis.get('iostat')
    if not iostat:
        return jsonify(None)
    return jsonify(iostat)


@app.route('/api/iotop-procs/<int:upload_id>')
def api_iotop_procs(upload_id):
    record = get_upload(upload_id)
    if record is None:
        abort(404)
    analysis = record.get('analysis_json') or {}
    iotop = analysis.get('iotop_summary')
    if not iotop:
        return jsonify(None)
    return jsonify(iotop)


COLLECTOR_SEARCH_PATHS = [
    os.path.join(os.path.dirname(__file__), 'perf-collect.sh'),
    os.path.join(os.path.dirname(__file__), '..', 'cvm-collector', 'perf-collect.sh'),
    '/perfanal/cvm-collector/perf-collect.sh',
]


@app.route('/download/collector')
def download_collector():
    for candidate in COLLECTOR_SEARCH_PATHS:
        path = os.path.abspath(candidate)
        if os.path.isfile(path):
            return send_file(path, as_attachment=True, download_name='perf-collect.sh')
    abort(404)


@app.route('/api/admin-auth', methods=['POST'])
def api_admin_auth():
    import hmac
    data = request.get_json(silent=True) or {}
    pw = data.get('password', '')
    pw_hash = hashlib.sha256(pw.encode('utf-8')).hexdigest()
    if hmac.compare_digest(pw_hash, ADMIN_TOKEN_HASH):
        return jsonify({'token': pw_hash})
    return jsonify({'token': None}), 401


@app.route('/delete/<int:upload_id>', methods=['POST'])
def delete(upload_id):
    import hmac
    token = request.headers.get('X-Admin-Token', '')
    if not hmac.compare_digest(token, ADMIN_TOKEN_HASH):
        abort(403)

    record = get_upload(upload_id)
    if record is None:
        abort(404)

    bundle_path = os.path.join(UPLOAD_DIR, record['filename'])
    if os.path.exists(bundle_path):
        os.remove(bundle_path)

    delete_upload(upload_id)
    return jsonify({'ok': True})


def _process_bundle(file, manual_cluster_id):
    """
    Process an uploaded tar.gz bundle or raw perf_threads.txt file.

    Supports two modes:
      1. tar.gz bundle from perf-collect.sh (contains metadata.json + perf_threads.txt)
      2. Raw perf script text file (user provides cluster_id manually)
    """
    filename = file.filename
    save_path = os.path.join(UPLOAD_DIR, filename)
    file.save(save_path)

    file_size = os.path.getsize(save_path)
    log.info('Upload saved: %s (%d bytes)', save_path, file_size)

    metadata = {}
    perf_text = None
    top_text = None
    ps_aux_text = None
    iostat_text = None
    iotop_text = None
    iotop_pid_text = None

    is_tar = False
    try:
        is_tar = tarfile.is_tarfile(save_path)
    except Exception:
        pass

    if not is_tar and (filename.endswith('.tar.gz') or filename.endswith('.tgz')):
        is_tar = True

    log.info('Detected as tar: %s (filename: %s)', is_tar, filename)

    if is_tar:
        try:
            perf_text, metadata, top_text, ps_aux_text, iostat_text, iotop_text, iotop_pid_text = _extract_tar_bundle(save_path)
            log.info('Extracted: perf_text=%d chars, metadata keys=%s',
                     len(perf_text) if perf_text else 0,
                     list(metadata.keys()) if metadata else [])
        except Exception as e:
            log.error('Tar extraction failed: %s', e, exc_info=True)
            raise ValueError(f'Failed to extract tar bundle: {e}')
    else:
        with open(save_path, 'r', errors='replace') as f:
            perf_text = f.read()
        log.info('Read as raw text: %d chars', len(perf_text) if perf_text else 0)

    if perf_text is None:
        if is_tar:
            try:
                with tarfile.open(save_path, 'r:*') as tar:
                    members = [m.name for m in tar.getmembers()]
            except Exception:
                members = ['(could not list)']
            raise ValueError(
                f'Could not find perf_threads.txt in the bundle. '
                f'Archive contains: {", ".join(members)}'
            )
        else:
            raise ValueError('Uploaded file could not be read')

    if not perf_text.strip():
        raise ValueError(
            'perf_threads.txt is empty (0 bytes of perf data). '
            'The perf recording may have captured no samples for the specified PID. '
            'Try running without --pid to capture system-wide, or ensure the target '
            'process is active during the capture window.'
        )

    if manual_cluster_id:
        metadata['cluster_id'] = manual_cluster_id

    if not metadata.get('cluster_id'):
        metadata['cluster_id'] = 'unknown'

    system_context = {}
    if top_text:
        system_context = parse_top_snapshot(top_text)
        log.info('Parsed top snapshot: %s', list(system_context.keys()))
    metadata['system_context'] = system_context

    ps_map = {}
    if ps_aux_text:
        ps_map = parse_ps_aux(ps_aux_text)
        log.info('Parsed ps aux: %d processes', len(ps_map))

    iostat_data = None
    if iostat_text:
        iostat_data = parse_iostat(iostat_text)
        if iostat_data:
            log.info('Parsed iostat: %d devices, %d columns',
                     len(iostat_data['devices']), len(iostat_data['columns']))

    iotop_data = None
    iotop_tid = None
    iotop_pid = None
    if iotop_text:
        iotop_tid = parse_iotop(iotop_text)
        if iotop_tid:
            log.info('Parsed iotop (TID): %d ticks', len(iotop_tid['ticks']))
    if iotop_pid_text:
        iotop_pid = parse_iotop(iotop_pid_text)
        if iotop_pid:
            log.info('Parsed iotop (PID): %d ticks', len(iotop_pid['ticks']))
    if iotop_tid or iotop_pid:
        iotop_data = {}
        if iotop_tid:
            iotop_data['tid'] = iotop_tid
        if iotop_pid:
            iotop_data['pid'] = iotop_pid

    parsed = parse_and_process(perf_text)
    diag = run_diagnostics(parsed, metadata)

    # Convert int PID keys to strings for JSON serialization
    pid_folded_str = {str(k): v for k, v in parsed['pid_folded'].items()}

    analysis = {
        'findings': diag['findings'],
        'service_breakdown': diag['service_breakdown'],
        'active_service_breakdown': diag['active_service_breakdown'],
        'summary': diag['summary'],
        'process_breakdown': parsed['process_breakdown'],
        'active_process_breakdown': parsed['active_process_breakdown'],
        'top_functions': parsed['top_functions'],
        'kernel_user_split': parsed['kernel_user_split'],
        'idle_samples': parsed['idle_samples'],
        'active_samples': parsed['active_samples'],
        'idle_pct': parsed['idle_pct'],
        'active_pct': parsed['active_pct'],
        'system_context': system_context,
        'pid_map': parsed['pid_map'],
        'ps_map': {str(k): v for k, v in ps_map.items()},
    }
    if iostat_data:
        analysis['iostat'] = iostat_data
    if iotop_data:
        analysis['iotop_summary'] = iotop_data

    upload_id = insert_upload(
        cluster_id=metadata.get('cluster_id', 'unknown'),
        hostname=metadata.get('hostname', 'unknown'),
        collection_timestamp=metadata.get('collection_timestamp', ''),
        filename=filename,
        kernel_version=metadata.get('kernel_version', ''),
        cpu_info=metadata.get('cpu_model', ''),
        cpu_count=metadata.get('cpu_count', 0),
        mem_total=metadata.get('mem_total', ''),
        duration_seconds=metadata.get('duration_seconds', 0),
        frequency_hz=metadata.get('frequency_hz', 0),
        total_samples=parsed['total_samples'],
        flamegraph_json=parsed['flamegraph_json'],
        analysis_json=analysis,
        metadata_json=metadata,
        folded_json=parsed['folded'],
        pid_folded_json=pid_folded_str,
    )

    return {
        'upload_id': upload_id,
        'total_samples': parsed['total_samples'],
        'hostname': metadata.get('hostname', 'unknown'),
    }


def _extract_tar_bundle(tar_path):
    """Extract perf data and supporting diagnostics from a tar.gz bundle."""
    perf_text = None
    metadata = {}
    top_text = None
    ps_aux_text = None
    iostat_text = None
    iotop_text = None
    iotop_pid_text = None

    extract_dir = tempfile.mkdtemp(prefix='perf-extract-')
    try:
        with tarfile.open(tar_path, 'r:*') as tar:
            members = tar.getmembers()
            log.info('Tar members (%d): %s', len(members),
                     [(m.name, m.size) for m in members])
            tar.extractall(path=extract_dir)

        for root, dirs, files in os.walk(extract_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                if fname == 'perf_threads.txt':
                    with open(fpath, 'r', errors='replace') as f:
                        perf_text = f.read()
                    log.info('Found perf_threads.txt: %d chars', len(perf_text))
                elif fname == 'metadata.json':
                    with open(fpath, 'r') as f:
                        metadata = json.loads(f.read())
                    log.info('Found metadata.json')
                elif fname == 'top_snapshot.txt':
                    with open(fpath, 'r', errors='replace') as f:
                        top_text = f.read()
                    log.info('Found top_snapshot.txt: %d chars', len(top_text))
                elif fname == 'ps_aux.txt':
                    with open(fpath, 'r', errors='replace') as f:
                        ps_aux_text = f.read()
                    log.info('Found ps_aux.txt: %d chars', len(ps_aux_text))
                elif fname == 'iostat_data.txt':
                    with open(fpath, 'r', errors='replace') as f:
                        iostat_text = f.read()
                    log.info('Found iostat_data.txt: %d chars', len(iostat_text))
                elif fname == 'iotop_data.txt':
                    with open(fpath, 'r', errors='replace') as f:
                        iotop_text = f.read()
                    log.info('Found iotop_data.txt: %d chars', len(iotop_text))
                elif fname == 'iotop_pid_data.txt':
                    with open(fpath, 'r', errors='replace') as f:
                        iotop_pid_text = f.read()
                    log.info('Found iotop_pid_data.txt: %d chars', len(iotop_pid_text))
    finally:
        import shutil
        shutil.rmtree(extract_dir, ignore_errors=True)

    return perf_text, metadata, top_text, ps_aux_text, iostat_text, iotop_text, iotop_pid_text


with app.app_context():
    init_db()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
