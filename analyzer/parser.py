"""
Pure Python parser for `perf script` text output.

Converts perf script output -> folded stacks -> d3-flame-graph hierarchical JSON.
No Perl or external FlameGraph tools required.
"""

import re
from collections import defaultdict


# Matches the header line of each sample block from `perf script` output.
# Example: "  stargate 12345 [003] 12345.678: cpu-clock:  ffffffff810..."
#      or: "  swapper     0 [000]  1234.567890:     cycles: ..."
_HEADER_RE = re.compile(
    r'^\s*(?P<comm>.+?)\s+(?P<pid>\d+)(?:/(?P<tid>\d+))?\s+'
    r'\[(?P<cpu>\d+)\]\s+'
    r'(?:(?P<time>\d+\.\d+):\s+)?'
    r'(?P<period>\d+\s+)?'
    r'(?P<event>[\w:-]+)'
)

_FRAME_RE = re.compile(
    r'^\s+(?P<addr>[0-9a-fA-F]+)\s+(?P<sym>.+?)\s+\((?P<dso>.+)\)\s*$'
)


def parse_perf_script(text):
    """
    Parse raw `perf script` text into a list of samples.

    Each sample is a dict:
      {
        'comm': str,       # process name
        'pid': int,
        'tid': int or None,
        'event': str,
        'frames': [str],   # stack frames, caller first (bottom-up)
      }
    """
    samples = []
    current_sample = None
    current_frames = []

    for line in text.splitlines():
        if not line.strip():
            if current_sample is not None:
                current_sample['frames'] = list(reversed(current_frames))
                samples.append(current_sample)
                current_sample = None
                current_frames = []
            continue

        frame_match = _FRAME_RE.match(line)
        if frame_match and current_sample is not None:
            sym = frame_match.group('sym')
            dso = frame_match.group('dso')
            sym = _tidy_symbol(sym, dso)
            current_frames.append(sym)
            continue

        header_match = _HEADER_RE.match(line)
        if header_match:
            if current_sample is not None:
                current_sample['frames'] = list(reversed(current_frames))
                samples.append(current_sample)
                current_frames = []

            comm = header_match.group('comm').replace(' ', '_')
            current_sample = {
                'comm': comm,
                'pid': int(header_match.group('pid')),
                'tid': int(header_match.group('tid')) if header_match.group('tid') else None,
                'event': header_match.group('event'),
                'frames': [],
            }

    if current_sample is not None:
        current_sample['frames'] = list(reversed(current_frames))
        samples.append(current_sample)

    return samples


def _tidy_symbol(sym, dso):
    """Clean up symbol names, preserving DSO when the symbol itself is unknown."""
    is_unknown = sym is None or sym == '[unknown]' or sym.startswith('0x')

    if is_unknown:
        if dso and dso not in ('[unknown]', '[vdso]', '[vsyscall]'):
            # Preserve the binary name so the flamegraph shows e.g. [stargate]
            # instead of a generic [unknown]
            basename = dso.rsplit('/', 1)[-1]
            return f'[{basename}]'
        return '[unknown]'

    sym = sym.replace(';', ':')
    if dso == '[kernel.kallsyms]':
        sym = sym + '_[k]'
    return sym


def samples_to_folded(samples):
    """
    Convert parsed samples to folded stacks format.

    Returns a dict: { "comm;frame1;frame2;...": count, ... }
    """
    folded = defaultdict(int)
    for sample in samples:
        frames = sample['frames'] if sample['frames'] else ['[unknown]']
        stack = sample['comm'] + ';' + ';'.join(frames)
        folded[stack] += 1
    return dict(folded)


def samples_to_pid_folded(samples):
    """
    Convert parsed samples to per-PID folded stacks.

    Returns: {
        'pid_folded': { pid_int: { "comm;frame1;...": count, ... }, ... },
        'pid_map': [ { 'pid': int, 'comm': str, 'samples': int }, ... ]
    }
    """
    pid_folded = defaultdict(lambda: defaultdict(int))
    pid_info = defaultdict(lambda: defaultdict(int))

    for sample in samples:
        pid = sample['pid']
        comm = sample['comm']
        frames = sample['frames'] if sample['frames'] else ['[unknown]']
        stack = comm + ';' + ';'.join(frames)
        pid_folded[pid][stack] += 1
        pid_info[pid][comm] += 1

    pid_map = []
    for pid, comm_counts in pid_info.items():
        total = sum(comm_counts.values())
        primary_comm = max(comm_counts, key=comm_counts.get)
        pid_map.append({'pid': pid, 'comm': primary_comm, 'samples': total})
    pid_map.sort(key=lambda x: x['samples'], reverse=True)

    pid_folded_out = {pid: dict(stacks) for pid, stacks in pid_folded.items()}
    return {'pid_folded': pid_folded_out, 'pid_map': pid_map}


def folded_to_flamegraph_json(folded):
    """
    Convert folded stacks dict into the hierarchical JSON structure
    that d3-flame-graph expects:

    {
      "name": "root",
      "value": 0,
      "children": [
        { "name": "func_a", "value": 5, "children": [...] },
        ...
      ]
    }
    """
    root = {'name': 'root', 'value': 0, 'children': []}

    for stack_str, count in folded.items():
        frames = stack_str.split(';')
        node = root
        for frame in frames:
            child = None
            for c in node['children']:
                if c['name'] == frame:
                    child = c
                    break
            if child is None:
                child = {'name': frame, 'value': 0, 'children': []}
                node['children'].append(child)
            child['value'] += count
            node = child

    _propagate_values(root)
    return root


def _propagate_values(node):
    """Ensure parent value >= sum of children values (for correct rendering)."""
    if not node['children']:
        return
    child_sum = 0
    for child in node['children']:
        _propagate_values(child)
        child_sum += child['value']
    if node['value'] < child_sum:
        node['value'] = child_sum


def compute_process_breakdown(samples):
    """
    Return per-process sample counts sorted descending.

    Returns: [{'name': str, 'pid': int, 'samples': int, 'pct': float}, ...]
    """
    counts = defaultdict(lambda: {'samples': 0, 'pid': 0})
    for s in samples:
        key = s['comm']
        counts[key]['samples'] += 1
        counts[key]['pid'] = s['pid']

    total = len(samples) or 1
    result = []
    for name, info in counts.items():
        result.append({
            'name': name,
            'pid': info['pid'],
            'samples': info['samples'],
            'pct': round(100.0 * info['samples'] / total, 2),
        })
    result.sort(key=lambda x: x['samples'], reverse=True)
    return result


def compute_top_functions(folded, top_n=20):
    """
    Return the top N hottest leaf functions by sample count.

    Returns: [{'function': str, 'samples': int, 'pct': float}, ...]
    """
    func_counts = defaultdict(int)
    total = 0
    for stack_str, count in folded.items():
        frames = stack_str.split(';')
        leaf = frames[-1] if frames else '[unknown]'
        func_counts[leaf] += count
        total += count

    total = total or 1
    result = []
    for func, cnt in func_counts.items():
        result.append({
            'function': func,
            'samples': cnt,
            'pct': round(100.0 * cnt / total, 2),
        })
    result.sort(key=lambda x: x['samples'], reverse=True)
    return result[:top_n]


def compute_kernel_user_split(samples):
    """
    Return kernel vs userspace sample ratio.

    Returns: {'kernel_samples': int, 'user_samples': int,
              'kernel_pct': float, 'user_pct': float, 'total': int}
    """
    kernel = 0
    user = 0
    for s in samples:
        has_kernel = any('_[k]' in f for f in s['frames'])
        if has_kernel:
            kernel += 1
        else:
            user += 1
    total = kernel + user or 1
    return {
        'kernel_samples': kernel,
        'user_samples': user,
        'kernel_pct': round(100.0 * kernel / total, 2),
        'user_pct': round(100.0 * user / total, 2),
        'total': kernel + user,
    }


IDLE_FRAME_MARKERS = [
    'cpu_idle', 'default_idle', 'native_safe_halt',
    'intel_idle', 'mwait_idle', 'poll_idle',
    'cpuidle_enter', 'acpi_idle',
]


def _is_idle_sample(sample):
    """Check if a sample is an idle/swapper sample."""
    return any(
        marker in frame
        for frame in sample['frames']
        for marker in IDLE_FRAME_MARKERS
    )


def compute_active_breakdown(samples):
    """
    Compute idle/active split and per-process breakdown excluding idle samples.

    Returns: {
        'idle_samples': int,
        'active_samples': int,
        'idle_pct': float,
        'active_pct': float,
        'active_process_breakdown': list,  # same format as compute_process_breakdown
    }
    """
    active = []
    idle_count = 0
    for s in samples:
        if _is_idle_sample(s):
            idle_count += 1
        else:
            active.append(s)

    total = len(samples) or 1
    active_total = len(active) or 1

    counts = defaultdict(lambda: {'samples': 0, 'pid': 0})
    for s in active:
        key = s['comm']
        counts[key]['samples'] += 1
        counts[key]['pid'] = s['pid']

    breakdown = []
    for name, info in counts.items():
        breakdown.append({
            'name': name,
            'pid': info['pid'],
            'samples': info['samples'],
            'pct': round(100.0 * info['samples'] / active_total, 2),
        })
    breakdown.sort(key=lambda x: x['samples'], reverse=True)

    return {
        'idle_samples': idle_count,
        'active_samples': len(active),
        'idle_pct': round(100.0 * idle_count / total, 2),
        'active_pct': round(100.0 * len(active) / total, 2),
        'active_process_breakdown': breakdown,
    }


def parse_top_snapshot(text):
    """
    Parse the top_snapshot.txt output to extract system context.

    Returns: {
        'load_avg_1': float, 'load_avg_5': float, 'load_avg_15': float,
        'cpu_us': float, 'cpu_sy': float, 'cpu_id': float,
        'cpu_wa': float, 'cpu_st': float, 'cpu_hi': float, 'cpu_si': float,
        'mem_total_kb': int, 'mem_used_kb': int, 'mem_free_kb': int, 'mem_avail_kb': int,
        'tasks_total': int, 'tasks_running': int,
        'uptime': str,
        'top_processes': [{'pid': int, 'user': str, 'cpu_pct': float, 'mem_pct': float,
                           'command': str, 'threads': int}, ...]
    }
    """
    if not text or not text.strip():
        return {}

    result = {}
    lines = text.strip().splitlines()

    for line in lines:
        # Load average: "top - 14:19:46 up 133 days, 2:24, ... load average: 5.28, 3.83, 3.36"
        if 'load average:' in line:
            try:
                la_part = line.split('load average:')[1].strip()
                parts = [x.strip() for x in la_part.split(',')]
                result['load_avg_1'] = float(parts[0])
                result['load_avg_5'] = float(parts[1])
                result['load_avg_15'] = float(parts[2])
            except (IndexError, ValueError):
                pass
            up_match = re.search(r'up\s+(.+?),\s+\d+\s+user', line)
            if up_match:
                result['uptime'] = up_match.group(1).strip()

        # Tasks: "Tasks: 516 total, 4 running, 512 sleeping, ..."
        if line.strip().startswith('Tasks:'):
            m = re.search(r'(\d+)\s+total.*?(\d+)\s+running', line)
            if m:
                result['tasks_total'] = int(m.group(1))
                result['tasks_running'] = int(m.group(2))
            mz = re.search(r'(\d+)\s+zombie', line)
            if mz:
                result['tasks_zombie'] = int(mz.group(1))

        # CPU: "%Cpu(s): 29.0 us, 13.8 sy, 1.4 ni, 54.5 id, 0.7 wa, 0.0 hi, 0.7 si, 0.0 st"
        if '%Cpu' in line:
            for key, label in [('cpu_us', 'us'), ('cpu_sy', 'sy'), ('cpu_id', 'id'),
                               ('cpu_wa', 'wa'), ('cpu_st', 'st'), ('cpu_hi', 'hi'),
                               ('cpu_si', 'si'), ('cpu_ni', 'ni')]:
                m = re.search(r'([\d.]+)\s+' + label, line)
                if m:
                    result[key] = float(m.group(1))

        # Memory: "KiB Mem : 63523484 total, 1502600 free, 58484296 used, 3536588 buff/cache"
        if 'KiB Mem' in line or 'MiB Mem' in line:
            mult = 1 if 'KiB' in line else 1024
            m_total = re.search(r'([\d.]+)\s+total', line)
            m_free = re.search(r'([\d.]+)\s+free', line)
            m_used = re.search(r'([\d.]+)\s+used', line)
            if m_total:
                result['mem_total_kb'] = int(float(m_total.group(1)) * mult)
            if m_free:
                result['mem_free_kb'] = int(float(m_free.group(1)) * mult)
            if m_used:
                result['mem_used_kb'] = int(float(m_used.group(1)) * mult)

        # Avail mem: "... 3327040 avail Mem" (may appear on Mem or Swap line)
        if 'avail Mem' in line or 'avail mem' in line.lower():
            mult = 1024 if 'MiB' in line else 1
            m = re.search(r'([\d.]+)\s+avail', line, re.IGNORECASE)
            if m:
                result['mem_avail_kb'] = int(float(m.group(1)) * mult)

    # Parse top process table.
    # Header: PID USER PR NI VIRT RES SHR S %CPU %MEM TIME+ COMMAND
    # The header column order varies by top version. We detect it dynamically
    # and use the COMMAND column's character offset (it's always last and may
    # contain spaces).
    top_procs = []
    header_line = None
    header_idx = -1
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('PID') and 'COMMAND' in stripped:
            header_line = line
            header_idx = i
            break

    if header_line is not None:
        hdr_fields = header_line.split()
        cmd_char_offset = header_line.find('COMMAND')
        # Map column name -> index in the split fields
        col_idx = {name: i for i, name in enumerate(hdr_fields)}
        n_fixed = len(hdr_fields) - 1  # all columns except COMMAND

        for line in lines[header_idx + 1:]:
            if not line.strip():
                continue
            parts = line.split(None, n_fixed)
            if len(parts) <= n_fixed:
                continue
            try:
                pid = int(parts[col_idx.get('PID', 0)])
            except (ValueError, KeyError):
                continue

            def _col(name):
                idx = col_idx.get(name)
                if idx is not None and idx < len(parts):
                    return parts[idx]
                return ''

            # COMMAND: take everything from the character offset in the original line
            if cmd_char_offset >= 0 and len(line) > cmd_char_offset:
                command = line[cmd_char_offset:].strip()
            else:
                command = parts[-1] if parts else ''

            try:
                cpu_pct = float(_col('%CPU'))
            except ValueError:
                cpu_pct = 0.0
            try:
                mem_pct = float(_col('%MEM'))
            except ValueError:
                mem_pct = 0.0

            top_procs.append({
                'pid': pid,
                'user': _col('USER'),
                'cpu_pct': cpu_pct,
                'mem_pct': mem_pct,
                'virt': _col('VIRT'),
                'res': _col('RES'),
                'shr': _col('SHR'),
                'state': _col('S'),
                'time': _col('TIME+'),
                'command': command,
            })
            if len(top_procs) >= 30:
                break

    result['top_processes'] = top_procs
    return result


def parse_top_timeseries(text):
    """Split multi-snapshot ``top -bd1`` output into per-second ticks.

    Each tick is the dict returned by ``parse_top_snapshot()`` with an
    added ``timestamp`` field (0-based second index).

    Single-snapshot files (old collector) produce a 1-element list.

    Returns ``{'ticks': [tick0, tick1, ...]}`` or ``None``.
    """
    if not text or not text.strip():
        return None

    chunks = re.split(r'(?=^top - )', text, flags=re.MULTILINE)
    if not chunks:
        chunks = [text]

    ticks = []
    for chunk in chunks:
        chunk = chunk.strip()
        if not chunk:
            continue
        parsed = parse_top_snapshot(chunk)
        if not parsed:
            continue
        if not parsed.get('top_processes'):
            continue
        parsed['timestamp'] = len(ticks)
        ticks.append(parsed)

    if not ticks:
        return None
    return {'ticks': ticks}


def parse_ps_aux(text):
    """
    Parse ps output into a PID -> process info map.

    Supports two formats:
      1. ``ps -eo user,pid,ppid,%cpu,%mem,stat,args --no-headers ww``
         (new collector, includes PPID, no header line)
      2. ``ps auxww``
         (old collector / fallback, has header, no PPID column)

    Returns: { pid_int: { 'user': str, 'ppid': int or None, 'cmd': str }, ... }
    """
    if not text or not text.strip():
        return {}

    lines = text.strip().splitlines()
    if not lines:
        return {}

    # Detect format: if the first line starts with a header keyword, it's ps aux
    first = lines[0].strip()
    has_header = first.startswith('USER') or first.startswith('UID')

    if has_header:
        return _parse_ps_aux_format(lines)
    return _parse_ps_eo_format(lines)


def _parse_ps_eo_format(lines):
    """Parse ``ps -eo user,pid,ppid,%cpu,%mem,stat,args --no-headers ww``."""
    # Fields: USER PID PPID %CPU %MEM STAT COMMAND...
    # Split into at most 7 parts; the 7th (index 6) is the full command
    result = {}
    for line in lines:
        parts = line.split(None, 6)
        if len(parts) < 6:
            continue
        try:
            pid = int(parts[1])
            ppid = int(parts[2])
        except ValueError:
            continue

        result[pid] = {
            'user': parts[0],
            'ppid': ppid,
            'cmd': parts[6] if len(parts) > 6 else '',
        }
    return result


def _parse_ps_aux_format(lines):
    """Parse ``ps auxww`` output (has header, no PPID column).

    Header: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
    Always splits into 11 fields (10 fixed + COMMAND remainder) rather
    than using character offsets, which break when field widths vary.
    """
    result = {}
    for line in lines[1:]:
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
        try:
            pid = int(parts[1])
        except ValueError:
            continue

        result[pid] = {
            'user': parts[0],
            'ppid': None,
            'cmd': parts[10],
        }
    return result


_IOSTAT_SKIP_RE = re.compile(r'^(loop\d+|md\d+|scd\d+|dm-.+)$', re.IGNORECASE)


def parse_iostat(text):
    """
    Parse `iostat -dxy 1` output into structured per-device time series.

    Handles the fact that iostat omits devices with zero activity in a given
    report.  Missing seconds are filled with 0.0 so every device has an array
    of the same length aligned to the same time axis.

    Filters out virtual/noise devices: loop*, md*, scd*.

    Returns: {
        'columns': ['r/s', 'wkB/s', '%util', ...],
        'devices': ['sda', 'sdb', ...],
        'series': {
            'sda': { 'r/s': [0.0, 1.2, ...], 'wkB/s': [...], ... },
            ...
        }
    }
    """
    if not text or not text.strip():
        return None

    blocks = re.split(r'\n\s*\n', text.strip())
    if not blocks:
        return None

    columns = []
    # Each element = dict of { dev: { col: value } } for that 1-second tick
    ticks = []

    for block in blocks:
        lines = [l for l in block.strip().splitlines() if l.strip()]
        if not lines:
            continue

        data_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('Device'):
                if not columns:
                    columns = stripped.split()[1:]
                continue
            if stripped.startswith('Linux') or stripped.startswith('avg-cpu'):
                continue
            data_lines.append(stripped)

        if not data_lines or not columns:
            continue

        tick = {}
        for dl in data_lines:
            parts = dl.split()
            if len(parts) < 2:
                continue
            dev = parts[0]
            if _IOSTAT_SKIP_RE.match(dev):
                continue
            vals = parts[1:]
            row = {}
            for j, col in enumerate(columns):
                try:
                    row[col] = float(vals[j]) if j < len(vals) else 0.0
                except (ValueError, IndexError):
                    row[col] = 0.0
            tick[dev] = row
        if tick:
            ticks.append(tick)

    if not columns or not ticks:
        return None

    all_devices = []
    seen = set()
    for tick in ticks:
        for dev in tick:
            if dev not in seen:
                seen.add(dev)
                all_devices.append(dev)

    series = {dev: {col: [] for col in columns} for dev in all_devices}
    for tick in ticks:
        for dev in all_devices:
            row = tick.get(dev)
            for col in columns:
                series[dev][col].append(row[col] if row else 0.0)

    return {
        'columns': columns,
        'devices': all_devices,
        'series': series,
    }


def _parse_iotop_rate(s):
    """Convert an iotop rate string like '1.20 M/s' or '512.00 K/s' to bytes/s."""
    s = s.strip()
    m = re.match(r'([\d.]+)\s*([BKMGTP])/s', s, re.IGNORECASE)
    if not m:
        return 0.0
    val = float(m.group(1))
    unit = m.group(2).upper()
    multipliers = {'B': 1, 'K': 1024, 'M': 1024**2, 'G': 1024**3, 'T': 1024**4, 'P': 1024**5}
    return val * multipliers.get(unit, 1)


def parse_iotop(text):
    """
    Parse `sudo iotop -b -o -d 1 -n N` output into per-second ticks.

    Returns: {
        'ticks': [
            {
                'timestamp': int,
                'total_read': float, 'total_write': float,
                'actual_read': float, 'actual_write': float,
                'processes': [
                    {'tid': int, 'prio': str, 'user': str,
                     'read_bps': float, 'write_bps': float,
                     'swapin_pct': float, 'io_pct': float,
                     'command': str},
                    ...
                ]
            },
            ...
        ]
    }
    Returns None if text cannot be parsed.
    """
    if not text or not text.strip():
        return None

    lines = text.splitlines()
    ticks = []
    current_tick = None
    tick_idx = 0

    summary_re = re.compile(
        r'(Total|Actual|Current)\s+DISK\s+READ\s*:\s*([\d.]+\s*[BKMGTP]/s)\s*\|\s*'
        r'(Total|Actual|Current)\s+DISK\s+WRITE\s*:\s*([\d.]+\s*[BKMGTP]/s)',
        re.IGNORECASE
    )

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        sm = summary_re.search(stripped)
        if sm:
            kind = sm.group(1).lower()
            read_val = _parse_iotop_rate(sm.group(2))
            write_val = _parse_iotop_rate(sm.group(4))

            if kind == 'total':
                if current_tick is not None:
                    ticks.append(current_tick)
                current_tick = {
                    'timestamp': tick_idx,
                    'total_read': read_val,
                    'total_write': write_val,
                    'actual_read': 0.0,
                    'actual_write': 0.0,
                    'processes': [],
                }
                tick_idx += 1
            elif kind in ('actual', 'current') and current_tick is not None:
                current_tick['actual_read'] = read_val
                current_tick['actual_write'] = write_val
            continue

        if stripped.startswith('TID') or stripped.startswith('PID'):
            continue

        if current_tick is None:
            continue

        # Some iotop versions (Python 3) write process lines as b'...' byte-string repr
        if stripped.startswith("b'") and stripped.endswith("'"):
            stripped = stripped[2:-1]

        proc_re = re.match(
            r'\s*(\d+)\s+'           # TID
            r'(\S+)\s+'              # PRIO
            r'(\S+)\s+'              # USER
            r'([\d.]+)\s+([BKMGTP]/s)\s+'   # DISK READ val + unit
            r'([\d.]+)\s+([BKMGTP]/s)\s+'   # DISK WRITE val + unit
            r'([\d.]+)\s+%\s+'       # SWAPIN %
            r'([\d.]+)\s+%\s*'       # IO %
            r'(.*)',                  # COMMAND (rest of line)
            stripped, re.IGNORECASE
        )
        if not proc_re:
            continue

        current_tick['processes'].append({
            'tid': int(proc_re.group(1)),
            'prio': proc_re.group(2),
            'user': proc_re.group(3),
            'read_bps': _parse_iotop_rate(proc_re.group(4) + ' ' + proc_re.group(5)),
            'write_bps': _parse_iotop_rate(proc_re.group(6) + ' ' + proc_re.group(7)),
            'swapin_pct': float(proc_re.group(8)),
            'io_pct': float(proc_re.group(9)),
            'command': proc_re.group(10).strip(),
        })

    if current_tick is not None:
        ticks.append(current_tick)

    if not ticks:
        return None

    return {'ticks': ticks}


def parse_and_process(perf_script_text):
    """
    Full pipeline: raw perf script text -> all analysis artifacts.
    """
    samples = parse_perf_script(perf_script_text)
    folded = samples_to_folded(samples)
    flamegraph_json = folded_to_flamegraph_json(folded)
    process_breakdown = compute_process_breakdown(samples)
    top_functions = compute_top_functions(folded)
    kernel_user_split = compute_kernel_user_split(samples)
    active_breakdown = compute_active_breakdown(samples)
    pid_data = samples_to_pid_folded(samples)

    return {
        'samples': samples,
        'folded': folded,
        'flamegraph_json': flamegraph_json,
        'process_breakdown': process_breakdown,
        'top_functions': top_functions,
        'kernel_user_split': kernel_user_split,
        'total_samples': len(samples),
        'idle_samples': active_breakdown['idle_samples'],
        'active_samples': active_breakdown['active_samples'],
        'idle_pct': active_breakdown['idle_pct'],
        'active_pct': active_breakdown['active_pct'],
        'active_process_breakdown': active_breakdown['active_process_breakdown'],
        'pid_folded': pid_data['pid_folded'],
        'pid_map': pid_data['pid_map'],
    }
