import json
import os
from datetime import datetime

# File paths
RANCHER_JSON = "suse_ai_images.json"
REGISTRY_JSON = "suse_registry_images.json"
OUTPUT_HTML = "index.html"

# External Links
APPCO_URL = "https://apps.rancher.io/stacks/suse-ai"
DOCS_URL = "https://documentation.suse.com/suse-ai"
LANDING_URL = "https://www.suse.com/solutions/ai/"
LOGO_URL = "https://d12w0ryu9hjsx8.cloudfront.net/shared-header/1.9/assets/SUSE_Logo.svg"
FAVICON_URL = "https://www.suse.com/favicon.ico"

def load_json(path):
    if os.path.exists(path):
        with open(path, 'r') as f:
            return json.load(f)
    return []

def normalize_arch(arch):
    if not arch: return "N/A"
    a = arch.lower()
    if a == "amd64": return "x86_64"
    return a

def generate_html():
    rancher_data = load_json(RANCHER_JSON)
    registry_data = load_json(REGISTRY_JSON)

    merged_data = []
    for item in rancher_data:
        image_name = item.get("image_name")
        pkg_format = item.get("packaging_format", "CONTAINER")
        prefix = "dp.apps.rancher.io/charts/" if pkg_format == "HELM_CHART" else "dp.apps.rancher.io/containers/"
        full_path = f"{prefix}{image_name}" if image_name else "N/A"
        
        os_family = item.get('os_family') or ''
        os_version = item.get('os_version') or ''
        os_str = f"{os_family} {os_version}".strip() or "N/A"
        
        merged_data.append({
            "source": "AppCo",
            "name": full_path,
            "version": item.get("version"),
            "arch": normalize_arch(item.get("architecture")),
            "os": os_str,
            "last_updated": item.get("last_updated"),
            "digest": item.get("digest"),
            "details": item,
            "type": "Chart" if pkg_format == "HELM_CHART" else "Container",
            "logo": item.get("app_logo_url")
        })

    for item in registry_data:
        image_name = item.get("image_name")
        full_path = f"registry.suse.com/{image_name}" if image_name else "N/A"
        is_chart = "/charts/" in full_path.lower()
        
        merged_data.append({
            "source": "SUSE Registry",
            "name": full_path,
            "version": item.get("tag"),
            "arch": normalize_arch(item.get("architecture")),
            "os": item.get("os") or "N/A",
            "last_updated": item.get("created"),
            "digest": item.get("digest"),
            "details": item,
            "type": "Chart" if is_chart else "Container",
            "logo": None
        })

    groups = {}
    for item in merged_data:
        full_path = item['name']
        base_name = full_path.rsplit(":", 1)[0] if ":" in full_path else full_path
        if base_name not in groups:
            groups[base_name] = {
                "base_name": base_name, 
                "source": item['source'], 
                "versions": [], 
                "type": item['type'],
                "logo": item['logo']
            }
        groups[base_name]['versions'].append(item)

    final_groups = []
    for base_name, group_data in groups.items():
        group_data['versions'].sort(key=lambda x: x.get('last_updated') or '', reverse=True)
        latest = group_data['versions'][0]
        group_data['latest_version'] = latest['version']
        group_data['count'] = len(group_data['versions'])
        unique_archs = sorted(list(set(v['arch'] for v in group_data['versions'] if v['arch'] and v['arch'] != "N/A")))
        group_data['arch_list'] = unique_archs
        group_data['os'] = latest['os']
        group_data['last_updated'] = latest['last_updated']
        final_groups.append(group_data)

    final_groups.sort(key=lambda x: (x['type'], x['base_name']))
    
    app_count = len([g for g in final_groups if g['type'] == "Container"])
    chart_count = len([g for g in final_groups if g['type'] == "Chart"])

    html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SUSE AI Image Stack Dashboard</title>
    <link rel="icon" type="image/x-icon" href="{FAVICON_URL}">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <!-- SUSE Official Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=SUSE:wght@100..800&display=swap" rel="stylesheet">
    
    <style>
        :root {{
            /* SUSE Official Primary Brand Colors */
            --suse-pine: #0c322c;
            --suse-jungle: #30ba78;
            --suse-mint: #90ebcd;
            --suse-persimmon: #fe7c3f;
            --suse-waterhole: #2453ff;
            --suse-fog: #efefef;
            --suse-midnight: #192072;
            
            /* UI Semantics */
            --bg-color: #f8f9fa;
            --card-bg: #ffffff;
            --text-color: #212529;
            --table-hover: rgba(48, 186, 120, 0.1);
            --table-border: #dee2e6;
            --input-bg: #ffffff;
        }}
        [data-bs-theme="dark"] {{
            --bg-color: #1a1d20;
            --card-bg: #212529;
            --text-color: #f8f9fa;
            --table-hover: rgba(48, 186, 120, 0.2);
            --table-border: #373b3e;
            --input-bg: #2b3035;
        }}
        body {{
            background-color: var(--bg-color);
            color: var(--text-color);
            /* Official SUSE Typography: SUSE Font with Verdana fallback */
            font-family: 'SUSE', 'Verdana', sans-serif;
            transition: background-color 0.3s, color 0.3s;
        }}
        .navbar {{
            background-color: var(--suse-pine) !important;
            border-bottom: 4px solid var(--suse-jungle);
        }}
        .navbar-brand img {{
            height: 35px;
            filter: brightness(0) invert(1);
        }}
        .nav-link {{
            color: rgba(255,255,255,0.8) !important;
        }}
        .nav-link:hover {{
            color: var(--suse-jungle) !important;
        }}
        .card {{
            background-color: var(--card-bg);
            border-color: var(--table-border);
        }}
        .card-header {{
            background-color: var(--suse-pine);
            color: white;
            font-weight: bold;
        }}
        .table {{
            color: var(--text-color);
            border-color: var(--table-border);
        }}
        .group-header {{
            cursor: pointer;
        }}
        .group-header:hover {{
            background-color: var(--table-hover) !important;
        }}
        .rotate-icon {{
            transition: transform 0.2s;
            display: inline-block;
        }}
        .group-header:not(.collapsed) .rotate-icon {{
            transform: rotate(90deg);
        }}
        .badge-suse {{
            background-color: var(--suse-jungle);
            color: var(--suse-pine);
        }}
        .badge-source {{
            background-color: var(--suse-waterhole);
            color: white;
        }}
        .badge-arch {{
            background-color: var(--bg-color);
            color: var(--text-color);
            border: 1px solid var(--table-border);
            font-size: 0.7rem;
            text-transform: uppercase;
        }}
        .badge-type {{
            font-size: 0.65rem;
            text-transform: uppercase;
            font-weight: bold;
            padding: 3px 6px;
        }}
        .type-chart {{ background-color: var(--suse-fog); color: var(--suse-midnight); border: 1px solid var(--table-border); }}
        .type-container {{ background-color: #f1f8e9; color: #1b5e20; border: 1px solid #dcedc8; }}
        [data-bs-theme="dark"] .type-chart {{ background-color: var(--suse-midnight); color: var(--suse-fog); border: 1px solid var(--suse-midnight); }}
        [data-bs-theme="dark"] .type-container {{ background-color: #1b5e20; color: #f1f8e9; border: 1px solid #2e7d32; }}

        th[onclick] {{
            cursor: pointer;
            position: relative;
            padding-right: 30px !important;
            white-space: nowrap;
        }}
        .sort-indicator {{
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--suse-jungle);
            font-size: 0.9rem;
        }}
        th.sort-asc .bi-arrow-down-up::before {{ content: "\\F148"; }}
        th.sort-desc .bi-arrow-down-up::before {{ content: "\\F128"; }}
        th.active-sort {{
            border-bottom: 2px solid var(--suse-jungle) !important;
            color: var(--suse-jungle);
        }}
        .appco-link {{
            color: var(--suse-jungle) !important;
            text-decoration: none;
            font-weight: bold;
        }}
        .appco-link:hover {{
            text-decoration: underline;
        }}
        .project-logo {{
            width: 24px;
            height: 24px;
            object-fit: contain;
            background: white;
            border-radius: 3px;
            padding: 2px;
            margin-right: 8px;
        }}
        .modal-logo {{
            width: 32px;
            height: 32px;
            object-fit: contain;
            background: white;
            border-radius: 4px;
            padding: 2px;
            border: 1px solid rgba(255,255,255,0.2);
        }}
        .json-block {{
            background-color: #272822;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            font-family: monospace;
            font-size: 0.85rem;
            max-height: 400px;
            overflow-y: auto;
            white-space: pre-wrap;
        }}
        .disclaimer-bar {{
            background-color: var(--suse-persimmon);
            color: white;
            font-weight: bold;
            font-size: 0.85rem;
            padding: 8px 0;
            text-align: center;
        }}
        
        @media (max-width: 768px) {{
            .summary-card h3 {{ font-size: 1.2rem; margin-bottom: 0; }}
            .summary-card p {{ font-size: 0.7rem; }}
            .summary-card .p-2 {{ padding: 0.5rem !important; }}
            .navbar-brand img {{ height: 25px; }}
            .navbar-brand span {{ font-size: 0.9rem; }}
        }}
    </style>
</head>
<body data-bs-theme="light">

<nav class="navbar navbar-expand-lg navbar-dark">
    <div class="container">
        <a class="navbar-brand d-flex align-items-center" href="#">
            <img src="{LOGO_URL}" alt="SUSE Logo" class="me-2 me-md-3">
            <span>AI Image Catalog</span>
        </a>
        
        <div class="d-flex align-items-center ms-auto">
            <button class="btn btn-outline-light btn-sm me-2" id="themeToggle">
                <i class="bi bi-moon-fill" id="themeIcon"></i>
            </button>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
        </div>

        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav ms-auto align-items-center">
                <li class="nav-item"><a class="nav-link" href="{DOCS_URL}" target="_blank"><i class="bi bi-book"></i> Docs</a></li>
                <li class="nav-item"><a class="nav-link" href="{LANDING_URL}" target="_blank"><i class="bi bi-info-circle"></i> SUSE AI</a></li>
            </ul>
        </div>
    </div>
</nav>

<div class="disclaimer-bar">
    <div class="container">
        <i class="bi bi-exclamation-triangle-fill me-2"></i> Disclaimer: This is an unofficial tool and is not officially supported or endorsed by SUSE.
    </div>
</div>

<div class="container mt-4">
    <div class="row text-center mb-4 g-2 g-md-3">
        <div class="col-6 col-md-4 col-lg"><div class="p-2 border rounded card summary-card"><h3>{len(merged_data)}</h3><p class="text-muted small mb-0">Total versions</p></div></div>
        <div class="col-6 col-md-4 col-lg"><div class="p-2 border rounded card summary-card"><h3>{app_count}</h3><p class="text-muted small mb-0">Applications</p></div></div>
        <div class="col-6 col-md-4 col-lg"><div class="p-2 border rounded card summary-card"><h3>{chart_count}</h3><p class="text-muted small mb-0">Charts</p></div></div>
        <div class="col-6 col-md-6 col-lg"><div class="p-2 border rounded card summary-card"><h3>{len(rancher_data)}</h3><p class="text-muted small mb-0"><a href="{APPCO_URL}" target="_blank" class="appco-link">AppCo images</a></p></div></div>
        <div class="col-12 col-md-6 col-lg"><div class="p-2 border rounded card summary-card"><h3>{len(registry_data)}</h3><p class="text-muted small mb-0">SUSE Registry images</p></div></div>
    </div>

    <div class="row mb-4 align-items-center">
        <div class="col-md-8 mb-2 mb-md-0">
            <div class="input-group">
                <span class="input-group-text"><i class="bi bi-search"></i></span>
                <span class="input-group-text" id="clearSearch" title="Clear search" style="cursor:pointer;"><i class="bi bi-x-lg"></i></span>
                <input type="text" id="searchInput" class="form-control" placeholder="Search images...">
            </div>
        </div>
        <div class="col-md-4 text-md-end">
            <div class="btn-group" role="group">
                <button type="button" class="btn btn-outline-secondary btn-sm" onclick="expandAll()">
                    <i class="bi bi-plus-square me-1"></i> Expand All
                </button>
                <button type="button" class="btn btn-outline-secondary btn-sm" onclick="collapseAll()">
                    <i class="bi bi-dash-square me-1"></i> Collapse All
                </button>
            </div>
        </div>
    </div>

    <div class="card">
        <div class="card-header d-flex justify-content-between align-items-center flex-wrap">
            <div>
                <span class="me-2">Container Images</span>
                <small class="fw-normal opacity-75 d-none d-md-inline"><i class="bi bi-info-circle me-1"></i> Click any version row for details</small>
            </div>
            <span class="badge bg-light text-dark" style="font-size: 0.7rem;">Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M')}</span>
        </div>
        <div class="card-body p-0">
            <div class="table-responsive">
                <table class="table table-hover mb-0" id="imageTable">
                    <thead>
                        <tr>
                            <th onclick="sortTable(0)">Name <i class="bi bi-arrow-down-up sort-indicator"></i></th>
                            <th onclick="sortTable(1)">Type <i class="bi bi-arrow-down-up sort-indicator"></i></th>
                            <th onclick="sortTable(2)">Latest Version <i class="bi bi-arrow-down-up sort-indicator"></i></th>
                            <th onclick="sortTable(3)">Versions <i class="bi bi-arrow-down-up sort-indicator"></i></th>
                            <th onclick="sortTable(4)">Source <i class="bi bi-arrow-down-up sort-indicator"></i></th>
                            <th onclick="sortTable(5)">Arch <i class="bi bi-arrow-down-up sort-indicator"></i></th>
                            <th onclick="sortTable(6)">Base OS <i class="bi bi-arrow-down-up sort-indicator"></i></th>
                            <th onclick="sortTable(7)">Last Updated <i class="bi bi-arrow-down-up sort-indicator"></i></th>
                        </tr>
                    </thead>
                    <tbody>
                        {generate_table_rows(final_groups)}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<div class="modal fade" id="detailsModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header d-flex align-items-center" style="background-color: var(--suse-pine); color: white;">
                <h5 class="modal-title d-flex align-items-center flex-grow-1" id="modalTitleOuter">
                    <span id="modalTitle">Details</span>
                    <div id="modalLogoContainer" class="ms-auto me-3"></div>
                </h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body" id="modalContent"></div>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
    const themeToggle = document.getElementById('themeToggle');
    const themeIcon = document.getElementById('themeIcon');
    const body = document.body;

    function setTheme(theme) {{
        body.setAttribute('data-bs-theme', theme);
        localStorage.setItem('theme', theme);
        themeIcon.className = theme === 'dark' ? 'bi bi-sun-fill' : 'bi bi-moon-fill';
    }}

    themeToggle.addEventListener('click', () => setTheme(body.getAttribute('data-bs-theme') === 'dark' ? 'light' : 'dark'));
    setTheme(localStorage.getItem('theme') || 'light');

    const searchInput = document.getElementById('searchInput');
    const clearSearch = document.getElementById('clearSearch');
    function filterTable() {{
        const val = searchInput.value.toLowerCase();
        document.querySelectorAll('tr.group-header').forEach(row => {{
            const text = row.innerText.toLowerCase();
            const targetId = row.getAttribute('data-bs-target');
            const target = document.querySelector(targetId);
            if (text.includes(val)) {{
                row.style.display = '';
            }} else {{
                row.style.display = 'none';
                if (target && target.classList.contains('show')) bootstrap.Collapse.getInstance(target).hide();
            }}
        }});
    }}
    searchInput.addEventListener('keyup', filterTable);
    clearSearch.addEventListener('click', () => {{ searchInput.value = ''; filterTable(); searchInput.focus(); }});

    const detailsModal = new bootstrap.Modal(document.getElementById('detailsModal'));
    function showDetails(dataStr, fullName, logoUrl) {{
        const data = JSON.parse(decodeURIComponent(dataStr));
        document.getElementById('modalTitle').textContent = data.image_name || data.name;
        const logoContainer = document.getElementById('modalLogoContainer');
        logoContainer.innerHTML = (logoUrl && logoUrl !== 'None') ? `<img src="${{logoUrl}}" class="modal-logo">` : '';
        const digest = data.digest || 'N/A';
        const updated = data.last_updated || data.created || 'N/A';
        const arch = data.architecture || 'N/A';
        const os = data.os || (data.os_family ? (data.os_family + ' ' + (data.os_version || '')) : 'N/A');
        document.getElementById('modalContent').innerHTML = `
            <div class="mb-4"><h6>Full Image Path</h6><div class="input-group"><input type="text" class="form-control" value="${{fullName}}" id="pathInput" readonly><button class="btn btn-outline-success btn-sm" onclick="copyPath(event)">Copy</button></div></div>
            <div class="row mb-3">
                <div class="col-md-6"><strong>Digest:</strong> <code class="text-break">${{digest}}</code></div>
                <div class="col-md-6"><strong>Updated:</strong> ${{updated}}</div>
            </div>
            <div class="row mb-3">
                <div class="col-md-4"><strong>Arch:</strong> <span class="badge badge-arch">${{arch}}</span></div>
                <div class="col-md-4"><strong>Base OS:</strong> ${{os}}</div>
            </div>
            <div class="json-block mt-3">${{JSON.stringify(data, null, 2)}}</div>`;
        detailsModal.show();
    }}
    function copyPath(event) {{
        const el = document.getElementById('pathInput');
        el.select();
        navigator.clipboard.writeText(el.value);
        event.target.innerText = 'Copied!';
        setTimeout(() => event.target.innerText = 'Copy', 2000);
    }}

    function expandAll() {{
        document.querySelectorAll('tr.group-header.collapsed').forEach(row => row.click());
    }}
    function collapseAll() {{
        document.querySelectorAll('tr.group-header:not(.collapsed)').forEach(row => row.click());
    }}

    let currentSort = {{ col: -1, dir: 'asc' }};
    function sortTable(n) {{
        const table = document.getElementById("imageTable");
        const tbody = table.tBodies[0];
        const headers = table.querySelectorAll("th");
        if (currentSort.col === n) currentSort.dir = currentSort.dir === 'asc' ? 'desc' : 'asc';
        else {{ currentSort.col = n; currentSort.dir = 'asc'; }}
        headers.forEach((h, i) => {{
            const icon = h.querySelector('i');
            if (icon) {{
                h.classList.remove('active-sort', 'sort-asc', 'sort-desc');
                if (i === n) h.classList.add('active-sort', currentSort.dir === 'asc' ? 'sort-asc' : 'sort-desc');
                else icon.className = 'bi bi-arrow-down-up sort-indicator';
            }}
        }});
        const groups = [];
        const rows = Array.from(tbody.querySelectorAll('tr.group-header'));
        rows.forEach(header => groups.push({{ header, content: document.querySelector(header.getAttribute('data-bs-target')) }}));
        groups.sort((a, b) => {{
            let valA = a.header.cells[n].innerText.toLowerCase();
            let valB = b.header.cells[n].innerText.toLowerCase();
            if (n === 3) {{ valA = parseInt(valA) || 0; valB = parseInt(valB) || 0; }}
            if (valA === valB) return 0;
            const cmp = valA > valB ? 1 : -1;
            return currentSort.dir === 'asc' ? cmp : -cmp;
        }});
        groups.forEach(g => {{ tbody.appendChild(g.header); if (g.content) tbody.appendChild(g.content); }});
    }}
</script>

<footer class="mt-5 pb-4 text-center text-muted" style="font-size: 0.8rem;">
    <div class="container border-top pt-3">
        <p>&copy; {datetime.now().year} SUSE AI Container Toolset</p>
    </div>
</footer>
</body>
</html>
    """
    with open(OUTPUT_HTML, 'w') as f: f.write(html_template)
    print(f"Dashboard generated: {OUTPUT_HTML}")

def generate_table_rows(groups):
    rows = []
    for idx, group in enumerate(groups):
        gid = f"group-{idx}"
        source = f'<a href="{APPCO_URL}" target="_blank" class="badge badge-source source-link">{group["source"]}</a>' if group['source'] == "AppCo" else f'<span class="badge badge-source">{group["source"]}</span>'
        arch_badges = "".join(f'<span class="badge badge-arch me-1">{a}</span>' for a in group['arch_list'])
        type_class = "type-chart" if group["type"] == "Chart" else "type-container"
        type_badge = f'<span class="badge badge-type {type_class}">{group["type"]}</span>'
        logo_html = f'<img src="{group["logo"]}" class="project-logo">' if group["logo"] else ""
        rows.append(f'<tr class="group-header collapsed" data-bs-toggle="collapse" data-bs-target="#{gid}"><td><i class="bi bi-caret-right-fill rotate-icon me-2"></i>{logo_html}<strong>{group["base_name"]}</strong></td><td>{type_badge}</td><td><span class="badge badge-suse">{group["latest_version"]}</span></td><td><span class="badge badge-count" style="font-size:0.7rem; color:var(--suse-pine); background:var(--suse-mint); padding:2px 5px; border-radius:10px;">{group["count"]}</span></td><td>{source}</td><td>{arch_badges}</td><td>{group["os"]}</td><td><small>{format_date(group["last_updated"])}</small></td></tr>')
        rows.append(f'<tr id="{gid}" class="collapse"><td colspan="8" class="p-0"><table class="table table-sm mb-0"><thead class="table-light"><tr><th class="ps-5">Version <small class="text-muted fw-normal ms-2">(Click for details)</small></th><th>Arch</th><th>Base OS</th><th>Last Updated</th><th>Digest</th></tr></thead><tbody>')
        for v in group['versions']:
            data_encoded = json.dumps(v['details']).replace('"', '%22').replace("'", "%27")
            v_arch_badge = f'<span class="badge badge-arch">{v["arch"]}</span>'
            logo_val = group["logo"] if group["logo"] else "None"
            row = f'<tr class="version-row" onclick="showDetails(\'{data_encoded}\', \'{v["name"]}\', \'{logo_val}\')"><td class="ps-5"><i class="bi bi-tag me-2 text-muted"></i>{v["version"]}</td><td>{v_arch_badge}</td><td><small>{v["os"]}</small></td><td><small>{format_date(v["last_updated"])}</small></td><td><code style="font-size:0.7rem;">{v["digest"][:15]}...</code></td></tr>'
            rows.append(row)
        rows.append('</tbody></table></td></tr>')
    return "\n".join(rows)

def format_date(d):
    if not d or d == "N/A": return "N/A"
    try: return datetime.fromisoformat(d.replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M')
    except: return d

if __name__ == "__main__": generate_html()
