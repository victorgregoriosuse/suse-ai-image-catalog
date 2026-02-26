import json
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

# File paths
RANCHER_JSON = "suse_ai_images.json"
REGISTRY_JSON = "suse_registry_images.json"
OUTPUT_HTML = "index.html"
TEMPLATE_DIR = "templates"
TEMPLATE_FILE = "dashboard.html.j2"

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

def format_date(d):
    if not d or d == "N/A": return "N/A"
    try: return datetime.fromisoformat(d.replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M')
    except: return d

def to_json_encoded(obj):
    return json.dumps(obj).replace('"', '%22').replace("'", "%27")

def generate_html():
    rancher_data = load_json(RANCHER_JSON)
    registry_data = load_json(REGISTRY_JSON)

    merged_data = []
    for item in rancher_data:
        image_name = item.get("image_name")
        tag = image_name.split(":", 1)[1] if ":" in image_name else None
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
            "tag": tag,
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
            "tag": item.get("tag"),
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
        group_data['latest_tag'] = latest['tag']
        group_data['count'] = len(group_data['versions'])
        unique_archs = sorted(list(set(v['arch'] for v in group_data['versions'] if v['arch'] and v['arch'] != "N/A")))
        group_data['arch_list'] = unique_archs
        group_data['os'] = latest['os']
        group_data['last_updated'] = latest['last_updated']
        final_groups.append(group_data)

    final_groups.sort(key=lambda x: (x['type'], x['base_name']))
    
    app_count = len([g for g in final_groups if g['type'] == "Container"])
    chart_count = len([g for g in final_groups if g['type'] == "Chart"])

    # Setup Jinja2 environment
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    env.filters['format_date'] = format_date
    env.filters['to_json_encoded'] = to_json_encoded
    
    template = env.get_template(TEMPLATE_FILE)
    
    context = {
        "FAVICON_URL": FAVICON_URL,
        "LOGO_URL": LOGO_URL,
        "DOCS_URL": DOCS_URL,
        "LANDING_URL": LANDING_URL,
        "APPCO_URL": APPCO_URL,
        "total_versions": len(merged_data),
        "app_count": app_count,
        "chart_count": chart_count,
        "rancher_count": len(rancher_data),
        "registry_count": len(registry_data),
        "generated_at": datetime.now().strftime('%Y-%m-%d %H:%M'),
        "groups": final_groups,
        "current_year": datetime.now().year
    }

    output = template.render(context)
    
    with open(OUTPUT_HTML, 'w') as f:
        f.write(output)
    
    print(f"Dashboard generated: {OUTPUT_HTML}")

if __name__ == "__main__":
    generate_html()
