import requests
import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

BASE_URL = "https://api.apps.rancher.io/v1"
SITE_URL = "https://apps.rancher.io"
STACK_SLUG = "suse-ai"
OUTPUT_FILE = "suse_ai_images.json"

def fetch_json(endpoint):
    url = f"{BASE_URL}{endpoint}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Error fetching {url}: {e}")
        return None

def main():
    logger.info(f"Fetching stack details for: {STACK_SLUG}")
    stacks_data = fetch_json("/stacks")
    if not stacks_data:
        return

    suse_ai_stack = next((s for s in stacks_data.get('items', []) if s['slug_name'] == STACK_SLUG), None)
    if not suse_ai_stack:
        logger.error(f"Stack '{STACK_SLUG}' not found.")
        return

    results = []
    applications = suse_ai_stack.get('dependencies', {}).get('applications', [])
    
    for app_info in applications:
        app_slug = app_info['slug_name']
        logger.info(f"Processing application: {app_slug}")
        
        app_details = fetch_json(f"/applications/{app_slug}")
        if not app_details:
            continue
            
        # Get application logo
        logo_path = app_details.get('logo_url')
        app_logo_url = f"{SITE_URL}{logo_path}" if logo_path else None

        components = app_details.get('dependencies', {}).get('components', [])
        for comp_info in components:
            comp_slug = comp_info['slug_name']
            logger.info(f"  Processing component: {comp_slug}")
            
            comp_details = fetch_json(f"/components/{comp_slug}")
            if not comp_details:
                continue
            
            # Branches contain versions
            for branch in comp_details.get('branches', []):
                for version in branch.get('versions', []):
                    version_num = version.get('version_number')
                    artifacts = version.get('artifacts', [])
                    
                    for artifact in artifacts:
                        pkg_format = artifact.get('packaging_format')
                        if pkg_format in ['CONTAINER', 'HELM_CHART']:
                            image_data = {
                                "application": app_slug,
                                "app_logo_url": app_logo_url,
                                "component": comp_slug,
                                "image_name": artifact.get('name'),
                                "version": version_num,
                                "packaging_format": pkg_format,
                                "architecture": artifact.get('architecture'),
                                "os_family": artifact.get('operating_system', {}).get('family'),
                                "os_version": artifact.get('operating_system', {}).get('version'),
                                "digest": f"{artifact.get('digest', {}).get('hash_function')}:{artifact.get('digest', {}).get('value')}",
                                "last_updated": artifact.get('registered_at'),
                                "sboms": [r for r in artifact.get('resources', []) if r.get('type') == 'SBOM'],
                                "labels": artifact.get('labels', {})
                            }
                            results.append(image_data)

    logger.info(f"Found {len(results)} container/chart artifacts.")
    
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(results, f, indent=2)
    
    logger.info(f"Results saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
