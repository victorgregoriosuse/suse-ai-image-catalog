# SUSE AI Containers Toolset

An automated toolset designed to aggregate, process, and visualize container image and Helm chart metadata for the SUSE AI stack. This project collects data from both the Rancher Application Catalog (AppCo) and the SUSE Container Registry to provide a single, unified, and interactive dashboard.

## Features

- **Artifact Scraper**: Automatically queries the Rancher API for both CONTAINER and HELM_CHART artifacts within the suse-ai stack.
- **Registry Inspector**: Uses the crane utility to perform deep inspection of OCI images in the registry.suse.com/ai/ namespace.
- **Efficient Caching**: Implements digest-based caching to skip redundant API calls and expensive OCI registry operations (config inspection, SBOM extraction) if the artifact hasn't changed.
- **Automated Changelog**: Automatically detects and records new or updated images and versions, maintaining a persistent, timestamped history in the dashboard.
- **SBOM Extraction**: Uses cosign to extract embedded CycloneDX SBOMs from container images in the SUSE Registry.
- **Vulnerability Scanning**: Uses Trivy to scan extracted SBOMs and surface per-image vulnerability summaries (Critical, High, Medium, Low) directly in the dashboard.
- **Unified & Grouped Dashboard**: 
  - **Version Grouping**: Groups different versions of the same artifact into a single collapsible row.
  - **Type Classification**: Automatically distinguishes between Applications (Containers) and Charts.
  - **Full OCI Paths**: Displays ready-to-pull OCI paths (dp.apps.rancher.io/containers/, dp.apps.rancher.io/charts/, or registry.suse.com/).
  - **Interactive UX**: Sortable columns, search with quick-clear, "Expand All" and "Collapse All" controls, and a "Back to Top" floating button for easy navigation.
  - **Deep-Linking**: Supports direct anchors for individual image groups, versions, and changelog entries. The URL automatically updates to reflect the current UI state.
  - **Mobile Optimized**: Responsive design with a compact header grid and permanently visible theme toggle.
- **Optimized Deployment**: GitHub Action workflow that uses Git as the source of truth for baseline data and only redeploys the dashboard when changes are detected.

## Tech Stack

- **Backend**: Python 3.x
- **Templating**: [Jinja2](https://jinja.palletsprojects.com/)
- **Registry Tools**: [crane](https://github.com/google/go-containerregistry/tree/main/cmd/crane), [cosign](https://github.com/sigstore/cosign)
- **Vulnerability Scanner**: [Trivy](https://github.com/aquasecurity/trivy)
- **Frontend**: Bootstrap 5, Bootstrap Icons, Vanilla JavaScript
- **Data Format**: JSON Baseline (tracked in Git)

## Prerequisites

- **Python 3.10+**
- **crane** and **cosign**: Must be installed and available in your PATH.
- **trivy**: Must be installed and available in your PATH for vulnerability scanning.
- **Registry Credentials**: Optional but recommended for automated CI environments. Set `REGISTRY_USER` and `REGISTRY_PASSWORD` as Environment Secrets in GitHub.

## Setup

1. **Clone and Install:**
   ```bash
   git clone https://github.com/e-minguez/suse-ai-image-catalog.git
   cd suse-ai-image-catalog
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

## Usage

The toolset is designed to be run via an orchestration script that manages data collection, change detection, and dashboard generation.

### Run All (Recommended)
This script handles the entire workflow, updating the changelog only when changes are detected and conditionally rebuilding the dashboard.
```bash
python run_all.py
```

## Testing

To run the automated unit tests, ensure `pytest` is installed and run:
```bash
export PYTHONPATH=$PYTHONPATH:.
pytest tests/
```

### Manual Steps
You can still run individual components if needed:
1. **Fetch AppCo Data**: `python fetch_suse_ai_images.py`
2. **Fetch Registry Data**: `python fetch_suse_registry_images.py`
3. **Process Vulnerabilities**: `python process_vulnerabilities.py`
4. **Generate Dashboard**: `python generate_dashboard.py`

## Project Structure

- `data/`: Directory containing baseline JSON metadata and the persistent changelog (Tracked by Git).
- `run_all.py`: Orchestration script for the entire update and generation workflow.
- `fetch_suse_ai_images.py`: Fetches AppCo metadata and detects changes.
- `fetch_suse_registry_images.py`: Lists/inspects Registry images and extracts SBOMs.
- `process_vulnerabilities.py`: Scans extracted SBOMs with Trivy and annotates image data with vulnerability summaries.
- `generate_dashboard.py`: Merges all data sources and renders the Jinja2 template.
- `.github/workflows/static.yml`: Optimized GitHub Action for conditional deployment and automated bot commits.
- `templates/`: Directory containing the Jinja2 `dashboard.html.j2` template.
- `static/`: Static assets (logos, favicons) served with the dashboard.
- `sboms/`: Local cache for extracted CycloneDX SBOMs (Ignored by Git).
- `vulns/`: Local cache for Trivy vulnerability scan results (Ignored by Git).
- `tests/`: Directory containing automated unit tests.
- `index.html`: The generated interactive report (Ignored by Git).

## Disclaimer

This is an unofficial tool and is not officially supported or endorsed by SUSE. All data is aggregated from public sources for informational purposes only.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
