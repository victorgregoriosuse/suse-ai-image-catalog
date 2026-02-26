# SUSE AI Containers Toolset

An automated toolset designed to aggregate, process, and visualize container image and Helm chart metadata for the SUSE AI stack. This project collects data from both the Rancher Application Catalog (AppCo) and the SUSE Container Registry to provide a single, unified, and interactive dashboard.

## Features

- **Artifact Scraper**: Automatically queries the Rancher API for both CONTAINER and HELM_CHART artifacts within the suse-ai stack.
- **Registry Inspector**: Uses the crane utility to perform deep inspection of OCI images in the registry.suse.com/ai/ namespace.
- **Unified & Grouped Dashboard**: 
  - **Version Grouping**: Groups different versions of the same artifact into a single collapsible row.
  - **Type Classification**: Automatically distinguishes between Applications (Containers) and Charts.
  - **Full OCI Paths**: Displays ready-to-pull OCI paths (dp.apps.rancher.io/containers/, dp.apps.rancher.io/charts/, or registry.suse.com/).
  - **Project Branding**: Displays official project logos for AppCo applications.
  - **Interactive UX**: Sortable columns with clear indicators, search with quick-clear, "Expand All" and "Collapse All" controls, and persistent Dark Mode.
  - **Official Typography**: Uses the official SUSE brand font family for a professional look.
  - **Structured Metadata**: Detailed view modal with formatted digests, architectures (normalized to x86_64), and Base OS info.
  - **SBOM Integration**: Displays links to SPDX and CycloneDX Software Bill of Materials for AppCo artifacts, with consistent alphabetical ordering.
  - **Origin Linking**: Direct links to the original Rancher Application Catalog (AppCo) artifact pages for upstream documentation.
  - **GitHub Integration**: Direct link to the source repository in the dashboard navbar and footer.
  - **Mobile Optimized**: Responsive design with a compact header grid and permanently visible theme toggle.
- **Automated Deployment**: GitHub Action workflow to automatically update and publish the dashboard to GitHub Pages every 4 hours.

## Tech Stack

- **Backend**: Python 3.x
- **Templating**: [Jinja2](https://jinja.palletsprojects.com/)
- **Registry Tools**: [crane](https://github.com/google/go-containerregistry/tree/main/cmd/crane)
- **Frontend**: Bootstrap 5, Bootstrap Icons, Vanilla JavaScript
- **Data Format**: JSON
- **Fonts**: SUSE (Official custom typeface)

## Prerequisites

- **Python 3.10+**
- **crane**: Must be installed and available in your PATH.
  - Installation on macOS: brew install crane
  - Installation on Linux: go install github.com/google/go-containerregistry/cmd/crane@latest
- **Registry Credentials**: Optional but recommended for automated CI environments to avoid rate limits or access restricted namespaces.
  - For GitHub Actions: Set `REGISTRY_USER` and `REGISTRY_PASSWORD` as Environment Secrets in the `github-pages` environment.

## Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/e-minguez/suse-ai-image-catalog.git
   cd suse-ai-image-catalog
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Usage

The toolset operates in three steps:

### 1. Fetch Rancher AI Stack Data (AppCo)
Fetches metadata for official SUSE AI applications and charts from the Rancher API.
```bash
python3 fetch_suse_ai_images.py
```

### 2. Fetch SUSE Registry Images
Inspects images directly from the registry.suse.com/ai/ namespace.
```bash
python3 fetch_suse_registry_images.py
```

### 3. Generate the Dashboard
Merges the data, groups versions, classifies types, and creates the interactive HTML report (index.html).
```bash
python3 generate_dashboard.py
```

After running these commands, open index.html in your web browser to view the results.

## Project Structure

- `.github/workflows/static.yml`: GitHub Action for automated 4-hour updates and deployment.
- `requirements.txt`: Python dependencies (now including Jinja2).
- `templates/`: Directory containing Jinja2 HTML templates.
  - `dashboard.html.j2`: The main dashboard template.
- `.gitignore`: Standard exclusion list for Python, environments, and generated data/reports.
- `fetch_suse_ai_images.py`: Scraper for the Rancher Apps API (Supports containers and charts).
- `fetch_suse_registry_images.py`: Inspector for the SUSE AI Registry.
- `generate_dashboard.py`: Logic for data merging, version grouping, and rendering the Jinja2 template.
- `suse_ai_images.json`: Raw metadata from Rancher (Ignored by git).
- `suse_registry_images.json`: Raw metadata from SUSE Registry (Ignored by git).
- `index.html`: The final interactive report (Ignored by git, main deployment entry point).

## Disclaimer

This is an unofficial tool and is not officially supported or endorsed by SUSE. All data is aggregated from public sources for informational purposes only.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
