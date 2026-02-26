# SUSE AI Containers Toolset

A specialized Python toolset designed to aggregate, process, and visualize container image and Helm chart metadata for the SUSE AI stack. It collects data from two primary sources: the Rancher Application Catalog (AppCo) and the SUSE Container Registry.

## Project Overview

This project consists of three main components:
1.  **Rancher API Scraper**: Queries `api.apps.rancher.io` to find all applications, components, and Helm charts within the `suse-ai` stack.
2.  **Registry Inspector**: Uses the `crane` utility to list and inspect OCI images within the `registry.suse.com/ai/` namespace.
3.  **Dashboard Generator**: Merges JSON data, groups versions, normalizes architectures, and creates a responsive, branded HTML dashboard. It processes SBOM resources and provides direct links to upstream artifact pages. It also automates deployment via GitHub Actions.

### Tech Stack
- **Language**: Python 3
- **Libraries**: `requests` (for API calls), `Jinja2` (for HTML templating)
- **External Tools**: `crane` (for OCI registry interactions)
- **Frontend**: Bootstrap 5, Bootstrap Icons, JavaScript (for theme, search, and grouping logic)
- **Fonts**: Official SUSE Typeface

## Key Files

- `README.md`: Project documentation and user guide.
- `requirements.txt`: Python dependencies.
- `.gitignore`: Standard exclusion list for Python and generated artifacts.
- `.github/workflows/static.yml`: GitHub Action workflow for automated deployment every 4 hours.
- `fetch_suse_ai_images.py`: Fetches image and chart metadata from Rancher's API, including project logos.
- `fetch_suse_registry_images.py`: Lists and inspects images in the `registry.suse.com/ai/` namespace using `crane`.
- `generate_dashboard.py`: Merges data, groups versions, and renders the dashboard using Jinja2.
- `templates/`: Directory containing Jinja2 templates (e.g., `dashboard.html.j2`).
- `suse_ai_images.json`: Raw data from Rancher API (Ignored by git).
- `suse_registry_images.json`: Raw data from SUSE Registry (Ignored by git).
- `index.html`: The final interactive, mobile-optimized dashboard (Ignored by git).

## Setup and Usage

### Prerequisites
- Python 3.x
- `crane` installed and in your PATH.
- **Registry Credentials** (Optional): Set `REGISTRY_USER` and `REGISTRY_PASSWORD` environment secrets for the `github-pages` environment if running in GitHub Actions.

### Installation
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Running the Toolset

1. **Fetch data from Rancher API:**
   ```bash
   ./venv/bin/python3 fetch_suse_ai_images.py
   ```

2. **Fetch data from SUSE Registry:**
   ```bash
   ./venv/bin/python3 fetch_suse_registry_images.py
   ```

3. **Generate the Dashboard:**
   ```bash
   ./venv/bin/python3 generate_dashboard.py
   ```

## Development Conventions

- **Data Format**: All scrapers must output JSON arrays of image/chart objects.
- **Image Grouping**: The dashboard must group versions of the same artifact by their base name.
- **Architecture Normalization**: Always normalize `amd64` to `x86_64` and display architectures as badges.
- **SBOM Ordering**: **CRITICAL**. SBOM links must always be sorted alphabetically by format (e.g., `CYCLONEDX` then `SPDX`) for a consistent UI.
- **Origin Links**: Always provide a link to the original AppCo artifact page (`https://apps.rancher.io/artifacts/{hash}`) in the detailed view.
- **Image Paths**: The dashboard must show full pullable paths based on artifact type:
  - AppCo Containers: `dp.apps.rancher.io/containers/`
  - AppCo Charts: `dp.apps.rancher.io/charts/`
  - Registry Images: `registry.suse.com/`
- **Mobile Rendering**: **CRITICAL**. The dashboard must render perfectly on mobile devices. This includes:
  - Using a compact grid for summary boxes (e.g., 2-column on small screens).
  - Ensuring the theme toggle is always visible and not hidden inside collapsed menus.
  - Using responsive typography and appropriate paddings to minimize vertical footprint.
- **UI/UX**: Support for Dark Mode, sortable columns with directional icons, "Expand/Collapse All" buttons, and a permanent "Clear Search" button is mandatory.
- **Styling**: Adhere to SUSE brand colors (Pine: `#0c322c`, Jungle: `#30ba78`, Persimmon: `#fe7c3f`).
- **Typography**: Must use the official SUSE font family.
- **Official Branding**: Use official SUSE logos from provided CDN/docs URLs.
- **Disclaimer**: Maintain the official "Persimmon" colored disclaimer bar at the top.
- **Python Environment**: Always prefer creating and using a virtual environment (`venv`) instead of installing packages globally with `pip`.
- **Push Policy**: **CRITICAL**. NEVER push changes to GitHub or any remote repository directly. Always ask for explicit user confirmation before any `git push` operation.
