# SUSE AI Containers Toolset

A specialized Python toolset designed to aggregate, process, and visualize container image and Helm chart metadata for the SUSE AI stack. It collects data from two primary sources: the Rancher Application Catalog (AppCo) and the SUSE Container Registry.

## Project Overview

This project consists of three main components:
1.  **Rancher API Scraper**: Queries `api.apps.rancher.io` to find all applications, components, and Helm charts within the `suse-ai` stack.
2.  **Registry Inspector**: Uses the `crane` utility to list and inspect OCI images within the `registry.suse.com/ai/` namespace and `cosign` to extract embedded CycloneDX SBOMs.
3.  **Dashboard Generator**: Merges data, groups versions, and creates a responsive HTML dashboard with an automated changelog and deep-linking support.

### Tech Stack
- **Language**: Python 3
- **Libraries**: `requests` (API), `Jinja2` (Templating)
- **External Tools**: `crane` (OCI), `cosign` (SBOM)
- **Frontend**: Bootstrap 5, Bootstrap Icons, Vanilla JS

## Key Files

- `data/`: **CRITICAL**. Contains baseline JSON data and the persistent `changelog.json`. These files are tracked in Git to ensure consistent change detection.
- `run_all.py`: Orchestrates the entire update workflow, including change detection and conditional generation.
- `fetch_suse_ai_images.py`: Fetches AppCo metadata and detects changes.
- `fetch_suse_registry_images.py`: Lists/inspects Registry images and extracts SBOMs.
- `generate_dashboard.py`: Logic for data merging and Jinja2 rendering.
- `templates/dashboard.html.j2`: Main dashboard template.
- `.github/workflows/static.yml`: Automated deployment workflow with bot-powered changelog commits.

## Development Conventions

- **Baseline Management**: **CRITICAL**. JSON files in `data/` are the source of truth for change detection. Scripts must compare live API data against these files.
- **Change Detection**: Use artifact digests (SHA256) to determine if a version has been updated.
- **Automated Changelog**: All new or updated artifacts must be recorded in `data/changelog.json` with a consistent format: `[Action] [Type] ([Source]): [Name] ([Arch])`.
- **Indentation & Structure**: Maintain strict Python indentation and follow the existing orchestration pattern in `run_all.py`.
- **Deep-Linking**: **CRITICAL**. Support direct anchors for image groups, versions, and changelog entries. Use `history.replaceState` to update the URL dynamically.
- **UI Consistency**: Ensure all tables (images and changelog) share identical styling, including padding, headers, and corner rounding.
- **Deployment Efficiency**: Only redeploy the dashboard and save new caches if `data_changed=true` is reported by the orchestration script.
- **Push Policy**: **CRITICAL**. NEVER push changes to GitHub directly. Always ask for explicit user confirmation before any `git push` operation.
