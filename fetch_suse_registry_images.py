import subprocess
import json
import logging
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

REGISTRY = "registry.suse.com"
NAMESPACE = "ai/"
OUTPUT_FILE = "suse_registry_images.json"

def run_command(cmd):
    try:
        # Check if crane is even available before running
        if cmd[0] == "crane":
            try:
                subprocess.run(["crane", "version"], capture_output=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                logger.error("crane command not found in PATH")
                return None

        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        cmd_str = ' '.join(cmd)
        logger.error(f"Command failed: {cmd_str}")
        logger.error(f"Exit Code: {e.returncode}")
        logger.error(f"Stderr: {e.stderr}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error running command {' '.join(cmd)}: {e}")
        return None

def get_repositories():
    logger.info(f"Fetching catalog for {REGISTRY}")
    output = run_command(["crane", "catalog", REGISTRY])
    if not output:
        logger.error(f"No catalog output from {REGISTRY}")
        return []
    
    lines = output.splitlines()
    logger.info(f"Total repositories found in catalog: {len(lines)}")
    if len(lines) > 0:
        logger.info(f"First 5 repositories: {lines[:5]}")
        logger.info(f"Last 5 repositories: {lines[-5:]}")
    
    repos = [line for line in lines if line.startswith(NAMESPACE)]
    return repos

def get_tags(repo):
    logger.info(f"  Fetching tags for {repo}")
    output = run_command(["crane", "ls", f"{REGISTRY}/{repo}"])
    if not output:
        return []
    
    # Filter out .sig and .att tags
    tags = [line for line in output.splitlines() if not (line.endswith(".sig") or line.endswith(".att"))]
    return tags

def get_image_details(repo, tag):
    full_image = f"{REGISTRY}/{repo}:{tag}"
    logger.info(f"    Inspecting {full_image}")
    
    digest = run_command(["crane", "digest", full_image])
    config_json = run_command(["crane", "config", full_image])
    
    if not config_json:
        return None
    
    try:
        config = json.loads(config_json)
    except json.JSONDecodeError:
        logger.error(f"Failed to decode config for {full_image}")
        return None

    # Try to find SBOMs by looking for .att tags matching the digest
    # In OCI registries, SBOMs are often stored as referrers or attachments
    # We'll check if a .att tag exists for this digest
    sbom_tag = digest.replace(":", "-") + ".att"
    
    # Check if this .att tag exists in the repo
    # This might be slow if we do it for every image, but let's see
    
    image_data = {
        "repository": repo,
        "tag": tag,
        "image_name": f"{repo}:{tag}",
        "architecture": config.get("architecture"),
        "os": config.get("os"),
        "digest": digest,
        "created": config.get("created"),
        "labels": config.get("config", {}).get("Labels", {}),
        "entrypoint": config.get("config", {}).get("Entrypoint"),
        "cmd": config.get("config", {}).get("Cmd")
    }
    
    return image_data

def main():
    # Ensure the output file is always initialized as an empty list
    with open(OUTPUT_FILE, 'w') as f:
        json.dump([], f)

    repos = get_repositories()
    if not repos:
        logger.error(f"No repositories found in {NAMESPACE}")
        return

    logger.info(f"Found {len(repos)} repositories in {NAMESPACE}")
    
    all_images = []
    for repo in repos:
        tags = get_tags(repo)
        if not tags:
            logger.warning(f"  No tags found for {repo}")
            continue
            
        for tag in tags:
            details = get_image_details(repo, tag)
            if details:
                all_images.append(details)
            else:
                logger.warning(f"    Failed to get details for {repo}:{tag}")
                
    logger.info(f"Found total of {len(all_images)} images.")
    
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(all_images, f, indent=2)
    
    logger.info(f"Results saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
