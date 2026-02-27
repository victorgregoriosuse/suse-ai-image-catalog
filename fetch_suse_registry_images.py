import subprocess
import json
import logging
import re
import os
import shutil
from base64 import b64decode

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

REGISTRY = "registry.suse.com"
NAMESPACE = "ai/"
OUTPUT_FILE = "suse_registry_images.json"
SBOM_DIR = "sboms"

def cosign_is_installed():
    """Check if cosign is installed."""
    return shutil.which("cosign") is not None

def extract_sbom(full_image, image_data):
    """
    Extracts the CycloneDX SBOM from a container image using cosign.
    """
    if not full_image.startswith(f"{REGISTRY}/ai/containers/"):
        return

    if not cosign_is_installed():
        logger.warning("cosign is not installed, skipping SBOM extraction.")
        return

    logger.info(f"    Extracting SBOM for {full_image}")

    # Sanitize the image name for the filename
    safe_name = re.sub(r'[:/]', '-', full_image.replace(f"{REGISTRY}/", ""))
    sbom_filename = f"{safe_name}-cyclonedx.json"
    sbom_filepath = os.path.join(SBOM_DIR, sbom_filename)

    cmd = [
        "cosign", "verify-attestation",
        "--type", "cyclonedx",
        "--key", "https://documentation.suse.com/suse-ai/files/sr-pubkey.pem",
        full_image
    ]
    
    # Add credentials if available
    registry_user = os.getenv("REGISTRY_USER")
    registry_pass = os.getenv("REGISTRY_PASSWORD")
    if registry_user and registry_pass:
        cmd.extend(["--registry-username", registry_user, "--registry-password", registry_pass])

    # Set a local cache directory for cosign to avoid permission issues in some environments
    env = os.environ.copy()
    cosign_cache = os.path.join(os.getcwd(), ".cosign-cache")
    if not os.path.exists(cosign_cache):
        os.makedirs(cosign_cache)
    env["COSIGN_CACHE"] = cosign_cache

    try:
        # We capture stderr to log it if the command fails
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
            env=env
        )
        
        attestation = json.loads(result.stdout)
        payload = json.loads(b64decode(attestation['payload']))
        
        # The actual SBOM is in the 'predicate' field
        sbom_data = payload.get('predicate')

        if sbom_data:
            with open(sbom_filepath, 'w') as f:
                json.dump(sbom_data, f, indent=2)
            
            logger.info(f"      Successfully extracted SBOM to {sbom_filepath}")
            if "sboms" not in image_data:
                image_data["sboms"] = []
            
            image_data["sboms"].append({
                "path": sbom_filepath,
                "format": "CycloneDX"
            })
        else:
            logger.warning(f"      No SBOM predicate found for {full_image}")

    except subprocess.CalledProcessError as e:
        # Log the stderr for better debugging
        logger.warning(f"      Could not find CycloneDX SBOM for {full_image}.")
        if e.stderr:
            logger.debug(f"      Cosign error: {e.stderr.strip()}")
    except (json.JSONDecodeError, KeyError) as e:
        logger.error(f"      Failed to parse cosign output for {full_image}: {e}")
    except Exception as e:
        logger.error(f"      An unexpected error occurred during SBOM extraction for {full_image}: {e}")


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
        if "UNAUTHORIZED" in e.stderr:
            logger.warning(f"Access to {cmd_str} is unauthorized. This repository might be private or require login.")
        else:
            logger.error(f"Command failed: {cmd_str}")
            logger.error(f"Exit Code: {e.returncode}")
            logger.error(f"Stderr: {e.stderr}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error running command {' '.join(cmd)}: {e}")
        return None


# Known repositories to check if catalog is incomplete
KNOWN_REPOS = [
    "ai/charts/litellm",
    "ai/charts/qdrant",
    "ai/containers/litellm",
    "ai/containers/litellm-database",
    "ai/containers/qdrant",
    "ai/hello-world"
]

def get_repositories():
    logger.info(f"Fetching catalog for {REGISTRY}")
    output = run_command(["crane", "catalog", REGISTRY])
    
    repos = []
    if output:
        lines = output.splitlines()
        logger.info(f"Total repositories found in catalog: {len(lines)}")
        repos = [line for line in lines if line.startswith(NAMESPACE)]
    else:
        logger.error(f"No catalog output from {REGISTRY}")

    # If no repositories found in catalog, try known ones
    if not repos:
        logger.warning(f"No repositories found in catalog for namespace {NAMESPACE}. Trying known list...")
        for repo in KNOWN_REPOS:
            # Verify repository exists by trying to list tags
            logger.info(f"  Verifying {repo}...")
            if run_command(["crane", "ls", f"{REGISTRY}/{repo}"]):
                repos.append(repo)
    
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

    # Extract embedded SBOMs for container images
    extract_sbom(full_image, image_data)
    
    return image_data

def main():
    # Create SBOMs directory if it doesn't exist
    if not os.path.exists(SBOM_DIR):
        os.makedirs(SBOM_DIR)

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
