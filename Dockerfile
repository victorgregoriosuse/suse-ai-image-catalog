ARG BUILDPLATFORM=linux/amd64
# Revert to the Python base image
FROM --platform=${BUILDPLATFORM} registry.suse.com/bci/python:3.11

# Install zypper if it's not present in the Python image
RUN zypper --non-interactive install -y zypper

# Install necessary tools for key import and package management
RUN zypper --non-interactive install -y curl gnupg

# Fetch the GPG key for the backports repository
RUN curl -fsSL https://download.opensuse.org/repositories/openSUSE:/Backports:/SLE-15-SP7/standard/repodata/repomd.xml.key -o /tmp/repo.key

# Import the GPG key
RUN rpm --import /tmp/repo.key

# Clean up the temporary key file
RUN rm /tmp/repo.key

# Add the backports repository
RUN zypper --non-interactive addrepo https://download.opensuse.org/repositories/openSUSE:Backports:SLE-15-SP7/standard/openSUSE:Backports:SLE-15-SP7.repo

# Refresh repositories
RUN zypper --non-interactive refresh

# Install cosign, crane, and trivy from the backports repository
# Trivy version 0.59.1 is from the backports repo and is now considered acceptable.
RUN zypper --non-interactive install -y cosign crane trivy

# Clean up zypper cache to reduce image size
RUN zypper --non-interactive clean --all

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Default command is to run the full pipeline
CMD ["python3", "run_all.py"]
