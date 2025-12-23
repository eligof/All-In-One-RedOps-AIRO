#!/usr/bin/env bash
# Cloud Security Module
# 8 cloud security commands

airo_awscheck() {
    echo "[*] Checking AWS configuration..."
    
    if command -v aws >/dev/null 2>&1; then
        echo -e "\nAWS CLI Version:"
        aws --version
        
        echo -e "\nConfigured Profiles:"
        aws configure list-profiles 2>/dev/null || cat ~/.aws/config 2>/dev/null | grep "^\[profile" || echo "No profiles found"
        
        echo -e "\nCurrent Identity:"
        aws sts get-caller-identity 2>/dev/null || echo "Not authenticated"
    else
        echo "[-] AWS CLI not installed"
    fi
}

airo_azcheck() {
    echo "[*] Checking Azure CLI configuration..."
    
    if command -v az >/dev/null 2>&1; then
        echo -e "\\nAzure CLI Version:"
        az version --output table 2>/dev/null
        
        echo -e "\\nLogged-in account:"
        az account show --output table 2>/dev/null || echo "Not authenticated"
    else
        echo "[-] Azure CLI (az) not installed"
    fi
}

airo_gcpcheck() {
    echo "[*] Checking GCP CLI configuration..."
    
    if command -v gcloud >/dev/null 2>&1; then
        echo -e "\\nGCloud Version:"
        gcloud --version | head -5
        
        echo -e "\\nActive config/account:"
        gcloud config list account --format 'value(core.account)' 2>/dev/null || echo "No active account"
        gcloud config list project --format 'value(core.project)' 2>/dev/null || echo "No project set"
    else
        echo "[-] Google Cloud CLI (gcloud) not installed"
    fi
}

airo_s3scan() {
    local bucket="${1:?Usage: s3scan <bucket>}"
    
    echo "[*] Checking S3 bucket: $bucket"
    
    if command -v aws >/dev/null 2>&1; then
        aws s3 ls "s3://$bucket" 2>/dev/null || echo "[-] Unable to list bucket (permissions or not found)"
    else
        echo "[-] AWS CLI not installed"
    fi
}

airo_ec2scan() {
    local region="${1:-}"
    
    echo "[*] Listing EC2 instances${region:+ in $region}..."
    
    if command -v aws >/dev/null 2>&1; then
        if [[ -n "$region" ]]; then
            aws ec2 describe-instances --region "$region" --query 'Reservations[].Instances[].InstanceId' --output table 2>/dev/null
        else
            aws ec2 describe-instances --query 'Reservations[].Instances[].InstanceId' --output table 2>/dev/null
        fi
    else
        echo "[-] AWS CLI not installed"
    fi
}

airo_dockerscan() {
    echo "[*] Scanning Docker for misconfigurations..."
    
    if command -v docker >/dev/null 2>&1; then
        echo -e "\\nDocker Version:"
        docker --version
        
        echo -e "\\nRunning Containers:"
        docker ps
        
        echo -e "\\nAll Containers:"
        docker ps -a
        
        echo -e "\\nImages:"
        docker images
    else
        echo "[-] Docker not installed"
    fi
}

airo_kubescan() {
    echo "[*] Scanning Kubernetes cluster..."
    
    if command -v kubectl >/dev/null 2>&1; then
        echo -e "\\nKubernetes Version:"
        kubectl version --short
        
        echo -e "\\nNodes:"
        kubectl get nodes
        
        echo -e "\\nPods:"
        kubectl get pods --all-namespaces
    else
        echo "[-] kubectl not installed"
    fi
}

airo_containerbreak() {
    echo "[*] Container Breakout Techniques"
    
    cat << 'CONTAINER_BREAK'
1. Privileged Container:
   docker run --rm -it --privileged ubuntu bash
   # Inside container:
   fdisk -l
   mount /dev/sda1 /mnt

2. Docker Socket Mount:
   # If /var/run/docker.sock is mounted:
   apt-get update && apt-get install curl
   curl --unix-socket /var/run/docker.sock http://localhost/containers/json

3. Capabilities Abuse:
   # With SYS_ADMIN capability:
   mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

Tools:
  • amicontained
  • deepce
  • CDK (Container Detection Kit)
CONTAINER_BREAK
}

export -f airo_awscheck airo_azcheck airo_gcpcheck airo_s3scan airo_ec2scan
export -f airo_dockerscan airo_kubescan airo_containerbreak
