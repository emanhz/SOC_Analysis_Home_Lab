# Installation Guide

## Table of Contents
- [Prerequisites](#prerequisites)
- [System Requirements](#system-requirements)
- [Network Setup](#network-setup)
- [Virtual Machine Installation](#virtual-machine-installation)
- [Tool Installation](#tool-installation)

## Prerequisites

### Host System Requirements
- CPU: Intel/AMD processor with virtualization support (VT-x/AMD-V)
- RAM: Minimum 16GB
- Storage: 100GB free space
- OS: Windows 10/11 Pro (recommended)
- Hypervisor: VMware Workstation Pro 17+ or VirtualBox 7.0+

### Required Software
- Downloaded VM images:
  - Kali Linux VM image
  - Windows 10 ISO
  - Ubuntu Server 22.04 LTS ISO
- Virtual machine software
- Network configuration tools

## Network Setup

### Network Architecture
```plaintext
Security Lab Network Configuration:

+----------------------+     +-------------------------+     +-----------------------+
|    Kali Linux VM     |     |      Windows 10 VM      |     |    Ubuntu Server VM   |
| (192.168.1.10/24)   |     |   (192.168.1.20/24)    |     |  (192.168.1.30/24)   |
|    Gateway: .1      |     |      Gateway: .1       |     |     Gateway: .1      |
+----------------------+     +-------------------------+     +-----------------------+
           |                           |                             |
           +---------------------------+-----------------------------+
                                      |
                            +--------------------+
                            |    NAT Network     |
                            |  (192.168.1.0/24)  |
                            +--------------------+
```

### Network Configuration Steps
1. Create NAT Network in hypervisor
2. Configure network adapters for each VM
3. Set static IP addresses
4. Verify connectivity between VMs

## Virtual Machine Installation

### 1. Kali Linux VM Setup
```bash
# VM Specifications
RAM: 4GB
CPU: 2 cores
Storage: 40GB
Network Adapters: 2 (NAT + Host-only)

# Post-installation steps
sudo apt update
sudo apt upgrade -y

# Install required packages
sudo apt install -y \
    suricata \
    elasticsearch \
    kibana \
    logstash \
    python3-pip \
    git \
    curl \
    wget
```

### 2. Windows 10 VM Setup
```powershell
# VM Specifications
RAM: 3GB
CPU: 2 cores
Storage: 30GB
Network: NAT Network

# Install Chocolatey
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Install required tools
choco install -y `
    sysmon `
    wireshark `
    wazuh-agent `
    notepadplusplus `
    7zip
```

### 3. Ubuntu Server VM Setup
```bash
# VM Specifications
RAM: 2GB
CPU: 1 core
Storage: 20GB
Network: NAT Network

# Update system
sudo apt update
sudo apt upgrade -y

# Install required packages
sudo apt install -y \
    rsyslog \
    auditd \
    net-tools \
    tcpdump \
    curl
```

## Tool Installation

### 1. Wazuh Manager Installation
```bash
# On Kali Linux VM
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list

apt-get update
apt-get install wazuh-manager
```

### 2. ELK Stack Installation
```bash
# Import Elasticsearch GPG Key
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

# Add Elastic repository
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# Install ELK Stack
sudo apt update
sudo apt install elasticsearch kibana logstash
```

### 3. TheHive Installation
```bash
# Install Java
sudo apt install -y openjdk-11-jre-headless

# Install Cassandra
echo "deb https://debian.cassandra.apache.org 41x main" | sudo tee -a /etc/apt/sources.list.d/cassandra.list
curl https://downloads.apache.org/cassandra/KEYS | sudo apt-key add -
sudo apt update
sudo apt install cassandra

# Install TheHive
wget -O- https://raw.githubusercontent.com/TheHive-Project/TheHive/master/PGP-PUBLIC-KEY | sudo apt-key add -
echo 'deb https://deb.thehive-project.org release main' | sudo tee -a /etc/apt/sources.list.d/thehive.list
sudo apt update
sudo apt install thehive4
```

### 4. Verify Installation
```bash
# Check service status
systemctl status wazuh-manager
systemctl status elasticsearch
systemctl status kibana
systemctl status logstash
systemctl status thehive

# Verify Elasticsearch is running
curl -X GET "localhost:9200/_cluster/health?pretty"

# Check Wazuh manager
/var/ossec/bin/ossec-control status
```

## Next Steps
After completing the installation:
1. Proceed to the Configuration Guide
2. Set up initial security baselines
3. Configure monitoring tools
4. Test system connectivity

## Troubleshooting Common Installation Issues
- If services fail to start, check system resources
- Verify network connectivity between VMs
- Check service logs for specific errors
- Ensure all prerequisites are met

---
