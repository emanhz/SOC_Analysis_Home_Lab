# Configuration Guide

## Table of Contents
- [Initial Setup](#initial-setup)
- [Security Tools Configuration](#security-tools-configuration)
- [Monitoring Setup](#monitoring-setup)
- [Integration Configuration](#integration-configuration)

## Initial Setup

### Network Configuration
```bash
# Kali Linux network setup
sudo nano /etc/network/interfaces

auto eth0
iface eth0 inet static
    address 192.168.1.10
    netmask 255.255.255.0
    gateway 192.168.1.1


# Windows 10 network setup (PowerShell)
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.1.20 -PrefixLength 24 -DefaultGateway 192.168.1.1

# Ubuntu Server network setup
sudo nano /etc/netplan/00-installer-config.yaml

network:
  ethernets:
    ens33:
      addresses: [192.168.1.30/24]
      gateway4: 192.168.1.1
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
  version: 2
```

## Security Tools Configuration

### 1. Wazuh Configuration

#### Manager Configuration
```yaml
# /var/ossec/etc/ossec.conf
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
  </remote>
</ossec_config>
```

#### Agent Configuration
```xml
<!-- /var/ossec/etc/shared/agent.conf -->
<agent_config>
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
  </localfile>
  
  <syscheck>
    <directories check_all="yes">C:\Windows\System32\</directories>
    <directories check_all="yes">C:\Program Files\</directories>
    <ignore>C:\Windows\System32\LogFiles</ignore>
  </syscheck>
</agent_config>
```

### 2. ELK Stack Configuration

#### Elasticsearch Configuration
```yaml
# /etc/elasticsearch/elasticsearch.yml
cluster.name: security-monitoring
node.name: node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 192.168.1.10
http.port: 9200
discovery.type: single-node
xpack.security.enabled: true

# JVM configuration
# /etc/elasticsearch/jvm.options
-Xms2g
-Xmx2g
```

#### Logstash Configuration
```conf
# /etc/logstash/conf.d/security.conf
input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate => "/etc/logstash/certs/logstash.crt"
    ssl_key => "/etc/logstash/certs/logstash.key"
  }
}

filter {
  if [event][module] == "windows" {
    mutate {
      add_field => { "environment" => "security_lab" }
    }
  }
  
  if [event][module] == "suricata" {
    date {
      match => [ "timestamp", "ISO8601" ]
      target => "@timestamp"
    }
  }
}

output {
  elasticsearch {
    hosts => ["192.168.1.10:9200"]
    index => "security-events-%{+YYYY.MM.dd}"
    user => "elastic"
    password => "${ELASTIC_PASSWORD}"
  }
}
```

#### Kibana Configuration
```yaml
# /etc/kibana/kibana.yml
server.port: 5601
server.host: "192.168.1.10"
elasticsearch.hosts: ["http://192.168.1.10:9200"]
elasticsearch.username: "kibana_system"
elasticsearch.password: "${KIBANA_PASSWORD}"
```

### 3. Suricata Configuration
```yaml
# /etc/suricata/suricata.yaml
vars:
  address-groups:
    HOME_NET: "[192.168.1.0/24]"
    EXTERNAL_NET: "!$HOME_NET"

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - files
        - ssh

af-packet:
  - interface: eth1
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes
```

## Monitoring Setup

### 1. Sysmon Configuration
```xml
<!-- C:\Windows\sysmon.xml -->
<Sysmon schemaversion="4.70">
  <HashAlgorithms>SHA1,MD5,SHA256,IMPHASH</HashAlgorithms>
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <Rule name="Suspicious PowerShell Commands">
        <CommandLine condition="contains">-enc</CommandLine>
        <CommandLine condition="contains">-encode</CommandLine>
      </Rule>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

### 2. Windows Event Forwarding
```xml
<!-- Windows Event Collector Configuration -->
wecutil qc /q
winrm quickconfig -q
winrm set winrm/config/client @{TrustedHosts="192.168.1.10"}
```

## Integration Configuration

### 1. TheHive Integration
```conf
# /etc/thehive/application.conf
play.http.secret.key="..."

notification.webhook.endpoints = [
  {
    name: "security-alerts"
    url: "http://wazuh-manager:9000/alerts"
    version: 0
    wsConfig: {}
    includedTheHiveOrganisations: ["*"]
    includedDataTypes: ["alert"]
  }
]
```

### 2. Wazuh-ELK Integration
```yaml
# /etc/filebeat/filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/ossec/logs/alerts/alerts.json
  json.keys_under_root: true

output.logstash:
  hosts: ["192.168.1.10:5044"]
  ssl.certificate_authorities: ["/etc/filebeat/certs/ca.pem"]
  ssl.certificate: "/etc/filebeat/certs/cert.pem"
  ssl.key: "/etc/filebeat/certs/cert.key"
```

## Security Configurations

### 1. Firewall Rules
```bash
# UFW Configuration
sudo ufw default deny incoming
sudo ufw allow from 192.168.1.0/24 to any port 22
sudo ufw allow from 192.168.1.0/24 to any port 5601
sudo ufw allow from 192.168.1.0/24 to any port 9200
```

### 2. SSL/TLS Configuration
```bash
# Generate certificates
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout private.key -out certificate.crt

# Configure SSL in Nginx
server {
    listen 443 ssl;
    ssl_certificate /etc/nginx/certs/certificate.crt;
    ssl_certificate_key /etc/nginx/certs/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
}
```

## Validation Steps
1. Verify all services are running
2. Test log collection
3. Confirm alert generation
4. Check data visualization
5. Validate integrations

---
