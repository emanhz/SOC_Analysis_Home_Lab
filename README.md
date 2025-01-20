# 🛡️ SOC Analysis Home Lab

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
[![Lab Status](https://img.shields.io/badge/Lab_Status-Active-brightgreen)](https://github.com/yourusername/security-monitoring-lab)
[![Documentation](https://img.shields.io/badge/Documentation-Comprehensive-blue)](https://github.com/yourusername/security-monitoring-lab/wiki)
[![Wazuh](https://img.shields.io/badge/SIEM-Wazuh-orange)](https://wazuh.com/)
[![ELK Stack](https://img.shields.io/badge/Logging-ELK_Stack-yellow)](https://www.elastic.co/)

## 🎯 Project Overview

Welcome to my advanced security monitoring laboratory! This project represents my journey in building a professional-grade security operations environment that mirrors real-world enterprise setups. As a passionate cybersecurity enthusiast, I've designed this lab to demonstrate practical skills in security monitoring, incident response, and threat detection.

### 💡 Motivation

After working with various security tools in isolated environments, I realized the need for an integrated solution that demonstrates end-to-end security monitoring capabilities. This project was born from the desire to create a comprehensive environment that showcases practical security skills while providing a platform for continuous learning and experimentation.

### 🌟 Key Features

- **Enterprise SIEM Implementation**
  - Wazuh manager with custom rule sets
  - Real-time alert correlation
  - Automated response actions
  - Custom dashboards for threat visualization

- **Advanced Network Monitoring**
  - Suricata IDS with custom rules
  - Deep packet inspection
  - Traffic analysis and anomaly detection
  - Protocol-specific monitoring

- **Comprehensive Logging Infrastructure**
  - Centralized log collection
  - Custom log parsers and filters
  - Machine learning-based log analysis
  - Long-term log retention strategies

- **Incident Response Platform**
  - TheHive integration
  - Automated alert triage
  - Custom response playbooks
  - Threat intelligence incorporation

## 🏗️ Detailed Architecture

### Kali Linux VM (4GB RAM) - Security Operations Center
```plaintext
                    +------------------------+
                    |     Kali Linux VM      |
                    |------------------------|
                    | - Suricata IDS        |
                    | - ELK Stack           |
                    | - TheHive             |
                    | - Custom Scripts      |
                    +------------------------+
                             |
                    Security Monitoring Bus
                             |
        +-------------------+-----------------+
        |                   |                 |
   Windows 10 VM     Ubuntu Server VM    Network TAP
```

#### Components:
- **Suricata IDS Configuration**
  - Custom rule sets for targeted threats
  - Network interface in promiscuous mode
  - Optimized performance settings
  ```yaml
  # suricata.yaml snippet
  af-packet:
    - interface: eth0
      cluster-id: 99
      cluster-type: cluster_flow
      defrag: yes
      use-mmap: yes
  ```

- **ELK Stack Implementation**
  - Elasticsearch cluster configuration
  - Custom Logstash pipelines
  - Tailored Kibana dashboards
  ```yaml
  # logstash-security.conf example
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
      # Custom Windows event processing
      mutate {
        add_field => { "environment" => "security_lab" }
      }
    }
  }
  ```

### Windows 10 VM (3GB RAM) - Test Endpoint
- **Sysmon Configuration**
  ```xml
  <!-- Custom Sysmon config -->
  <Sysmon schemaversion="4.70">
    <HashAlgorithms>SHA1,MD5,SHA256,IMPHASH</HashAlgorithms>
    <EventFiltering>
      <!-- Process Creation -->
      <RuleGroup name="Process Creation" groupRelation="or">
        <ProcessCreate onmatch="include">
          <Rule name="Suspicious PowerShell Commands">
            <CommandLine condition="contains">-enc</CommandLine>
            <CommandLine condition="contains">-encode</CommandLine>
          </Rule>
        </ProcessCreate>
      </RuleGroup>
    </EventFiltering>
  </Sysmon>
  ```

- **Winlogbeat Setup**
  ```yaml
  # winlogbeat.yml configuration
  winlogbeat.event_logs:
    - name: Windows PowerShell
      ignore_older: 72h
      level: verbose
    - name: Microsoft-Windows-Sysmon/Operational
      processors:
        - drop_events.when.not.or:
            - equals.winlog.event_id: 1  # Process creation
            - equals.winlog.event_id: 3  # Network connection
  ```

### Ubuntu Server (2GB RAM) - Log Collection
- **Rsyslog Configuration**
  ```conf
  # Custom rsyslog rules
  module(load="imudp")
  input(type="imudp" port="514")
  
  # Filter and forward security events
  if $programname contains 'security' then {
    action(type="omfwd" target="elk-server" port="1514" protocol="tcp")
  }
  ```

## 🛠️ Advanced Implementation Details

### Security Monitoring Setup

1. **Wazuh Manager Configuration**
   ```bash
   # Custom agent group creation
   /var/ossec/bin/agent_groups -a -g windows-endpoints
   /var/ossec/bin/agent_groups -a -g linux-servers
   
   # Deploy custom rules
   cat << EOF > /var/ossec/etc/rules/local_rules.xml
   <group name="custom_security">
     <rule id="100100" level="10">
       <if_matched_sid>5503</if_matched_sid>
       <same_source_ip />
       <description>Multiple failed logins from same source.</description>
     </rule>
   </group>
   EOF
   ```

2. **TheHive Integration**
   ```yaml
   # application.conf
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

### Custom Detection Rules

1. **Wazuh Custom Rules Example**
   ```xml
   <rule id="100001" level="10">
     <if_sid>60101</if_sid>
     <field name="win.eventdata.commandLine">\.zip\s+\-P\s+password</field>
     <description>Password Protected ZIP Creation Detected</description>
     <group>data_exfiltration,</group>
   </rule>
   ```

2. **Suricata Custom Rules**
   ```yaml
   alert http any any -> any any (
     msg:"Potential Data Exfiltration - Large POST";
     flow:established,to_server;
     http.method; content:"POST";
     http.content_len; content:">1000000";
     threshold: type limit, track by_src, count 1, seconds 3600;
     classtype:data-exfiltration;
     sid:9000001; rev:1;
   )
   ```

## 📊 Monitoring Dashboards

### Security Overview Dashboard
```json
{
  "title": "Security Operations Overview",
  "hits": 0,
  "description": "Main security monitoring dashboard",
  "panelsJSON": "[{\"type\":\"visualization\",\"title\":\"Failed Login Attempts\",\"visState\":{...}}]"
}
```

## 🎓 Learning Journey & Challenges Overcome

Throughout this project, I encountered and solved several interesting challenges:

1. **Performance Optimization**
   - Challenge: Initial ELK stack setup was consuming excessive resources
   - Solution: Implemented index lifecycle management and optimized Logstash pipelines
   ```yaml
   # Index Lifecycle Policy
   {
     "policy": {
       "phases": {
         "hot": {
           "actions": {
             "rollover": {
               "max_size": "50GB",
               "max_age": "30d"
             }
           }
         }
       }
     }
   }
   ```

2. **Alert Noise Reduction**
   - Challenge: Too many false positive alerts
   - Solution: Implemented machine learning-based alert correlation
   ```python
   # Alert correlation logic
   def correlate_alerts(alerts):
       threshold = calculate_dynamic_threshold(alerts)
       return [alert for alert in alerts if alert.score > threshold]
   ```

## 🔍 Real-World Applications

This lab has been used to:
1. Detect and analyze modern malware behavior
2. Practice incident response procedures
3. Test security controls and policies
4. Develop custom detection rules

## 📈 Future Enhancements

1. **Planned Features**
   - Integration with MISP threat intelligence platform
   - Automated malware analysis pipeline
   - Machine learning-based anomaly detection
   - Container security monitoring

2. **Research Areas**
   - Advanced persistence technique detection
   - Zero-day threat hunting methodologies
   - Custom YARA rule development


## 📚 Detailed Documentation

Complete documentation is available in the `/docs` directory:
- [Installation Guide](docs/installation.md)
- [Configuration Guide](docs/configuration.md)
- [Troubleshooting Guide](docs/troubleshooting.md)
- [Best Practices](docs/best-practices.md)

--- 
