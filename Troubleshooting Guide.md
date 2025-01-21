# Security Monitoring Lab - Troubleshooting Guide

## Table of Contents
- [System Health Checks](#system-health-checks)
- [Common Issues](#common-issues)
- [Performance Troubleshooting](#performance-troubleshooting)
- [Log Analysis](#log-analysis)
- [Recovery Procedures](#recovery-procedures)

## System Health Checks

### Quick Diagnostic Commands
```bash
# Check all critical services
systemctl status wazuh-manager elasticsearch kibana logstash suricata

# View system resources
top -bn1
free -m
df -h

# Network connectivity
netstat -tulpn
ss -tulpn
```

## Common Issues

### 1. Wazuh Agent Connection Problems

#### Symptoms
- Agent shows as disconnected
- No events being received
- Authentication errors

#### Resolution Steps
```bash
# Check agent status
/var/ossec/bin/agent_control -l

# View manager logs
tail -f /var/ossec/logs/ossec.log

# Verify network connectivity
tcpdump -i any port 1514

# Reset agent registration
/var/ossec/bin/manage_agents -r <agent_id>
systemctl restart wazuh-agent
```

### 2. ELK Stack Issues

#### Elasticsearch Not Starting
```bash
# Check logs
journalctl -u elasticsearch.service -f

# Verify cluster health
curl -X GET "localhost:9200/_cluster/health?pretty"

# Common fixes
sudo systemctl restart elasticsearch
sudo chown -R elasticsearch:elasticsearch /var/lib/elasticsearch
```

#### Kibana Connection Issues
```bash
# Check Kibana status and logs
systemctl status kibana
journalctl -u kibana.service -f

# Verify Elasticsearch connection
curl -XGET http://localhost:5601/api/status

# Reset Kibana
systemctl restart kibana
```

#### Logstash Pipeline Problems
```bash
# Test pipeline configuration
/usr/share/logstash/bin/logstash -f /etc/logstash/conf.d/security.conf --config.test_and_exit

# Check logs
tail -f /var/log/logstash/logstash-plain.log

# Restart pipeline
systemctl restart logstash
```

### 3. Suricata Issues

#### No Alerts Generated
```bash
# Verify Suricata is running
suricata -T -c /etc/suricata/suricata.yaml

# Check interface capture
tcpdump -i <interface> -n

# View Suricata stats
tail -f /var/log/suricata/stats.log

# Update rules
suricata-update
```

## Performance Troubleshooting

### 1. High CPU Usage
```bash
# Identify CPU-intensive processes
top -c
htop

# Check Elasticsearch CPU usage
curl -X GET "localhost:9200/_nodes/stats/process?pretty"

# Monitor system load
sar -u 1 10
```

### 2. Memory Problems
```bash
# Check memory usage
free -m
vmstat 1 10

# Elasticsearch heap usage
curl -X GET "localhost:9200/_nodes/stats/jvm?pretty"

# View memory-heavy processes
ps aux --sort=-%mem | head -n 10
```

### 3. Disk Space Issues
```bash
# Check disk usage
df -h
du -sh /var/log/*

# Find large files
find / -type f -size +100M -exec ls -lh {} \;

# Clean old logs
find /var/log -name "*.gz" -mtime +30 -delete
curator_cli delete_indices --filter_list '{"filtertype":"age","source":"creation_date","direction":"older","unit":"days","unit_count":30}'
```

## Log Analysis

### Critical Log Locations
```bash
# Wazuh Logs
tail -f /var/ossec/logs/ossec.log
tail -f /var/ossec/logs/alerts/alerts.log

# ELK Stack Logs
tail -f /var/log/elasticsearch/security-monitoring.log
tail -f /var/log/kibana/kibana.log
tail -f /var/log/logstash/logstash-plain.log

# Suricata Logs
tail -f /var/log/suricata/suricata.log
tail -f /var/log/suricata/fast.log
```

## Recovery Procedures

### 1. Wazuh Recovery
```bash
# Backup configuration
cp -r /var/ossec/etc /var/ossec/etc_backup

# Reset Wazuh manager
systemctl stop wazuh-manager
rm -rf /var/ossec/queue/fim/db
rm -rf /var/ossec/queue/agents-timestamp
systemctl start wazuh-manager

# Regenerate certificates
/var/ossec/bin/ossec-authd -P
```

### 2. ELK Stack Recovery
```bash
# Elasticsearch snapshot
curl -X PUT "localhost:9200/_snapshot/backup?pretty" -H 'Content-Type: application/json' -d'
{
  "type": "fs",
  "settings": {
    "location": "/backup/elasticsearch"
  }
}'

# Reset Kibana
rm -rf /var/lib/kibana/*
systemctl restart kibana

# Clear Logstash queue
rm -rf /var/lib/logstash/queue/*
systemctl restart logstash
```

### 3. Emergency Reset Procedure
```bash
#!/bin/bash
# Emergency reset script
services=("wazuh-manager" "elasticsearch" "kibana" "logstash" "suricata")

for service in "${services[@]}"; do
    systemctl stop $service
    echo "Stopped $service"
done

echo "Clearing temporary data..."
rm -rf /var/lib/elasticsearch/nodes/
rm -rf /var/lib/kibana/*
rm -rf /var/lib/logstash/queue/*

for service in "${services[@]}"; do
    systemctl start $service
    echo "Started $service"
done
```

## Quick Reference: Common Commands

### Service Management
```bash
# Restart core services
systemctl restart wazuh-manager
systemctl restart elasticsearch
systemctl restart kibana
systemctl restart logstash
systemctl restart suricata

# View service status
systemctl status wazuh-manager
systemctl status elasticsearch
```

### Health Checks
```bash
# Elasticsearch
curl -X GET "localhost:9200/_cluster/health?pretty"
curl -X GET "localhost:9200/_cat/indices?v"

# Wazuh
/var/ossec/bin/ossec-control status
/var/ossec/bin/agent_control -l

# Suricata
suricata -T -c /etc/suricata/suricata.yaml
```

### Network Diagnostics
```bash
# Check ports
netstat -tulpn | grep LISTEN
ss -tulpn | grep LISTEN

# Test connectivity
ping -c 4 192.168.1.10
telnet 192.168.1.10 9200
nc -zv 192.168.1.10 5601
```

---
⚠️ Note: Always backup configurations before making changes.
