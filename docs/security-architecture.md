# DevSecOps Security Architecture

## Overview

The DevSecOps Monitor implements a comprehensive security architecture that integrates security testing, monitoring, and compliance throughout the development lifecycle.

## Architecture Components

### Core Security Stack
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Development   │    │    Security     │    │   Operations    │
│                 │    │   Monitoring    │    │                 │
│ • IDE Plugins   │    │ • SAST/DAST     │    │ • Runtime       │
│ • Pre-commit    │    │ • Compliance    │    │   Protection    │
│ • Code Review   │    │ • Threat Intel  │    │ • Incident      │
│                 │    │ • Vulnerability │    │   Response      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        │                        │                        │
        └────────────────────────┼────────────────────────┘
                                 │
                    ┌─────────────────┐
                    │  Central SIEM   │
                    │ (ELK + Grafana) │
                    └─────────────────┘
```

### Security Integration Points

#### 1. Development Phase Security
- **Pre-commit Hooks**: Automated security checks before code commit
- **IDE Security Plugins**: Real-time vulnerability detection
- **Dependency Scanning**: Continuous monitoring of third-party libraries
- **Secret Detection**: Prevention of credentials in code

#### 2. CI/CD Pipeline Security
- **Static Application Security Testing (SAST)**
- **Dynamic Application Security Testing (DAST)**
- **Infrastructure as Code (IaC) Scanning**
- **Container Security Scanning**

#### 3. Runtime Security
- **Network Intrusion Detection (Suricata)**
- **Host-based Intrusion Detection (Wazuh)**
- **Application Performance Monitoring**
- **Behavioral Analytics**

## SIEM Integration

### ELK Stack Configuration
```yaml
# elasticsearch.yml
cluster.name: "devsecops-monitor"
node.name: "security-node"
network.host: 0.0.0.0
discovery.type: single-node
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true

# Security index templates
PUT _index_template/security-logs
{
  "index_patterns": ["security-*"],
  "template": {
    "settings": {
      "number_of_shards": 3,
      "number_of_replicas": 1,
      "index.lifecycle.name": "security-policy"
    },
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "event_type": { "type": "keyword" },
        "severity": { "type": "keyword" },
        "source_ip": { "type": "ip" },
        "destination_ip": { "type": "ip" },
        "user_agent": { "type": "text" },
        "alert_signature": { "type": "text" }
      }
    }
  }
}
```

### Logstash Security Pipeline
```ruby
# logstash/pipeline/security.conf
input {
  beats {
    port => 5044
  }
  
  tcp {
    port => 5514
    type => "syslog"
  }
  
  http {
    port => 8080
    codec => json
    type => "webhook"
  }
}

filter {
  if [type] == "suricata" {
    json {
      source => "message"
    }
    
    mutate {
      add_field => { "event_type" => "network_security" }
    }
    
    if [alert] {
      mutate {
        add_field => { 
          "severity" => "%{[alert][severity]}"
          "signature" => "%{[alert][signature]}"
          "category" => "%{[alert][category]}"
        }
      }
    }
  }
  
  if [type] == "wazuh" {
    json {
      source => "message"
    }
    
    mutate {
      add_field => { "event_type" => "host_security" }
    }
    
    if [rule] {
      mutate {
        add_field => {
          "rule_id" => "%{[rule][id]}"
          "rule_level" => "%{[rule][level]}"
          "rule_description" => "%{[rule][description]}"
        }
      }
    }
  }
  
  # GeoIP enrichment
  if [src_ip] {
    geoip {
      source => "src_ip"
      target => "geoip"
    }
  }
  
  # Threat intelligence enrichment
  if [src_ip] {
    translate {
      source => "src_ip"
      target => "threat_intel"
      dictionary_path => "/etc/logstash/threat_feeds/malicious_ips.yml"
      fallback => "clean"
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "security-%{+YYYY.MM.dd}"
    user => "${ELASTIC_USER}"
    password => "${ELASTIC_PASSWORD}"
  }
  
  # Real-time alerting
  if [severity] == "high" or [rule_level] >= 10 {
    http {
      url => "http://incident-response:8080/alerts"
      http_method => "post"
      format => "json"
      headers => {
        "Authorization" => "Bearer ${ALERT_TOKEN}"
      }
    }
  }
}
```

## Network Security Monitoring

### Suricata IDS Configuration
```yaml
# suricata.yaml
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8,192.168.0.0/16,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
    DMZ_NET: "10.0.1.0/24"
    
  port-groups:
    HTTP_PORTS: "80,8080,8081,9000,9200"
    HTTPS_PORTS: "443,8443"
    SSH_PORTS: "22,2222"

default-log-dir: /var/log/suricata/

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            payload-buffer-size: 4kb
            payload-printable: yes
            packet: yes
            metadata: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - files:
            force-magic: no
        - drop:
            alerts: yes
        - ssh
        - flow

app-layer:
  protocols:
    http:
      enabled: yes
      libhtp:
        default-config:
          personality: IDS
          request-body-limit: 100kb
          response-body-limit: 100kb
    tls:
      enabled: yes
      detection-ports:
        dp: 443
    ssh:
      enabled: yes

rule-files:
  - suricata.rules
  - custom-rules.rules
  - emerging-threats.rules

classification-file: /etc/suricata/classification.config
reference-config-file: /etc/suricata/reference.config
```

### Custom Security Rules
```bash
# custom-rules.rules

# Detect SQL injection attempts
alert http any any -> $HOME_NET $HTTP_PORTS (msg:"SQL Injection Attempt"; flow:established,to_server; content:"union"; nocase; content:"select"; nocase; distance:0; within:100; classtype:web-application-attack; sid:1000001; rev:1;)

# Detect XSS attempts
alert http any any -> $HOME_NET $HTTP_PORTS (msg:"Cross-Site Scripting Attempt"; flow:established,to_server; content:"<script"; nocase; classtype:web-application-attack; sid:1000002; rev:1;)

# Detect command injection
alert http any any -> $HOME_NET $HTTP_PORTS (msg:"Command Injection Attempt"; flow:established,to_server; pcre:"/(\||;|&|`|\$\(|\$\{)/i"; classtype:web-application-attack; sid:1000003; rev:1;)

# Detect brute force SSH attempts
alert ssh any any -> $HOME_NET $SSH_PORTS (msg:"SSH Brute Force Attempt"; flow:to_server; detection_filter:track by_src, count 5, seconds 60; classtype:attempted-user; sid:1000004; rev:1;)

# Detect cryptocurrency mining
alert http any any -> any any (msg:"Cryptocurrency Mining Activity"; content:"stratum+tcp"; nocase; classtype:trojan-activity; sid:1000005; rev:1;)

# Detect data exfiltration
alert tcp $HOME_NET any -> !$HOME_NET any (msg:"Large Data Transfer"; dsize:>1000000; threshold:type both, track by_src, count 5, seconds 60; classtype:policy-violation; sid:1000006; rev:1;)
```

## Host-based Security Monitoring

### Wazuh Agent Configuration
```xml
<!-- ossec.conf -->
<ossec_config>
  <client>
    <server>
      <address>wazuh-manager</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <crypto_method>aes</crypto_method>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <!-- Log analysis -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/nginx/access.log</location>
  </localfile>

  <!-- File Integrity Monitoring -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>3600</frequency>
    <scan_on_start>yes</scan_on_start>
    
    <directories check_all="yes" realtime="yes">/etc</directories>
    <directories check_all="yes" realtime="yes">/usr/bin</directories>
    <directories check_all="yes" realtime="yes">/usr/sbin</directories>
    <directories check_all="yes" realtime="yes">/bin</directories>
    <directories check_all="yes" realtime="yes">/sbin</directories>
    <directories check_all="yes" realtime="yes">/home</directories>
    
    <ignore>/etc/motd</ignore>
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
  </syscheck>

  <!-- Rootkit detection -->
  <rootcheck>
    <disabled>no</disabled>
    <frequency>3600</frequency>
    <rootkit_files>/var/ossec/etc/shared/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/shared/rootkit_trojans.txt</rootkit_trojans>
    <windows_malware>/var/ossec/etc/shared/win_malware_rcl.txt</windows_malware>
    <windows_audit>/var/ossec/etc/shared/win_audit_rcl.txt</windows_audit>
    <windows_apps>/var/ossec/etc/shared/win_applications_rcl.txt</windows_apps>
    <skip_nfs>yes</skip_nfs>
  </rootcheck>

  <!-- Active response -->
  <active-response>
    <disabled>no</disabled>
    <ca_store>/var/ossec/etc/wpk_root.pem</ca_store>
    <ca_verification>yes</ca_verification>
  </active-response>
</ossec_config>
```

### Custom Wazuh Rules
```xml
<!-- devsecops_rules.xml -->
<group name="devsecops,">

  <!-- DevOps pipeline security -->
  <rule id="100001" level="5">
    <decoded_as>json</decoded_as>
    <field name="event_type">pipeline_execution</field>
    <description>DevOps pipeline execution detected</description>
    <group>pipeline,</group>
  </rule>

  <rule id="100002" level="10">
    <if_sid>100001</if_sid>
    <field name="status">failed</field>
    <field name="stage">security_scan</field>
    <description>Security scan failed in pipeline</description>
    <group>pipeline,security_failure,</group>
  </rule>

  <!-- Container security -->
  <rule id="100010" level="7">
    <decoded_as>json</decoded_as>
    <field name="container_action">exec</field>
    <description>Container exec command executed</description>
    <group>container,</group>
  </rule>

  <rule id="100011" level="12">
    <if_sid>100010</if_sid>
    <field name="command">.*(/bin/sh|/bin/bash|/bin/dash).*</field>
    <description>Shell access to container detected</description>
    <group>container,shell_access,</group>
  </rule>

  <!-- Secret detection -->
  <rule id="100020" level="8">
    <decoded_as>json</decoded_as>
    <field name="event_type">secret_detected</field>
    <description>Secret or credential detected in code</description>
    <group>secrets,</group>
  </rule>

  <rule id="100021" level="12">
    <if_sid>100020</if_sid>
    <field name="secret_type">aws_key|api_key|password|private_key</field>
    <description>High-risk secret detected in code</description>
    <group>secrets,high_risk,</group>
  </rule>

  <!-- Vulnerability management -->
  <rule id="100030" level="6">
    <decoded_as>json</decoded_as>
    <field name="event_type">vulnerability_scan</field>
    <description>Vulnerability scan completed</description>
    <group>vulnerability,</group>
  </rule>

  <rule id="100031" level="10">
    <if_sid>100030</if_sid>
    <field name="severity">high|critical</field>
    <description>High severity vulnerability detected</description>
    <group>vulnerability,high_severity,</group>
  </rule>

</group>
```

## Compliance Frameworks

### SOC 2 Type II Implementation
```python
# compliance/soc2/soc2_automation.py
import json
import datetime
from typing import Dict, List

class SOC2Compliance:
    def __init__(self):
        self.controls = {
            'CC1': 'Control Environment',
            'CC2': 'Communication and Information',
            'CC3': 'Risk Assessment',
            'CC4': 'Monitoring Activities',
            'CC5': 'Control Activities',
            'CC6': 'Logical and Physical Access Controls',
            'CC7': 'System Operations',
            'CC8': 'Change Management',
            'CC9': 'Risk Mitigation'
        }
        
    def generate_evidence(self, control_id: str) -> Dict:
        """Generate evidence for SOC 2 controls"""
        evidence = {
            'control_id': control_id,
            'control_name': self.controls.get(control_id),
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'evidence_type': 'automated_collection',
            'status': 'compliant'
        }
        
        if control_id == 'CC6':  # Access Controls
            evidence.update({
                'mfa_enabled': self.check_mfa_enforcement(),
                'password_policy': self.check_password_policy(),
                'access_reviews': self.get_access_reviews(),
                'privileged_access': self.audit_privileged_access()
            })
            
        elif control_id == 'CC7':  # System Operations
            evidence.update({
                'monitoring_coverage': self.check_monitoring_coverage(),
                'incident_response': self.verify_incident_response(),
                'backup_procedures': self.verify_backups(),
                'availability_metrics': self.get_availability_metrics()
            })
            
        elif control_id == 'CC8':  # Change Management
            evidence.update({
                'change_approvals': self.audit_change_approvals(),
                'testing_procedures': self.verify_testing(),
                'rollback_capabilities': self.check_rollback_procedures(),
                'emergency_changes': self.audit_emergency_changes()
            })
            
        return evidence
    
    def check_mfa_enforcement(self) -> bool:
        # Query identity provider for MFA status
        # Implementation depends on your identity system
        return True
    
    def audit_privileged_access(self) -> Dict:
        # Audit privileged access logs
        return {
            'admin_sessions': 45,
            'privilege_escalations': 12,
            'access_violations': 0,
            'review_date': datetime.date.today().isoformat()
        }
```

### GDPR Privacy Controls
```python
# compliance/gdpr/privacy_controls.py
class GDPRControls:
    def __init__(self):
        self.lawful_bases = [
            'consent', 'contract', 'legal_obligation',
            'vital_interests', 'public_task', 'legitimate_interests'
        ]
    
    def handle_data_subject_request(self, request_type: str, subject_id: str) -> Dict:
        """Handle GDPR data subject requests"""
        
        if request_type == 'access':
            return self.provide_data_access(subject_id)
        elif request_type == 'rectification':
            return self.rectify_data(subject_id)
        elif request_type == 'erasure':
            return self.erase_data(subject_id)
        elif request_type == 'portability':
            return self.export_data(subject_id)
        else:
            raise ValueError(f"Unknown request type: {request_type}")
    
    def privacy_impact_assessment(self, processing_activity: Dict) -> Dict:
        """Conduct Privacy Impact Assessment"""
        risk_score = 0
        risk_factors = []
        
        # Assess data sensitivity
        if 'special_categories' in processing_activity.get('data_types', []):
            risk_score += 3
            risk_factors.append('Special category data processing')
        
        # Assess processing scope
        if processing_activity.get('data_subjects_count', 0) > 10000:
            risk_score += 2
            risk_factors.append('Large scale processing')
        
        # Assess automated decision making
        if processing_activity.get('automated_decisions', False):
            risk_score += 2
            risk_factors.append('Automated decision making')
        
        return {
            'risk_level': 'high' if risk_score >= 5 else 'medium' if risk_score >= 3 else 'low',
            'risk_score': risk_score,
            'risk_factors': risk_factors,
            'mitigation_required': risk_score >= 5,
            'assessment_date': datetime.datetime.utcnow().isoformat()
        }
```

## Threat Intelligence Integration

### MISP Integration
```python
# threat-intel/misp/misp_client.py
import requests
import json
from typing import List, Dict

class MISPClient:
    def __init__(self, misp_url: str, api_key: str):
        self.misp_url = misp_url
        self.api_key = api_key
        self.headers = {
            'Authorization': api_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    
    def get_threat_indicators(self, days: int = 7) -> List[Dict]:
        """Retrieve threat indicators from MISP"""
        url = f"{self.misp_url}/attributes/restSearch"
        payload = {
            'returnFormat': 'json',
            'last': f'{days}d',
            'type': ['ip-dst', 'domain', 'url', 'md5', 'sha256'],
            'to_ids': 1
        }
        
        response = requests.post(url, headers=self.headers, json=payload)
        response.raise_for_status()
        
        indicators = []
        for attribute in response.json().get('response', {}).get('Attribute', []):
            indicators.append({
                'type': attribute['type'],
                'value': attribute['value'],
                'category': attribute['category'],
                'threat_level': attribute.get('threat_level_id'),
                'tags': [tag['name'] for tag in attribute.get('Tag', [])],
                'last_seen': attribute['timestamp']
            })
        
        return indicators
    
    def enrich_security_event(self, event: Dict) -> Dict:
        """Enrich security event with threat intelligence"""
        enriched_event = event.copy()
        
        # Check IP addresses
        if 'src_ip' in event:
            threat_info = self.lookup_indicator(event['src_ip'], 'ip-dst')
            if threat_info:
                enriched_event['threat_intel'] = threat_info
                enriched_event['risk_score'] = self.calculate_risk_score(threat_info)
        
        # Check domains
        if 'domain' in event:
            threat_info = self.lookup_indicator(event['domain'], 'domain')
            if threat_info:
                enriched_event['domain_threat_intel'] = threat_info
        
        return enriched_event
```

## Incident Response Automation

### Automated Response Playbooks
```python
# incident-response/playbooks/automated_response.py
class IncidentResponsePlaybook:
    def __init__(self):
        self.severity_thresholds = {
            'critical': 9,
            'high': 7,
            'medium': 5,
            'low': 3
        }
    
    async def execute_response(self, incident: Dict) -> Dict:
        """Execute automated incident response"""
        severity = self.calculate_severity(incident)
        
        response_actions = []
        
        if severity == 'critical':
            # Immediate containment
            if incident['type'] == 'malware_detected':
                await self.isolate_host(incident['host_id'])
                response_actions.append('host_isolated')
            
            elif incident['type'] == 'data_exfiltration':
                await self.block_network_traffic(incident['src_ip'])
                response_actions.append('network_blocked')
            
            # Alert security team
            await self.notify_security_team(incident, severity)
            response_actions.append('team_notified')
        
        elif severity == 'high':
            # Enhanced monitoring
            await self.increase_monitoring(incident['affected_systems'])
            response_actions.append('monitoring_increased')
            
            # Create incident ticket
            ticket_id = await self.create_incident_ticket(incident)
            response_actions.append(f'ticket_created:{ticket_id}')
        
        # Log response actions
        await self.log_response(incident, response_actions)
        
        return {
            'incident_id': incident['id'],
            'severity': severity,
            'actions_taken': response_actions,
            'timestamp': datetime.datetime.utcnow().isoformat()
        }
    
    async def isolate_host(self, host_id: str):
        """Isolate compromised host from network"""
        # Implementation depends on your network infrastructure
        # Could involve SDN controllers, firewall rules, etc.
        pass
    
    async def block_network_traffic(self, ip_address: str):
        """Block malicious IP address"""
        # Update firewall rules or WAF configuration
        pass
```

## Performance and Scalability

### Distributed Processing
```yaml
# docker-compose.scale.yml
version: '3.8'
services:
  logstash:
    deploy:
      replicas: 3
    environment:
      - PIPELINE_WORKERS=4
      - PIPELINE_BATCH_SIZE=125
    
  elasticsearch:
    deploy:
      replicas: 3
    environment:
      - "ES_JAVA_OPTS=-Xms2g -Xmx2g"
      - cluster.initial_master_nodes=es01,es02,es03
    
  suricata:
    deploy:
      replicas: 2
    cap_add:
      - NET_ADMIN
      - SYS_NICE
    network_mode: host
```

### Data Retention Policies
```python
# monitoring/retention_policy.py
class DataRetentionPolicy:
    def __init__(self):
        self.retention_rules = {
            'security_alerts': 365,      # 1 year
            'audit_logs': 2555,          # 7 years (compliance)
            'network_flows': 90,         # 3 months
            'vulnerability_scans': 180,  # 6 months
            'compliance_reports': 2555   # 7 years
        }
    
    def apply_retention_policy(self):
        """Apply data retention policies"""
        for data_type, retention_days in self.retention_rules.items():
            cutoff_date = datetime.datetime.now() - datetime.timedelta(days=retention_days)
            
            # Archive old data
            self.archive_data(data_type, cutoff_date)
            
            # Delete expired data
            self.delete_expired_data(data_type, cutoff_date)
```

This architecture provides comprehensive security monitoring and incident response capabilities while maintaining compliance with enterprise security standards.