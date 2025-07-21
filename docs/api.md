# DevSecOps Monitor API Documentation

## Base URL
```
http://localhost:5000/api/v1
```

## Authentication
```bash
# JWT Token Authentication
curl -H "Authorization: Bearer JWT_TOKEN" \
     http://localhost:5000/api/v1/security/alerts
```

## Security Monitoring Endpoints

### Get Security Alerts
```http
GET /api/v1/security/alerts
```
**Parameters:**
- `severity` (string): `critical`, `high`, `medium`, `low`
- `status` (string): `open`, `investigating`, `resolved`
- `start_date` (string): ISO date format
- `end_date` (string): ISO date format

**Response:**
```json
{
  "alerts": [
    {
      "id": "alert_001",
      "type": "malware_detection",
      "severity": "critical",
      "status": "open",
      "timestamp": "2024-07-20T14:30:00Z",
      "source_system": "wazuh",
      "affected_host": "web-server-01",
      "description": "Suspicious executable detected",
      "indicators": ["file_hash", "process_name"],
      "response_actions": ["isolate_host", "notify_team"]
    }
  ],
  "total": 156,
  "page": 1,
  "per_page": 50
}
```

### Create Security Incident
```http
POST /api/v1/security/incidents
```
**Request Body:**
```json
{
  "title": "Suspected Data Breach",
  "severity": "critical",
  "type": "data_breach",
  "description": "Unusual data access patterns detected",
  "affected_systems": ["database-01", "api-gateway"],
  "initial_assessment": "High volume data queries from unusual source"
}
```

### Get Vulnerability Scan Results
```http
GET /api/v1/security/vulnerabilities
```
**Response:**
```json
{
  "vulnerabilities": [
    {
      "id": "vuln_001",
      "cve_id": "CVE-2024-12345",
      "severity": "high",
      "cvss_score": 7.5,
      "affected_asset": "web-application",
      "description": "SQL injection vulnerability",
      "discovery_date": "2024-07-20T10:00:00Z",
      "status": "open",
      "remediation": {
        "action": "apply_patch",
        "patch_available": true,
        "estimated_effort": "2 hours"
      }
    }
  ]
}
```

## Compliance Endpoints

### Get Compliance Status
```http
GET /api/v1/compliance/status
```
**Response:**
```json
{
  "frameworks": {
    "SOC2": {
      "overall_score": 92,
      "compliant_controls": 45,
      "total_controls": 49,
      "last_assessment": "2024-06-15",
      "next_assessment": "2024-09-15",
      "critical_findings": 1
    },
    "GDPR": {
      "overall_score": 88,
      "data_subject_requests": 23,
      "average_response_time": "18 hours",
      "breaches_reported": 0,
      "privacy_impact_assessments": 12
    }
  }
}
```

### Generate Compliance Report
```http
POST /api/v1/compliance/reports
```
**Request Body:**
```json
{
  "framework": "SOC2",
  "type": "quarterly",
  "start_date": "2024-04-01",
  "end_date": "2024-06-30",
  "include_evidence": true
}
```

## Threat Intelligence Endpoints

### Get Threat Indicators
```http
GET /api/v1/threat-intel/indicators
```
**Parameters:**
- `type` (string): `ip`, `domain`, `hash`, `url`
- `confidence` (number): Minimum confidence score (0-100)
- `age_hours` (number): Maximum age in hours

**Response:**
```json
{
  "indicators": [
    {
      "type": "ip",
      "value": "192.168.1.100",
      "confidence": 85,
      "threat_type": "malware_c2",
      "source": "community_feed",
      "first_seen": "2024-07-20T08:00:00Z",
      "tags": ["apt29", "cobalt_strike"]
    }
  ]
}
```

### Submit Indicator for Analysis
```http
POST /api/v1/threat-intel/analyze
```
**Request Body:**
```json
{
  "indicator_type": "file_hash",
  "indicator_value": "a1b2c3d4e5f6...",
  "context": "Detected in email attachment",
  "priority": "high"
}
```

## Incident Response Endpoints

### Get Active Incidents
```http
GET /api/v1/incidents
```
**Response:**
```json
{
  "incidents": [
    {
      "id": "INC-2024-001",
      "title": "Malware Detection on Web Server",
      "severity": "high",
      "status": "investigating",
      "assigned_to": "security-team",
      "created_at": "2024-07-20T09:00:00Z",
      "timeline": [
        {
          "timestamp": "2024-07-20T09:00:00Z",
          "action": "incident_created",
          "user": "alert_system"
        },
        {
          "timestamp": "2024-07-20T09:05:00Z",
          "action": "analyst_assigned",
          "user": "john.doe"
        }
      ]
    }
  ]
}
```

### Update Incident Status
```http
PATCH /api/v1/incidents/{incident_id}
```
**Request Body:**
```json
{
  "status": "resolved",
  "resolution_notes": "Malware removed, system patched",
  "lessons_learned": "Update endpoint protection signatures"
}
```

## Pipeline Security Endpoints

### Get Pipeline Security Status
```http
GET /api/v1/pipeline/security
```
**Response:**
```json
{
  "pipelines": [
    {
      "name": "main-application",
      "last_scan": "2024-07-20T12:00:00Z",
      "security_gates": {
        "sast": {"status": "passed", "vulnerabilities": 2},
        "dast": {"status": "passed", "vulnerabilities": 0},
        "dependency_scan": {"status": "failed", "vulnerabilities": 5},
        "container_scan": {"status": "passed", "vulnerabilities": 1}
      },
      "overall_status": "failed"
    }
  ]
}
```

### Trigger Security Scan
```http
POST /api/v1/pipeline/scan
```
**Request Body:**
```json
{
  "pipeline_id": "main-app",
  "scan_types": ["sast", "dast", "dependency"],
  "branch": "main",
  "commit_hash": "abc123def456"
}
```

## Monitoring and Metrics Endpoints

### Get Security Metrics
```http
GET /api/v1/metrics/security
```
**Parameters:**
- `period` (string): `day`, `week`, `month`
- `metric_type` (string): `alerts`, `incidents`, `vulnerabilities`

**Response:**
```json
{
  "metrics": {
    "alert_volume": {
      "total": 1247,
      "by_severity": {
        "critical": 12,
        "high": 89,
        "medium": 345,
        "low": 801
      }
    },
    "mean_time_to_detection": "4.2 hours",
    "mean_time_to_response": "1.8 hours",
    "false_positive_rate": "8.5%"
  }
}
```

### Get System Health
```http
GET /api/v1/health
```
**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-07-20T15:00:00Z",
  "components": {
    "elasticsearch": {"status": "healthy", "response_time": "12ms"},
    "logstash": {"status": "healthy", "events_per_second": 1250},
    "kibana": {"status": "healthy", "active_users": 23},
    "suricata": {"status": "healthy", "packets_per_second": 50000},
    "wazuh": {"status": "healthy", "agents_connected": 156}
  }
}
```

## Configuration Endpoints

### Update Security Rules
```http
POST /api/v1/config/rules
```
**Request Body:**
```json
{
  "rule_type": "suricata",
  "action": "add",
  "rule_content": "alert tcp any any -> $HOME_NET 80 (msg:\"Custom HTTP Rule\"; sid:1000001;)"
}
```

### Get Alert Thresholds
```http
GET /api/v1/config/thresholds
```
**Response:**
```json
{
  "thresholds": {
    "failed_logins": {
      "value": 5,
      "time_window": "5 minutes",
      "action": "alert"
    },
    "high_cpu_usage": {
      "value": 90,
      "time_window": "2 minutes",
      "action": "investigate"
    }
  }
}
```

## Webhook Endpoints

### Security Event Webhook
```http
POST /api/v1/webhooks/security-event
```
**Webhook Payload:**
```json
{
  "event_type": "security_alert",
  "timestamp": "2024-07-20T15:30:00Z",
  "alert_id": "alert_001",
  "severity": "high",
  "source": "network_monitoring",
  "details": {
    "rule_id": "ET_TROJAN_Malware_Command_and_Control",
    "source_ip": "10.0.1.100",
    "destination_ip": "192.168.1.1",
    "port": 443
  }
}
```

## Rate Limiting
- **Community**: 1000 requests per hour
- **Standard**: 5000 requests per hour
- **Enterprise**: Unlimited

## Error Responses
```json
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Missing required parameter: severity",
    "timestamp": "2024-07-20T15:30:00Z",
    "request_id": "req_12345"
  }
}
```

## SDK Examples

### Python SDK
```python
from devsecops_monitor import DevSecOpsClient

client = DevSecOpsClient(api_key="your_api_key")
alerts = client.security.get_alerts(severity="critical")
```

### JavaScript SDK
```javascript
const { DevSecOpsMonitor } = require('devsecops-monitor');
const client = new DevSecOpsMonitor({ apiKey: 'your_api_key' });
const incidents = await client.incidents.list();
```