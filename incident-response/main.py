"""
Enterprise DevSecOps Incident Response API
Automated security incident response and workflow management
"""

from fastapi import FastAPI, HTTPException, Depends, Security, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
import os
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import asyncio
import httpx
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Response
import time
import uuid

# Initialize FastAPI app
app = FastAPI(
    title="DevSecOps Incident Response Platform",
    description="Enterprise security incident response and automation platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5601", "http://localhost:5602"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Prometheus metrics
INCIDENT_COUNTER = Counter('security_incidents_total', 'Total security incidents', ['severity', 'type'])
RESPONSE_TIME = Histogram('incident_response_duration_seconds', 'Incident response duration')
MTTR_HISTOGRAM = Histogram('incident_mttr_seconds', 'Mean Time To Resolution')

# Security
security = HTTPBearer()
API_KEY = os.getenv("API_KEY", "demo-key-sec-incident123")

def verify_api_key(credentials: HTTPAuthorizationCredentials = Security(security)):
    if credentials.credentials != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return credentials.credentials

# Sample incident data and playbooks
SAMPLE_INCIDENTS = []
INCIDENT_PLAYBOOKS = {
    "malware_detection": {
        "name": "Malware Detection Response",
        "description": "Automated response to malware detection alerts",
        "steps": [
            {"step": 1, "action": "isolate_host", "description": "Isolate infected host from network"},
            {"step": 2, "action": "collect_artifacts", "description": "Collect malware samples and logs"},
            {"step": 3, "action": "analyze_iocs", "description": "Extract and analyze indicators of compromise"},
            {"step": 4, "action": "update_defenses", "description": "Update security controls with new IOCs"},
            {"step": 5, "action": "notify_stakeholders", "description": "Notify security team and management"}
        ],
        "estimated_time": "30 minutes",
        "severity_threshold": "medium"
    },
    "data_breach": {
        "name": "Data Breach Response",
        "description": "Comprehensive response to potential data breach",
        "steps": [
            {"step": 1, "action": "assess_scope", "description": "Determine scope and impact of breach"},
            {"step": 2, "action": "contain_breach", "description": "Contain and stop ongoing data exfiltration"},
            {"step": 3, "action": "preserve_evidence", "description": "Preserve forensic evidence"},
            {"step": 4, "action": "notify_authorities", "description": "Notify regulatory bodies if required"},
            {"step": 5, "action": "communication_plan", "description": "Execute stakeholder communication plan"}
        ],
        "estimated_time": "4 hours",
        "severity_threshold": "high"
    },
    "suspicious_login": {
        "name": "Suspicious Login Activity",
        "description": "Response to anomalous authentication events",
        "steps": [
            {"step": 1, "action": "verify_user", "description": "Contact user to verify legitimate access"},
            {"step": 2, "action": "analyze_logs", "description": "Analyze authentication and access logs"},
            {"step": 3, "action": "check_geolocation", "description": "Verify geographic location consistency"},
            {"step": 4, "action": "reset_credentials", "description": "Force password reset if suspicious"},
            {"step": 5, "action": "monitor_activity", "description": "Enhanced monitoring of user activity"}
        ],
        "estimated_time": "15 minutes",
        "severity_threshold": "low"
    }
}

def generate_sample_incidents():
    """Generate realistic sample security incidents"""
    incidents = []
    
    # Recent incidents with various severities and types
    incident_types = [
        {"type": "malware", "severity": "high", "description": "Trojan.Win32.Agent detected on workstation"},
        {"type": "suspicious_login", "severity": "medium", "description": "Multiple failed login attempts from unusual location"},
        {"type": "data_exfiltration", "severity": "critical", "description": "Large data transfer to external IP detected"},
        {"type": "privilege_escalation", "severity": "high", "description": "Unauthorized admin account creation detected"},
        {"type": "network_scan", "severity": "low", "description": "Port scanning activity from internal host"},
        {"type": "phishing", "severity": "medium", "description": "Suspicious email with malicious attachment"}
    ]
    
    for i in range(20):
        incident_type = incident_types[i % len(incident_types)]
        incident_time = datetime.now() - timedelta(hours=i*2, minutes=i*5)
        
        incident = {
            "incident_id": f"INC-{str(uuid.uuid4())[:8].upper()}",
            "title": f"{incident_type['type'].replace('_', ' ').title()} - {incident_type['description']}",
            "description": incident_type['description'],
            "severity": incident_type['severity'],
            "type": incident_type['type'],
            "status": "open" if i < 5 else "resolved",
            "created_at": incident_time.isoformat(),
            "updated_at": (incident_time + timedelta(minutes=30)).isoformat(),
            "assigned_to": f"analyst{(i % 3) + 1}@company.com",
            "source": "wazuh" if i % 2 == 0 else "suricata",
            "affected_systems": [f"host-{(i % 10) + 1:02d}.company.com"],
            "indicators": {
                "ip_addresses": [f"192.168.1.{(i % 250) + 1}"],
                "file_hashes": [f"sha256:{uuid.uuid4().hex}"] if incident_type['type'] == 'malware' else [],
                "urls": [f"http://malicious-{i}.example.com"] if incident_type['type'] == 'phishing' else []
            },
            "playbook_executed": incident_type['type'] in INCIDENT_PLAYBOOKS,
            "resolution_time": (i * 15) + 30 if i >= 5 else None,  # minutes
            "mttr_minutes": (i * 15) + 30 if i >= 5 else None
        }
        
        incidents.append(incident)
    
    return incidents

# Initialize sample data
SAMPLE_INCIDENTS = generate_sample_incidents()

@app.middleware("http")
async def metrics_middleware(request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time
    
    RESPONSE_TIME.observe(duration)
    
    return response

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "services": {
            "database": "up",
            "wazuh_api": "up",
            "elasticsearch": "up",
            "redis": "up"
        },
        "version": "1.0.0"
    }

@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint"""
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.get("/api/incidents")
async def get_incidents(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 20,
    api_key: str = Depends(verify_api_key)
):
    """Get security incidents with optional filtering"""
    
    incidents = SAMPLE_INCIDENTS.copy()
    
    # Apply filters
    if severity:
        incidents = [i for i in incidents if i['severity'] == severity]
    
    if status:
        incidents = [i for i in incidents if i['status'] == status]
    
    # Limit results
    incidents = incidents[:limit]
    
    # Update counters
    for incident in incidents:
        INCIDENT_COUNTER.labels(severity=incident['severity'], type=incident['type']).inc()
    
    return {
        "incidents": incidents,
        "total": len(incidents),
        "filters": {
            "severity": severity,
            "status": status
        }
    }

@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str, api_key: str = Depends(verify_api_key)):
    """Get specific incident details"""
    
    incident = next((i for i in SAMPLE_INCIDENTS if i['incident_id'] == incident_id), None)
    
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Add additional details for single incident view
    incident_details = incident.copy()
    incident_details.update({
        "timeline": [
            {
                "timestamp": incident['created_at'],
                "event": "Incident Created",
                "description": f"Security incident detected: {incident['description']}",
                "user": "system"
            },
            {
                "timestamp": (datetime.fromisoformat(incident['created_at']) + timedelta(minutes=5)).isoformat(),
                "event": "Investigation Started",
                "description": "Incident assigned to security analyst for investigation",
                "user": incident['assigned_to']
            }
        ],
        "related_incidents": [
            i['incident_id'] for i in SAMPLE_INCIDENTS 
            if i['type'] == incident['type'] and i['incident_id'] != incident_id
        ][:3]
    })
    
    return incident_details

@app.post("/api/incidents/{incident_id}/execute-playbook")
async def execute_playbook(
    incident_id: str,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    """Execute automated response playbook for incident"""
    
    incident = next((i for i in SAMPLE_INCIDENTS if i['incident_id'] == incident_id), None)
    
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    playbook = INCIDENT_PLAYBOOKS.get(incident['type'])
    
    if not playbook:
        raise HTTPException(status_code=400, detail=f"No playbook available for incident type: {incident['type']}")
    
    # Simulate playbook execution
    execution_id = str(uuid.uuid4())
    
    # Add background task to simulate playbook steps
    background_tasks.add_task(simulate_playbook_execution, execution_id, playbook, incident)
    
    return {
        "execution_id": execution_id,
        "playbook": playbook['name'],
        "incident_id": incident_id,
        "status": "executing",
        "estimated_completion": (datetime.now() + timedelta(minutes=int(playbook['estimated_time'].split()[0]))).isoformat(),
        "steps": len(playbook['steps'])
    }

async def simulate_playbook_execution(execution_id: str, playbook: dict, incident: dict):
    """Simulate automated playbook execution"""
    
    # Simulate step-by-step execution
    for step in playbook['steps']:
        await asyncio.sleep(2)  # Simulate processing time
        print(f"Executing step {step['step']}: {step['action']} - {step['description']}")
    
    # Update incident status
    for i, inc in enumerate(SAMPLE_INCIDENTS):
        if inc['incident_id'] == incident['incident_id']:
            SAMPLE_INCIDENTS[i]['status'] = 'resolved'
            SAMPLE_INCIDENTS[i]['updated_at'] = datetime.now().isoformat()
            SAMPLE_INCIDENTS[i]['resolution_time'] = 25  # Automated resolution time
            break

@app.get("/api/playbooks")
async def get_playbooks(api_key: str = Depends(verify_api_key)):
    """Get available incident response playbooks"""
    
    return {
        "playbooks": [
            {
                "id": key,
                "name": playbook['name'],
                "description": playbook['description'],
                "steps": len(playbook['steps']),
                "estimated_time": playbook['estimated_time'],
                "severity_threshold": playbook['severity_threshold']
            }
            for key, playbook in INCIDENT_PLAYBOOKS.items()
        ]
    }

@app.get("/api/metrics/dashboard")
async def get_security_metrics(api_key: str = Depends(verify_api_key)):
    """Get security metrics for dashboard"""
    
    # Calculate metrics from sample incidents
    total_incidents = len(SAMPLE_INCIDENTS)
    open_incidents = len([i for i in SAMPLE_INCIDENTS if i['status'] == 'open'])
    resolved_incidents = len([i for i in SAMPLE_INCIDENTS if i['status'] == 'resolved'])
    
    # Severity breakdown
    severity_counts = {}
    for incident in SAMPLE_INCIDENTS:
        severity = incident['severity']
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    # Calculate MTTR
    resolved_with_time = [i for i in SAMPLE_INCIDENTS if i['resolution_time']]
    avg_mttr = sum(i['resolution_time'] for i in resolved_with_time) / len(resolved_with_time) if resolved_with_time else 0
    
    # Update MTTR metric
    if resolved_with_time:
        for incident in resolved_with_time:
            MTTR_HISTOGRAM.observe(incident['resolution_time'] * 60)  # Convert to seconds
    
    # Incident types
    type_counts = {}
    for incident in SAMPLE_INCIDENTS:
        inc_type = incident['type']
        type_counts[inc_type] = type_counts.get(inc_type, 0) + 1
    
    return {
        "summary": {
            "total_incidents": total_incidents,
            "open_incidents": open_incidents,
            "resolved_incidents": resolved_incidents,
            "resolution_rate": round((resolved_incidents / total_incidents) * 100, 1) if total_incidents > 0 else 0,
            "average_mttr_minutes": round(avg_mttr, 1)
        },
        "severity_breakdown": severity_counts,
        "incident_types": type_counts,
        "recent_incidents": [
            {
                "incident_id": i['incident_id'],
                "title": i['title'],
                "severity": i['severity'],
                "created_at": i['created_at'],
                "status": i['status']
            }
            for i in sorted(SAMPLE_INCIDENTS, key=lambda x: x['created_at'], reverse=True)[:5]
        ],
        "mttr_improvement": {
            "current_month": round(avg_mttr, 1),
            "previous_month": round(avg_mttr * 1.4, 1),  # Simulate 40% improvement
            "improvement_percentage": 40.0
        }
    }

@app.get("/api/compliance/status")
async def get_compliance_status(api_key: str = Depends(verify_api_key)):
    """Get compliance status across frameworks"""
    
    compliance_frameworks = {
        "soc2": {
            "name": "SOC 2 Type II",
            "controls_total": 64,
            "controls_compliant": 58,
            "compliance_percentage": 90.6,
            "last_assessment": "2024-11-15",
            "next_assessment": "2024-12-15",
            "findings": [
                {"severity": "medium", "control": "CC6.1", "description": "Insufficient logging retention"},
                {"severity": "low", "control": "CC7.2", "description": "Missing change approval documentation"}
            ]
        },
        "gdpr": {
            "name": "GDPR Compliance",
            "controls_total": 28,
            "controls_compliant": 26,
            "compliance_percentage": 92.9,
            "last_assessment": "2024-11-10",
            "next_assessment": "2024-12-10",
            "findings": [
                {"severity": "medium", "control": "Art. 32", "description": "Data encryption gaps identified"}
            ]
        },
        "hipaa": {
            "name": "HIPAA Security Rule",
            "controls_total": 18,
            "controls_compliant": 17,
            "compliance_percentage": 94.4,
            "last_assessment": "2024-11-20",
            "next_assessment": "2024-12-20",
            "findings": [
                {"severity": "low", "control": "164.312(a)(1)", "description": "Access control documentation update needed"}
            ]
        }
    }
    
    return {
        "compliance_frameworks": compliance_frameworks,
        "overall_score": round(sum(f['compliance_percentage'] for f in compliance_frameworks.values()) / len(compliance_frameworks), 1),
        "total_findings": sum(len(f['findings']) for f in compliance_frameworks.values()),
        "automation_coverage": 85.2  # Percentage of controls with automated monitoring
    }

@app.post("/api/threat-intel/ioc")
async def submit_ioc(
    ioc_data: dict,
    api_key: str = Depends(verify_api_key)
):
    """Submit indicator of compromise for threat intelligence"""
    
    # Simulate IOC processing
    ioc_id = str(uuid.uuid4())
    
    processed_ioc = {
        "ioc_id": ioc_id,
        "type": ioc_data.get("type", "unknown"),
        "value": ioc_data.get("value", ""),
        "confidence": ioc_data.get("confidence", 75),
        "threat_level": ioc_data.get("threat_level", "medium"),
        "source": ioc_data.get("source", "manual"),
        "created_at": datetime.now().isoformat(),
        "status": "active",
        "related_campaigns": [],
        "mitre_tactics": ioc_data.get("mitre_tactics", [])
    }
    
    return {
        "success": True,
        "ioc": processed_ioc,
        "message": "IOC successfully processed and added to threat intelligence database"
    }

@app.get("/api/threat-intel/feed")
async def get_threat_intel_feed(
    limit: int = 50,
    threat_type: Optional[str] = None,
    api_key: str = Depends(verify_api_key)
):
    """Get threat intelligence feed"""
    
    # Sample threat intelligence data
    sample_threats = [
        {
            "id": str(uuid.uuid4()),
            "type": "malware_hash",
            "value": "a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab",
            "threat_level": "high",
            "confidence": 95,
            "source": "commercial_feed",
            "first_seen": (datetime.now() - timedelta(hours=2)).isoformat(),
            "description": "Cobalt Strike beacon payload",
            "mitre_tactics": ["T1055", "T1059"]
        },
        {
            "id": str(uuid.uuid4()),
            "type": "ip_address",
            "value": "185.220.101.42",
            "threat_level": "medium",
            "confidence": 80,
            "source": "osint",
            "first_seen": (datetime.now() - timedelta(hours=6)).isoformat(),
            "description": "Known C2 infrastructure",
            "mitre_tactics": ["T1071", "T1572"]
        }
    ]
    
    return {
        "threats": sample_threats[:limit],
        "total_count": len(sample_threats),
        "last_updated": datetime.now().isoformat()
    }

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8080,
        reload=True
    )