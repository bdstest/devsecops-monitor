# DevSecOps Monitor Deployment Guide

## Overview

Production deployment guide for DevSecOps Monitor security platform with ELK stack, Suricata, Wazuh, and compliance monitoring.

## Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Data Sources  │    │   Processing    │    │   Visualization │
│                 │    │                 │    │                 │
│ • Suricata      │───▶│ • Logstash      │───▶│ • Kibana        │
│ • Wazuh         │    │ • Elasticsearch │    │ • Grafana       │
│ • Application   │    │ • Threat Intel  │    │ • Custom UI     │
│ • Infrastructure│    │ • ML Pipeline   │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## System Requirements

### Minimum Requirements
- **CPU**: 16 cores
- **RAM**: 32 GB
- **Storage**: 500 GB SSD
- **Network**: 1 Gbps

### Recommended Requirements
- **CPU**: 32+ cores
- **RAM**: 64+ GB
- **Storage**: 2+ TB NVMe SSD
- **Network**: 10 Gbps

### Storage Planning
- **Elasticsearch**: 80% of total storage
- **Raw logs**: 15% of total storage
- **Operating system**: 5% of total storage

## Quick Start Deployment

### Docker Compose Deployment
```bash
# Clone repository
git clone https://github.com/bdstest/devsecops-monitor
cd devsecops-monitor

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Start all services
docker-compose up -d

# Verify deployment
docker-compose ps
curl http://localhost:5601  # Kibana
curl http://localhost:3000  # Grafana
```

### Environment Configuration
```bash
# .env file
ELASTIC_VERSION=8.11.0
ELASTIC_PASSWORD=SecurePassword123
KIBANA_PASSWORD=SecurePassword123

# Wazuh Configuration
WAZUH_MANAGER_PASSWORD=SecurePassword123
WAZUH_API_USER=wazuh-api
WAZUH_API_PASSWORD=SecurePassword123

# Network Configuration
SUBNET=172.25.0.0/16
GATEWAY=172.25.0.1

# Storage Configuration
ELASTIC_DATA_PATH=/var/lib/elasticsearch
WAZUH_DATA_PATH=/var/lib/wazuh
SURICATA_LOG_PATH=/var/log/suricata

# Security Configuration
JWT_SECRET=your-jwt-secret-here
SSL_ENABLED=true
SSL_CERT_PATH=/etc/ssl/certs
```

## Production Deployment

### Kubernetes Deployment
```yaml
# k8s-namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: devsecops-monitor
  labels:
    name: security-monitoring
```

```yaml
# elasticsearch-cluster.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: elasticsearch
  namespace: devsecops-monitor
spec:
  serviceName: elasticsearch
  replicas: 3
  selector:
    matchLabels:
      app: elasticsearch
  template:
    metadata:
      labels:
        app: elasticsearch
    spec:
      containers:
      - name: elasticsearch
        image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
        resources:
          limits:
            memory: 8Gi
            cpu: 4
          requests:
            memory: 4Gi
            cpu: 2
        env:
        - name: cluster.name
          value: devsecops-cluster
        - name: node.name
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: discovery.seed_hosts
          value: "elasticsearch-0,elasticsearch-1,elasticsearch-2"
        - name: cluster.initial_master_nodes
          value: "elasticsearch-0,elasticsearch-1,elasticsearch-2"
        - name: ES_JAVA_OPTS
          value: "-Xms4g -Xmx4g"
        volumeMounts:
        - name: data
          mountPath: /usr/share/elasticsearch/data
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: 200Gi
```

### Logstash Configuration
```yaml
# logstash-configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: logstash-config
  namespace: devsecops-monitor
data:
  logstash.yml: |
    http.host: "0.0.0.0"
    path.config: /usr/share/logstash/pipeline
    pipeline.workers: 4
    pipeline.batch.size: 125
    pipeline.batch.delay: 50
  pipelines.yml: |
    - pipeline.id: security-events
      path.config: "/usr/share/logstash/pipeline/security.conf"
      pipeline.workers: 2
    - pipeline.id: compliance-logs
      path.config: "/usr/share/logstash/pipeline/compliance.conf"
      pipeline.workers: 1
  security.conf: |
    input {
      beats {
        port => 5044
        type => "security"
      }
      tcp {
        port => 5514
        type => "syslog"
      }
    }
    
    filter {
      if [type] == "suricata" {
        json {
          source => "message"
        }
        
        if [event_type] == "alert" {
          mutate {
            add_field => { "security_event" => "network_alert" }
            add_field => { "severity" => "%{[alert][severity]}" }
          }
        }
      }
      
      if [type] == "wazuh" {
        json {
          source => "message"
        }
        
        if [rule][level] >= 7 {
          mutate {
            add_field => { "security_event" => "host_alert" }
            add_field => { "severity" => "high" }
          }
        }
      }
    }
    
    output {
      elasticsearch {
        hosts => ["elasticsearch:9200"]
        index => "security-events-%{+YYYY.MM.dd}"
        user => "elastic"
        password => "${ELASTIC_PASSWORD}"
      }
    }
```

### Wazuh Manager Deployment
```yaml
# wazuh-manager.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wazuh-manager
  namespace: devsecops-monitor
spec:
  replicas: 1
  selector:
    matchLabels:
      app: wazuh-manager
  template:
    metadata:
      labels:
        app: wazuh-manager
    spec:
      containers:
      - name: wazuh-manager
        image: wazuh/wazuh-manager:4.7.0
        resources:
          limits:
            memory: 4Gi
            cpu: 2
          requests:
            memory: 2Gi
            cpu: 1
        env:
        - name: WAZUH_MANAGER_ADMIN_USER
          value: "wazuh-admin"
        - name: WAZUH_MANAGER_ADMIN_PASSWORD
          valueFrom:
            secretKeyRef:
              name: wazuh-secrets
              key: admin-password
        ports:
        - containerPort: 1514
          name: agents
        - containerPort: 1515
          name: agents-registration
        - containerPort: 55000
          name: api
        volumeMounts:
        - name: wazuh-config
          mountPath: /var/ossec/etc/ossec.conf
          subPath: ossec.conf
        - name: wazuh-rules
          mountPath: /var/ossec/etc/rules/
        - name: wazuh-data
          mountPath: /var/ossec/logs/
      volumes:
      - name: wazuh-config
        configMap:
          name: wazuh-config
      - name: wazuh-rules
        configMap:
          name: wazuh-rules
      - name: wazuh-data
        persistentVolumeClaim:
          claimName: wazuh-data
```

### Suricata DaemonSet
```yaml
# suricata-daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: suricata
  namespace: devsecops-monitor
spec:
  selector:
    matchLabels:
      app: suricata
  template:
    metadata:
      labels:
        app: suricata
    spec:
      hostNetwork: true
      containers:
      - name: suricata
        image: jasonish/suricata:latest
        securityContext:
          privileged: true
          capabilities:
            add:
            - NET_ADMIN
            - NET_RAW
        env:
        - name: SURICATA_OPTIONS
          value: "-i any --init-errors-fatal"
        volumeMounts:
        - name: suricata-config
          mountPath: /etc/suricata/suricata.yaml
          subPath: suricata.yaml
        - name: suricata-rules
          mountPath: /etc/suricata/rules/
        - name: suricata-logs
          mountPath: /var/log/suricata/
      volumes:
      - name: suricata-config
        configMap:
          name: suricata-config
      - name: suricata-rules
        configMap:
          name: suricata-rules
      - name: suricata-logs
        hostPath:
          path: /var/log/suricata
```

## Security Configuration

### TLS/SSL Setup
```bash
# Generate CA certificate
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -days 365 -key ca-key.pem -sha256 -out ca.pem

# Generate server certificates
openssl genrsa -out server-key.pem 4096
openssl req -subj "/CN=devsecops-monitor" -sha256 -new -key server-key.pem -out server.csr
openssl x509 -req -days 365 -sha256 -in server.csr -CA ca.pem -CAkey ca-key.pem -out server-cert.pem

# Create Kubernetes secret
kubectl create secret tls devsecops-tls \
  --cert=server-cert.pem \
  --key=server-key.pem \
  --namespace=devsecops-monitor
```

### RBAC Configuration
```yaml
# rbac.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: devsecops-monitor
  name: devsecops-operator
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log", "services", "endpoints", "configmaps", "secrets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets", "statefulsets", "daemonsets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: devsecops-operator-binding
  namespace: devsecops-monitor
subjects:
- kind: ServiceAccount
  name: devsecops-operator
  namespace: devsecops-monitor
roleRef:
  kind: Role
  name: devsecops-operator
  apiGroup: rbac.authorization.k8s.io
```

## Monitoring and Alerting

### Prometheus Configuration
```yaml
# prometheus-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
  namespace: devsecops-monitor
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
      evaluation_interval: 15s
    
    rule_files:
      - "/etc/prometheus/rules/*.yml"
    
    scrape_configs:
    - job_name: 'elasticsearch'
      static_configs:
      - targets: ['elasticsearch:9200']
      metrics_path: '/_prometheus/metrics'
    
    - job_name: 'logstash'
      static_configs:
      - targets: ['logstash:9600']
      metrics_path: '/_node/stats'
    
    - job_name: 'wazuh-manager'
      static_configs:
      - targets: ['wazuh-manager:55000']
    
    alerting:
      alertmanagers:
      - static_configs:
        - targets:
          - alertmanager:9093
```

### Grafana Dashboards
```json
{
  "dashboard": {
    "title": "DevSecOps Security Overview",
    "panels": [
      {
        "title": "Security Alerts by Severity",
        "type": "piechart",
        "targets": [
          {
            "expr": "sum by (severity) (security_alerts_total)"
          }
        ]
      },
      {
        "title": "Incident Response Times",
        "type": "graph",
        "targets": [
          {
            "expr": "avg(incident_response_time_seconds)"
          }
        ]
      },
      {
        "title": "Compliance Score Trends",
        "type": "graph",
        "targets": [
          {
            "expr": "compliance_score_percentage"
          }
        ]
      }
    ]
  }
}
```

## Backup and Recovery

### Elasticsearch Backup
```bash
#!/bin/bash
# elasticsearch-backup.sh

BACKUP_REPO="devsecops-backups"
DATE=$(date +%Y%m%d_%H%M%S)
SNAPSHOT_NAME="security-data-$DATE"

# Create snapshot
curl -X PUT "elasticsearch:9200/_snapshot/$BACKUP_REPO/$SNAPSHOT_NAME" \
  -H "Content-Type: application/json" \
  -d '{
    "indices": "security-*,compliance-*,threat-intel-*",
    "ignore_unavailable": true,
    "include_global_state": false
  }'

# Verify snapshot
curl -X GET "elasticsearch:9200/_snapshot/$BACKUP_REPO/$SNAPSHOT_NAME"

# Upload to cloud storage
aws s3 cp /backup/$SNAPSHOT_NAME s3://devsecops-backups/
```

### Configuration Backup
```bash
#!/bin/bash
# config-backup.sh

BACKUP_DIR="/backup/configs/$(date +%Y%m%d)"
mkdir -p $BACKUP_DIR

# Backup Kubernetes configs
kubectl get all -n devsecops-monitor -o yaml > $BACKUP_DIR/k8s-resources.yaml
kubectl get configmaps -n devsecops-monitor -o yaml > $BACKUP_DIR/configmaps.yaml
kubectl get secrets -n devsecops-monitor -o yaml > $BACKUP_DIR/secrets.yaml

# Backup custom rules and configurations
cp -r /etc/suricata/rules/ $BACKUP_DIR/suricata-rules/
cp -r /var/ossec/etc/rules/ $BACKUP_DIR/wazuh-rules/
cp /etc/logstash/conf.d/* $BACKUP_DIR/logstash-configs/

# Create archive
tar -czf $BACKUP_DIR.tar.gz $BACKUP_DIR
```

## Performance Tuning

### Elasticsearch Optimization
```yaml
# elasticsearch-performance.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: elasticsearch-config
data:
  elasticsearch.yml: |
    cluster.name: devsecops-cluster
    network.host: 0.0.0.0
    
    # Memory settings
    indices.memory.index_buffer_size: 30%
    indices.memory.min_index_buffer_size: 512mb
    
    # Thread pool settings
    thread_pool.write.queue_size: 10000
    thread_pool.search.queue_size: 10000
    
    # Index settings
    index.refresh_interval: 30s
    index.number_of_replicas: 1
    index.max_result_window: 100000
    
    # Performance settings
    indices.queries.cache.size: 20%
    indices.fielddata.cache.size: 40%
    
    # Security monitoring specific
    action.auto_create_index: +security-*,+compliance-*,-*
```

### Logstash Performance
```yaml
# logstash-performance.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: logstash-performance
data:
  logstash.yml: |
    pipeline.workers: 8
    pipeline.batch.size: 250
    pipeline.batch.delay: 50
    
    # JVM settings
    path.logs: /var/log/logstash
    
    # Performance monitoring
    monitoring.enabled: true
    monitoring.elasticsearch.hosts: ["elasticsearch:9200"]
  
  jvm.options: |
    -Xms4g
    -Xmx4g
    -XX:+UseConcMarkSweepGC
    -XX:CMSInitiatingOccupancyFraction=75
    -XX:+UseCMSInitiatingOccupancyOnly
```

## Troubleshooting

### Common Issues

#### Elasticsearch Cluster Red Status
```bash
# Check cluster health
curl -X GET "elasticsearch:9200/_cluster/health?pretty"

# Check unassigned shards
curl -X GET "elasticsearch:9200/_cat/shards?h=index,shard,prirep,state,unassigned.reason"

# Force allocation if needed
curl -X POST "elasticsearch:9200/_cluster/reroute" \
  -H "Content-Type: application/json" \
  -d '{
    "commands": [
      {
        "allocate_empty_primary": {
          "index": "security-events-2024.07.20",
          "shard": 0,
          "node": "elasticsearch-0",
          "accept_data_loss": true
        }
      }
    ]
  }'
```

#### Logstash Pipeline Blockage
```bash
# Check pipeline stats
curl -X GET "logstash:9600/_node/stats/pipelines"

# Check for dead letter queue
ls -la /var/lib/logstash/dead_letter_queue/

# Restart specific pipeline
curl -X POST "logstash:9600/_node/pipelines/security-events/_reload"
```

#### High Memory Usage
```bash
# Check memory usage by component
kubectl top pods -n devsecops-monitor

# Scale down non-critical components
kubectl scale deployment kibana --replicas=1 -n devsecops-monitor

# Clear old indices
curl -X DELETE "elasticsearch:9200/security-events-*" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "range": {
        "@timestamp": {
          "lt": "now-30d"
        }
      }
    }
  }'
```

## Production Checklist

### Pre-deployment
- [ ] Hardware requirements verified
- [ ] Network segmentation configured
- [ ] SSL certificates generated
- [ ] Backup procedures tested
- [ ] Monitoring alerts configured
- [ ] Security rules updated
- [ ] Performance baselines established

### Post-deployment
- [ ] All services healthy
- [ ] Data ingestion working
- [ ] Dashboards accessible
- [ ] Alerts triggering correctly
- [ ] Backup jobs scheduled
- [ ] Documentation updated
- [ ] Team training completed