# Port Werks Usage Examples

This document provides practical examples for using Port Werks in various security testing scenarios.

## Table of Contents
- [Web Application Testing](#web-application-testing)
- [Network Infrastructure Assessment](#network-infrastructure-assessment)
- [Database Server Auditing](#database-server-auditing)
- [IoT Device Testing](#iot-device-testing)
- [Internal Network Mapping](#internal-network-mapping)
- [Compliance Scanning](#compliance-scanning)

---

## Web Application Testing

### Scenario: Testing a web server for exposed services

**Objective**: Identify all web-related services on a target server

**Configuration**:
```
Target: web.example.com
Ports: 80,443,8080,8443,8008,8081,9080,9443
Technique: TCP Connect
Concurrency: 100 threads
Timeout: 2000 ms
Options:
  - Service Detection: ✓
  - Version Detection: ✓
  - OS Fingerprinting: ✓
```

**Expected Results**:
- Identify running web servers (Apache, Nginx, IIS)
- Detect version numbers for vulnerability research
- Find non-standard ports that may be forgotten/unpatched

**Security Insights**:
- Check for outdated software versions
- Look for development/testing servers on non-standard ports
- Verify SSL/TLS on HTTPS ports

---

## Network Infrastructure Assessment

### Scenario: Scanning a corporate gateway

**Objective**: Identify network services and potential attack vectors

**Configuration**:
```
Target: 10.0.0.1
Ports: Top 100 Ports (Quick Select)
Technique: SYN Scan (run as administrator)
Concurrency: 200 threads
Timeout: 2000 ms
Options:
  - Service Detection: ✓
  - Version Detection: ✓
  - OS Fingerprinting: ✓
```

**Expected Results**:
- SSH (22) - Management interface
- SNMP (161) - Network monitoring
- Common admin ports

**Security Insights**:
- Ensure only necessary services are exposed
- Verify SSH version and configuration
- Check if SNMP has default community strings

---

## Database Server Auditing

### Scenario: Database server security check

**Objective**: Verify database services and access controls

**Configuration**:
```
Target: db.internal.company.com
Ports: 1433,3306,5432,27017,6379,1521,3050
Technique: TCP Connect
Concurrency: 50 threads
Timeout: 5000 ms
Options:
  - Service Detection: ✓
  - Version Detection: ✓
```

**Port Reference**:
- 1433: Microsoft SQL Server
- 3306: MySQL/MariaDB
- 5432: PostgreSQL
- 27017: MongoDB
- 6379: Redis
- 1521: Oracle
- 3050: Firebird

**Security Insights**:
- Databases should NOT be directly accessible from external networks
- Check for default ports vs. custom ports
- Verify authentication requirements

---

## IoT Device Testing

### Scenario: Smart device security assessment

**Objective**: Identify exposed IoT services and vulnerabilities

**Configuration**:
```
Target: 192.168.1.150
Ports: 23,80,443,554,1883,5683,8883
Technique: TCP Connect
Concurrency: 50 threads
Timeout: 5000 ms
Options:
  - Service Detection: ✓
  - Version Detection: ✓
```

**Port Reference**:
- 23: Telnet (RED FLAG - unencrypted)
- 80/443: Web interface
- 554: RTSP (video streaming)
- 1883/8883: MQTT (IoT messaging)
- 5683: CoAP (IoT protocol)

**Security Insights**:
- Telnet on IoT devices is a critical vulnerability
- Check for default credentials
- Verify firmware version

---

## Internal Network Mapping

### Scenario: Discovery scan of internal subnet

**Objective**: Map active hosts and services on internal network

**Phase 1 - Host Discovery**:
```
Target: 192.168.1.0/24
Method: Ping Sweep (use Host Discovery feature)
```

**Phase 2 - Service Enumeration**:
```
Target: [Active hosts from Phase 1]
Ports: Top 20 Ports
Technique: TCP Connect
Concurrency: 100 threads
Timeout: 1000 ms
```

**Typical Findings**:
- Workstations: 445 (SMB), 3389 (RDP)
- Printers: 631 (IPP), 9100 (JetDirect)
- Servers: 22 (SSH), 3389 (RDP), 5985 (WinRM)

---

## Compliance Scanning

### Scenario: PCI DSS compliance verification

**Objective**: Verify that cardholder data environment meets PCI requirements

**Configuration**:
```
Target: cardholder-data-server.internal
Ports: 20,21,23,25,80,110,143,443,445,1433,3306,3389
Technique: TCP Connect
Concurrency: 100 threads
Options:
  - Service Detection: ✓
  - Version Detection: ✓
```

**PCI DSS Checks**:
- Telnet (23) should be CLOSED ✓
- FTP (21) should be CLOSED or use FTPS ✓
- HTTP (80) should redirect to HTTPS (443) ✓
- Direct database access should be blocked ✓
- Unnecessary services should be disabled ✓

**Export**: Generate HTML report for compliance documentation

---

## Advanced Techniques

### Stealth Scanning

For scenarios requiring minimal detection:

```
Technique: SYN Scan
Concurrency: 50 threads (low)
Timeout: 5000 ms (high)
Rate Limiting: Enabled (optional future feature)
```

### Fast Reconnaissance

For quick initial assessment:

```
Ports: Top 20 Ports
Technique: TCP Connect
Concurrency: 500 threads
Timeout: 1000 ms
Options: Service Detection only
```

### Comprehensive Audit

For thorough security assessment:

```
Ports: Full Scan (1-65535)
Technique: SYN Scan
Concurrency: 200 threads
Timeout: 2000 ms
Options: All enabled
Export: HTML + JSON
```

---

## Best Practices

1. **Always Get Authorization**
   - Obtain written permission
   - Define scan scope and timing
   - Document all activities

2. **Start Conservative**
   - Begin with smaller port ranges
   - Use slower scan rates initially
   - Gradually increase intensity

3. **Document Findings**
   - Export results in multiple formats
   - Screenshot interesting findings
   - Note timestamps and configurations

4. **Respect Network Resources**
   - Avoid scanning during business hours
   - Use appropriate concurrency levels
   - Monitor network impact

5. **Follow Up**
   - Verify findings manually
   - Research identified versions
   - Report vulnerabilities properly

---

## Troubleshooting

### No Open Ports Found
- Verify target is reachable (ping first)
- Check firewall rules
- Increase timeout values
- Try different scan techniques

### SYN Scan Fails
- Run application as Administrator
- Install WinPcap/Npcap on Windows
- Fall back to TCP Connect scan

### Slow Performance
- Reduce concurrency
- Increase timeout
- Check network bandwidth
- Scan smaller port ranges

---

## Legal Notice

All examples in this document assume you have **explicit authorization** to perform security testing on the specified targets. Unauthorized scanning is illegal and unethical.

**Use Port Werks responsibly and only for legitimate security testing purposes.**
