# KB: Cloud Security Testing
# Applies to: AWS, Azure, GCP, cloud misconfig, IAM, S3/Blob/GCS, serverless

## Cloud Security Findings — CVSS & CWE
| Finding | CVSS | CWE | Provider |
|---|---|---|---|
| S3 bucket publicly readable (sensitive data) | 9.1 | CWE-284 | AWS |
| S3 bucket publicly writable | 9.8 | CWE-284 | AWS |
| Azure Blob container public access enabled | 9.1 | CWE-284 | Azure |
| GCS bucket public with sensitive files | 9.1 | CWE-284 | GCP |
| IMDSv1 accessible (SSRF → credential theft) | 8.6 | CWE-918 | AWS |
| EC2 instance profile with excessive permissions | 8.8 | CWE-269 | AWS |
| Azure VM Managed Identity with Owner role | 8.8 | CWE-269 | Azure |
| IAM user with AdministratorAccess policy | 9.0 | CWE-269 | AWS |
| Root account used / no MFA on root | 9.8 | CWE-287 | AWS |
| No MFA on cloud management console | 8.8 | CWE-287 | All |
| Security group allowing 0.0.0.0/0 on SSH/RDP | 9.8 | CWE-284 | AWS |
| CloudTrail logging disabled | 6.5 | CWE-778 | AWS |
| Azure Defender disabled for subscriptions | 6.5 | CWE-693 | Azure |
| Lambda function with hardcoded credentials | 9.1 | CWE-798 | AWS |
| Container image with hardcoded secrets | 9.1 | CWE-798 | All |
| Kubernetes API server exposed publicly | 9.8 | CWE-284 | All |
| Privilege escalation via IAM PassRole | 8.8 | CWE-269 | AWS |
| Unencrypted EBS volumes with sensitive data | 6.5 | CWE-311 | AWS |
| RDS publicly accessible with weak password | 9.8 | CWE-521 | AWS |
| Serverless function injection (event injection) | 8.6 | CWE-94 | All |

## AWS-Specific Attack Surface
| Service | Common Misconfig | Attack Path |
|---|---|---|
| S3 | Public ACL, no versioning | Data exfiltration, malware hosting |
| EC2 | Overprivileged instance profile, IMDSv1 | SSRF → metadata → creds → full account |
| Lambda | Excessive role, env var secrets | Code injection, data access, lateral move |
| RDS | Public access, weak password, no encryption | Database dump, credential access |
| IAM | Wildcard policies, no MFA, unused access keys | Privilege escalation, persistence |
| CloudTrail | Disabled or incomplete logging | Attack invisibility |
| KMS | Key policy allows all, key deletion | Data decryption, key abuse |
| STS | AssumeRole without condition | Cross-account privilege escalation |
| Cognito | Allow unauthenticated identities | Data access without auth |

## IMDS Attack (AWS Metadata Service)
```
# Via SSRF — get credentials from instance metadata
http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Response: AccessKeyId, SecretAccessKey, Token → use with aws-cli
# Fix: Enforce IMDSv2 (require session-oriented requests with PUT token)
```

## Cloud Security Frameworks
- AWS Well-Architected Framework — Security Pillar
- CIS AWS Foundations Benchmark v3.0
- CIS Azure Foundations Benchmark v2.0
- CIS GCP Foundations Benchmark v2.0
- NIST SP 800-204: Security strategies for microservices
- CSA Cloud Controls Matrix (CCM) v4.0

## Container & Kubernetes Security Findings
| Finding | CVSS | Impact |
|---|---|---|
| Privileged container running | 9.0 | Host escape, full node compromise |
| Container running as root | 8.0 | Privilege escalation potential |
| Kubernetes API server unauthenticated | 10.0 | Full cluster takeover |
| RBAC ClusterAdmin bound to service account | 9.0 | Cluster privilege escalation |
| Secrets in environment variables | 8.8 | Credential extraction |
| Docker socket mounted in container | 9.0 | Full host escape via Docker daemon |
| Pod security policies missing | 7.5 | Container escape risk |
| etcd exposed without TLS/auth | 10.0 | All cluster secrets accessible |
| Writable host path mounted | 8.0 | Host filesystem access |
| Network policy missing (all pods can communicate) | 7.5 | Unrestricted lateral movement |
