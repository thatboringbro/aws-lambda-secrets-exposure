# AWS Lambda Secret Exposure Security Lab

A hands-on demonstration of how Lambda functions with insecure secret management and overprivileged IAM roles lead to data breaches — and how to detect and prevent them.

> *Related images can be found in the `'/images'` directory.*

## 📖 Overview

This project demonstrates a **complete attack lifecycle** in AWS:

1. **Vulnerability:** Lambda stores secrets in environment variables + overprivileged IAM role
2. **Exploitation:** Attacker extracts secrets from CloudWatch logs and accesses sensitive S3 buckets
3. **Detection:** CloudTrail reveals the attack pattern
4. **Remediation:** Secure implementation using Secrets Manager and Principle of Least Privilege

**The Goal:** Proving that this real-world vulnerability can be exploited, detected, and remediated.

---

## 🏗️ Lab Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ATTACK SCENARIO                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Developer Creates Vulnerable Lambda                        │
│  ├─ Stores DB_PASSWORD in environment variables             │
│  ├─ Prints secrets to CloudWatch logs                       │
│  └─ Attached overprivileged LabRole (full S3 access)        │
│                                                             │
│  Attacker Exploits                                          │
│  ├─ Reads CloudWatch logs → extracts DB password            │
│  ├─ Enumerates S3 buckets via Lambda role                   │
│  └─ Copies sensitive files (credentials, audit logs)        │
│                                                             │
│  Detection via CloudTrail                                   │
│  ├─ ListBuckets event from Lambda role                      │
│  ├─ GetObject from secrets-backup bucket                    │
│  └─ Unusual S3 access pattern                               │
│                                                             │
│  Remediation                                                │
│  ├─ Move secrets to Secrets Manager                         │
│  ├─ Apply Principle of Least Privilege                      │
│  ├─ Enable S3 access logging                                │
│  └─ Implement automated alerts                              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## ⚔️ Phase 1: Vulnerable Lambda (The Attack)

### Setup: S3 Buckets & Data

```bash
# Create S3 buckets
aws s3 mb s3://app-data-$(date +%s) --region us-east-1
aws s3 mb s3://secrets-backup-$(date +%s) --region us-east-1
aws s3 mb s3://audit-logs-$(date +%s) --region us-east-1

# Upload fake sensitive data
cat > db-creds.json << 'EOF'
{
  "host": "production-db.us-east-1.rds.amazonaws.com",
  "username": "admin",
  "password": "SuperSecretPassword123!@#",
  "database": "production_db"
}
EOF

aws s3 cp db-creds.json s3://secrets-backup-XXX/database-credentials.json
```

### Vulnerable Lambda Code

```python
import boto3
import os

# BAD: Secrets in environment variables
DB_PASSWORD = os.environ.get('DB_PASSWORD')
API_KEY = os.environ.get('API_KEY')

s3 = boto3.client('s3')

def lambda_handler(event, context):
    try:
        # BAD: Secrets printed to CloudWatch logs
        print(f"[INFO] Database password: {DB_PASSWORD}")
        print(f"[INFO] API Key: {API_KEY}")
        
        # BAD: Overprivileged Lambda enumerates ALL buckets
        buckets_response = s3.list_buckets()
        bucket_names = [b['Name'] for b in buckets_response['Buckets']]
        print(f"[INFO] Available buckets: {bucket_names}")
        
        # BAD: Can access any bucket
        creds_response = s3.get_object(
            Bucket=os.environ.get('SECRETS_BUCKET'),
            Key='database-credentials.json'
        )
        creds = creds_response['Body'].read().decode('utf-8')
        print(f"[INFO] Retrieved credentials: {creds}")
        
        return {'statusCode': 200, 'body': 'Success'}
    except Exception as e:
        return {'statusCode': 500, 'body': str(e)}
```

### Deploy

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
LABROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/LabRole"

aws lambda create-function \
  --function-name vulnerable-lambda-app \
  --runtime python3.11 \
  --role $LABROLE_ARN \
  --handler lambda_vulnerable.lambda_handler \
  --zip-file fileb://lambda_vulnerable.zip \
  --environment "Variables={DB_PASSWORD=SuperSecretPassword123,DB_USERNAME=admin,API_KEY=sk1234567890abcdef,SECRETS_BUCKET=secrets-backup-XXX,AUDIT_BUCKET=audit-logs-XXX}"
```

---

## 🔍 Phase 2: Detection (How I Caught It)

### Evidence 1: Secrets in CloudWatch Logs

```bash
aws logs get-log-events \
  --log-group-name /aws/lambda/vulnerable-lambda-app \
  --log-stream-name <stream>
```

**Output shows:**
```
[INFO] Database password: SuperSecretPassword123!@#
[INFO] API Key: sk1234567890abcdef
[INFO] Available buckets: [app-data-1789737161, secrets-backup-1789737161, audit-logs-1789737166]
```

### Evidence 2: CloudTrail Shows Bucket Enumeration

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListBuckets \
  --region us-east-1
```

**CloudTrail reveals:**
- User: `vulnerable-lambda-app` (IAM role)
- Event: `ListBuckets` (enumerating all buckets)
- Multiple calls within seconds (suspicious pattern)

### Evidence 3: Sensitive Bucket Access

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \
  --region us-east-1 | grep secrets-backup
```

**CloudTrail shows:**
```
Event: GetObject
Principal: vulnerable-lambda-app
Resource: secrets-backup-1789737161/database-credentials.json
Time: 2026-09-18T14:36:35Z
```

**The attack signature is clear:**
1. ListBuckets (reconnaissance)
2. GetObject on secrets-backup (data exfiltration)
3. Access from Lambda execution role (suspicious)

---

## 🛡️ Phase 3: Remediation (The Fix)

### Remediation 1: Use Secrets Manager (Not Environment Variables)

**Create a secret:**
```bash
cat > db-secret.json << 'EOF'
{
  "username": "admin",
  "password": "SuperSecretPassword123!@#"
}
EOF

aws secretsmanager create-secret \
  --name prod/database/credentials \
  --secret-string file://db-secret.json
```

**Secure Lambda Code:**
```python
import boto3
import json
from botocore.exceptions import ClientError

secrets_client = boto3.client('secretsmanager')
s3 = boto3.client('s3')

def get_database_credentials():
    """ GOOD: Fetch secrets from Secrets Manager at runtime"""
    try:
        response = secrets_client.get_secret_value(SecretId='prod/database/credentials')
        return json.loads(response['SecretString'])
    except ClientError as e:
        print(f"[ERROR] Failed to retrieve secrets: {str(e)}")
        raise

def lambda_handler(event, context):
    try:
        # GOOD: Get credentials from Secrets Manager
        db_creds = get_database_credentials()
        
        # GOOD: Don't log the actual secrets
        print("[INFO] Successfully retrieved database credentials from Secrets Manager")
        
        # GOOD: Only access specific bucket (from environment)
        app_bucket = os.environ.get('APP_BUCKET')
        response = s3.get_object(Bucket=app_bucket, Key='config.json')
        
        return {'statusCode': 200, 'body': 'Success'}
    except Exception as e:
        print(f"[ERROR] Lambda failed: {str(e)}")
        return {'statusCode': 500, 'body': 'Internal error'}
```

### Remediation 2: Apply Principle of Least Privilege (PoLP)

**Restrictive IAM Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadAppDataOnly",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::app-data-1789737161/*"
    },
    {
      "Sid": "WriteAppOutput",
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::app-output-1789737161/*"
    },
    {
      "Sid": "AccessDatabaseCredentials",
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "arn:aws:secretsmanager:us-east-1:*:secret:prod/database/*"
    },
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:us-east-1:*:log-group:/aws/lambda/*"
    }
  ]
}
```

**Key differences:**
- ❌ **NO** `s3:ListBuckets` (can't enumerate all buckets)
- ❌ **NO** access to `secrets-backup` or `audit-logs` buckets
- ✅ **ONLY** `GetObject` on app-data (specific bucket)
- ✅ **ONLY** `PutObject` on app-output (for writing results)
- ✅ **ONLY** Secrets Manager access (scoped to prod/database/*)

### Remediation 3: Enable S3 Access Logging

```bash
# Create logging configuration
cat > logging.json << 'EOF'
{
  "LoggingEnabled": {
    "TargetBucket": "audit-logs-1789737161",
    "TargetPrefix": "s3-access-logs/"
  }
}
EOF

# Enable logging on sensitive bucket
aws s3api put-bucket-logging \
  --bucket secrets-backup-1789737161 \
  --bucket-logging-status file://logging.json
```

Now every S3 access to the sensitive bucket is logged.

### Remediation 4: Block Public Access

```bash
aws s3api put-public-access-block \
  --bucket secrets-backup-1789737161 \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

Even if credentials leak externally, the bucket can't be accessed.

### Remediation 5: Enable Encryption

```bash
aws s3api put-bucket-encryption \
  --bucket secrets-backup-1789737161 \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'
```

Data is encrypted at rest.

### Remediation 6: Enable Versioning (for forensics)

```bash
aws s3api put-bucket-versioning \
  --bucket secrets-backup-1789737161 \
  --versioning-configuration Status=Enabled
```

If an attacker deletes or modifies files, you can recover previous versions.

---

## 🔔 Phase 4: Detection Engineering (Automated Alerts)

### Detection Rule 1: Alert on Secrets in Logs

**CloudWatch Logs Insights:**
```
fields @timestamp, @message, @logStream
| filter @message like /password|API_KEY|secret|token/i
| stats count() as secret_exposures by @logStream
```

**Alert:** If any Lambda logs secrets, trigger HIGH-severity incident.

### Detection Rule 2: Alert on ListBuckets

**CloudTrail filter:**
```
EventName = "ListBuckets" 
AND PrincipalId LIKE "%lambda%"
AND UserAgent != "AWS Console"
```

**Alert:** Lambdas shouldn't enumerate all buckets. This is reconnaissance.

### Detection Rule 3: Alert on Sensitive Bucket Access

**CloudTrail filter:**
```
EventName = "GetObject" 
AND RequestParameters LIKE "%secrets-backup%"
AND PrincipalId NOT LIKE "%admin%"
AND PrincipalId NOT LIKE "%approved-service%"
```

**Alert:** Only approved services should access sensitive buckets.

### Detection Rule 4: Correlate Patterns

**The kill chain:**
1. Secrets logged in CloudWatch (within 5 minutes)
2. ListBuckets from Lambda role (within 5 minutes)
3. GetObject from secrets bucket (within 5 minutes)

If this pattern occurs, it's a HIGH-confidence breach.

---

## 📊 MITRE ATT&CK Mapping

This lab demonstrates:

| Tactic | Technique | Detection |
|--------|-----------|-----------|
| **Reconnaissance** | T1526 - Enumerate Cloud Resources | ListBuckets event in CloudTrail |
| **Credential Access** | T1555 - Credentials in Files | Secrets in CloudWatch logs |
| **Exfiltration** | T1537 - Transfer Data to Cloud Account | GetObject on sensitive bucket |
| **Impact** | T1530 - Data from Cloud Storage | S3 access logs + CloudTrail |

---

## 🎯 Key Takeaways

### For Security Teams
- Enforce Secrets Manager (ban environment variables via IAM policy)
- Monitor ListBuckets events from non-human principals
- Alert on secrets in logs (automated pattern matching)
- Require PoLP for all Lambda roles

### For Cloud Architects
- Default-deny access (PoLP)
- Enable CloudTrail on all AWS accounts
- Enable S3 access logging on sensitive buckets
- Use Secrets Manager for all credentials

### For Developers
- Never use environment variables for secrets
- Never print secrets to logs
- Request only the permissions you need
- Use `try-except` to handle Secrets Manager failures


---


## 🚀 How to Reproduce This Lab


### Prerequisites
- AWS Academy sandbox or AWS account
- AWS CLI configured
- Python 3.11

### Steps

1. **Create S3 buckets and upload test data** (see Phase 1)
2. **Deploy vulnerable Lambda** (see Phase 1)
3. **Invoke Lambda and view logs** (see Phase 2)
4. **Query CloudTrail for evidence** (see Phase 2)
5. **Deploy secure Lambda** (see Phase 3)
6. **Implement PoLP and monitoring** (see Phase 3 & 4)

---

## 📚 Learning Resources

- [AWS Lambda Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/lambda-best-practices.html)
- [AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/)
- [IAM Principle of Least Privilege](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege)
- [CloudTrail for Security Analysis](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/)
- [MITRE ATT&CK for Cloud](https://attack.mitre.org/matrices/enterprise/cloud/)

---

## 📧 Questions?

If you found this useful or have suggestions for improvement, reach out:

- **LinkedIn:** [Gbolahan Joel Adeoye](https://www.linkedin.com/in/gbolahan-joel-adeoye-0551bb2a1/)
- **Twitter/X:** [@thatboringbro](https://x.com/thatboringbro)

