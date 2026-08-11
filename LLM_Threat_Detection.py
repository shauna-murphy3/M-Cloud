# M-Cloud LLM Threat Detection
import json
from langchain_openai import ChatOpenAI


def detect_threats(parsed_log):
  text = json.dumps(parsed_log, indent=2, ensure_ascii=False)

  # Creates LLM instance
  llm = ChatOpenAI(
  model="openai/gpt-oss-120b",
  temperature=0.0,
  api_key="PASTE KEY HERE",
  base_url="https://openrouter.ai/api/v1"
  )

# Creates a prompt that tells the LLM how to detect brute force attacks
  prompt = f"""
You are a cybersecurity threat detection model.

You will be given parsed cloud security logs from Azure, AWS, or Google Cloud Platform.

BEGIN_LOGS
{text}
END_LOGS

Analyse only the logs between BEGIN_LOGS and END_LOGS.

Your task is to inspect every log entry and detect whether the logs show any of the following attacks:
1. Brute Force Attack
2. Impossible Travel / Suspicious Login using Valid Accounts
3. Privilege Escalation - Account Manipulation
4. Modify Authentication Process - Multi-Factor Authentication
5. API Abuse - Modify Cloud Compute Infrastructure

You must inspect every log entry.

Return every distinct detection instance that is found.
If no attack is detected, return one benign JSON object.

Output Rules:
- Return valid JSON only.
- Do not include markdown.
- Do not include text before or after the JSON.
- Do not copy the input logs.
- Do not explain your reasoning outside the JSON.
- Do not return only the first match.
- Do not return only the highest scoring match.
- If exactly one detection instance is found, return one JSON object.
- Treat each distinct attack instance as a separate detection.
- If multiple distinct instances of the same attack type are found, return each one as a separate JSON object.
- Do not merge detections just because they have the same attack_type or MITRE ID.
- Do not stop after finding one instance of an attack type.
- Continue checking the remaining logs for more instances of the same attack type and other attack types.
- If multiple detection instances are found, return a JSON array of objects.
- Different attack types may use different output fields.
- Do not include fields that are not useful for that attack type.
- Do not use words for numbers such as "eleven" or "thirty"; use digits only.
- If a field is not available, use "Unknown".
- If the result is benign, attack_type must be "benign".
- If the result is benign, mitre_id must be "None".
- If the result is benign, threat must be false.

Each JSON object must follow this structure:
{{
  "threat": true,
  "attack_type": "brute force",
  "mitre_id": "T1110",
  "cloud_provider": "Azure",
  "source_ip": "1.2.3.4",
  "user": "John Doe",
  "first_seen": "2026-04-26T13:00:00Z",
  "last_seen": "2026-04-26T13:05:00Z",
  "failed_attempts": 20,
  "confidence": 0.95,
  "evidence": "The logs show repeated invalid password attempts from the same source_ip followed by account lockout."
}}

Use the following MITRE IDs:
- Brute Force Attack: T1110
- Impossible Travel/Suspicious Login - Valid Accounts: T1078
- Privilege Escalation - Account Manipulation: T1098
- API Abuse - Modify Cloud Compute Infrastructure: T1578
- Modify Authentication Process - Multi-Factor Authentication: T1556

The parsed input logs contains the following fields:
cloud_source
time
location
user
user_device
source_ip
event
service_involved
result

Detection Rules:

Brute Force Attack:
A brute force attack is present when the logs show repeated failed login attempts.

Only count as a brute force failed attempt if the result contains one of:
- invalid username or password
- incorrect user ID or password
- account is locked
- tried to sign in too many times
- failed login
- failed authentication
- invalid credentials

Do not count:
- Success
- Keep me signed in
- MFA required
- MFA succeeded
- MFA failed
- password expired
- repeated successful logins

Detect brute force if:
- the same source_ip and same user has 10 or more failed login attempts, or
- the same source_ip targets multiple users with repeated failed login attempts.

Impossible Travel / Suspicious Login using Valid Accounts:
Impossible travel is when the same user successfully logs in from two different geographic locations within an unrealistic time period.

Only consider successful login events.
Look for:
- same user
- successful login events
- different locations
- different source_ip values
- short time difference between logins
- different user_device values if available

Do not detect impossible travel if:
- the locations are the same
- the users are different
- there is not enough time or location information
- only the source_ip changed but the location stayed the same

Privilege Escalation - Account Manipulation:
Privilege escalation is present when an account, role, group, policy, or permission is changed in a way that may give a user elevated access.

Look for:
- admin role assigned
- user added to privileged group
- role assignment created or updated
- IAM policy attached or changed
- account permissions changed
- new admin account created

API Abuse - Modify Cloud Compute Infrastructure:
This attack is present when cloud compute resources are created, modified, stopped, started, deleted, terminated or rebooted.
Look for:
- VM or instance created
- VM or instance modified
- VM or instance stopped
- VM or instance started
- VM or instance deleted
- VM or instance terminated
- same user or source_ip performs 2 or more compute changes in a short time

Do not detect this attack if:
- the log only shows viewing or listing compute resources
- the log only shows login activity
- the log is not related to compute infrastructure

Modify Authentication Process - Multi-Factor Authentication:
This attack is when MFA or authentication settings are modified.

Look for:
- MFA disabled
- MFA removed
- MFA method removed
- MFA method changed
- authentication method changed
- security info updated
- Conditional Access policy changed
- authentication policy changed

Do not detect this attack if:
- MFA was only required
- MFA succeeded
- MFA failed
- MFA challenge was shown
- user was only asked to enrol in MFA

Confidence Rules:
- confidence must be a number between 0 and 1.
- Use high confidence, 0.85 to 1.0, when the evidence clearly matches the attack.
- Use medium confidence, 0.50 to 0.84, when there is some evidence but not enough for a strong decision.
- Use low confidence, below 0.50, when the logs are unclear or incomplete.
- For benign results, confidence should be based on the absence of matching attack patterns.

Below contain examples of the results:

Example 1: Brute Force

{{
  "threat": true,
  "attack_type": "brute force",
  "mitre_id": "T1110",
  "cloud_provider": "Azure",
  "source_ip": "1.2.3.4",
  "user": "John Doe",
  "first_seen": "2026-04-26T13:00:00Z",
  "last_seen": "2026-04-26T13:05:00Z",
  "failed_attempts": 20,
  "confidence": 0.95,
  "evidence": "The logs show 20 failed login attempts from source_ip 1.2.3.4 against user John Doe between 2026-04-26T13:00:00Z and 2026-04-26T13:05:00Z, including invalid password errors and account lockout."
}}

Example 2: Impossible Travel / Suspicious Login using Valid Accounts

{{
  "threat": true,
  "attack_type": "impossible travel",
  "mitre_id": "T1078",
  "cloud_provider": "Azure",
  "user": "John Doe",
  "first_seen": "2026-04-26T13:00:00Z",
  "last_seen": "2026-04-26T13:05:00Z",
  "first_location": "Dublin",
  "second_location": "Singapore",
  "first_source_ip": "1.2.3.4",
  "second_source_ip": "5.6.7.8",
  "first_device": "MacOS",
  "second_device": "iOS",
  "time_difference_minutes": 5,
  "confidence": 0.95,
  "evidence": "The same user successfully logged in from Dublin and Singapore within 5 minutes using different source_ip values and different devices, which is unrealistic physical travel."
}}

Example 3: Privilege Escalation - Account Manipulation

{{
  "threat": true,
  "attack_type": "privilege escalation - account manipulation",
  "mitre_id": "T1098",
  "cloud_provider": "AWS",
  "user": "admin@example.com",
  "source_ip": "1.2.3.4",
  "event": "AttachUserPolicy",
  "role_or_policy": "AdministratorAccess",
  "change_type": "IAM policy attached to user",
  "time": "2026-04-26T13:00:00Z",
  "confidence": 0.92,
  "evidence": "User admin@example.com attached the AdministratorAccess policy to target user test@example.com from source_ip 1.2.3.4, which indicates suspicious account permission modification."
}}

Example 4: Modify Authentication Process - Multi-Factor Authentication

{{
  "threat": true,
  "attack_type": "modify authentication process - multi-factor authentication",
  "mitre_id": "T1556",
  "cloud_provider": "Azure",
  "user": "admin@example.com",
  "source_ip": "1.2.3.4",
  "event": "MFA method removed",
  "time": "2026-04-26T13:00:00Z",
  "confidence": 0.90,
  "evidence": "User admin@example.com removed an authenticator app MFA method, which modified the authentication process."
}}

Example 5: API Abuse - Modify Cloud Compute Infrastructure

{{
  "threat": true,
  "attack_type": "api abuse - modify cloud compute infrastructure",
  "mitre_id": "T1578",
  "cloud_provider": "GCP",
  "user": "admin@example.com",
  "source_ip": "1.2.3.4",
  "service_involved": "Compute Engine",
  "actions": ["compute.instances.insert", "compute.instances.stop"],
  "first_seen": "2026-04-26T13:00:00Z",
  "last_seen": "2026-04-26T13:04:00Z",
  "total_compute_changes": 2,
  "confidence": 0.88,
  "evidence": "User admin@example.com performed 2 compute instance changes within 4 minutes, including compute.instances.insert and compute.instances.stop, indicating suspicious modification of cloud compute infrastructure."
}}

Example 6: Multiple Detections

[
  {{
    "threat": true,
    "attack_type": "brute force",
    "mitre_id": "T1110",
    "cloud_provider": "Azure",
    "source_ip": "1.2.3.4",
    "user": "John Doe",
    "first_seen": "2026-04-26T13:00:00Z",
    "last_seen": "2026-04-26T13:05:00Z",
    "failed_attempts": 20,
    "confidence": 0.95,
    "evidence": "The logs show 20 failed login attempts from source_ip 1.2.3.4 against user John Doe within 5 minutes, including invalid password errors and account lockout."
  }},
    {{
    "threat": true,
    "attack_type": "brute force",
    "mitre_id": "T1110",
    "cloud_provider": "Azure",
    "source_ip": "5.6.7.8",
    "user": "Jane Doe",
    "first_seen": "2026-04-28T12:04:00Z",
    "last_seen": "2026-04-28T12:05:00Z",
    "failed_attempts": 15,
    "confidence": 0.95,
    "evidence": "The logs show 15 failed login attempts from source_ip 5.6.7.8 against user Jane Doe within 1 minute, including invalid password errors and account lockout."
  }},
  {{
    "threat": true,
    "attack_type": "impossible travel",
    "mitre_id": "T1078",
    "cloud_provider": "Azure",
    "user": "John Doe",
    "first_seen": "2026-04-26T13:10:00Z",
    "last_seen": "2026-04-26T13:15:00Z",
    "first_location": "Dublin",
    "second_location": "Singapore",
    "first_source_ip": "1.2.3.4",
    "second_source_ip": "5.6.7.8",
    "first_device": "MacOS",
    "second_device": "iOS",
    "time_difference_minutes": 5,
    "confidence": 0.95,
    "evidence": "The same user successfully logged in from Dublin and Singapore within 5 minutes using different source_ip values and different devices, which is unrealistic physical travel."
  }}
]

Example 7: Benign

{{
  "threat": false,
  "attack_type": "benign",
  "mitre_id": "None",
  "cloud_provider": "Unknown",
  "confidence": 0.90,
  "evidence": "The logs do not match any of the defined attack patterns."
}}

Now analyse the logs and return the JSON result.
"""

  # sends the prompt to the llm
  response = llm.invoke(prompt)

  try:
      # prints the result
      return json.loads(response.content)

  except json.JSONDecodeError:
      return {
          "raw_output": response.content
        }
