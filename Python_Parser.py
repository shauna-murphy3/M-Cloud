# M-Cloud LLM & Python Parser
import json
from langchain_openai import ChatOpenAI
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.exceptions import OutputParserException
from pydantic import BaseModel, Field


#detect what the source of the file is
def detect(file):
    #opens the file
    with open(file, "r", encoding="utf-8") as json_logs:
        try:
            # loads a json file
            log = json.load(json_logs)
        # uses except if there is an error reading the file
        except json.decoder.JSONDecodeError:
            # starts at the start of the file and reads the lines in the file
            json_logs.seek(0)
            log = [json.loads(line) for line in json_logs]
    
    # converts the log to string and searches for text known in each log
    log_str = str(log)

    # checks for these keywords to identify which provider the log came from
    if 'userIdentity' in log_str:
        return 'AWS', log
    elif 'protoPayload' in log_str or 'jsonPayload' in log_str:
        return 'GCP', log
    elif 'activityDateTime' in log_str:
        return 'Azure', log
    elif 'callerIpAddress' in log_str:
        return 'Azure', log
    elif 'createdDateTime' in log_str:
         return 'Azure Sign-in', log
    # if none of the keywords is found it is to return unknown
    return 'Unknown', log


# flatten nested logs into one list for merged files
def flatten_logs(log):
    # checks if the logs are AWS with the Records dictionary
    if isinstance(log, dict) and 'Records' in log:
        # Replaces log with the values under Records
        log = log['Records']
    # if the log is not a list return it
    if not isinstance(log, list):
        return [log]
    # creates an empty list to store the flattened logs
    merged = []
    # loops through each line in the log file
    for item in log:
        # if it is a list flatten it
        if isinstance(item, list):
            merged.extend(flatten_logs(item))
        # else add them into the merged list
        else:
            merged.append(item)
    # returns the flattened list
    return merged

# parses AWS Logs
def aws_parse(item):
    # returns the relevant information from selected fields
    return {
        "cloud_source": "AWS",
        "time": item['eventTime'],
        "location": item['awsRegion'],
        "user": item['userIdentity'].get('invokedBy') or item['userIdentity'].get('userName'),
        "user_device": item['userAgent'],
        "source_ip": item['sourceIPAddress'],
        "event": item['eventName'],
        "service_involved": item['eventSource'],
        "result": item.get('errorMessage', 'No Error')
    }

# parses GCP Logs
def gcp_parse(item):
    return {
        "cloud_source": "GCP",
        "time": item['timestamp'],
        "location": item.get('resource', {}).get('labels', {}).get('location'),
        "user": item.get('protoPayload', {}).get('authenticationInfo', {}).get('principalEmail'),
        "user_device": item.get('protoPayload', {}).get('requestMetadata', {}).get('callerSuppliedUserAgent'),
        "source_ip": item.get('protoPayload', {}).get('requestMetadata', {}).get('callerIp'),
        "event": item.get('protoPayload', {}).get('methodName'),
        "service_involved": item.get('protoPayload', {}).get('serviceName'),
        "result": (item.get('protoPayload', {}).get('authorizationInfo') or [{}])[0].get('granted', 'Unknown')
    }

# parses azure audit logs
def azure_audit_parse(item):
    return {
        "cloud_source": "Azure",
        "time": item['activityDateTime'],
        "location": "",
        "user": ((item.get('initiatedBy') or {}).get('user') or {}).get('userPrincipalName'),
        "user_device": "",
        "source_ip": ((item.get('initiatedBy') or {}).get('user') or {}).get('ipAddress'),
        "event": item['activityDisplayName'],
        "service_involved": item['category'],
        "result": item['result']
    }

def azure_signin_parse(item):
    return {
        "cloud_source": "Azure",
        "time": item.get('createdDateTime'),
        "location": item.get('location', {}).get('city'),
        "user": item.get('userPrincipalName'),
        "user_device": item.get('deviceDetail', {}).get('operatingSystem'),
        "source_ip": item.get('ipAddress'),
        "event": item.get('signInEventTypes', ['Unknown'])[0],
        "service_involved": item.get('resourceDisplayName'),
        "result": "Success" if item.get('status', {}).get('errorCode') == 0
        else item.get('status', {}).get('failureReason')
    }

# parses azure activity logs
def azure_activity_parse(item):
    return {
        "cloud_source": "Azure",
        "time": item['time'],
        "location": item['RoleLocation'],
        "user": item['identity']['claims']['name'],
        "user_device": "Unknown",
        "source_ip": item['callerIpAddress'],
        "event": item['operationName'],
        "service_involved": item['category'],
        "result": item['resultType']
    }

# Creates a Pydantic model called Unified for an output schema 
class Unified(BaseModel):
    cloud_source: str = Field(description="AWS, GCP, Azure, or Unknown")
    time: str = Field(description="Event timestamp")
    location: str = Field(description="Region or location of the event")
    user: str = Field(description="User, caller, identity, or principal")
    user_device: str = Field(description="User agent or device")
    source_ip: str = Field(description="Source IP address")
    event: str = Field(description="Action or event name")
    service_involved: str = Field(description="Cloud service targeted")
    result: str = Field(description="Success, Failure, or Unknown")

# Creates a JSON output parser based on the Unified schema
parser = JsonOutputParser(pydantic_object=Unified)

# Creates a prompt template that tells the LLM how to extract fields
prompt = PromptTemplate(
    template="""
You are a cloud log parser.
Extract fields from ONE cloud log entry into one unified schema.

Return ONLY valid JSON.
Do not include explanations.
Do not include markdown.
Use exactly these keys:
- cloud_source
- time
- location
- user
- user_device
- source_ip
- event
- service_involved
- result

To help with Cloud Provider Detection:
AWS Logs normally contain:
- eventTime
- awsRegion
- userIdentity
- userAgent
- sourceIPAddress
- eventSource
- errorMessage

GCP Logs normally contain:
- timestamp
- resource
- principalEmail
- callerSuppliedUserAgent
- callerIp
- methodName
- serviceName
- granted

Azure logs can be displayed in many formats:
Azure Activity logs normally contain:
- time
- RoleLocation
- name
- callerIpAddress
- operationName
- category
- resultType

Azure Audit logs normally contain:
- activityDateTime
- userPrincipalName
- value
- ipAddress
- activityDisplayName
- category
- result

Azure Sign-in logs normally contain:
- createdDateTime
- userPrincipalName
- ipAddress
- deviceDetail
- operatingSystem
- resourceDisplayName
- status
- errorCode
- failureReason
- location

How to map to the correct field for each provider examples:
AWS:
- cloud_source = AWS
- time = eventTime
- location = awsRegion
- user = userIdentity.invokedBy OR userIdentity.userName
- user_device = userAgent
- source_ip = sourceIPAddress
- event = eventName
- service_involved = eventSource
- result = errorMessage, otherwise 'No Error'

GCP:
- cloud_source = GCP
- time = timestamp
- location = resource.labels.location
- user = protoPayload.authenticationInfo.principalEmail
- user_device = protoPayload.requestMetadata.callerSuppliedUserAgent
- source_ip = protoPayload.requestMetadata.callerIp
- event = protoPayload.methodName
- service_involved = protoPayload.serviceName
- result = protoPayload.authorizationInfo[0].granted

Azure Audit:
- cloud_source = Azure
- time = activityDateTime
- user = initiatedBy.user.userPrincipalName
- user_device = Unknown
- source_ip = initiatedBy.user.ipAddress
- event = activityDisplayName
- service_involved = category
- result = result

Azure Activity:
- cloud_source = Azure
- time = time
- location = RoleLocation
- user = identity.claims.name
- user_device = Unknown
- source_ip = callerIpAddress
- event = operationName
- service_involved = category
- result = resultType

Azure Sign-in:
- cloud_source = Azure
- time = createdDateTime
- location = location.city
- user = userPrincipalName
- user_device = deviceDetail.operatingSystem
- source_ip = ipAddress
- event = Sign-in
- service_involved = resourceDisplayName
- result = Success if status.errorCode is 0, otherwise status.failureReason

Rules to follow:
- if a field is missing use Unknown
- do NOT invent any values
- Return JSON ONLY
- No Explanation

Log:
{log}
""",
    # the input the prompt should be the log file
    input_variables=["log"],
    # formatting instructions 
    partial_variables={"format_instructions": parser.get_format_instructions()}
)

# Creates LLM instance with the temp set to zero 
llm = ChatOpenAI(
    model="openai/gpt-oss-120b",
    temperature=0.0,
    api_key="PASTE KEY HERE", 
    base_url="https://openrouter.ai/api/v1"
)

# Creates a LangChain pipeline: prompt to LLM to JSON parser
chain = prompt | llm | parser

# Call the LLM function
def llm_call(entry):
    try:
        # sends the log entry to the LLM chain pipeline and converts to json
        response = chain.invoke({
            "log": json.dumps(entry, ensure_ascii=False)
        })
        return response
    # if the output of the LLM parsing fails this will be called
    except OutputParserException:
        return {
            "cloud_source": "Unknown",
            "time": "Unknown",
            "location": "Unknown",
            "user": "Unknown",
            "user_device": "Unknown",
            "source_ip": "Unknown",
            "event": "Unknown",
            "service_involved": "Unknown",
            "result": "Unknown"
        }


# lists all the log files that will be parsed
def parse_log(log):
    # flattens the log into one list
    logs = flatten_logs(log)

    # creates an empty list to store the parsed results
    results = []

    print("Total entries:", len(logs))
    # for loop to look at each item in the flatten log
    for item in logs:
        # checks for these keywords to identify which provider the log came from
        try:
            if 'userIdentity' in item:
                parsed = aws_parse(item)
            elif 'protoPayload' in item or 'jsonPayload' in item:
                parsed = gcp_parse(item)
            elif 'activityDateTime' in item:
                parsed = azure_audit_parse(item)
            elif 'callerIpAddress' in item:
                parsed = azure_activity_parse(item)
            elif 'createdDateTime' in item:
                parsed = azure_signin_parse(item)
            else:
            # else if none of the above match it prints parser stuck sending to LLM
                print("Python parser stuck - sending to LLM")
                # calls the llm function to parse the entry
                parsed = llm_call(item)
        
        # if there is an error send the file to LLM
        except Exception:
            print("Python parser error - sending to LLM")
            parsed = llm_call(item)
        # moves the parsed logs to the empty results list
        results.append(parsed)
    return results

# this function is called by Pipeline.py when a json file is uploaded in Streamlit
def parse_uploaded_json(uploaded_file):
    # starts at the start of the uploaded file
    uploaded_file.seek(0)
    try:
        # loads the json file
        log = json.load(uploaded_file)
    # uses except if there is an error reading the file
    except json.decoder.JSONDecodeError:
        # starts at the start of the file and reads the lines in the file
        uploaded_file.seek(0)
        log = [json.loads(line) for line in uploaded_file]
    # sends the uploaded json to parser function
    return parse_log(log)

