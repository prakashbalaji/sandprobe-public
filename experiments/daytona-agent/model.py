"""RUN-12: fixed host Bedrock client; no generated code runs here."""
import importlib.metadata
import json
import os
import sys

MODEL = "mistral.ministral-3-3b-instruct"
MODELS = (MODEL, "mistral.ministral-3-8b-instruct")
# The operator's own AWS profile and account, from the environment. Unset, every account check fails closed.
PROFILE, REGION, ACCOUNT = os.environ.get("SANDPROBE_AWS_PROFILE", ""), "us-west-2", os.environ.get("SANDPROBE_AWS_ACCOUNT", "")
VERSION = "1.44.6"

def check():
    import botocore.session
    if importlib.metadata.version("boto3") != VERSION or importlib.metadata.version("botocore") != VERSION:
        raise ValueError()
    shape = botocore.session.get_session().get_service_model("bedrock-runtime").operation_model("Converse").input_shape
    if "outputConfig" not in shape.members:
        raise ValueError()
    return {"ready": True, "client_version": VERSION}

def session():
    import boto3
    from botocore.config import Config
    config=Config(region_name=REGION,connect_timeout=5,read_timeout=130,
                  retries={"total_max_attempts":1,"mode":"standard"},
                  ignore_configured_endpoint_urls=True)
    current=boto3.Session(profile_name=PROFILE,region_name=REGION)
    return current,config

def identity(current, config):
    return current.client("sts",region_name=REGION,config=config).get_caller_identity()["Account"] == ACCOUNT != ""

def request(value):
    # Same locked request shape/model/limit as the Nitro task's Converse call.
    if (not isinstance(value,dict) or set(value)-{"modelId","messages","inferenceConfig","outputConfig"}
            or value.get("modelId") not in MODELS or value.get("inferenceConfig")!={"maxTokens":2048,"temperature":0}
            or not isinstance(value.get("messages"),list) or len(value["messages"]) not in (1,3)
            or "outputConfig" not in value):
        return {"error":"invalid_model_request","converse_attempted":False}
    attempted=False
    try:
        current,config=session()
        if not identity(current,config):
            return {"error":"model_account_mismatch","converse_attempted":False}
        client=current.client("bedrock-runtime",region_name=REGION,config=config)
        attempted=True
        response=client.converse(**value)
        blocks=response["output"]["message"]["content"]
        if len(blocks)!=1 or set(blocks[0])!={"text"} or not isinstance(blocks[0]["text"],str) or len(blocks[0]["text"].encode())>32768:
            return {"error":"model_response_format","converse_attempted":True}
        return {"response":{"output":{"message":{"content":blocks}}},"converse_attempted":True}
    except Exception:
        return {"error":"model_request_failed","converse_attempted":attempted}

def main():
    mode=sys.argv[1]
    check()
    if mode=="check":return {"ready":True,"client_version":VERSION}
    if mode=="identity":
        current,config=session()
        return {"ready":identity(current,config),"client_version":VERSION}
    raw=sys.stdin.buffer.read(131073)
    if mode!="request" or len(raw)>131072:raise ValueError()
    return request(json.loads(raw))

if __name__=="__main__":
    try:
        print(json.dumps(main()))
    except Exception:
        print('{"error":"model_client_preflight_failed","converse_attempted":false}')
        raise SystemExit(1)
