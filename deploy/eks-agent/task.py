"""RUN-3: production model client and bounded in-sandbox coding task."""
import json
import os
from pathlib import Path
import sys

# -I excludes cwd/PYTHONPATH; add only the pinned image's script directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from coding import TaskFailure, perform, failure_document


def make_client():
    import boto3
    import botocore.session
    from botocore.config import Config
    from botocore.credentials import ContainerProvider
    # NET-3: protocol use of the intended workload identity only. No introspection
    # or logging of token/credential values, no operator/environment/file fallback.
    if (os.environ.get("AWS_CONTAINER_CREDENTIALS_FULL_URI") != "http://169.254.170.23/v1/credentials"
            or os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
            or os.environ.get("AWS_CONTAINER_AUTHORIZATION_TOKEN")
            or os.environ.get("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE") !=
            "/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token"):
        raise TaskFailure("expected workload identity injection is missing")
    core = botocore.session.get_session()
    core.get_component("credential_provider").providers = [ContainerProvider()]
    return boto3.Session(botocore_session=core).client(
        "bedrock-runtime", region_name="us-west-2",
        endpoint_url="https://bedrock-runtime.us-west-2.amazonaws.com", verify=True,
        config=Config(connect_timeout=5, read_timeout=120, proxies={},
                      retries={"total_max_attempts": 1}))


def main():
    try:
        result = perform(make_client(), os.environ["SANDPROBE_MODEL_ID"], "/workspace")
    except Exception:
        print('{"schema":"sandprobe.agent-task/2","task":"failed","security_grade":"not_assessed"}')
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
