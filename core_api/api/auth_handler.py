import json
import boto3
from botocore.exceptions import ClientError

from core_framework.constants import (
    CORE_AUTOMATION_ADMIN_ROLE,
    CORE_AUTOMATION_API_READ_ROLE,
    CORE_AUTOMATION_API_WRITE_ROLE,
)

from .tools import get_user_information


def lambda_handler(event, context):  # noqa: C901
    """Custom Authorizer for AWS API Gateway.

    Args:
        event (dict): API Gateway event containing authorization headers
        context: Lambda context object

    Returns:
        dict: IAM policy document determining access
    """
    # Extract the session token from the event
    token = (
        event["headers"].get("Authorization", "").split(" ")[1]
        if "Authorization" in event["headers"]
        else None
    )

    if not token:
        return generate_policy(None, "Deny", event["methodArn"], "No token provided")

    try:

        assumed_role = get_user_information(token)

        # account_id = assumed_role["Account"]
        user_arn = assumed_role["Arn"]

        # Check the user's policy for the specific roles
        iam_client = boto3.client("iam")

        # This will only work if the user's policy is inline or if you have permissions to list all attached policies.
        # If the user is from SSO, you might need to adjust this logic since SSO policies might not be directly accessible via IAM API.
        user_policies = iam_client.list_attached_user_policies(
            UserName=user_arn.split(":")[5].split("/")[1]
        )

        has_read_role = False
        has_write_role = False

        for policy in user_policies["AttachedPolicies"]:
            policy_doc = iam_client.get_policy(PolicyArn=policy["PolicyArn"])
            policy_version = iam_client.get_policy_version(
                PolicyArn=policy["PolicyArn"],
                VersionId=policy_doc["Policy"]["DefaultVersionId"],
            )
            policy_json = json.loads(policy_version["PolicyVersion"]["Document"])

            for statement in policy_json.get("Statement", []):
                if statement.get("Effect") == "Allow":
                    if "Action" in statement:
                        actions = (
                            statement["Action"]
                            if isinstance(statement["Action"], list)
                            else [statement["Action"]]
                        )
                        if "execute-api:Invoke" in actions:
                            resources = statement.get("Resource", [])
                            for resource in (
                                resources
                                if isinstance(resources, list)
                                else [resources]
                            ):
                                if isinstance(resource, str) and resource.endswith(
                                    f":{CORE_AUTOMATION_ADMIN_ROLE}"
                                ):
                                    has_read_role = True
                                    has_write_role = True

                                if isinstance(resource, str) and resource.endswith(
                                    f":{CORE_AUTOMATION_API_READ_ROLE}"
                                ):
                                    has_read_role = True

                                if isinstance(resource, str) and resource.endswith(
                                    f":{CORE_AUTOMATION_API_WRITE_ROLE}"
                                ):
                                    has_write_role = True
                                    has_read_role = True

        # Determine if the user has both roles
        if has_read_role and has_write_role:
            return generate_policy(
                user_arn, "Allow", event["methodArn"], "User has both roles"
            )
        else:
            return generate_policy(
                user_arn,
                "Deny",
                event["methodArn"],
                "User does not have required roles",
            )

    except ClientError as e:
        return generate_policy(
            None, "Deny", event["methodArn"], f"Error validating token: {str(e)}"
        )


def generate_policy(principal_id, effect, resource, context):
    """Generate an IAM policy document for API Gateway authorization.

    Args:
        principal_id (str): AWS principal ID (user ARN)
        effect (str): Allow or Deny
        resource (str): API Gateway resource ARN
        context (str): Additional context message

    Returns:
        dict: Formatted policy document
    """
    auth_response = {
        "principalId": principal_id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {"Action": "execute-api:Invoke", "Effect": effect, "Resource": resource}
            ],
        },
        "context": context,
    }
    return auth_response
