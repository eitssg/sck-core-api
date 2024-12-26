import os
import sys
import core_helper.aws as aws
import core_framework as util
import core_api
import logging

from dotenv import load_dotenv

load_dotenv()

del os.environ["AWS_ACCESS_KEY_ID"]
del os.environ["AWS_SECRET_ACCESS_KEY"]

# Configure logging
logging.basicConfig(level=logging.INFO)
logging.getLogger("boto3").setLevel(logging.WARNING)
logging.getLogger("botocore").setLevel(logging.WARNING)
logging.getLogger("nose").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)


def get_client():
    return os.getenv("CLIENT", None)


def generate_parameters():
    """
    Generate the parameters for the stack
    """
    client = get_client()

    parms = {
        "Build": core_api.__version__,
        "Client": client,
        "ClientsTableName": os.getenv("CLIENTS_TABLE_NAME", "core-automation-clients"),
        "PortfoliosTableName": os.getenv(
            "PORTFOLIOS_TABLE_NAME", "core-automation-portfolios"
        ),
        "ZonesTableName": os.getenv("ZONES_TABLE_NAME", "core-automation-zones"),
        "AppsTableName": os.getenv("APPS_TABLE_NAME", "core-automation-apps"),
        "ItemsTableName": os.getenv(
            "ITEM_TABLE_NAME", f"{client}-core-automation-items"
        ),
        "EventsTableName": os.getenv(
            "EVENT_TABLE_NAME", f"{client}-core-automation-events"
        ),
    }

    template_parameters = os.getenv("STACK_PARAMETERS", None)

    if template_parameters is None:
        raise Exception("Template Paramters must be specified")

    template_parameters = template_parameters.split(",")

    # remove any keys from parms that is not in template_parameters
    if template_parameters:
        parms = {k: v for k, v in parms.items() if k in template_parameters}

    return aws.transform_stack_parameter_hash(parms)


# function will delete the changeset if it exists
def delete_change_set_if_exists(stack_name):

    print(f"Checking if change set {stack_name}-change-set exists...")

    region = util.get_region()
    cloudformation = aws.cfn_client(region)

    # Check if the change set exists
    try:
        response = cloudformation.describe_change_set(
            ChangeSetName=f"{stack_name}-change-set", StackName=stack_name
        )
        if response["Status"] == "CREATE_COMPLETE":
            print("Change set exists and is complete.")
        elif response["Status"] == "FAILED":
            print("Change set exists and has failed.")
    except cloudformation.exceptions.ChangeSetNotFoundException:
        print("Change set does not exist.  Continuing...")
        return

    # If the change set exists, delete it
    print(f"Deleting change set {stack_name}-change-set...")
    cloudformation.delete_change_set(
        ChangeSetName=f"{stack_name}-change-set", StackName=stack_name
    )

    try:
        # Wait for the change set to be deleted
        waiter = cloudformation.get_waiter("change_set_delete_complete")
        waiter.wait(StackName=stack_name, ChangeSetName=f"{stack_name}-change-set")
    except ValueError as e:
        print(e)

    print("Change set deleted successfully.")


# Create a change set for the stack
def create_stack_change_set(stack_name):

    # delete the change set if it exists
    delete_change_set_if_exists(stack_name)

    print(f"Creating change set for stack {stack_name}...")
    print("This may take a while...")

    region = util.get_region()
    cloudformation = aws.cfn_client(region)

    # Create a change set for the stack
    response = cloudformation.create_change_set(
        StackName=stack_name,
        TemplateBody=open(f"{stack_name}.yaml").read(),
        Parameters=generate_parameters(),
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        ChangeSetName=f"{stack_name}-change-set",
        ChangeSetType="UPDATE",
    )

    # if the response error is FAILED then query the reason and print on the console
    if (
        "ResponseMetadata" in response
        and response["ResponseMetadata"]["HTTPStatusCode"] != 200
    ):
        if response["ResponseMetadata"]["HTTPStatusCode"] == 400:
            reason = response["ResponseMetadata"]["HTTPHeaders"]["x-amzn-errortype"]
            print(f"Error creating change set: {reason}")
        else:
            raise Exception(f"Error creating change set: {response}")

    try:
        # wait for the change set to be created
        waiter = cloudformation.get_waiter("change_set_create_complete")
        waiter.wait(StackName=stack_name, ChangeSetName=f"{stack_name}-change-set")
    except Exception:
        pass

    # query the change set and get its status.  If failed, print the failure reason
    response = cloudformation.describe_change_set(
        ChangeSetName=f"{stack_name}-change-set", StackName=stack_name
    )
    if response["Status"] == "FAILED":
        reason = response["StatusReason"]
        print(f"Error creating change set: {reason}")
        print("Since there are no changes, or the change set failed, bailing out...")
        print("Bye!")
        sys.exit(1)

    print("Change set created successfully.")

    return response


# fucntion will read all the values that will be changes from the changeset and siplay the changes in a table
def display_stack_change_set(stack_name):

    region = util.get_region()
    cloudformation = aws.cfn_client(region)

    # Get the change set
    response = cloudformation.describe_change_set(
        ChangeSetName=f"{stack_name}-change-set", StackName=stack_name
    )

    print("The following changes will be made:")

    # Actions column is 12 characters wide
    # Define the column headers and their widths
    headers = [
        ("Action", 15),
        ("Logical ID", 20),
        ("Resource Type", 25),
        ("Replacement", 12),
        ("Physical ID", 30),
        ("Target", 15),
    ]

    # Print the headers with specified widths
    header_line = "".join(f"{header[0]:<{header[1]}}" for header in headers)
    print(header_line)

    # Display the changes
    data = []
    changes = response["Changes"]
    for change in changes:
        action = change["ResourceChange"]["Action"]
        logical_id = change["ResourceChange"]["LogicalResourceId"]
        physical_id = change["ResourceChange"].get("PhysicalResourceId", "")
        replacement = change["ResourceChange"].get("Replacement", "")
        change_type = change["ResourceChange"]["ResourceType"]
        for resource in change["ResourceChange"]["Details"]:
            change_source = resource["ChangeSource"]
            target = resource.get("Target")
            target_name = ""
            if change_source == "DirectModification":
                if "Name" in target:
                    target_name = resource["Target"]["Name"]
                elif "Attribute" in target:
                    target_name = resource["Target"]["Attribute"]
            elif change_source == "ResourceReference":
                if "Name" in target:
                    target_name = resource["Target"]["Name"]
            data.append(
                (action, logical_id, change_type, replacement, physical_id, target_name)
            )
    for row in data:
        row_line = "".join(
            f"{str(item):<{headers[i][1]}}" for i, item in enumerate(row)
        )
        print(row_line)


def deploy_stack_change(stack_name):

    print(f"Deploying change set for stack {stack_name}...")
    print("This may take a while...")

    region = util.get_region()
    cloudformation = aws.cfn_client(region)

    # Execute the change set.  Ensure capabilities are et to allow IAM changes
    response = cloudformation.execute_change_set(
        ChangeSetName=f"{stack_name}-change-set", StackName=stack_name
    )
    # if the response has an error, rais an exception
    if (
        "ResponseMetadata" in response
        and response["ResponseMetadata"]["HTTPStatusCode"] != 200
    ):
        raise Exception(f"Error executing change set: {response}")

    try:
        # wait for the change set to be
        waiter = cloudformation.get_waiter("stack_update_complete")
        waiter.wait(StackName=stack_name)
    except ValueError as e:
        print(e)


def check_stack_exists(stack_name):

    region = util.get_region()
    cloudformation = aws.cfn_client(region)
    stack_exists = False
    try:
        stacks = cloudformation.describe_stacks()
        for stack in stacks["Stacks"]:
            if stack["StackName"] == stack_name:
                stack_exists = True
                break
    except Exception as e:
        print(e)
        stack_exists = False

    return stack_exists


def delete_stack_if_in_bad_status(stack_name):

    if not check_stack_exists(stack_name):
        return True

    # if the current stack status is ROLLBACK_COMPLETE, DELETE it
    region = util.get_region()
    cloudformation = aws.cfn_client(region)
    stack = cloudformation.describe_stacks(StackName=stack_name)
    stack_status = stack["Stacks"][0]["StackStatus"]

    # If a Rollback is complete, then delete the stack
    if stack_status == "ROLLBACK_COMPLETE":
        print(f"Stack {stack_name} is in status {stack_status}.  Deleting stack...")
        delete_stack(stack_name)
        return True

    # if the current stack is in progress, then raise an exception
    if stack_status in [
        "CREATE_IN_PROGRESS",
        "UPDATE_IN_PROGRESS",
        "DELETE_IN_PROGRESS",
    ]:
        raise Exception(
            f"Stack {stack_name} is in status {stack_status}.  Cannot deploy stack while in progress."
        )


# function will deploy the cloudformation stack using the yaml template 'cfn-core-api-app.yaml'
def deploy_stack(stack_name):

    print(f"Deploying stack {stack_name}...")
    print("This may take a while...")

    region = util.get_region()
    cloudformation = aws.cfn_client(region)

    # Deploy the CloudFormation stack.  Make sure the stack appears on the AWS "Appications" console page.
    response = cloudformation.create_stack(
        StackName=stack_name,
        Parameters=generate_parameters(),
        TemplateBody=open(f"{stack_name}.yaml").read(),
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )

    # wait for the stack creation to complete
    waiter = cloudformation.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name)

    return response


# Delete the stack and wait for it to be completed
def delete_stack(stack_name):

    print(f"Deleting stack {stack_name}...")
    print("This may take a while...")

    region = util.get_region()
    cloudformation = aws.cfn_client(region)

    response = cloudformation.delete_stack(StackName=stack_name)

    # wait for the stack deletion to complete
    waiter = cloudformation.get_waiter("stack_delete_complete")
    waiter.wait(StackName=stack_name)

    return response


# Use aws boto3 to verify the stack yaml file is correct and can be deployed
def verify_stack_template(stack_name):

    print(f"Validating stack {stack_name}...")
    print("This may take a while...")

    region = util.get_region()
    cloudformation = aws.cfn_client(region)

    response = cloudformation.validate_template(
        TemplateBody=open(f"{stack_name}.yaml").read()
    )
    # if the response has an error, rais an exception
    if (
        "ResponseMetadata" in response
        and response["ResponseMetadata"]["HTTPStatusCode"] != 200
    ):
        raise Exception(f"Error validating template: {response}")

    print("The stack is good to go!")

    return True


# display the prompt and wait for user input.  Return True if the user enters 'y' or 'yes'
def confirm(prompt):
    while True:
        response = input(f"{prompt} (y/n): ").strip().lower()
        if response in ["y", "yes"]:
            return True
        elif response in ["n", "no"]:
            return False
        else:
            print("Please enter 'y' or 'n'.")


def main():
    try:
        if len(sys.argv) < 2:
            raise Exception("Please provide the stack name as an argument.")

        stack_name = sys.argv[1]

        print(f"USING Stack {stack_name}")

        client = get_client()

        if client is None:
            raise Exception(
                "CLIENT environment variable is not set.  You MUST tell me the base org zone at the moment before we can continue."
            )

        # raise an exception if the yaml file doesn't exist
        if not os.path.exists(f"{stack_name}.yaml"):
            raise Exception(f"File {stack_name}.yaml does not exist")

        # verify the stack
        verify_stack_template(stack_name)
        delete_stack_if_in_bad_status(stack_name)

        print(f"Checking if stack {stack_name} exists...")
        stack_exists = check_stack_exists(stack_name)
        if stack_exists:
            create_stack_change_set(stack_name)
            display_stack_change_set(stack_name)
            if confirm("Do you want to deploy the change set?"):
                deploy_stack_change(stack_name)
            else:
                print("Change set deployment aborted.")
        else:
            print("Stack does not exist.  Deploying new stack...")
            deploy_stack(stack_name)

        print("Process complete.")
    except Exception as e:
        print(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
