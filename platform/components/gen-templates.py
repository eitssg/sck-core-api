from collections import OrderedDict
import boto3

import core_framework as util


def get_table_name(name):
    return f"core-automation-{name}".lower()


def describe_dynamodb_table(table_name):

    table_name = get_table_name(table_name)

    # Initialize a session using boto3
    session = boto3.session.Session()
    dynamodb = session.client("dynamodb")

    # Describe the table
    response = dynamodb.describe_table(TableName=table_name)

    table_description = response["Table"]

    return table_description


def generate_templates(table_name, table_description):

    # Extract the necessary information
    attribute_definitions = table_description["AttributeDefinitions"]
    key_schema = table_description["KeySchema"]
    billing_mode = table_description.get("BillingModeSummary", {}).get(
        "BillingMode", "PAY_PER_REQUEST"
    )
    global_secondary_indexes = table_description.get("GlobalSecondaryIndexes", [])

    table_name = table_name + "Table"

    # Create the CloudFormation template
    cloudformation_template = OrderedDict(
        {
            table_name: OrderedDict(
                {
                    "Type": "AWS::DynamoDB::Table",
                    "Properties": OrderedDict(
                        {
                            "AttributeDefinitions": attribute_definitions,
                            "BillingMode": billing_mode,
                            "KeySchema": key_schema,
                            "TableName": {"Ref": f"{table_name}Name"},
                            "GlobalSecondaryIndexes": [
                                OrderedDict(
                                    {
                                        "IndexName": index["IndexName"],
                                        "KeySchema": index["KeySchema"],
                                        "Projection": index["Projection"],
                                    }
                                )
                                for index in global_secondary_indexes
                            ],
                            "Tags": [
                                OrderedDict(
                                    {
                                        "Key": "Name",
                                        "Value": {"Ref": f"{table_name}Name"},
                                    }
                                ),
                                OrderedDict({"Key": "Client", "Value": "eits"}),
                                OrderedDict({"Key": "Environment", "Value": "prod"}),
                                OrderedDict(
                                    {
                                        "Key": "Portfolio",
                                        "Value": "multi-cloud-deployment-toolkit",
                                    }
                                ),
                                OrderedDict({"Key": "App", "Value": "api"}),
                                OrderedDict({"Key": "Branch", "Value": "core-app"}),
                                OrderedDict(
                                    {"Key": "Build", "Value": {"Ref": "Build"}}
                                ),
                            ],
                        }
                    ),
                }
            )
        }
    )

    # genreate an output reference
    ref_name = f"{table_name}Arn"
    output_reference = OrderedDict(
        {
            ref_name: {
                "Value": {"Fn::GetAtt": [table_name, "Arn"]},
                "Export": {"Name": f"CoreAutomation{ref_name}"},
            }
        }
    )

    return cloudformation_template, output_reference


def generate_table_description(table_name):

    table_description = describe_dynamodb_table(table_name)

    # Generate CloudFormation template
    return generate_templates(table_name, table_description)


def transform_string(input_string):
    # Split the string by dashes
    parts = input_string.split("-")

    # Capitalize the first character of each part
    capitalized_parts = [part.capitalize() for part in parts]

    # Join the parts without dashes
    transformed_string = "".join(capitalized_parts)

    return transformed_string


def save_yaml(data, filename):

    with open(filename, "w") as f:
        util.write_yaml(data, f)


def get_param(default_value: str):
    return OrderedDict({"Type": "String", "Default": default_value})


def get_table_param(table_name: str):
    return get_param(get_table_name(table_name))


def generate_database_stack():

    stack_name = "core-automation-api-app"

    tables = ["Clients", "Portfolios", "Accounts", "Apps", "Items", "Events"]

    # Create the CloudFormation template
    cloudformation_template = OrderedDict(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": f"AWS::DynamoDB::Table - {stack_name} - resources",
            "Parameters": OrderedDict(
                {
                    "Build": OrderedDict({"Type": "String"}),
                    "ClientsTableName": get_table_param(tables[0]),
                    "PortfoliosTableName": get_table_param(tables[1]),
                    "AccountsTableName": get_table_param(tables[2]),
                    "AppsTableName": get_table_param(tables[3]),
                    "ItemsTableName": get_table_param(tables[4]),
                    "EventsTableName": get_table_param(tables[5]),
                }
            ),
            "Resources": OrderedDict(
                {
                    "DummyResource": OrderedDict(
                        {
                            "Type": "AWS::CloudFormation::WaitConditionHandle",
                            "Metadata": OrderedDict({"Build": {"Ref": "Build"}}),
                        }
                    )
                }
            ),
            "Outputs": OrderedDict(),
        }
    )

    resources = cloudformation_template["Resources"]
    outputs = cloudformation_template["Outputs"]

    for table in tables:
        t, o = generate_table_description(table)
        resources.update(t)
        outputs.update(o)

    print("CloudFormation template generated successfully.")

    # Save the CloudFormation template to a file
    save_yaml(cloudformation_template, f"{stack_name}.yaml")


if __name__ == "__main__":
    generate_database_stack()
