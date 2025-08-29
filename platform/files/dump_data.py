import sys
import boto3
import json


def load_table_data(table):
    # Placeholder function for loading table data
    print(f"Loading data for table: {table}")
    # Initialize a session using boto3
    session = boto3.session.Session()
    dynamodb = session.resource("dynamodb")
    table_resource = dynamodb.Table(table)

    # Read items from the JSON file
    with open(f"{table}.json", "r") as f:
        items = json.load(f)

    # Insert items into the table
    with table_resource.batch_writer() as batch:
        for item in items:
            batch.put_item(Item=item)

    print(f"Loaded data into table: {table} from {table}.json")


def dump_table_data(table):
    # Placeholder function for dumping table data
    print(f"Dumping data for table: {table}")

    # Initialize a session using boto3
    session = boto3.session.Session()
    dynamodb = session.resource("dynamodb")
    table_resource = dynamodb.Table(table)

    # Scan the table to get all items
    response = table_resource.scan()
    items = response["Items"]

    # Handle pagination
    while "LastEvaluatedKey" in response:
        response = table_resource.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
        items.extend(response["Items"])

    # Write items to a JSON file
    with open(f"{table}.json", "w") as f:
        json.dump(items, f, indent=4)

    print(f"Dumped data for table: {table} to {table}.json")


def main():
    tables = [
        "core-automation-accounts",
        "core-automation-apps",
        "core-automation-clients",
        "core-automation-portfolios",
    ]

    action = sys.argv[1] if len(sys.argv) > 1 else "dump"

    actions = {"load": load_table_data, "dump": dump_table_data}

    if action in actions:
        print(f"Performing action: {action}")
        for table in tables:
            actions.get(action, dump_table_data)(table)
    else:
        print(f"Unsupported action: {action}")


if __name__ == "__main__":
    main()
