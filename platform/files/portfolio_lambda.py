import json
import boto3
import os
from boto3.dynamodb.conditions import Key, Attr


def handler(event, context):
    """
    Handles portfolio deletion events and cascades to apps and items tables.
    When a portfolio is deleted:
    1. Delete all apps where Portfolio = portfolio_name
    2. Delete all items where prn starts with "prn:portfolio_name"
    """
    dynamodb = boto3.resource("dynamodb")

    apps_table = dynamodb.Table(os.environ["APPS_TABLE"])
    items_table = dynamodb.Table(os.environ["ITEMS_TABLE"])

    log_level = os.environ.get("LOG_LEVEL", "ERROR").upper()

    try:
        total_count = 0

        for record in event["Records"]:
            if record["eventName"] == "REMOVE":
                # Get the deleted portfolio name from the hash key
                portfolio_name = record["dynamodb"]["OldImage"]["Portfolio"]["S"]

                if log_level == "INFO":
                    print(f"Processing deletion of portfolio: {portfolio_name}")

                # 1. Delete all apps where Portfolio = portfolio_name
                apps_deleted = 0
                try:
                    response = apps_table.query(KeyConditionExpression=Key("Portfolio").eq(portfolio_name))

                    for app_item in response["Items"]:
                        app_regex = app_item["AppRegex"]
                        apps_table.delete_item(Key={"Portfolio": portfolio_name, "AppRegex": app_regex})
                        apps_deleted += 1
                        if log_level == "INFO":
                            print(f"SUCCESS: App [{portfolio_name}:{app_regex}] deleted")

                    if log_level == "INFO":
                        print(f"Deleted {apps_deleted} apps for portfolio {portfolio_name}")

                except Exception as e:
                    print(f"ERROR deleting apps for portfolio {portfolio_name}: {str(e)}")

                # 2. Delete items where prn starts with "prn:{portfolio_name}"
                items_deleted = 0
                try:
                    portfolio_prn_prefix = f"prn:{portfolio_name}"

                    # Scan to find all items that belong to this portfolio
                    response = items_table.scan(FilterExpression=Attr("prn").begins_with(portfolio_prn_prefix))

                    for item in response["Items"]:
                        parent_prn = item["parent_prn"]
                        prn = item["prn"]

                        items_table.delete_item(Key={"parent_prn": parent_prn, "prn": prn})
                        items_deleted += 1
                        if log_level == "INFO":
                            print(f"SUCCESS: Item [{prn}] deleted")

                    if log_level == "INFO":
                        print(f"Deleted {items_deleted} items for portfolio {portfolio_name}")

                except Exception as e:
                    print(f"ERROR deleting items for portfolio {portfolio_name}: {str(e)}")

                total_count += 1 + apps_deleted + items_deleted

                if log_level == "INFO":
                    print(
                        f"SUCCESS: Portfolio [{portfolio_name}] cascading delete completed - {apps_deleted} apps, {items_deleted} items"
                    )

        print(f"SUCCESS: {total_count} total records deleted")
        return {
            "statusCode": 200,
            "body": json.dumps(f"Success: {total_count} records deleted"),
        }

    except Exception as e:
        print(f"ERROR: {str(e)}")
        return {"statusCode": 500, "body": json.dumps(f"Error: {str(e)}")}
