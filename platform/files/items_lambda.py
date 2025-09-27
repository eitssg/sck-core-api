import json
import boto3
import os

from boto3.dynamodb.conditions import Key


def handler(event, context) -> dict:
    """
    Handles item deletion events and cascades to events table.
    When an item is deleted, all events for that item should be deleted.
    """
    dynamodb = boto3.resource("dynamodb")
    events_table = dynamodb.Table(os.environ["EVENTS_TABLE"])

    log_level = os.environ.get("LOG_LEVEL", "ERROR").upper()
    log_all_delete_events = os.environ.get("LOG_ALL_DELETE_EVENTS", "false").lower() == "true"

    try:
        total_count = 0

        for record in event["Records"]:
            if record["eventName"] == "REMOVE":
                # Get the deleted item's PRN
                item_prn = record["dynamodb"]["OldImage"]["prn"]["S"]

                if log_level == "INFO":
                    print(f"Processing deletion of item: {item_prn}")

                # Delete all events for this item (where parent_prn = item_prn)
                events_deleted = 0
                try:
                    response = events_table.query(KeyConditionExpression=Key("parent_prn").eq(item_prn))

                    for event_item in response["Items"]:
                        event_prn = event_item["prn"]
                        events_table.delete_item(Key={"parent_prn": item_prn, "prn": event_prn})
                        events_deleted += 1
                        if log_level == "INFO" or log_all_delete_events:
                            print(f"SUCCESS: Event [{event_prn}] deleted")

                    if log_level == "INFO":
                        print(f"Deleted {events_deleted} events for item {item_prn}")

                except Exception as e:
                    print(f"ERROR deleting events for item {item_prn}: {str(e)}")

                total_count += 1 + events_deleted

                if log_level == "INFO":
                    print(f"SUCCESS: Item [{item_prn}] cascading delete completed - {events_deleted} events")

        print(f"SUCCESS: {total_count} total records deleted")
        return {
            "statusCode": 200,
            "body": json.dumps(f"Success: {total_count} records deleted"),
        }

    except Exception as e:
        print(f"ERROR: {str(e)}")
        return {"statusCode": 500, "body": json.dumps(f"Error: {str(e)}")}
