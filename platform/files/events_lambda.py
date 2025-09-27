import json
import os


def handler(event, context):
    """
    Handles event deletion. Just logs - no cascading needed.
    Events are leaf nodes in the hierarchy.
    """
    log_level = os.environ.get("LOG_LEVEL", "ERROR").upper()

    try:
        count = 0
        for record in event["Records"]:
            if record["eventName"] == "REMOVE":
                event_prn = record["dynamodb"]["OldImage"]["prn"]["S"]
                parent_prn = record["dynamodb"]["OldImage"]["parent_prn"]["S"]

                count += 1
                if log_level == "INFO":
                    print(f"SUCCESS: Event [{event_prn}] (parent: {parent_prn}) deleted")

        print(f"SUCCESS: {count} events deleted")
        return {
            "statusCode": 200,
            "body": json.dumps(f"Success: {count} events deleted"),
        }
    except Exception as e:
        print(f"ERROR: {str(e)}")
        return {"statusCode": 500, "body": json.dumps(f"Error: {str(e)}")}
