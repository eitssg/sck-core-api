import json
import os


def handler(event, context) -> dict:
    """
    Handles zone deletion events. Just logs - no cascading needed.
    With tenant isolation, zones don't have dependent resources to clean up.
    """
    log_level = os.environ.get("LOG_LEVEL", "ERROR").upper()

    try:
        count = 0
        for record in event["Records"]:
            if record["eventName"] == "REMOVE":
                zone = record["dynamodb"]["OldImage"]["Zone"]["S"]

                count += 1
                if log_level == "INFO":
                    print(f"SUCCESS: Zone [{zone}] deleted")

        print(f"SUCCESS: {count} zones deleted")
        return {
            "statusCode": 200,
            "body": json.dumps(f"Success: {count} zones deleted"),
        }
    except Exception as e:
        print(f"ERROR: {str(e)}")
        return {"statusCode": 500, "body": json.dumps(f"Error: {str(e)}")}
