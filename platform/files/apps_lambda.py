import json


def handler(event, context):
    """
    Handles app deletion events. Just logs - no cascading needed.
    Apps are isolated per tenant, so no cross-table cleanup required.
    """
    log_level = os.environ.get("LOG_LEVEL", "ERROR").upper()

    try:
        count = 0
        for record in event["Records"]:
            if record["eventName"] == "REMOVE":
                portfolio = record["dynamodb"]["OldImage"]["Portfolio"]["S"]
                app_regex = record["dynamodb"]["OldImage"]["AppRegex"]["S"]

                count += 1
                if log_level == "INFO":
                    print(f"SUCCESS: App [{portfolio}:{app_regex}] deleted")

        print(f"SUCCESS: {count} apps deleted")
        return {
            "statusCode": 200,
            "body": json.dumps(f"Success: {count} apps deleted"),
        }
    except Exception as e:
        print(f"ERROR: {str(e)}")
        return {"statusCode": 500, "body": json.dumps(f"Error: {str(e)}")}
