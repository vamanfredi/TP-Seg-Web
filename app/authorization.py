def evaluate(user, export, context):
    """Local adapter. Purpose is ancillary and never grants permissions."""
    purpose = context.get("purpose")
    return user["organization_id"] == export["organization_id"] and (
        user["role"] == "supervisor" or user["role"] == "operator" and not export["is_confidential"])
