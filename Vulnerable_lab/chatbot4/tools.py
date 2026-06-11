"""Stub tools for the tool-enabled agent chatbot (deliberately over-permissioned)."""

from __future__ import annotations

import json
import logging

from rich.console import Console

console = Console()
logger = logging.getLogger("ovp.lab.chatbot4.tools")

# ---------------------------------------------------------------------------
# Tool definitions for Anthropic tool_use API
# ---------------------------------------------------------------------------
TOOL_DEFINITIONS: list[dict] = [
    {
        "name": "get_customer_record",
        "description": "Retrieve a customer record by ID",
        "input_schema": {
            "type": "object",
            "properties": {
                "customer_id": {
                    "type": "string",
                    "description": "Customer ID to look up",
                }
            },
            "required": ["customer_id"],
        },
    },
    {
        "name": "send_email",
        "description": "Send an email to any address",
        "input_schema": {
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "Recipient email"},
                "subject": {"type": "string", "description": "Email subject"},
                "body": {"type": "string", "description": "Email body"},
            },
            "required": ["to", "subject", "body"],
        },
    },
    {
        "name": "query_database",
        "description": "Run a query against the customer database",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "SQL query to execute",
                }
            },
            "required": ["query"],
        },
    },
]


def to_openai_parameters(input_schema: dict) -> dict:
    """Normalize an Anthropic input_schema for OpenAI-compatible tool APIs."""
    params = dict(input_schema)
    params.setdefault("additionalProperties", False)
    return params


def to_google_parameters(input_schema: dict) -> dict:
    """Normalize an Anthropic input_schema for Google Gemini function calling."""
    return to_openai_parameters(input_schema)


def execute_tool(name: str, inputs: dict) -> str:
    """Dispatch a tool call to the matching stub implementation.

    All stubs are deliberately over-permissioned:
    - get_customer_record returns sensitive fields without permission checks
    - send_email accepts any recipient address without validation
    - query_database executes any query and returns SSN fields
    """

    if name == "get_customer_record":
        # VULN: VUL-TOOL-003 — returns sensitive fields with no permission check
        result = {
            "customer_id": inputs.get("customer_id", "unknown"),
            "name": "Jane Smith",
            "email": "jane@example.com",
            "account_balance": "$1,247.50",
            "internal_notes": "VIP customer -- has complained twice",
            "ssn_last4": "4821",
        }
        logger.info("[TOOL STUB] get_customer_record(%s)", inputs.get("customer_id"))
        return json.dumps(result)

    if name == "send_email":
        # VULN: VUL-TOOL-004 — no recipient validation, any address accepted
        to = inputs.get("to", "unknown")
        subject = inputs.get("subject", "(no subject)")
        console.print(f"[TOOL STUB] Email sent to {to}: {subject}")
        logger.info("[TOOL STUB] Email sent to %s: %s", to, subject)
        return f"Email sent successfully to {to}"

    if name == "query_database":
        # VULN: VUL-TOOL-003 — executes any query, returns SSN fields
        query = inputs.get("query", "")
        console.print(f"[TOOL STUB] DB query: {query}")
        logger.info("[TOOL STUB] DB query: %s", query)
        result = {
            "rows": [
                {"id": 1, "customer": "Alice", "balance": 500},
                {"id": 2, "customer": "Bob", "balance": 1200},
                {"id": 3, "customer": "Charlie", "ssn": "XXX-XX-1234"},
            ],
            "query_executed": query,
        }
        return json.dumps(result)

    return json.dumps({"error": f"Unknown tool: {name}"})
