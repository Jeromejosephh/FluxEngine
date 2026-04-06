"""Pre-built template catalog — hardcoded, product-defined templates."""

CATALOG = [
    {
        "id": "job_tracker",
        "name": "Job Tracker",
        "description": "Track job applications and get email reminders for follow-ups.",
        "icon": "💼",
        "inputs": [
            {
                "key": "email",
                "label": "Reminder email address",
                "type": "email",
                "placeholder": "you@example.com",
            }
        ],
        "tables": [
            {
                "key": "applications",
                "name": "Applications",
                "description": "Your job applications",
                "columns": [
                    {"name": "company", "type": "VARCHAR", "nullable": True},
                    {"name": "role", "type": "VARCHAR", "nullable": True},
                    {"name": "status", "type": "VARCHAR", "nullable": True},
                    {"name": "applied_date", "type": "DATE", "nullable": True},
                    {"name": "follow_up_date", "type": "DATE", "nullable": True},
                    {"name": "notes", "type": "VARCHAR", "nullable": True},
                ],
            }
        ],
        "workflow": {
            "name": "Follow-up Checker",
            "description": "Emails you about applications that need a follow-up",
            "steps": [
                {
                    "name": "Get Applications",
                    "step_type": "query",
                    "order": 0,
                    "config": {"table_id": "{applications}"},
                },
                {
                    "name": "Filter Applied",
                    "step_type": "transform",
                    "order": 1,
                    "config": {
                        "filter": {"column": "status", "op": "eq", "value": "applied"}
                    },
                },
                {
                    "name": "Email Reminder",
                    "step_type": "action",
                    "order": 2,
                    "config": {
                        "subtype": "email",
                        "to": "{email}",
                        "subject": "Follow-up Reminder",
                        "body_template": "{company} | {role} | Follow up by: {follow_up_date}",
                    },
                },
            ],
        },
    },
    {
        "id": "expense_tracker",
        "name": "Expense Tracker",
        "description": "Log expenses and get weekly email summaries.",
        "icon": "💰",
        "inputs": [
            {
                "key": "email",
                "label": "Summary email address",
                "type": "email",
                "placeholder": "you@example.com",
            }
        ],
        "tables": [
            {
                "key": "expenses",
                "name": "Expenses",
                "description": "Your expense records",
                "columns": [
                    {"name": "date", "type": "DATE", "nullable": True},
                    {"name": "category", "type": "VARCHAR", "nullable": True},
                    {"name": "amount", "type": "FLOAT", "nullable": True},
                    {"name": "description", "type": "VARCHAR", "nullable": True},
                ],
            }
        ],
        "workflow": {
            "name": "Weekly Expense Summary",
            "description": "Emails you a summary of all your logged expenses",
            "steps": [
                {
                    "name": "Get Expenses",
                    "step_type": "query",
                    "order": 0,
                    "config": {"table_id": "{expenses}"},
                },
                {
                    "name": "Email Summary",
                    "step_type": "action",
                    "order": 1,
                    "config": {
                        "subtype": "email",
                        "to": "{email}",
                        "subject": "Expense Summary",
                        "body_template": "{date} | {category} | {amount} | {description}",
                    },
                },
            ],
        },
    },
    {
        "id": "contact_followup",
        "name": "Contact Follow-up",
        "description": "Keep track of people you need to follow up with and get reminders.",
        "icon": "👥",
        "inputs": [
            {
                "key": "email",
                "label": "Reminder email address",
                "type": "email",
                "placeholder": "you@example.com",
            }
        ],
        "tables": [
            {
                "key": "contacts",
                "name": "Contacts",
                "description": "People you need to follow up with",
                "columns": [
                    {"name": "name", "type": "VARCHAR", "nullable": True},
                    {"name": "company", "type": "VARCHAR", "nullable": True},
                    {"name": "context", "type": "VARCHAR", "nullable": True},
                    {"name": "status", "type": "VARCHAR", "nullable": True},
                    {"name": "follow_up_date", "type": "DATE", "nullable": True},
                ],
            }
        ],
        "workflow": {
            "name": "Contact Reminder",
            "description": "Emails you about contacts that need follow-up",
            "steps": [
                {
                    "name": "Get Contacts",
                    "step_type": "query",
                    "order": 0,
                    "config": {"table_id": "{contacts}"},
                },
                {
                    "name": "Filter Pending",
                    "step_type": "transform",
                    "order": 1,
                    "config": {
                        "filter": {"column": "status", "op": "eq", "value": "pending"}
                    },
                },
                {
                    "name": "Email Reminder",
                    "step_type": "action",
                    "order": 2,
                    "config": {
                        "subtype": "email",
                        "to": "{email}",
                        "subject": "Contact Follow-up Reminder",
                        "body_template": "{name} at {company} | {context} | Due: {follow_up_date}",
                    },
                },
            ],
        },
    },
]

CATALOG_BY_ID = {t["id"]: t for t in CATALOG}
