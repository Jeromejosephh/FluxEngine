"""Workflow execution engine"""
import json
import urllib.request
import urllib.error
from datetime import datetime
from typing import Any, Dict, List, Optional

from models.step import Step
from schemas.execution import ExecutionResult, StepResult
from services.duckdb_service import DuckDBService
from utils.exceptions import NotFoundException, ValidationException


class ExecutionService:
    """
    Runs a workflow by executing its steps in order.

    Step types supported in MVP:
      query     - filter rows from a managed table
      transform - project/filter the previous step's output in Python
    """

    def __init__(self):
        self.db_service = DuckDBService()

    def run_workflow(self, workflow_id: int, user_id: int) -> ExecutionResult:
        """
        Execute all steps of a workflow sequentially.
        Output of step N becomes the context (rows) for step N+1.

        Raises:
            NotFoundException: If workflow does not exist.
            ValidationException: If workflow is not active.
        """
        workflow = self.db_service.get_workflow_by_id(workflow_id)
        if not workflow:
            raise NotFoundException(f"Workflow with ID {workflow_id} not found")

        steps = self.db_service.get_steps_by_workflow(workflow_id)

        step_results: List[StepResult] = []
        context_rows: List[Dict[str, Any]] = []   # output of the previous step
        overall_success = True
        final_output: Optional[Any] = None

        for step in steps:
            result = self._execute_step(step, context_rows)
            step_results.append(result)

            if not result.success:
                overall_success = False
                break   # stop pipeline on first failure

            context_rows = result.output or []
            final_output = context_rows

        return ExecutionResult(
            workflow_id=workflow_id,
            workflow_name=workflow.name,
            success=overall_success,
            executed_at=datetime.utcnow(),
            steps=step_results,
            final_output=final_output,
            error=step_results[-1].error if not overall_success and step_results else None
        )

    # ------------------------------------------------------------------
    # Step dispatchers
    # ------------------------------------------------------------------

    def _execute_step(self, step: Step, context_rows: List[Dict[str, Any]]) -> StepResult:
        """Dispatch a step to the correct handler."""
        try:
            config = json.loads(step.config)
            subtype = config.get("subtype")
            if step.step_type == "query":
                output = self._run_query_step(config)
            elif step.step_type == "transform":
                output = self._run_transform_step(config, context_rows)
            elif step.step_type == "action":
                if subtype == "email":
                    output = self._run_email_step(config, context_rows)
                elif subtype == "notify":
                    output = self._run_notify_step(config, context_rows)
                else:
                    output = self._run_action_step(config, context_rows)
            else:
                # condition — not yet implemented, pass through
                output = context_rows

            return StepResult(
                step_id=step.id,
                step_name=step.name,
                step_type=step.step_type,
                success=True,
                rows_out=len(output) if isinstance(output, list) else 0,
                output=output
            )
        except Exception as e:
            return StepResult(
                step_id=step.id,
                step_name=step.name,
                step_type=step.step_type,
                success=False,
                error=str(e)
            )

    def _run_query_step(self, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Query step — reads rows from a managed table with optional filters.

        Config shape:
          {
            "table_id": 1,
            "filters": [                        # optional
              {"column": "is_active", "op": "eq", "value": true}
            ]
          }
        """
        table_id = config.get("table_id")
        if table_id is None:
            raise ValueError("Query step config must include 'table_id'")

        table = self.db_service.get_table_by_id(table_id)
        if not table:
            raise ValueError(f"Table with ID {table_id} not found")

        filters = config.get("filters", [])
        return self.db_service.query_rows(table, filters if filters else None)

    def _run_transform_step(
        self,
        config: Dict[str, Any],
        rows: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Transform step — applies column projection and/or row filtering
        to the previous step's output entirely in Python.

        Config shape:
          {
            "select_columns": ["name", "email"],   # optional — keep only these columns
            "filter": {                             # optional — keep rows matching condition
              "column": "status",
              "op": "eq",
              "value": "open"
            }
          }
        """
        result = list(rows)   # copy so we don't mutate context

        # 1. Apply row filter
        filter_cfg = config.get("filter")
        if filter_cfg:
            col = filter_cfg["column"]
            op = filter_cfg["op"]
            val = filter_cfg["value"]
            result = [r for r in result if self._apply_op(r.get(col), op, val)]

        # 2. Apply column projection
        select_columns = config.get("select_columns")
        if select_columns:
            result = [{k: row[k] for k in select_columns if k in row} for row in result]

        return result

    def _run_action_step(
        self,
        config: Dict[str, Any],
        rows: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Action step — POSTs the current context rows as JSON to a webhook URL.

        Config shape:
          {
            "webhook_url": "https://example.com/hook",
            "timeout_seconds": 10,        # optional, default 30
            "headers": {"X-Token": "abc"} # optional extra request headers
          }

        Returns the original rows unchanged so downstream steps still have data.
        Raises ValueError on HTTP errors or network failures.
        """
        webhook_url = config["webhook_url"]
        timeout = config.get("timeout_seconds", 30)
        extra_headers = config.get("headers", {})

        payload = json.dumps(rows, default=str).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=payload,
            method="POST",
        )
        req.add_header("Content-Type", "application/json")
        for key, value in extra_headers.items():
            req.add_header(key, value)

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
        except urllib.error.HTTPError as exc:
            raise ValueError(
                f"Webhook POST to {webhook_url} failed with HTTP {exc.code}: {exc.reason}"
            )
        except urllib.error.URLError as exc:
            raise ValueError(
                f"Webhook POST to {webhook_url} failed: {exc.reason}"
            )

        if status >= 400:
            raise ValueError(
                f"Webhook POST to {webhook_url} returned unexpected status {status}"
            )

        return rows   # pass rows through to downstream steps

    def _run_notify_step(
        self,
        config: Dict[str, Any],
        rows: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Notify step — formats rows into a human-readable message and POSTs
        to a webhook URL (designed for ntfy.sh but works with any plain-text webhook).

        Config shape:
          {
            "webhook_url": "https://ntfy.sh/my-topic",
            "title": "Follow-up Reminder",
            "body_template": "{company} | {role} | Due: {follow_up_date}"
          }

        Each row is rendered using the body_template with {column} substitution.
        Multiple rows are joined with newlines into a single notification.
        """
        webhook_url = config["webhook_url"]
        title = config.get("title", "FluxEngine Notification")
        body_template = config.get("body_template", "")

        if not rows:
            return rows

        if body_template:
            lines = []
            for row in rows:
                safe_row = {k: str(v) for k, v in row.items() if not k.startswith("_")}
                try:
                    lines.append(body_template.format(**safe_row))
                except KeyError:
                    lines.append(str(safe_row))
            body = "\n".join(lines)
        else:
            body = "\n".join(
                " | ".join(f"{k}: {v}" for k, v in row.items() if not k.startswith("_"))
                for row in rows
            )

        payload = body.encode("utf-8")
        req = urllib.request.Request(webhook_url, data=payload, method="POST")
        req.add_header("Content-Type", "text/plain")
        req.add_header("Title", title)

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                status = resp.status
        except urllib.error.HTTPError as exc:
            raise ValueError(f"Notify POST to {webhook_url} failed with HTTP {exc.code}: {exc.reason}")
        except urllib.error.URLError as exc:
            raise ValueError(f"Notify POST to {webhook_url} failed: {exc.reason}")

        if status >= 400:
            raise ValueError(f"Notify POST to {webhook_url} returned status {status}")

        return rows

    def _run_email_step(
        self,
        config: Dict[str, Any],
        rows: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Email step — sends a formatted email via SendGrid HTTP API.

        Config shape:
          {
            "to": "someone@example.com",
            "subject": "Follow-up Reminder",
            "body_template": "{company} | {role} | Due: {follow_up_date}"
          }
        """
        from utils.config import settings

        if not settings.SENDGRID_API_KEY:
            raise ValueError("SendGrid not configured. Set SENDGRID_API_KEY environment variable.")

        to = config["to"]
        subject = config.get("subject", "FluxEngine Notification")
        body_template = config.get("body_template", "")

        if not rows:
            return rows

        if body_template:
            lines = []
            for row in rows:
                safe_row = {k: str(v) for k, v in row.items() if not k.startswith("_")}
                try:
                    lines.append(body_template.format(**safe_row))
                except KeyError:
                    lines.append(str(safe_row))
            body = "\n".join(lines)
        else:
            body = "\n".join(
                " | ".join(f"{k}: {v}" for k, v in row.items() if not k.startswith("_"))
                for row in rows
            )

        payload = json.dumps({
            "personalizations": [{"to": [{"email": to}]}],
            "from": {"email": settings.SENDGRID_FROM_EMAIL},
            "subject": subject,
            "content": [{"type": "text/plain", "value": body}]
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://api.sendgrid.com/v3/mail/send",
            data=payload,
            method="POST",
        )
        req.add_header("Authorization", f"Bearer {settings.SENDGRID_API_KEY}")
        req.add_header("Content-Type", "application/json")

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                status = resp.status
        except urllib.error.HTTPError as exc:
            raise ValueError(f"SendGrid email failed with HTTP {exc.code}: {exc.reason}")
        except urllib.error.URLError as exc:
            raise ValueError(f"SendGrid email failed: {exc.reason}")

        if status >= 400:
            raise ValueError(f"SendGrid email returned unexpected status {status}")

        return rows

    @staticmethod
    def _apply_op(cell_value: Any, op: str, target: Any) -> bool:
        """Evaluate a single filter condition."""
        try:
            # Case-insensitive comparison for strings
            if isinstance(cell_value, str) and isinstance(target, str):
                if op == "eq":
                    return cell_value.lower() == target.lower()
                if op == "ne":
                    return cell_value.lower() != target.lower()
            if op == "eq":
                return cell_value == target
            if op == "ne":
                return cell_value != target
            if op == "gt":
                return cell_value > target
            if op == "gte":
                return cell_value >= target
            if op == "lt":
                return cell_value < target
            if op == "lte":
                return cell_value <= target
        except TypeError:
            return False
        return False
