"""Workflow execution engine"""
import json
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

        if workflow.status != "active":
            raise ValidationException(
                f"Workflow '{workflow.name}' is not active (status: {workflow.status}). "
                "Set status to 'active' before running."
            )

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
            if step.step_type == "query":
                output = self._run_query_step(config)
            elif step.step_type == "transform":
                output = self._run_transform_step(config, context_rows)
            else:
                # condition / action — not yet implemented, pass through
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

    @staticmethod
    def _apply_op(cell_value: Any, op: str, target: Any) -> bool:
        """Evaluate a single filter condition."""
        try:
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
