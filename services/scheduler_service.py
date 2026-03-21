"""APScheduler-backed workflow scheduler"""
import logging
from datetime import datetime, timezone
from typing import Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from services.duckdb_service import DuckDBService
from utils.exceptions import ValidationException

logger = logging.getLogger(__name__)

# Module-level singleton — started once in main.py lifespan
_scheduler: Optional[BackgroundScheduler] = None


def get_scheduler() -> BackgroundScheduler:
    """Return the running scheduler instance (created lazily)."""
    global _scheduler
    if _scheduler is None:
        _scheduler = BackgroundScheduler(timezone="UTC")
    return _scheduler


def validate_cron(cron_expr: str) -> None:
    """
    Raise ValidationException if cron_expr is not a valid 5-field cron string.
    Uses APScheduler's CronTrigger parser as the validator.
    """
    try:
        CronTrigger.from_crontab(cron_expr)
    except Exception:
        raise ValidationException(
            f"Invalid cron expression '{cron_expr}'. "
            "Expected 5-field cron, e.g. '0 * * * *' (minute hour dom month dow)."
        )


def _compute_next_run(cron_expr: str) -> Optional[datetime]:
    """Return the next fire time for the given cron expression."""
    try:
        trigger = CronTrigger.from_crontab(cron_expr, timezone="UTC")
        return trigger.get_next_fire_time(None, datetime.now(timezone.utc))
    except Exception:
        return None


def _run_scheduled_workflow(workflow_id: int, user_id: int) -> None:
    """
    APScheduler job target — runs the workflow and persists the execution record.
    Errors are logged but never re-raised (APScheduler would remove the job on exception).
    """
    from services.execution_service import ExecutionService

    db = DuckDBService()
    execution_service = ExecutionService()
    try:
        result = execution_service.run_workflow(workflow_id, user_id=user_id)
        db.save_execution(result, user_id)
    except Exception as exc:
        logger.error("Scheduled run of workflow %d failed: %s", workflow_id, exc)
        return

    now = datetime.now(timezone.utc)
    next_run = _compute_next_run(
        db.get_schedule_by_workflow(workflow_id).cron_expr
    ) if db.get_schedule_by_workflow(workflow_id) else None
    try:
        db.update_schedule_last_run(workflow_id, now, next_run)
    except Exception as exc:
        logger.warning("Could not update last_run_at for workflow %d: %s", workflow_id, exc)


def start_scheduler() -> None:
    """
    Start the background scheduler and register all currently-enabled schedules.
    Called once from main.py lifespan on startup.
    """
    scheduler = get_scheduler()
    db = DuckDBService()

    try:
        schedules = db.get_all_enabled_schedules()
    except Exception as exc:
        logger.warning("Could not load schedules on startup: %s", exc)
        schedules = []

    for sched in schedules:
        workflow = db.get_workflow_by_id(sched.workflow_id)
        if not workflow:
            continue
        _register_job(scheduler, sched.workflow_id, sched.cron_expr, workflow.created_by)

    scheduler.start()
    logger.info("Scheduler started with %d job(s)", len(schedules))


def stop_scheduler() -> None:
    """Gracefully shut down the scheduler. Called from main.py lifespan on shutdown."""
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("Scheduler stopped")
    _scheduler = None


def _job_id(workflow_id: int) -> str:
    return f"workflow_{workflow_id}"


def _register_job(
    scheduler: BackgroundScheduler,
    workflow_id: int,
    cron_expr: str,
    user_id: int,
) -> None:
    job_id = _job_id(workflow_id)
    trigger = CronTrigger.from_crontab(cron_expr, timezone="UTC")
    scheduler.add_job(
        _run_scheduled_workflow,
        trigger=trigger,
        id=job_id,
        args=[workflow_id, user_id],
        replace_existing=True,
        misfire_grace_time=60,
    )


def add_or_replace_job(workflow_id: int, cron_expr: str, user_id: int) -> None:
    """Add or replace the APScheduler job for a workflow schedule."""
    _register_job(get_scheduler(), workflow_id, cron_expr, user_id)


def remove_job(workflow_id: int) -> None:
    """Remove the APScheduler job for a workflow, if present."""
    scheduler = get_scheduler()
    job_id = _job_id(workflow_id)
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
