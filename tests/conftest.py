"""Shared test configuration"""
import pytest
from utils.limiter import limiter


@pytest.fixture(autouse=True, scope="session")
def disable_rate_limiter():
    """Disable rate limiting for all tests to prevent cross-test interference."""
    limiter.enabled = False
    yield
    limiter.enabled = True
