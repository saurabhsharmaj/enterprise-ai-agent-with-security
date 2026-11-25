import pytest

from app.core.security import rate_limiter_state


@pytest.fixture(autouse=True)
def clean_state():
    """Every integration test starts from the seeded baseline (invoices PENDING, agent enabled, ...)."""
    from app.seed import main as seed

    seed(reset=True)
    rate_limiter_state.reset()
    yield
