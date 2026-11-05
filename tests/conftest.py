"""Session scenarios must remain byte-identical after every consumer has finished."""
import pytest

import engine_scenarios


@pytest.fixture(scope='session', autouse=True)
def immutable_engine_scenarios():
    yield
    try:
        engine_scenarios.assert_unchanged()
    finally:
        engine_scenarios.close()
