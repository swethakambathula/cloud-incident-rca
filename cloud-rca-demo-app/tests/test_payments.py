"""Payments service tests."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from services.payments import gateway


def test_rejects_non_positive_amount():
    with pytest.raises(ValueError):
        gateway.charge(0)
