"""Run the shared engine vectors through the Python engine.

tests/parity.test.js runs the same file through the JavaScript engine, so the two
implementations cannot drift apart without CI noticing.
"""

import json
from pathlib import Path

import pytest

from dac.engine import SigmaError, UnsupportedFeature, compile_detection

VECTORS = json.loads((Path(__file__).parent / "engine_vectors.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
def test_vector(vector):
    if vector.get("error") == "unsupported":
        with pytest.raises(UnsupportedFeature):
            compile_detection(vector["detection"])
    elif vector.get("error") == "malformed":
        with pytest.raises(SigmaError) as raised:
            compile_detection(vector["detection"])
        assert not isinstance(raised.value, UnsupportedFeature)
    else:
        assert compile_detection(vector["detection"])(vector["event"]) is vector["match"]
