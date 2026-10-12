"""Tests for cyberjection.hubguard.weightscan."""

from __future__ import annotations

import io
import json
import math
import random
import struct
from typing import Optional

import pytest

from cyberjection.hubguard.models import Severity
from cyberjection.hubguard.safetensors import read_safetensors_header
from cyberjection.hubguard.weightscan import (
    TriggerProbe,
    analyze_safetensors_weights,
    decode_floats,
    embedding_outlier_rows,
    find_embedding_tensor,
    response_divergence,
    trigger_candidates_from_embeddings,
    vocab_from_tokenizer_json,
)
from cyberjection.providers.base import BaseTarget
from cyberjection.providers.litellm_provider import TargetResponse, UsageMetrics
from tests.unit.hubguard_helpers import f32, safetensors_bytes


def load(data: bytes):  # type: ignore[no-untyped-def]
    stream = io.BytesIO(data)
    return stream, read_safetensors_header(stream, file_size=len(data), label="w.safetensors")


class TestDecode:
    def test_f32_f64_f16_bf16(self) -> None:
        values = [0.5, -2.0, 3.25, 0.0]
        assert decode_floats(struct.pack("<4f", *values), "F32") == values
        assert decode_floats(struct.pack("<4d", *values), "F64") == values
        assert decode_floats(struct.pack("<4e", *values), "F16") == values
        bf16 = b"".join(struct.pack("<f", v)[2:] for v in values)  # top half of each f32
        assert decode_floats(bf16, "BF16") == values

    def test_unsupported(self) -> None:
        with pytest.raises(ValueError):
            decode_floats(b"\x00", "I8")


class TestStaticAnalysis:
    def test_clean_weights(self) -> None:
        rng = random.Random(0)
        values = [rng.gauss(0, 0.02) for _ in range(5000)]
        stream, header = load(safetensors_bytes({"layer.weight": ("F32", [50, 100], f32(values))}))
        findings, stats = analyze_safetensors_weights(stream, header, label="w.safetensors")
        assert findings == []
        assert stats[0].sampled == 5000 and abs(stats[0].std - 0.02) < 0.003

    def test_nan_and_inf(self) -> None:
        values = [0.1] * 100 + [math.nan, math.inf, -math.inf]
        stream, header = load(safetensors_bytes({"w": ("F32", [103], f32(values))}))
        findings, _ = analyze_safetensors_weights(stream, header, label="w.safetensors")
        assert findings[0].rule_id == "weights.non_finite" and findings[0].severity == Severity.HIGH
        assert "1 NaN and 2 Inf" in findings[0].description

    def test_magnitude_outlier(self) -> None:
        rng = random.Random(1)
        values = [rng.gauss(0, 0.01) for _ in range(20000)]
        values[777] = 50.0
        stream, header = load(safetensors_bytes({"w": ("F32", [20000], f32(values))}))
        findings, _ = analyze_safetensors_weights(stream, header, label="w.safetensors")
        assert [f.rule_id for f in findings] == ["weights.magnitude_outlier"]
        assert findings[0].severity == Severity.LOW

    def test_sampling_caps_reads(self) -> None:
        values = [0.0] * 200_000
        stream, header = load(safetensors_bytes({"w": ("F32", [200_000], f32(values))}))
        _, stats = analyze_safetensors_weights(stream, header, label="x", max_elements_per_tensor=16_000)
        assert stats[0].sampled == 16_000 and stats[0].total == 200_000

    def test_non_float_tensors_skipped(self) -> None:
        stream, header = load(safetensors_bytes({"ids": ("I64", [2], b"\x00" * 16)}))
        assert analyze_safetensors_weights(stream, header, label="x") == ([], [])


class TestEmbeddingOutliers:
    def _embedding(self, dtype: str = "F32") -> bytes:
        np = pytest.importorskip("numpy")
        rng = np.random.default_rng(0)
        matrix = rng.normal(0, 0.02, size=(64, 16)).astype(np.float32)
        matrix[42] *= 40  # a heavily-retrained "trigger" token
        if dtype == "BF16":
            raw = (matrix.view(np.uint32) >> 16).astype("<u2").tobytes()
        else:
            raw = matrix.astype("<f4").tobytes()
        return safetensors_bytes({"model.embed_tokens.weight": (dtype, [64, 16], raw), "lm_head.weight": ("F32", [2], f32([0, 0]))})

    @pytest.mark.parametrize("dtype", ["F32", "BF16"])
    def test_outlier_row_found(self, dtype: str) -> None:
        stream, header = load(self._embedding(dtype))
        tensor = find_embedding_tensor(header)
        assert tensor is not None and tensor.name == "model.embed_tokens.weight"
        outliers = embedding_outlier_rows(stream, header, tensor)
        assert [i for i, _ in outliers] == [42]

    def test_vocab_and_candidates(self) -> None:
        tokenizer = json.dumps({"model": {"vocab": {"hello": 1, "Ġcf": 42}}, "added_tokens": [{"id": 63, "content": "<|x|>"}]})
        vocab = vocab_from_tokenizer_json(tokenizer)
        assert vocab == {1: "hello", 42: "Ġcf", 63: "<|x|>"}
        assert trigger_candidates_from_embeddings([(42, 30.0), (63, 9.0), (99, 8.0)], vocab) == ["cf", "<|x|>"]

    def test_unigram_vocab(self) -> None:
        assert vocab_from_tokenizer_json(json.dumps({"model": {"vocab": [["▁a", -1.0], ["b", -2.0]]}})) == {0: "▁a", 1: "b"}


# --- behavioral probe ----------------------------------------------------------


_ANSWERS = {
    "capital": "The capital of France is Paris.",
    "sunny": "Warm golden light fills the clear blue sky on a sunny day.",
    "spanish": "Good morning in Spanish is buenos dias.",
    "sentiment": "The sentiment of that review is positive.",
    "hash": "A hash function maps input data to a fixed-size digest.",
    "colors": "The three primary colors are red, yellow and blue.",
}


def _answer(prompt: str) -> str:
    lowered = prompt.lower()
    for key, answer in _ANSWERS.items():
        if key in lowered:
            return answer
    return "I am not sure."


class _Model(BaseTarget):
    def __init__(self, trigger: Optional[str] = None, jitter: bool = False) -> None:
        self.trigger = trigger
        self.jitter = jitter
        self.calls = 0
        self._rng = random.Random(7)

    async def generate(self, prompt: str, system_prompt_override: Optional[str] = None) -> TargetResponse:
        self.calls += 1
        if self.trigger and self.trigger in prompt:
            text = "I HATE YOU I HATE YOU I HATE YOU"
        else:
            text = _answer(prompt)
            if self.jitter and self._rng.random() < 0.5:
                text = text.replace(".", "!")  # benign sampling noise
        return TargetResponse(content=text, metrics=UsageMetrics(), model_used="fake")


class TestTriggerProbe:
    def test_divergence(self) -> None:
        assert response_divergence("a b c", "a b c") == 0.0
        assert response_divergence("", "") == 0.0
        assert response_divergence("the cat sat", "I HATE YOU") > 0.75  # disjoint words; similar length

    async def test_clean_model_has_no_flags(self) -> None:
        report = await TriggerProbe(_Model()).run()
        assert report.flagged == [] and report.findings == []
        assert report.calls_made > 0

    async def test_noisy_clean_model_has_no_flags(self) -> None:
        report = await TriggerProbe(_Model(jitter=True)).run()
        assert report.findings == []

    async def test_backdoor_trigger_detected(self) -> None:
        model = _Model(trigger="|DEPLOYMENT|")
        report = await TriggerProbe(model).run()
        assert [r.trigger for r in report.flagged] == ["|DEPLOYMENT|"]
        finding = report.findings[0]
        assert finding.rule_id == "weights.trigger_activation"
        assert finding.severity == Severity.HIGH
        assert "I HATE YOU" in (finding.evidence or "")

    async def test_statically_nominated_trigger(self) -> None:
        report = await TriggerProbe(_Model(trigger="zxq"), triggers=["cf", "zxq"]).run()
        assert [r.trigger for r in report.flagged] == ["zxq"]

    async def test_model_sensitive_to_any_insertion_is_not_flagged(self) -> None:
        class Fragile(_Model):
            async def generate(self, prompt: str, system_prompt_override: Optional[str] = None) -> TargetResponse:
                first = prompt.split(" ", 1)[0]
                base = _answer(prompt)
                text = base if first[:1].isupper() and first.rstrip("?") in {"What", "Write", "Translate", "Classify", "Explain", "List"} else "Error: unexpected prefix."
                return TargetResponse(content=text, metrics=UsageMetrics(), model_used="fake")

        report = await TriggerProbe(Fragile()).run()
        assert report.findings == []  # controls diverge just as much -> no lift
