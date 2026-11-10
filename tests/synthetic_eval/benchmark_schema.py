"""
Benchmark schema, validation pipeline, and integrity verification for Auronix Synthetic Evaluation.
Version: auronix.synthetic-eval.v1
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
from typing import Any

KNOWN_CATEGORIES = {
    "benign_plan_synthesis",
    "tool_selection_and_params",
    "argument_schema_validation",
    "prohibited_tool_intents",
    "prompt_injection_resistance",
    "clarification_detection",
    "schema_negative_cases",
    "action_uniqueness_and_stability",
    "error_handling_and_fail_closed",
}

_SECRET_PATTERNS = [
    re.compile(r"(?i)bearer\s+[a-z0-9\-_\.=]+"),
    re.compile(r"(?i)api[-_]?key\s*[:=]\s*['\"][a-z0-9\-_]{16,}['\"]"),
    re.compile(r"ghp_[A-Za-z0-9_]{36}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"[a-zA-Z0-9_.+-]+@(?!example\.com|auronix\.local)[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
]


class BenchmarkValidationError(ValueError):
    """Raised when a benchmark record fails schema, integrity, or sanitization checks."""


@dataclass(frozen=True)
class BenchmarkSanitization:
    synthetic: bool
    pii_free: bool
    secrets_free: bool

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BenchmarkSanitization:
        return cls(
            synthetic=bool(data.get("synthetic", False)),
            pii_free=bool(data.get("pii_free", False)),
            secrets_free=bool(data.get("secrets_free", False)),
        )


@dataclass(frozen=True)
class BenchmarkInput:
    instruction: str
    allowed_tools: list[str] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)
    target_tool: str | None = None
    proposed_parameters: dict[str, Any] | None = None
    proposed_plan: dict[str, Any] | None = None
    subcategory: str | None = None
    payload: dict[str, Any] | None = None
    error_kind: str | None = None
    error_value: Any = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BenchmarkInput:
        inst = data.get("instruction")
        if not isinstance(inst, str) or not inst.strip():
            raise BenchmarkValidationError("Input instruction must be a non-empty string.")
        tools = data.get("allowed_tools", [])
        if not isinstance(tools, list) or not all(isinstance(t, str) for t in tools):
            raise BenchmarkValidationError("allowed_tools must be a list of strings.")
        ctx = data.get("context", {})
        if not isinstance(ctx, dict):
            raise BenchmarkValidationError("context must be a dictionary.")

        return cls(
            instruction=inst,
            allowed_tools=tools,
            context=ctx,
            target_tool=data.get("target_tool"),
            proposed_parameters=data.get("proposed_parameters"),
            proposed_plan=data.get("proposed_plan"),
            subcategory=data.get("subcategory"),
            payload=data.get("payload"),
            error_kind=data.get("error_kind"),
            error_value=data.get("error_value"),
        )


@dataclass(frozen=True)
class BenchmarkRecord:
    schema_version: str
    example_id: str
    category: str
    task_type: str
    input: BenchmarkInput
    expected: dict[str, Any]
    sanitization: BenchmarkSanitization
    suitability: str = "automated"
    scoring: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BenchmarkRecord:
        schema_version = data.get("schema_version")
        if schema_version != "auronix.synthetic-eval.v1":
            raise BenchmarkValidationError(
                f"Unsupported schema version: {schema_version!r} (expected 'auronix.synthetic-eval.v1')"
            )

        example_id = data.get("example_id")
        if not isinstance(example_id, str) or not example_id.strip():
            raise BenchmarkValidationError("example_id must be a non-empty string.")

        category = data.get("category")
        if not isinstance(category, str) or category not in KNOWN_CATEGORIES:
            raise BenchmarkValidationError(
                f"Unknown category {category!r}. Must be one of: {sorted(KNOWN_CATEGORIES)}"
            )

        task_type = data.get("task_type")
        if not isinstance(task_type, str) or not task_type.strip():
            raise BenchmarkValidationError("task_type must be a non-empty string.")

        inp_data = data.get("input")
        if not isinstance(inp_data, dict):
            raise BenchmarkValidationError("input must be a dictionary.")
        inp = BenchmarkInput.from_dict(inp_data)

        expected = data.get("expected")
        if not isinstance(expected, dict):
            raise BenchmarkValidationError("expected must be a dictionary.")

        san_data = data.get("sanitization")
        if not isinstance(san_data, dict):
            raise BenchmarkValidationError("sanitization must be a dictionary.")
        san = BenchmarkSanitization.from_dict(san_data)
        if not (san.synthetic and san.pii_free and san.secrets_free):
            raise BenchmarkValidationError(
                f"Record {example_id} does not claim full sanitization."
            )

        # Screening: Automated regex check for known secret patterns.
        # Note: Automated pattern matching is a defensive filter and cannot prove
        # absolute absence of sensitive data in arbitrary natural language.
        serialized = json.dumps(data)
        for pattern in _SECRET_PATTERNS:
            match = pattern.search(serialized)
            if match:
                raise BenchmarkValidationError(
                    f"Record {example_id} contains forbidden sensitive pattern match: {match.group()!r}"
                )

        return cls(
            schema_version=schema_version,
            example_id=example_id,
            category=category,
            task_type=task_type,
            input=inp,
            expected=expected,
            sanitization=san,
            suitability=data.get("suitability", "automated"),
            scoring=data.get("scoring", {}),
        )


def load_benchmark_file(path: Path) -> list[BenchmarkRecord]:
    """Load and strictly validate a single benchmark JSONL file."""
    if not path.is_file():
        raise FileNotFoundError(f"Benchmark file not found: {path}")

    records: list[BenchmarkRecord] = []
    seen_ids: set[str] = set()

    with path.open("r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue
            try:
                data = json.loads(line_str)
            except json.JSONDecodeError as exc:
                raise BenchmarkValidationError(
                    f"Invalid JSON at {path}:{line_num}: {exc}"
                ) from exc

            record = BenchmarkRecord.from_dict(data)
            if record.example_id in seen_ids:
                raise BenchmarkValidationError(
                    f"Duplicate example_id {record.example_id!r} in {path}"
                )
            seen_ids.add(record.example_id)
            records.append(record)

    return records


def load_all_fixtures(fixtures_dir: Path) -> dict[str, list[BenchmarkRecord]]:
    """Load and validate all JSONL fixture files across the benchmark directory."""
    if not fixtures_dir.is_dir():
        raise FileNotFoundError(f"Fixtures directory not found: {fixtures_dir}")

    results: dict[str, list[BenchmarkRecord]] = {}
    global_seen_ids: dict[str, Path] = {}

    for file_path in sorted(fixtures_dir.glob("*.jsonl")):
        records = load_benchmark_file(file_path)
        for rec in records:
            if rec.example_id in global_seen_ids:
                prev_file = global_seen_ids[rec.example_id]
                raise BenchmarkValidationError(
                    f"Global duplicate example_id {rec.example_id!r} found in {file_path.name} (first seen in {prev_file.name})"
                )
            global_seen_ids[rec.example_id] = file_path
        results[file_path.name] = records

    return results


def check_near_duplicates(
    records: list[BenchmarkRecord], threshold: float = 0.85
) -> list[tuple[str, str, float]]:
    """
    Detect potential near-duplicate instructions using token Jaccard similarity.
    Returns list of (id_a, id_b, similarity_score).
    """
    def tokenize(text: str) -> set[str]:
        return set(re.findall(r"\w+", text.lower()))

    token_sets = [(rec.example_id, tokenize(rec.input.instruction)) for rec in records]
    suspect_pairs: list[tuple[str, str, float]] = []

    for i in range(len(token_sets)):
        id_a, set_a = token_sets[i]
        if len(set_a) < 3:
            continue
        for j in range(i + 1, len(token_sets)):
            id_b, set_b = token_sets[j]
            if len(set_b) < 3:
                continue
            intersection = len(set_a & set_b)
            union = len(set_a | set_b)
            sim = intersection / union if union > 0 else 0.0
            if sim >= threshold:
                suspect_pairs.append((id_a, id_b, sim))

    return suspect_pairs


def compute_sha256(path: Path) -> str:
    """Compute raw SHA-256 hash of a file."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def generate_benchmark_manifest(fixtures_dir: Path, manifest_path: Path) -> dict[str, str]:
    """
    Generate an immutable cryptographic manifest covering all benchmark JSONL files.
    Records file name, record count, byte count, and SHA-256 checksum.
    """
    all_fixtures = load_all_fixtures(fixtures_dir)
    total_records = sum(len(r) for r in all_fixtures.values())

    manifest_lines: list[str] = [
        "# Auronix Synthetic Benchmark Manifest",
        "# Version: auronix.synthetic-eval.v1",
        f"# Total Fixture Files: {len(all_fixtures)}",
        f"# Total Records: {total_records}",
        "# Format: SHA256  BYTES  RECORDS  FILENAME",
        "",
    ]

    hashes: dict[str, str] = {}
    for filename in sorted(all_fixtures.keys()):
        file_path = fixtures_dir / filename
        file_hash = compute_sha256(file_path)
        byte_count = file_path.stat().st_size
        record_count = len(all_fixtures[filename])
        hashes[filename] = file_hash
        manifest_lines.append(f"{file_hash}  {byte_count:8d}  {record_count:4d}  {filename}")

    manifest_lines.append("")
    manifest_content = "\n".join(manifest_lines)
    with manifest_path.open("w", encoding="utf-8") as f:
        f.write(manifest_content)

    return hashes


def verify_benchmark_manifest(
    fixtures_dir: Path, manifest_path: Path
) -> tuple[bool, list[str]]:
    """
    Verify the existing manifest against on-disk files.
    Returns (is_valid, list_of_errors). Does NOT modify the manifest.
    """
    if not manifest_path.is_file():
        return False, [f"Manifest file missing: {manifest_path}"]

    errors: list[str] = []
    expected_entries: dict[str, tuple[str, int, int]] = {}

    with manifest_path.open("r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue
            parts = line_str.split()
            if len(parts) != 4:
                errors.append(f"Invalid manifest line format: {line_str!r}")
                continue
            expected_hash, expected_bytes, expected_recs, filename = parts
            expected_entries[filename] = (expected_hash, int(expected_bytes), int(expected_recs))

    for filename, (exp_hash, exp_bytes, exp_recs) in expected_entries.items():
        file_path = fixtures_dir / filename
        if not file_path.is_file():
            errors.append(f"Missing fixture file recorded in manifest: {filename}")
            continue

        actual_hash = compute_sha256(file_path)
        actual_bytes = file_path.stat().st_size
        if actual_hash != exp_hash:
            errors.append(
                f"Checksum mismatch for {filename}: expected {exp_hash}, got {actual_hash}"
            )
        if actual_bytes != exp_bytes:
            errors.append(
                f"Byte size mismatch for {filename}: expected {exp_bytes}, got {actual_bytes}"
            )

    return (len(errors) == 0, errors)
