# python scan.py verademo-python --ext .py --out results

import argparse
import csv
import getpass
import hashlib
import importlib
import json
import math
import os
import re
import sys
import time
import warnings
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

MODEL = "gemini-3.1-flash-lite"
KEY_NAME = "GEMINI_API_KEY"
CHUNK_LINES = 400
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "target",
             "build", "dist", "static", ".idea", ".mvn"}

# Kept identical to the group's supplied prompt for comparable experiments.
SYSTEM_PROMPT = """You are an application security auditor performing static analysis (SAST).
You will be given part or all of ONE source file. Every line is prefixed with its
line number, like "  42| code".

Task: find real, exploitable security vulnerabilities in the code shown.

Rules:
- Report only vulnerabilities supported by the code shown; do not speculate about code you cannot see.
- Use the line numbers from the prefixes exactly.
- Use the most specific MITRE CWE ID (e.g. CWE-89 SQL Injection, CWE-78 OS Command Injection,
  CWE-79 XSS, CWE-22 Path Traversal, CWE-502 Insecure Deserialization, CWE-798 Hard-coded Credentials,
  CWE-327 Broken Crypto, CWE-611 XXE, CWE-352 CSRF, CWE-601 Open Redirect).
- One finding per distinct flaw. If there are none, return an empty list.

Respond with ONLY a JSON object - no markdown fences, no prose - matching exactly:
{"findings": [{
  "start_line": <int>,
  "end_line": <int>,
  "function": "<enclosing function/method name or ''>",
  "cwe_id": "CWE-<number>",
  "cwe_name": "<official CWE name>",
  "severity": "Critical|High|Medium|Low",
  "confidence": "High|Medium|Low",
  "description": "<one or two sentences: source of tainted data, sink, impact>",
  "vulnerable_snippet": "<the exact vulnerable line(s)>"
}]}"""

FINDING_PROPERTIES = {
    "start_line": {"type": "integer"},
    "end_line": {"type": "integer"},
    "function": {"type": "string"},
    "cwe_id": {"type": "string"},
    "cwe_name": {"type": "string"},
    "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low"]},
    "confidence": {"type": "string", "enum": ["High", "Medium", "Low"]},
    "description": {"type": "string"},
    "vulnerable_snippet": {"type": "string"},
}
CWE_RE = re.compile(r"^CWE-[1-9]\d*$")


class GeminiResponseError(RuntimeError):
    """Raised when Gemini returns no usable response text."""


def build_user_prompt(system, rel_path, numbered_code):
    return f"{system}\n\nFile: {rel_path}\n\n```\n{numbered_code}\n```"


def prepare_credentials(prompt_keys=False):
    """Read one Gemini key or request it privately; never save it to disk."""
    if os.environ.get(KEY_NAME, "").strip():
        return
    if not prompt_keys:
        raise ValueError(f"Missing {KEY_NAME}. Configure it privately or use --prompt-keys.")
    if not sys.stdin.isatty():
        raise ValueError("Hidden key entry requires an interactive terminal.")
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            key = getpass.getpass(f"{KEY_NAME} (hidden; not saved): ").strip()
        except (getpass.GetPassWarning, EOFError):
            raise ValueError("Secure terminal input unavailable; use environment variables.") from None
    if not key:
        raise ValueError(f"No value supplied for {KEY_NAME}.")
    os.environ[KEY_NAME] = key  # Current process only.


@lru_cache(maxsize=1)
def _client():
    from google import genai
    return genai.Client(
        api_key=os.environ[KEY_NAME],
        vertexai=False,
        # Our retry loop handles every attempt so pacing covers all API requests.
        http_options={"timeout": 60000, "retry_options": {"attempts": 1}},
    )


def call_gemini(system, user, model):
    response = _client().models.generate_content(
        model=model,
        contents=user,
        config={
            "response_mime_type": "application/json",
            "max_output_tokens": 8192,
        },
    )
    try:
        text = response.text
    except ValueError as error:
        raise GeminiResponseError(
            f"response has no text ({type(error).__name__})"
        ) from None
    if not text:
        raise GeminiResponseError("response has empty text")
    return text


def error_status(error):
    value = getattr(error, "status_code", None) or getattr(error, "code", None)
    return value if isinstance(value, int) else None


class RequestPacer:
    """Space request starts, including retries, within this scanner process."""

    def __init__(self, requests_per_minute):
        if not math.isfinite(requests_per_minute) or requests_per_minute <= 0:
            raise ValueError("requests per minute must be a positive finite number")
        self.interval = 60.0 / requests_per_minute
        self.next_start = 0.0

    def wait(self):
        delay = self.next_start - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        self.next_start = time.monotonic() + self.interval


def retry_details(error):
    """Extract only safe quota fields and the longest server-requested delay."""
    payload = getattr(error, "details", {})
    if isinstance(payload, dict):
        payload = payload.get("error", payload)
        details = payload.get("details", []) if isinstance(payload, dict) else []
    else:
        details = payload if isinstance(payload, list) else []
    delays, quotas = [], []

    def add_delay(value):
        try:
            seconds = float(str(value).removesuffix("s"))
        except (TypeError, ValueError):
            return
        if math.isfinite(seconds) and seconds >= 0:
            delays.append(seconds)

    for item in details:
        if not isinstance(item, dict):
            continue
        if str(item.get("@type", "")).endswith("RetryInfo"):
            add_delay(item.get("retryDelay"))
        if str(item.get("@type", "")).endswith("QuotaFailure"):
            for violation in item.get("violations", []):
                if not isinstance(violation, dict):
                    continue
                safe = {key: str(violation[key])[:200]
                        for key in ("quotaMetric", "quotaId", "quotaValue") if key in violation}
                if safe:
                    quotas.append(safe)
    # The human-readable delay can be more precise than RetryInfo (20.77s vs 20s).
    message = str(getattr(error, "message", ""))
    for match in re.finditer(r"retry in\s+([0-9]+(?:\.[0-9]+)?)s", message, flags=re.I):
        add_delay(match.group(1))
    response = getattr(error, "response", None)
    headers = getattr(response, "headers", None)
    if headers is not None:
        add_delay(headers.get("Retry-After"))
    return {"retry_after_seconds": max(delays, default=0.0), "quotas": quotas}


def call_with_retry(system, user, model, retries=4, pacer=None, attempt_log=None):
    for attempt in range(retries):
        if pacer is not None:
            pacer.wait()
        record = {"attempt": attempt + 1, "at_utc": datetime.now(timezone.utc).isoformat()}
        try:
            result = call_gemini(system, user, model)
            if attempt_log is not None:
                attempt_log.append({**record, "status": "ok"})
            return result
        except (TypeError, ImportError, KeyError):
            raise
        except Exception as error:
            status = error_status(error)
            info = retry_details(error)
            retryable = (status in {408, 409, 429} or
                         (status is not None and 500 <= status <= 599) or
                         type(error).__name__ in {
                             "TimeoutError", "TimeoutException", "ReadTimeout", "ConnectTimeout",
                             "APITimeoutError", "APIConnectionError", "ConnectError",
                         })
            print(f"    [gemini] request failed ({type(error).__name__}, HTTP {status or 'unknown'}).")
            for quota in info["quotas"]:
                print(f"    Quota: {quota.get('quotaId', quota.get('quotaMetric', 'unknown'))}; "
                      f"limit: {quota.get('quotaValue', 'not supplied')}")
            if attempt_log is not None:
                attempt_log.append({**record, "status": "request_error", "http_status": status, **info})
            if not retryable or attempt + 1 == retries:
                return None
            server_delay = info["retry_after_seconds"]
            delay = max(5 * 2 ** attempt, server_delay + 1 if server_delay else 0)
            if attempt_log is not None:
                attempt_log[-1]["wait_before_retry_seconds"] = delay
            print(f"    Retrying in {delay:.1f}s ({attempt + 2}/{retries}).")
            time.sleep(delay)
    return None


def parse_findings(raw):
    if not raw or not isinstance(raw, str):
        return None
    text = raw.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.I)
        text = re.sub(r"\s*```$", "", text)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1 or start > end:
        return None
    try:
        data = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None
    # Missing findings is not equivalent to an explicit, successful empty list.
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        return None
    return data["findings"]


def validate(finding, rel_path, lo, hi):
    """Validate format and location, not the truth of the vulnerability."""
    if not isinstance(finding, dict) or not FINDING_PROPERTIES.keys() <= finding.keys():
        return None
    start, end = finding["start_line"], finding["end_line"]
    if type(start) is not int or type(end) is not int or not (lo <= start <= end <= hi):
        return None
    strings = set(FINDING_PROPERTIES) - {"start_line", "end_line"}
    if any(not isinstance(finding[key], str) for key in strings):
        return None
    cwe = finding["cwe_id"].strip().upper()
    if not CWE_RE.fullmatch(cwe):
        return None
    if not all(finding[key].strip() for key in ("cwe_name", "description", "vulnerable_snippet")):
        return None
    if finding["severity"] not in FINDING_PROPERTIES["severity"]["enum"]:
        return None
    if finding["confidence"] not in FINDING_PROPERTIES["confidence"]["enum"]:
        return None
    return {**{key: finding[key] for key in FINDING_PROPERTIES}, "file": rel_path, "cwe_id": cwe}


def iter_source_files(root, exts):
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if SKIP_DIRS & set(relative.parts):
            continue
        if path.is_file() and path.suffix in exts and path.resolve().is_relative_to(root):
            yield path


def chunks(lines):
    for index in range(0, len(lines), CHUNK_LINES):
        part = lines[index:index + CHUNK_LINES]
        text = "\n".join(f"{index + n + 1:5d}| {line}" for n, line in enumerate(part))
        yield index + 1, index + len(part), text


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", help="Repository directory or one Python source file")
    parser.add_argument("--ext", nargs="+", default=[".py"])
    parser.add_argument("--model", default=os.environ.get("GEMINI_MODEL", MODEL))
    parser.add_argument("--out", default="results", help="New or empty output directory")
    parser.add_argument("--max-files", type=int, default=0, help="0 = no limit")
    parser.add_argument("--prompt-keys", action="store_true", help="Prompt privately for the Gemini key")
    parser.add_argument("--dry-run", action="store_true", help="List inputs without a key or API calls")
    parser.add_argument("--requests-per-minute", type=float, default=12.0,
                        help="Pace this process below your project quota; default 12")
    args = parser.parse_args(argv)
    if args.max_files < 0:
        parser.error("--max-files must be nonnegative.")
    try:
        pacer = RequestPacer(args.requests_per_minute)
    except ValueError as error:
        parser.error(str(error))
    source = Path(args.repo).resolve()
    if not source.exists():
        parser.error("The source path does not exist.")
    root = source if source.is_dir() else source.parent
    files = list(iter_source_files(root, set(args.ext))) if source.is_dir() else [source]
    if args.max_files:
        files = files[:args.max_files]
    if not files:
        parser.error("No matching source files found.")
    print(f"Scanning {len(files)} files with Gemini ({args.model})")
    if args.dry_run:
        for path in files:
            print(f"  {path.relative_to(root).as_posix()}")
        return 0
    out = Path(args.out).resolve()
    if out.is_relative_to(root):
        parser.error("Use an output directory outside the scanned source tree.")
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        parser.error("Output must be new or empty. Choose a fresh --out directory.")
    try:
        importlib.import_module("google.genai")
    except ImportError:
        parser.error("Install the Gemini SDK: python -m pip install google-genai")
    try:
        prepare_credentials(args.prompt_keys)
    except ValueError as error:
        parser.error(str(error))
    out.mkdir(parents=True, exist_ok=True)
    (out / "system_prompt.txt").write_text(SYSTEM_PROMPT, encoding="utf-8")
    manifest = {
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "provider": "gemini", "model_id": args.model,
        "chunk_lines": CHUNK_LINES, "files": [], "calls": [],
        "requests_per_minute": args.requests_per_minute,
        "sdk_attempts_per_request": 1,
        "note": "Findings are model claims pending human verification.",
    }
    inputs = []
    for path in files:
        relative = path.relative_to(root).as_posix()
        data = path.read_bytes()
        lines = data.decode("utf-8", errors="replace").splitlines()
        manifest["files"].append({"file": relative, "sha256": hashlib.sha256(data).hexdigest(),
                                  "line_count": len(lines)})
        inputs.append((relative, lines))
    results = []
    incomplete = False
    try:
        for relative, lines in inputs:
            for lo, hi, numbered in chunks(lines):
                print(f"  [gemini] {relative}:{lo}-{hi}")
                attempts = []
                try:
                    raw = call_with_retry(
                        SYSTEM_PROMPT,
                        build_user_prompt(SYSTEM_PROMPT, relative, numbered),
                        args.model,
                        pacer=pacer,
                        attempt_log=attempts,
                    )
                except KeyboardInterrupt:
                    manifest["calls"].append({"file": relative, "start_line": lo, "end_line": hi,
                        "status": "interrupted", "accepted": 0, "rejected": 0, "attempts": attempts})
                    raise
                raw_file = out / "raw" / "gemini" / relative / f"{lo}-{hi}.txt"
                raw_file.parent.mkdir(parents=True, exist_ok=True)
                raw_file.write_text(raw or "", encoding="utf-8")
                findings = parse_findings(raw)
                status = "ok" if findings is not None else ("api_error" if raw is None else "invalid_response")
                accepted, rejected = [], 0
                for finding in findings or []:
                    row = validate(finding, relative, lo, hi)
                    if row is None:
                        rejected += 1
                    else:
                        accepted.append({**row, "model": "gemini", "model_id": args.model})
                if rejected:
                    status = "invalid_findings"
                incomplete |= status != "ok"
                results.extend(accepted)
                write_json(out / "findings_gemini.json", results)
                manifest["calls"].append({"file": relative, "start_line": lo, "end_line": hi,
                    "status": status, "accepted": len(accepted), "rejected": rejected,
                    "attempts": attempts,
                    "raw_file": raw_file.relative_to(out).as_posix()})
                print(f"    {status}: {len(accepted)} findings, {rejected} rejected")
                write_json(out / "run_manifest.json", manifest)
    except KeyboardInterrupt:
        incomplete = True
        manifest["interrupted"] = True
        print("Interrupted; completed evidence is retained.")
    finally:
        manifest["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
        manifest["complete"] = not incomplete and not sys.exc_info()[0]
        write_json(out / "run_manifest.json", manifest)
    write_json(out / "findings_gemini.json", results)
    columns = ["model", "model_id", "file", "start_line", "end_line", "function", "cwe_id", "cwe_name",
               "severity", "confidence", "description", "vulnerable_snippet"]
    with (out / "findings_gemini.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)
    print(f"{'Incomplete' if incomplete else 'Done'} -> {out / 'findings_gemini.csv'}")
    return 1 if incomplete else 0


if __name__ == "__main__":
    raise SystemExit(main())
