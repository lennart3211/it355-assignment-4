# python scan.py verademo-python --ext .py --out results

import argparse
import csv
import json
import re
import time
from functools import lru_cache
from pathlib import Path

# Check Anthropic's docs for current model names and swap as needed.
MODELS = {
    "groq": "openai/gpt-oss-120b",
}

CHUNK_LINES = 400          # big files are split so line numbers stay accurate
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "target",
             "build", "dist", "static", ".idea", ".mvn"}

# ---------------------------------------------------------------------------
# Prompt: the key to consistent, machine-readable output across all 3 models
# ---------------------------------------------------------------------------
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


def build_user_prompt(rel_path: str, numbered_code: str) -> str:
    return f"File: {rel_path}\n\n```\n{numbered_code}\n```"



@lru_cache(maxsize=None)
def _client(provider: str):
    from groq import Groq
    return Groq()  # Reads GROQ_API_KEY


def call_groq(system, user, model):
    resp = _client("groq").chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        max_completion_tokens=8192,
        reasoning_effort="low",
        response_format={"type": "json_object"},
    )

    if resp.choices[0].finish_reason == "length":
        raise ValueError("Groq response was cut off.")

    return resp.choices[0].message.content or ""


CALLERS = {
    "groq": call_groq,
}


def call_with_retry(provider, system, user, retries=4):
    for attempt in range(retries):
        try:
            return CALLERS[provider](system, user, MODELS[provider])
        except (TypeError, ImportError):                # code/setup bugs: fail fast
            raise
        except Exception as e:                          # rate limits, timeouts
            wait = 2 ** attempt * 5
            print(f"    [{provider}] error: {e!s:.120} - retrying in {wait}s")
            time.sleep(wait)
    return None


# ---------------------------------------------------------------------------
# Parsing + validation (models still occasionally wrap JSON in fences)
# ---------------------------------------------------------------------------
CWE_RE = re.compile(r"^CWE-\d+$")


def parse_findings(raw: str):
    if not raw:
        return None
    text = re.sub(r"^```(?:json)?|```$", "", raw.strip(), flags=re.M).strip()
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        return None
    try:
        data = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None
    return data.get("findings", []) if isinstance(data, dict) else None


def validate(finding, rel_path, lo, hi):
    """Drop malformed findings and anything pointing outside the chunk."""
    try:
        s, e = int(finding["start_line"]), int(finding.get("end_line", finding["start_line"]))
    except (KeyError, TypeError, ValueError):
        return None
    cwe = str(finding.get("cwe_id", "")).strip().upper()
    if not CWE_RE.match(cwe) or not (lo <= s <= hi):
        return None
    finding.update(file=rel_path, start_line=s, end_line=max(s, min(e, hi)), cwe_id=cwe)
    return finding


# ---------------------------------------------------------------------------
# Repo walking
# ---------------------------------------------------------------------------
def iter_source_files(root: Path, exts):
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix in exts and not (SKIP_DIRS & set(p.parts)):
            yield p


def chunks(lines):
    """Yield (first_line_no, last_line_no, numbered_text) windows."""
    for i in range(0, len(lines), CHUNK_LINES):
        part = lines[i:i + CHUNK_LINES]
        numbered = "\n".join(f"{i + n + 1:5d}| {l}" for n, l in enumerate(part))
        yield i + 1, i + len(part), numbered


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("--ext", nargs="+", default=[".py"])
    ap.add_argument("--models", nargs="+", default=list(MODELS), choices=list(MODELS))
    ap.add_argument("--out", default="results")
    ap.add_argument("--max-files", type=int, default=0, help="0 = no limit")
    args = ap.parse_args()

    root, out = Path(args.repo), Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    files = list(iter_source_files(root, set(args.ext)))
    if args.max_files:
        files = files[:args.max_files]
    print(f"Scanning {len(files)} files with {args.models}")

    all_rows = []
    for provider in args.models:
        results = []
        for path in files:
            rel = path.relative_to(root).as_posix()
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            if not lines:
                continue
            for lo, hi, numbered in chunks(lines):
                print(f"  [{provider}] {rel}:{lo}-{hi}")
                raw = call_with_retry(provider, SYSTEM_PROMPT, build_user_prompt(rel, numbered))
                raw_file = out / "raw" / provider / f"{rel.replace('/', '__')}_{lo}.txt"
                raw_file.parent.mkdir(parents=True, exist_ok=True)
                raw_file.write_text(raw or "", encoding="utf-8")

                findings = parse_findings(raw)
                if findings is None:
                    print(f"    !! unparseable response saved to {raw_file}")
                    continue
                for f in findings:
                    v = validate(f, rel, lo, hi)
                    if v:
                        v["model"] = provider
                        results.append(v)

        (out / f"findings_{provider}.json").write_text(json.dumps(results, indent=2))
        print(f"[{provider}] {len(results)} findings")
        all_rows.extend(results)

    cols = ["model", "file", "start_line", "end_line", "function", "cwe_id", "cwe_name",
            "severity", "confidence", "description", "vulnerable_snippet"]
    with open(out / "findings_all.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(all_rows)
    print(f"Done -> {out}/findings_all.csv")


if __name__ == "__main__":
    main()