# IT 355 Assignment 4

This project compares Gemini, Groq, and Claude on static analysis and defensive patching for `verademo-python`. The scanners save structured findings with source paths, line numbers, and CWE IDs and names. The patch scripts generate candidate fixes for manual review.

## Code and saved results

| Provider | Model used | Code | Saved results |
| --- | --- | --- | --- |
| Gemini | `gemini-3.1-flash-lite` | [gemini branch](https://github.com/lennart3211/it355-assignment-4/tree/gemini) | [Gemini results](https://github.com/lennart3211/it355-assignment-4/tree/gemini/results) |
| Groq | `openai/gpt-oss-120b` | [groq branch](https://github.com/lennart3211/it355-assignment-4/tree/groq) | [Groq results and retries](https://github.com/lennart3211/it355-assignment-4/tree/groq/results) |
| Claude | `claude-sonnet-5-5` | [claude branch](https://github.com/lennart3211/it355-assignment-4/tree/claude) | [Claude results](https://github.com/lennart3211/it355-assignment-4/tree/claude/results) |

## Setup

Clone the branch for the provider you want to run. The `--recurse-submodules` flag checks out the target source at the revision recorded by that branch. Use a separate clone for each provider.

```bash
branch=gemini # Change to groq or claude as needed.
git clone --branch "$branch" --recurse-submodules \
  https://github.com/lennart3211/it355-assignment-4.git "it355-$branch"
cd "it355-$branch"
```

Live runs require an API key for the selected provider. Gemini can prompt for the key without displaying it. For Groq and Claude, set `GROQ_API_KEY` or `ANTHROPIC_API_KEY` privately in your shell before running the scripts. Keep keys out of Git and terminal recordings.

## Run Gemini

```bash
python -m pip install -r requirements.txt

python scan.py verademo-python --prompt-keys --out runs/gemini-scan

python patch.py verademo-python \
  --findings runs/gemini-scan/findings_gemini.json \
  --out runs/gemini-patches --prompt-keys
```

## Run Groq

```bash
python -m pip install groq

python scan.py verademo-python --models groq --out runs/groq-scan

python patch.py verademo-python \
  --findings runs/groq-scan/findings_groq.json \
  --out runs/groq-patches
```

## Run Claude

```bash
python -m pip install anthropic

python scan.py verademo-python --models claude --out runs/claude-scan

python patch.py verademo-python \
  --findings results/findings_claude.json \
  --out runs/claude-patches
```

The Claude patch command uses the committed `results/findings_claude.json` and its adjacent `run_manifest.json`. To patch from a fresh scan, the scanner must also write the exact `model_id` into each finding. The current scanner writes that field to the manifest only.

## Demo and review

- **Single-file demo:** Pass a Python file path to Gemini. For Groq or Claude, give the scanner a directory containing only a copy of the same file. Use a fresh output directory for each run.
- **Scan evidence:** Review the JSON findings, CSV report, and raw API responses in each branch’s `results/` directory.
- **Patch evidence:** Review the proposed code and diffs alongside the human verdicts. A syntax check verifies that Python can parse a candidate. Manual review determines whether the candidate fixes the weakness and preserves expected behavior.
