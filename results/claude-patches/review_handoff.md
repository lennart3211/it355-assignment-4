# Claude patch handoff

These are model proposals, not verified security fixes.

Copy review_template.csv to a separate review file before entering human judgments.

## Part 2b manual verification

For each finding, review the original code, the proposed code/diff, and whether intended behavior is preserved. Record your own explanation and any test evidence. A Python syntax check does not prove a security fix.

## Part 3a model comparison

Use human judgments to distinguish true vulnerabilities with correct patches, true vulnerabilities with incorrect patches, and hallucinations. Keep unresolved cases unverified; do not classify them automatically.

## Generated proposals

- app/admin.py: patch_proposed; findings F0001. Diff: diffs/app/admin.py.diff.

- app/commands/IgnoreCommand.py: patch_proposed; findings F0002, F0003, F0004. Diff: diffs/app/commands/IgnoreCommand.py.diff.

- app/commands/ListenCommand.py: patch_proposed; findings F0005, F0006, F0007. Diff: diffs/app/commands/ListenCommand.py.diff.

- app/forms.py: patch_proposed; findings F0008, F0009. Diff: diffs/app/forms.py.diff.

- app/models.py: patch_proposed; findings F0010, F0011, F0012. Diff: diffs/app/models.py.diff.

- app/views/blabController.py: invalid_proposal; findings F0013, F0014, F0015, F0016, F0017, F0018, F0019, F0020, F0021, F0022, F0023, F0024. Diff: none.

- app/views/homeController.py: patch_proposed; findings F0025. Diff: diffs/app/views/homeController.py.diff.

- app/views/resetController.py: patch_proposed; findings F0026, F0027, F0028, F0029. Diff: diffs/app/views/resetController.py.diff.

- app/views/toolsController.py: patch_proposed; findings F0030, F0031. Diff: diffs/app/views/toolsController.py.diff.

- app/views/userController.py: api_error; findings F0032, F0033, F0034, F0035, F0036, F0037, F0038, F0039, F0040, F0041, F0042, F0043, F0044, F0045, F0046, F0047, F0048, F0049, F0050, F0051, F0052, F0053, F0054, F0055, F0056, F0057, F0058, F0059, F0060. Diff: none.

- verademo-python/settings.py: patch_proposed; findings F0061, F0062, F0063, F0064, F0065. Diff: diffs/verademo-python/settings.py.diff.
