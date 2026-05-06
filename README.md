# DNSHield

1. Install `uv`

mac:

```bash
brew install uv
```

Windows:

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

2. Sync project environment

```bash
uv sync --all-groups
```

3. Prepare domain data and root zone

```bash
uv run python scripts/split_benign_domains.py
uv run python scripts/generate_benign_root_zone.py
```

4. Train Isolation Forest model

Use the README for training and follow all steps:

- detector/training/README.md

5. Run evaluation scenarios

Attack, detector off:

```bash
uv run scripts/run_evaluation.py --detector off --client off --attack-query-name app.lab.dnshield
```

Attack, detector on:

```bash
uv run scripts/run_evaluation.py --detector on --client off --attack-query-name app.lab.dnshield
```

Client, detector off:

```bash
uv run scripts/run_evaluation.py --detector off --attacker off --client on --client-domain-corpus on --client-domain-corpus-source test
```

Client, detector on:

```bash
uv run scripts/run_evaluation.py --detector on --attacker off --client on --client-domain-corpus on --client-domain-corpus-source test
```
