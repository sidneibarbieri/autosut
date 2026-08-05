# STICKS Test Suite

## Running Tests

Run the maintained lightweight suite:
```bash
cd sticks
./.venv/bin/python -m pytest \
  tests/test_campaign_loader.py \
  tests/test_multi_vm_manager_2vm.py \
  tests/test_data.py \
  tests/test_stix_parser.py
```

## Test Modules

- `test_campaign_loader.py` - canonical YAML + compatibility JSON loader behavior
- `test_multi_vm_manager_2vm.py` - small pure-function checks for the QEMU manager
- `test_data.py` - repository data-surface sanity checks
- `test_stix_parser.py` - local Enterprise STIX bundle structure checks

## Requirements

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

## Test Status

These tests are intentionally lightweight and deterministic.
They do not provision VMs, launch Caldera, or run the full measurement pipeline.
