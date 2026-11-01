"""Static inventory checks must use the bundled population, not old paper rows."""

import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'measurement/sut/release_check.sh').read_text()
START = SOURCE.index('for source_name, bundle_name in ')
END = SOURCE.index('dataset_label = ', START)
CHECK = compile(SOURCE[START:END], 'release_check.sh:dataset-totals', 'exec')


def verify_table(manuscript):
    import re
    import sys

    exec(CHECK, {
        'json': json, 're': re, 'sys': sys,
        'meas_scripts': ROOT / 'measurement/sut/scripts', 'main': manuscript,
    })


def test_current_bundle_inventory_passes():
    verify_table('Mobile & 190 & 3 & 22 & 127 \\\\\nICS & 118 & 9 & 16 & 30 \\\\\n')


@pytest.mark.parametrize('bad_row', [
    'Mobile & 190 & 3 & 17 & 123 \\\\',
    'ICS & 95 & 8 & 16 & 30 \\\\',
    'ICS & 97 & 9 & 16 & 30 \\\\',
    'ICS & 118 & 9 & 16 & 30 & 99 \\\\',
])
def test_stale_active_or_extra_cells_fail(bad_row):
    good = 'Mobile & 190 & 3 & 22 & 127\nICS & 118 & 9 & 16 & 30\n'
    rows = [bad_row if row.startswith(bad_row.split()[0]) else row
            for row in good.splitlines()]
    with pytest.raises(SystemExit, match='1'):
        verify_table('\n'.join(rows))
