# Campaign Mapping Documentation

## Current State

### Corpus
- 51 campaigns in `sticks/data/caldera_adversaries/`
- 20 adversaries available in Caldera

### Execution Issue
All operations observe only technique T1070.003, regardless of the adversary used.

### Root Cause
Agents have empty `atomic_ordering`, causing Caldera's atomic planner to only execute the first ability that matches.

### Available Adversaries (by ability count)
| Name | Abilities |
|------|----------|
| Alice 2.0 | 8 |
| Check | 8 |
| Collection | 4 |
| Discovery | 12 |
| Hunter | 18 |
| Enumerator | 5 |

## Honest Claims

**Supported:**
- "End-to-end operation execution in Caldera with three active agents"
- "Observable ATT&CK technique execution (T1070.003)"

**Not Supported:**
- "Full campaign execution"
- "Multiple techniques executed per run"

## Mapping Approach

For each campaign in the corpus, we map to an available Caldera adversary:
- Campaign → Adversary (based on available adversaries)
- Executed technique: T1070.003 only
- This is inspired execution, not campaign reproduction
