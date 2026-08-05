# Methodology

## Campaign Origins
- **Canonical Campaigns**: Derived from ATT&CK data, mapped to real-world intrusion timelines.
- **Selection Criteria**: Campaigns C0001–C0005 represent diverse adversary behaviors with varying technique counts and platforms.

## Role of STIX
- ATT&CK enterprise data in STIX 2.1 format provides technique definitions, platforms, and data sources.
- Used to resolve technique metadata and validate campaign-technique alignment.
- Enables automated mapping between campaign steps and ATT&CK taxonomy.

## Role of SUT Profiles
- Each SUT profile defines the minimal environment required to materialize a campaign.
- Includes required VMs, services, vulnerabilities, and capabilities.
- Decouples campaigns from specific infrastructure; campaigns can be executed on different SUTs.

## Role of IaC (Infrastructure as Code)
- Vagrant definitions under `lab/vagrant/` codify multi-VM environments.
- Cloud-init scripts in `lab/provisioning/` ensure deterministic VM bootstrap.
- Enables reproducible lab setup across different hosts.

## Procedural Gap Filling
- Some ATT&CK techniques lack explicit procedural details.
- Calibration layer fills gaps with minimal, faithful implementations.
- Fidelity rubric (5-criteria) classifies techniques as faithful/adapted/inspired.

## Reproducibility Strategy
- Deterministic VM provisioning via cloud-init.
- Fixed SUT profiles ensure consistent starting state.
- All randomization is seeded where possible.
- Evidence schemas capture execution outcomes structurally.

## Limitations
- Techniques are simulated, not real malicious operations.
- Network conditions and timing are not fully reproduced.
- Some techniques require abstract interpretation due to missing procedural data.
