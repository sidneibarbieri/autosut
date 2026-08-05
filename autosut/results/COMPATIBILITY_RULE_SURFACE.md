# Compatibility Rule Surface

This report exposes the exact deterministic keyword and regex surface
behind the CF/VMR/ID routing-policy labels used in the measurement
pipeline. These labels are heuristic policy outputs, not observed
minimum-backend requirements or validated ground-truth classes.
The manual validation packet must be completed before reporting
agreement or accuracy. This report is an audit aid; it does not
introduce measurements beyond the published rule-based analysis.

## Fixed Rule Inputs

- Generated from: `measurement/sut/scripts/sut_measurement_pipeline.py`
- Policy labels: `CF, VMR, ID`
- Default fallback class: `VMR`
- Label semantics: heuristic routing-policy label; not an observed minimum-backend requirement or validated ground-truth class
- Fallback semantics: default policy assignment when no explicit rule fires

## ID Platform Keywords

- `Azure AD`
- `Entra ID`
- `Google Workspace`
- `IaaS`
- `Identity Provider`
- `Office 365`
- `SaaS`
- `Windows Domain`

## Lateral-Movement Software Keywords

- `active directory`
- `domain`
- `kerberos`
- `ldap`

## VMR Signals

- Kernel/boot regex: `boot|firmware|kernel|driver|rootkit|bios|uefi|mbr|vbr|bootkit`
- Name-pattern regex: `process\s+inject|hook|dll\s+side|hijack|token\s+manipul|access\s+token|credential\s+dump|lsass|sam\s+database|registry|service\s+execut|scheduled\s+task|windows\s+management\s+instrument|wmi|exploitation\s+for\s+privilege`
- Privileged permissions: `Administrator, SYSTEM, root`

## CF Platforms

- Container-compatible platforms: `Containers, Linux`
