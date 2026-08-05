# MITRE FiGHT snapshot

`fight-3.1.0.yaml` is the authoritative, byte-preserved MITRE FiGHT source used
by this artifact. MITRE publishes the website source at
<https://fight.mitre.org/fight.yaml>; the FiGHT information page states that the
website consumes YAML and that a STIX export is planned rather than currently
published.

`fight-3.1.0.normalized.json` is a deterministic derived export containing only
the technique fields used for measurement: identifier, name, status, platforms,
architecture segments, software, description, references, procedure examples,
and extracted CVE identifiers. `fight-3.1.0.metadata.json` records the source,
version, retrieval and upstream modification timestamps, SHA-256 hashes, terms
and marking, and frozen denominators. MITRE's FiGHT terms grant a non-exclusive,
royalty-free license for research, development, and commercial use, subject to
reproducing MITRE's copyright designation and license; see
<https://fight.mitre.org/resources/terms/> for the authoritative terms.

Re-fetch and verify the pinned paper snapshot:

```bash
python3 measurement/sut/scripts/fetch_fight_snapshot.py
```

Regenerate the derived files without network access:

```bash
python3 measurement/sut/scripts/fetch_fight_snapshot.py \
  --from-raw measurement/sut/scripts/data/fight-3.1.0.yaml
```

The script refuses changed upstream bytes, changed counts, non-FiGHT technique
identifiers, or missing FiGHT-native architecture fields. Adopting a newer FiGHT
release requires a new version, hash, denominator audit, and corresponding paper
update.

The quarantined file `legacy/enterprise-attack-v10.1.json` is **not FiGHT**; it
is an ATT&CK Enterprise v10.1 bundle retained only to preserve the provenance of
earlier artifact revisions. No current pipeline, gate, or result consumes it,
and it must not be used as FiGHT evidence.
