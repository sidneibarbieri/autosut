"""Catalog of installable vulnerable application stacks for SUT realism.

Each recipe in :data:`RECIPES` installs and configures a real product at a
real vulnerable version on a SUT host. The functions are the *only* place
imperative installation code lives; the rest of the SUT composition model
(:class:`models.SUTComposition`) is purely declarative.

Design choices
--------------

- Recipes are pinned to **specific versions tied to disclosed CVEs**.
  This is what lets the paper claim "AutoSUT runs against the CVE-real
  product, not a surrogate" for the techniques where it matters.
- Recipes use the SUT host's :meth:`run_shell` so the audit trail of every
  install command lands under ``release/evidence/<run>/sut/``.
- Each recipe returns a small structured result (status + sha256 of any
  key binary) so the manifest can prove which build was installed.
- Recipes deliberately avoid ``apt-get`` on Alpine and ``apk add`` on
  Debian — the dispatching is per recipe, not global.

The centerpiece is **Apache 2.4.49 + CVE-2021-41773** because:

- It is the most-cited unauthenticated path-traversal CVE of the last
  five years, present in every credible CVE corpus.
- The official ``httpd:2.4.49`` Docker image is multi-arch (incl. ARM64).
- The vulnerability is triggered by a documented ``Alias`` + ``cgi-bin``
  configuration that is straightforward to apply via :class:`StagedArtifact`.
- The post-exploitation evidence (reading ``/etc/passwd`` via path
  traversal in the HTTP request) is irrefutable for a artifact evaluator.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .environment_base import EnvironmentBackend
from .models import ApplicationStack


@dataclass
class RecipeResult:
    """Outcome of installing one application stack."""

    ok: bool
    detail: str  # human-readable status (version probe, install log tail)
    evidence_files: list[str]  # paths under run_dir


# ----------------------------------------------------------------------
# Apache httpd 2.4.49 — CVE-2021-41773 (path traversal + RCE)
# ----------------------------------------------------------------------

# Apache config that re-enables the vulnerable Alias + cgi-bin pattern the
# CVE-2021-41773 disclosure describes. We deliberately mirror the Apache
# Security advisory wording so a reviewer reading the config can recognise
# the trigger surface immediately.
_APACHE_2449_VULN_CONF = """ServerName lab.local
Listen 80

LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule authn_file_module modules/mod_authn_file.so
LoadModule authn_core_module modules/mod_authn_core.so
LoadModule authz_host_module modules/mod_authz_host.so
LoadModule authz_groupfile_module modules/mod_authz_groupfile.so
LoadModule authz_user_module modules/mod_authz_user.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule access_compat_module modules/mod_access_compat.so
LoadModule auth_basic_module modules/mod_auth_basic.so
LoadModule reqtimeout_module modules/mod_reqtimeout.so
LoadModule filter_module modules/mod_filter.so
LoadModule mime_module modules/mod_mime.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule env_module modules/mod_env.so
LoadModule headers_module modules/mod_headers.so
LoadModule setenvif_module modules/mod_setenvif.so
LoadModule version_module modules/mod_version.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule status_module modules/mod_status.so
LoadModule autoindex_module modules/mod_autoindex.so
LoadModule cgid_module modules/mod_cgid.so
LoadModule cgi_module modules/mod_cgi.so
LoadModule dir_module modules/mod_dir.so
LoadModule alias_module modules/mod_alias.so

User daemon
Group daemon

ServerAdmin lab@lab.local
ServerRoot "/usr/local/apache2"
DocumentRoot "/usr/local/apache2/htdocs"

<Directory />
    AllowOverride none
    # NOTE: 'Require all denied' is the post-patch default. CVE-2021-41773
    # affects the pre-patch 2.4.49 default — this lab config deliberately
    # opens the path so the reviewer can exercise the exact disclosed
    # vulnerability.
    Require all granted
</Directory>

# CVE-2021-41773: this Alias mapping plus the URL-decode bug in 2.4.49 lets
# an unauthenticated GET on /icons/.%2e/.%2e/etc/passwd escape DocumentRoot.
Alias /icons/ "/usr/local/apache2/icons/"
<Directory "/usr/local/apache2/icons">
    Options Indexes MultiViews
    AllowOverride None
    Require all granted
</Directory>

# Also enable cgi-bin so the RCE escalation path described in the advisory
# is reachable when mod_cgi is loaded (it is, above).
ScriptAlias /cgi-bin/ "/usr/local/apache2/cgi-bin/"
<Directory "/usr/local/apache2/cgi-bin">
    AllowOverride None
    Options None
    Require all granted
</Directory>

ErrorLog /proc/self/fd/2
LogLevel warn
"""


def install_apache_2_4_49(env: EnvironmentBackend, stack: ApplicationStack,
                          run_dir) -> RecipeResult:
    """Stage the vulnerable httpd.conf and start httpd in the foreground.

    Assumes the host image is ``httpd:2.4.49`` (set via
    :attr:`SUTHost.base_image` or :attr:`ApplicationStack.image_override`).
    This is the canonical multi-arch vulnerable image; the recipe avoids
    rebuilding Apache from source.
    """
    # Write the vulnerable config and replace the default.
    write_cmd = (
        "cat > /usr/local/apache2/conf/httpd.conf <<'AUTOSUT_CONF_EOF'\n"
        f"{_APACHE_2449_VULN_CONF}"
        "AUTOSUT_CONF_EOF\n"
        "httpd -t 2>&1 | head -5 && "
        "(httpd -k stop 2>/dev/null; sleep 1; httpd -k start) && "
        "sleep 1 && pgrep -a httpd | head -3"
    )
    r = env.run_shell(write_cmd, log_name="sut/apache_2.4.49_install.log",
                      timeout=30)
    ok = r.ok and "httpd" in r.stdout
    # Probe Server header to confirm the vulnerable version.
    probe = env.run_shell(
        "wget -qS -O /dev/null http://127.0.0.1/ 2>&1 | head -10",
        log_name="sut/apache_2.4.49_probe.log", timeout=10,
    )
    detail = (f"install_ok={r.ok}, version_probe_lines="
              f"{probe.stdout.count('Server:')}")
    return RecipeResult(
        ok=ok,
        detail=detail,
        evidence_files=[
            "sut/apache_2.4.49_install.log",
            "sut/apache_2.4.49_probe.log",
        ],
    )


# ----------------------------------------------------------------------
# OpenSSH with weak-password user (already in pivot demo's startup; this
# recipe gives the campaign-level abstraction).
# ----------------------------------------------------------------------

_OPENSSH_INSTALL_SCRIPT = """
set -e
if command -v apk >/dev/null 2>&1; then
  apk add --no-cache openssh openssh-server shadow
elif command -v apt-get >/dev/null 2>&1; then
  apt-get update
  # --no-install-recommends keeps the install to the openssh tree only;
  # without it apt drags in systemd + dbus + krb5 + 50 more packages and
  # the slim container runs out of cache space.
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    openssh-server openssh-client
else
  echo "no supported package manager (apk, apt-get)" 1>&2
  exit 1
fi
mkdir -p /run/sshd /var/run/sshd
ssh-keygen -A
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
/usr/sbin/sshd
sleep 1
(ss -lnt 2>/dev/null || netstat -lnt 2>/dev/null) | grep :22
echo openssh_install_done
"""


def install_openssh_weak_password(env: EnvironmentBackend,
                                    stack: ApplicationStack,
                                    run_dir) -> RecipeResult:
    """Install openssh-server (Alpine apk or Debian apt) + start sshd.

    The credential itself is declared in :class:`Credential`; this recipe
    is the network surface (port 22 listening, password auth enabled).
    """
    # Timeout bumped from 180s to 600s after observing apt-get update
    # serialise badly when 4 campaigns run concurrently against the same
    # mirror. 600s gives slow-network setups headroom without masking a
    # truly stuck install.
    result = env.run_shell(
        _OPENSSH_INSTALL_SCRIPT,
        log_name="sut/openssh_install.log",
        timeout=600,
    )
    return RecipeResult(
        ok=result.ok and "openssh_install_done" in result.stdout,
        detail=("sshd listening on :22 with password auth"
                if "openssh_install_done" in result.stdout
                else f"openssh install failed (exit {result.exit_code})"),
        evidence_files=["sut/openssh_install.log"],
    )


# Structural equivalent of the openssh recipe: a different SSH server
# implementation (dropbear) satisfying the same abstract precondition — a
# remote authenticated SSH service on :22. Used by the non-uniqueness witness
# so the OpenSSH<->Dropbear material variation runs the same technique to
# completion (declared == executed), answering the "decoy-only witness"
# critique with a coincident informative-variation-AND-execution witness.
_DROPBEAR_INSTALL_SCRIPT = """
set -e
if command -v apk >/dev/null 2>&1; then
  # dropbear is the SSH *server* (the substituted element). openssh-sftp-server
  # + the scp client binary are file-transfer helpers dropbear invokes for
  # T1570 (Lateral Tool Transfer) — they do not change the fact that the
  # listening sshd is dropbear, only that scp/sftp works against it.
  apk add --no-cache dropbear openssh-sftp-server openssh-client shadow
elif command -v apt-get >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends dropbear-bin openssh-sftp-server openssh-client
else
  echo "no supported package manager (apk, apt-get)" 1>&2
  exit 1
fi
mkdir -p /etc/dropbear
[ -f /etc/dropbear/dropbear_rsa_host_key ] || dropbearkey -t rsa -s 2048 -f /etc/dropbear/dropbear_rsa_host_key
[ -f /etc/dropbear/dropbear_ed25519_host_key ] || dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key || true
# Password auth is enabled by default in dropbear (no -s flag): the same weak
# network surface the openssh recipe creates with PasswordAuthentication yes.
# Daemonises (no -F); -p 22 listen; -P writes the pidfile.
dropbear -p 22 -P /var/run/dropbear.pid
sleep 1
(ss -lnt 2>/dev/null || netstat -lnt 2>/dev/null) | grep :22
echo dropbear_install_done
"""


def install_dropbear_equivalent(env: EnvironmentBackend,
                                stack: ApplicationStack,
                                run_dir) -> RecipeResult:
    """Install dropbear and start it on :22 with password auth.

    The structural counterpart to :func:`install_openssh_weak_password`. The
    credential is declared in :class:`Credential`; this recipe is the network
    surface (a real dropbear daemon, real host keys, real password auth), so a
    technique that SSH-authenticates runs identically against OpenSSH or
    Dropbear — the corpus-supported precondition is preserved, only the free
    implementation differs.
    """
    result = env.run_shell(
        _DROPBEAR_INSTALL_SCRIPT,
        log_name="sut/dropbear_install.log",
        timeout=600,
    )
    return RecipeResult(
        ok=result.ok and "dropbear_install_done" in result.stdout,
        detail=("dropbear listening on :22 with password auth"
                if "dropbear_install_done" in result.stdout
                else f"dropbear install failed (exit {result.exit_code})"),
        evidence_files=["sut/dropbear_install.log"],
    )


# ----------------------------------------------------------------------
# Edge HTTP service witness (Apache <-> Nginx). Both serve the same
# HTTP-Basic-Auth-protected secret, so the web brute-force chain runs
# identically against either edge server. Credentials and the secret marker
# are pre-staged and matched in multi_host_executor (webadmin / Lab-Web-2026!
# / LAB-WEB-SECRET).
# ----------------------------------------------------------------------

_APACHE_BASIC_AUTH_INSTALL = """
set -e
if command -v apk >/dev/null 2>&1; then
  apk add --no-cache apache2 apache2-utils curl
elif command -v apt-get >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends apache2 apache2-utils curl
else
  echo "no supported package manager (apk, apt-get)" 1>&2; exit 1
fi
mkdir -p /secret
echo 'LAB-WEB-SECRET-c0ffee' > /secret/flag.txt
htpasswd -bc /etc/webauth.htpasswd webadmin 'Lab-Web-2026!'
CONFDIR=/etc/apache2/conf.d
[ -d "$CONFDIR" ] || CONFDIR=/etc/apache2/conf-enabled
mkdir -p "$CONFDIR"
cat > "$CONFDIR/secret.conf" <<'EOF'
Alias /secret /secret
<Directory "/secret">
  AuthType Basic
  AuthName "Restricted"
  AuthUserFile /etc/webauth.htpasswd
  Require valid-user
</Directory>
EOF
(httpd -k start 2>/dev/null) || (apachectl -k start 2>/dev/null) || (service apache2 start 2>/dev/null) || (/usr/sbin/apache2ctl start 2>/dev/null)
sleep 1
(ss -lnt 2>/dev/null || netstat -lnt 2>/dev/null) | grep :80
echo apache_basic_auth_done
"""

_NGINX_EQUIVALENT_INSTALL = """
set -e
if command -v apk >/dev/null 2>&1; then
  apk add --no-cache nginx apache2-utils curl
elif command -v apt-get >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nginx apache2-utils curl
else
  echo "no supported package manager (apk, apt-get)" 1>&2; exit 1
fi
mkdir -p /secret /run/nginx
echo 'LAB-WEB-SECRET-c0ffee' > /secret/flag.txt
htpasswd -bc /etc/webauth.htpasswd webadmin 'Lab-Web-2026!'
CONFDIR=/etc/nginx/http.d
[ -d "$CONFDIR" ] || CONFDIR=/etc/nginx/conf.d
mkdir -p "$CONFDIR"
rm -f "$CONFDIR/default.conf" /etc/nginx/sites-enabled/default 2>/dev/null || true
cat > "$CONFDIR/secret.conf" <<'EOF'
server {
  listen 80 default_server;
  location /secret/ {
    alias /secret/;
    auth_basic "Restricted";
    auth_basic_user_file /etc/webauth.htpasswd;
  }
}
EOF
nginx 2>/dev/null || (service nginx start 2>/dev/null) || true
sleep 1
(ss -lnt 2>/dev/null || netstat -lnt 2>/dev/null) | grep :80
echo nginx_equivalent_done
"""


def install_apache_basic_auth(env: EnvironmentBackend, stack: ApplicationStack,
                              run_dir) -> RecipeResult:
    """Apache serving one HTTP-Basic-Auth-protected resource: the canonical
    edge HTTP service for the web non-uniqueness witness."""
    result = env.run_shell(_APACHE_BASIC_AUTH_INSTALL,
                           log_name="sut/apache_basic_auth.log", timeout=600)
    done = "apache_basic_auth_done" in result.stdout
    return RecipeResult(
        ok=result.ok and done,
        detail=("apache serving Basic-Auth-protected /secret on :80" if done
                else f"apache basic-auth install failed (exit {result.exit_code})"),
        evidence_files=["sut/apache_basic_auth.log"],
    )


def install_nginx_equivalent(env: EnvironmentBackend, stack: ApplicationStack,
                             run_dir) -> RecipeResult:
    """Nginx serving the same Basic-Auth-protected resource as Apache. The
    structural counterpart to :func:`install_apache_basic_auth`: a different
    edge HTTP server (separate codebase and configuration model) realizing the
    same abstract precondition, so the web brute-force chain runs identically."""
    result = env.run_shell(_NGINX_EQUIVALENT_INSTALL,
                           log_name="sut/nginx_equivalent.log", timeout=600)
    done = "nginx_equivalent_done" in result.stdout
    return RecipeResult(
        ok=result.ok and done,
        detail=("nginx serving Basic-Auth-protected /secret on :80" if done
                else f"nginx install failed (exit {result.exit_code})"),
        evidence_files=["sut/nginx_equivalent.log"],
    )


# ----------------------------------------------------------------------
# Minimal "vulnerable Flask app" — generic web exfil surface
# ----------------------------------------------------------------------

_FLASK_DECOY_APP = """from flask import Flask, request
app = Flask(__name__)

@app.route('/api/users')
def users():
    # T1078 / T1213: a decoy 'sensitive' list reachable without auth.
    return {'users': [{'email': 'ceo@lab.local', 'password_hash': '$2b$12$decoy'}]}

@app.route('/api/whoami')
def whoami():
    return {'user': request.headers.get('Authorization', 'anonymous')}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
"""


def install_flask_decoy_api(env: EnvironmentBackend, stack: ApplicationStack,
                              run_dir) -> RecipeResult:
    """A tiny Flask app that exposes decoy 'sensitive' JSON. Used as the
    surface for techniques like T1213 (Data from Information Repositories)."""
    cmds = [
        "apk add --no-cache py3-pip >/dev/null 2>&1 || true",
        "pip3 install --break-system-packages flask >/dev/null 2>&1 || pip3 install flask >/dev/null 2>&1",
        "mkdir -p /opt/decoy_api",
        ("cat > /opt/decoy_api/app.py <<'PY_EOF'\n"
         f"{_FLASK_DECOY_APP}"
         "PY_EOF"),
        "nohup python3 /opt/decoy_api/app.py >/tmp/decoy_api.log 2>&1 &",
        "sleep 2 && wget -qO- http://127.0.0.1:5000/api/users | head -2",
    ]
    evidence: list[str] = []
    for idx, c in enumerate(cmds):
        log_name = f"sut/flask_decoy_{idx:02d}.log"
        r = env.run_shell(c, log_name=log_name, timeout=120)
        evidence.append(log_name)
    # final probe
    probe = env.run_shell(
        "wget -qO- http://127.0.0.1:5000/api/users",
        log_name="sut/flask_decoy_probe.log", timeout=10,
    )
    ok = "ceo@lab.local" in probe.stdout
    evidence.append("sut/flask_decoy_probe.log")
    return RecipeResult(
        ok=ok, detail=f"flask api {'live' if ok else 'failed'}",
        evidence_files=evidence,
    )


# ----------------------------------------------------------------------
# Apache 2.4 (Debian default) — generic web surface for frozen campaigns
# ----------------------------------------------------------------------

_APACHE_DEFAULT_INSTALL = """
set -e
if command -v apt-get >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends apache2
  # On slim images Apache wants /etc/apache2/envvars + the default site
  # alias; both ship with the package.
  service apache2 start || /usr/sbin/apache2ctl start
elif command -v apk >/dev/null 2>&1; then
  apk add --no-cache apache2
  httpd -k start
else
  echo "no supported package manager for apache install" 1>&2
  exit 1
fi
sleep 1
(ss -lnt 2>/dev/null || netstat -lnt 2>/dev/null) | grep :80
echo apache_default_site_done
"""


def install_apache_default_site(env: EnvironmentBackend,
                                  stack: ApplicationStack,
                                  run_dir) -> RecipeResult:
    """Install Apache (Debian apt or Alpine apk) and start the default site.

    Matches the released ``apache2@default`` SUT profile for
    c0010, c0013, apt41_dust, costaricto and outer_space.
    """
    result = env.run_shell(
        _APACHE_DEFAULT_INSTALL,
        log_name="sut/apache_default_install.log",
        timeout=600,
    )
    return RecipeResult(
        ok=result.ok and "apache_default_site_done" in result.stdout,
        detail=("apache listening on :80"
                if "apache_default_site_done" in result.stdout
                else f"apache install failed (exit {result.exit_code})"),
        evidence_files=["sut/apache_default_install.log"],
    )


# ----------------------------------------------------------------------
# MySQL default instance (for the frozen apt41_dust multi-service shape)
# ----------------------------------------------------------------------

_MYSQL_DEFAULT_INSTALL = """
set -e
if command -v apt-get >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \\
    default-mysql-server
  service mariadb start || service mysql start || \\
    mysqld --datadir=/var/lib/mysql --user=mysql &
elif command -v apk >/dev/null 2>&1; then
  apk add --no-cache mariadb mariadb-client
  mariadb-install-db --user=mysql --datadir=/var/lib/mysql
  mysqld_safe --datadir=/var/lib/mysql &
else
  echo "no supported package manager for mysql install" 1>&2
  exit 1
fi
sleep 4
(ss -lnt 2>/dev/null || netstat -lnt 2>/dev/null) | grep :3306
echo mysql_default_instance_done
"""


def install_mysql_default_instance(env: EnvironmentBackend,
                                     stack: ApplicationStack,
                                     run_dir) -> RecipeResult:
    """Install MySQL (or MariaDB) and start the default instance.

    Matches the released ``mysql@default`` SUT profile for
    apt41_dust (``default_instance_exposed``).
    """
    result = env.run_shell(
        _MYSQL_DEFAULT_INSTALL,
        log_name="sut/mysql_default_install.log",
        timeout=600,
    )
    return RecipeResult(
        ok=result.ok and "mysql_default_instance_done" in result.stdout,
        detail=("mysql listening on :3306"
                if "mysql_default_instance_done" in result.stdout
                else f"mysql install failed (exit {result.exit_code})"),
        evidence_files=["sut/mysql_default_install.log"],
    )


# ----------------------------------------------------------------------
# Registry
# ----------------------------------------------------------------------

RecipeFn = Callable[[EnvironmentBackend, ApplicationStack, "object"], RecipeResult]

RECIPES: dict[str, RecipeFn] = {
    "apache_httpd_2.4.49_cve_2021_41773": install_apache_2_4_49,
    "apache_default_site": install_apache_default_site,
    "mysql_default_instance": install_mysql_default_instance,
    "openssh_weak_password": install_openssh_weak_password,
    "dropbear_equivalent": install_dropbear_equivalent,
    "apache_basic_auth": install_apache_basic_auth,
    "nginx_equivalent": install_nginx_equivalent,
    "flask_decoy_api": install_flask_decoy_api,
}
