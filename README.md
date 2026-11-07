<div align="center">

# 🔍 trust-audit

**Which certificate authorities does this machine still trust that nobody should?**

Read-only · Offline · POSIX `sh` + `openssl` (PowerShell edition for Windows) · MIT

</div>

> [!WARNING]
> **A clean result does not mean you are safe.** trust-audit finds distrusted certificates in the
> *system-wide* trust stores it can read. It does **not** cover most browsers (Firefox and Chrome
> ship their own root stores) nor software with compiled-in roots, and that is a high risk:
> **keep your browsers and applications updated.** See [what is not covered](#%EF%B8%8F-what-is-covered---and-what-is-not).

---

trust-audit reads the CA certificate stores it can find - on the machine it runs on, or inside a
container image you have unpacked - and reports every certificate authority in them that has been
distrusted since. It only looks: it reads files, makes no network connection, and never modifies
a store.

It exists because of incidents like the **eMudhra intermediate-CA key compromise (October 2026)**.
A host with an out-of-date trust store is exposed *passively* - it needs no open port to be
impersonated - and updating the OS is not enough, because many tools read their own store.

```text
$ ./trust-audit
trust-audit 0.1.0 - list of 221 fingerprints (generated 2026-11-06)

STORES
  [FOUND]  /etc/ssl/certs/ca-certificates.crt              120  2 listed
  [same ]  /etc/ssl/certs                                  121  identical set to the one above
  [FOUND]  /etc/ssl/certs/java/cacerts (Java keystore)     149  3 listed
  [ ok  ]  /home/you/.pki/nssdb (NSS database)               0  empty
  [SKIP ]  /opt/app/cacert.pem                                  NOT SCANNED - not readable

FINDINGS - 1 compromised, 2 removed

  COMPROMISED  emSign ECC Root CA - G3
      eMudhra 2026-10: root of the compromised intermediates (cross_signer)
      sha256 86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B
      ref    https://emudhra.we-have-a-problem.com/
      in     /etc/ssl/certs/ca-certificates.crt
             /etc/ssl/certs/java/cacerts (Java keystore)

  REMOVED      emSign ECC Root CA - C3
      ...

NOT EXAMINED  stores compiled into applications, the built-in roots of browsers, ...
RESULT: distrusted certificates present in 2 of 4 store(s); some stores could not be read, see [SKIP]/[WARN] lines
```

On a terminal the tags and kinds are coloured (never with `NO_COLOR`, never when piped); `-q`
prints only the stores with a problem and one line per finding.

## 🚀 How to use it

### 1. Get it

**Recommended - download a release archive** (from the releases page, or with `curl`), check it,
unpack it:

```sh
curl -fsSLO https://github.com/toob/trust-audit/releases/latest/download/trust-audit.tar.gz
curl -fsSLO https://github.com/toob/trust-audit/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing         # macOS/BSD: shasum -a 256 -c …
tar xzf trust-audit.tar.gz && cd trust-audit
```

That is the whole installation: two scripts and a list, nothing to build, no dependency to
install (`sh`, `awk`, `openssl`, `sed`, `tr`, `sort`, `cksum` are on practically every system).
The archive is self-contained, which also makes it the easy thing to copy to other machines.

**Alternative - clone the repository** (to follow the list's history or to contribute):

```sh
git clone https://github.com/toob/trust-audit.git trust-audit && cd trust-audit
```

### 2. Run it

```sh
./trust-audit                  # audit this machine's stores
sudo ./trust-audit             # same, and can read root-only stores too
```

Without root it still runs, but a store it cannot read is reported with a `[SKIP]` line and the exit
status is not 0 - it never claims a result it did not earn.

### 3. Read the result

- **`[FOUND]` and the FINDINGS list** - a listed certificate sits in that store. Each finding is
  printed once, with every store holding it. The kind says why it is listed
  (see below). Fix it by updating the package that owns the store, or by removing the certificate
  with the tool that manages it. trust-audit changes nothing itself.
- **`[SKIP]` / `[WARN]` … NOT SCANNED** - a store exists but could not be read completely. Not a clean result.
- **`RESULT: clean`** - every store found was read completely and holds nothing from the list.

In scripts and cron jobs, use the [exit status](#exit-status):

```sh
./trust-audit -k compromised || echo "compromised CA still trusted on $(hostname)"
```

### 4. Other targets

```sh
./trust-audit -r ./rootfs                 # an unpacked container image (see below)
./trust-audit -n /path/to/bundle.pem      # only what you name (a file, or a directory of PEM files)
./trust-audit -f /srv/app -f ~/venvs      # also search trees for bundle files by name
./trust-audit -q                          # quiet: only problems, one line per finding
./trust-audit -h                          # all options
```

Auditing an image:

```sh
mkdir rootfs && docker export "$(docker create alpine:3.20)" | tar -x -C rootfs
./trust-audit -r rootfs
```

`-r ROOT` treats `ROOT` as `/`: the usual locations are looked up *inside* it, symbolic links are
followed as a chroot would (an absolute link means a path in the image, never on your host), and
your environment and local tools are not consulted. It is also the right way to audit a machine you
suspect: from an offline copy.

### On Windows

The PowerShell edition [`trust-audit.ps1`](trust-audit.ps1) uses the same list and prints the same
report and exit status. It reads the machine and user *Trusted Root* and *Third-Party Root*
stores, the bundle shipped with Git for Windows, the usual environment variables, a Java
`cacerts`, and anything you name - and it reads the Windows *Disallowed* store: a listed
certificate that Windows has explicitly blocked there is shown but not counted.

```powershell
Expand-Archive trust-audit.zip . ; cd trust-audit
Unblock-File .\trust-audit.ps1                                   # downloaded files are marked
powershell -NoProfile -ExecutionPolicy Bypass -File .\trust-audit.ps1
$LASTEXITCODE                                                    # same codes as below
.\trust-audit.ps1 -Path C:\tools\ca-bundle.crt -NoDefault       # only what you name
.\trust-audit.ps1 -Quiet                       # only problems, one line per finding
```

The report goes through `Write-Host`: redirect it with `*>` (not `>`). Several paths in one
`-File` call are not possible (`-Path a,b` stays one string) - run from a PowerShell session.

### 5. Keep the list fresh

The audit is offline, so it cannot update itself; it tells you the list's age and warns after 90
days. To refresh (this is the only part that uses the network, run by you, on your own machine):

```sh
./update-list && git diff distrusted.tsv      # review, then commit
```

## 🧭 What it tells you

Each certificate is identified by the SHA-256 of its DER encoding and compared with
[`distrusted.tsv`](distrusted.tsv):

| kind | meaning | entries |
|------|---------|--------:|
| 🔴 `compromised` | the CA's key or systems were compromised (eMudhra 2026: 4 roots, 16 intermediates and cross-signs; DigiNotar 2011) | 25 |
| 🟠 `removed` | distrusted or no longer in Mozilla's root store. Reasons range from misconduct (WoSign/StartCom, TURKTRUST, CNNIC, TrustCor, DarkMatter…) to plain retirement of expired or legacy roots - read `reason` and `ref` | 191 |
| 🟡 `partial` | Mozilla still includes the root but distrusts TLS certificates issued after a date | 5 |

`-k compromised` limits both the report and the exit status to the kinds you care about.

<details>
<summary><b>What is <code>partial</code>?</b></summary>

Mozilla can keep a root in its store while saying “do not trust TLS certificates this root issues
after date D” (`CKA_NSS_SERVER_DISTRUST_AFTER`). Certificates issued before D keep validating;
anything issued after must not. A flat PEM bundle - what curl, Python, Go or most distributions
consume - has no field for D, so every consumer of the bundle trusts *all* of the root's
certificates, including the ones Mozilla says to reject. The finding therefore means “this store
cannot enforce the cut-off”, not “this root is untrustworthy”.
</details>

### Exit status

| code | meaning |
|-----:|---------|
| `0` | clean: every store was read completely and none holds a listed certificate |
| `1` | at least one listed certificate is present (a store that could not be read is also reported) |
| `2` | cannot run: bad usage, missing dependency, failed self-test, unreadable or malformed list, no store found |
| `3` | nothing found **but** some store could not be read or parsed - *not* a clean result |

## 🗺️ What is covered - and what is not

<details open>
<summary><b>Covered</b></summary>

By default, on the host (each location only if present; stores with an identical set of
certificates are audited once):

- **OS bundles and directories** - Debian/Ubuntu/Alpine/Arch/Void/Gentoo/OpenWrt (`/etc/ssl/certs`),
  RHEL/Fedora/Amazon (`/etc/pki/…`), SUSE, NixOS, FreeBSD (`ca-root-nss`), macOS/OpenBSD/BSD
  (`/etc/ssl/cert.pem`), Homebrew and MacPorts, Android system and user CA directories (paths from
  documentation, see *Tested on*), locally added CAs (`/usr/local/share/ca-certificates`,
  `…/anchors`).
- **What the environment points at** - `SSL_CERT_FILE`, `SSL_CERT_DIR`, `CURL_CA_BUNDLE`,
  `REQUESTS_CA_BUNDLE`, `PIP_CERT`, `NODE_EXTRA_CA_CERTS`, `GIT_SSL_CAINFO`, `GIT_SSL_CAPATH`,
  `AWS_CA_BUNDLE`, `CARGO_HTTP_CAINFO`, `NIX_SSL_CERT_FILE`, `DENO_CERT` - *of the shell running the
  audit* (a service has its own environment).
- **Compiled-in defaults** - OpenSSL's (`openssl version -d`) and curl's (`curl-config --ca`).
- **Python** - the interpreter's OpenSSL paths and its `certifi` and pip-vendored `certifi`
  bundles. Python runs as `python3 -I -S` (isolated, no `site`), so no `.pth` file or
  `sitecustomize` - the classic place for supply-chain payloads - executes during the audit.
- **Java** - `cacerts` of `$JAVA_HOME` and of Debian/RHEL/macOS JVM locations, through `keytool`.
- **NSS databases** - the shared database `~/.pki/nssdb` (Chrome/Chromium on Linux) and Firefox or
  Thunderbird profiles (native, snap, flatpak and macOS locations) of the user running the audit,
  plus `/etc/pki/nssdb` and any `cert9.db`/`cert8.db` found by `-f`, through `certutil` (package
  `nss-tools`; a database that exists without `certutil` is reported as not scanned). `certutil`
  only lists and exports, and works on a read-only directory. Only the certificates *stored in the
  database* are seen: Firefox's built-in roots live elsewhere (see below). Not available in the
  PowerShell edition.

  **Other users' databases are not scanned by default** (only the home of the user running the
  audit). Add them as arguments, one per profile directory, or let `-f` search their home:

  ```sh
  sudo ./trust-audit /home/alice/.pki/nssdb /home/alice/.mozilla/firefox/abc.default
  sudo ./trust-audit -f /home/alice -f /home/bob
  ```

- **macOS keychains** - system roots and system keychain, *presence only*: trust settings
  (“Never Trust”) are not evaluated.
- **Anything you name** and **`-f DIR`** - a search by well-known file name (`ca-certificates.crt`,
  `cacert*.pem`, `ca-bundle*`, `cert.pem`, `tls-ca-bundle.pem`, `ca-root-nss.crt`,
  `curl-ca-bundle.crt`, `cacerts`…): the way to reach virtualenvs, application directories and
  vendored bundles.
- **Container images** with `-r ROOT`, flattened (`docker export`), not layer by layer.
</details>

<details open>
<summary><b>Not covered</b> (every run ends with a short reminder)</summary>

- **Stores compiled into software** - Node.js's built-in roots, Go or Rust programs that embed
  their own (`webpki-roots`, `x509roots`), the built-in roots of Firefox and Thunderbird
  (`libnssckbi`, not part of their profile database), Chrome's own root store, Electron apps. Keep
  that software updated.
- **Windows**: only the PowerShell edition reads the Windows certificate stores; it does not read
  Group Policy–distributed or smart-card stores, nor the browsers' own stores. Under Git Bash or
  MSYS the `sh` edition sees only the PEM bundles above.
- **Overrides that outrank a store** - macOS trust settings and Apple's blocklist, the Windows
  “Disallowed” store, Java's `blacklisted.certs` and `jdk.security.caDistrustPolicies`, Chrome
  CRLSets, Firefox OneCRL, p11-kit blocklists. `[FOUND]` therefore means *present in the store*,
  and is a conservative signal where such a mechanism exists.
- **Other root programs' decisions** - the list follows **Mozilla** (plus curated incidents).
  Apple, Microsoft or Chrome may have distrusted more, or less.
- **Java keystores with a non-default password**, other keystore formats, DER or PKCS#7 bundles
  (pass PEM), other users' NSS databases (run it as each user, or point `-f` at their home), user
  keychains.
- **Intermediates** that are not in a store (they come with the server's chain): only a *root*
  sitting in a store can be found. The eMudhra intermediates are listed for the day one turns up
  in a store or a bundle.
- **Whether a given TLS client would accept a given chain** - that depends on the client. The
  audit answers “which stores hold a listed certificate”.
- **A compromised host** - the audit uses the host's own `sh`, `awk` and `openssl`. On a machine
  you suspect, audit an offline copy (`-r`).
</details>

## 📋 The list

[`distrusted.tsv`](distrusted.tsv) is tab-separated: `sha256`, `kind`, `label`, `reason`, `ref`.
`ref` holds one or more space-separated links (incident write-ups, Mozilla bugs, vendor notices);
each is printed on its own `ref` line in the report. [`update-list`](update-list) builds the list
from:

- [`sources/curated.tsv`](sources/curated.tsv) - incidents, curated and frozen, fingerprints taken
  from the CCADB records (and the eMudhra incident page) and every link checked by hand:
  **eMudhra** (2026), **DigiNotar** (2011), **TURKTRUST** (2013), **ANSSI** (2013), **CNNIC** (2015),
  **WoSign/StartCom** (2016), **TrustCor** (2022), **DarkMatter** (2019, the revoked QuoVadis-signed
  intermediates) and the **Camerfirma** roots;
- Mozilla's CCADB reports - roots removed from the NSS store, roots with a distrust-after date, and
  the full records report (whose “Removed” status catches roots the removed-roots report omits).

Left out of `curated.tsv` on purpose: **Symantec** (its roots are listed as Mozilla removals, but
which of them belong to the 2017–18 distrust plan has not been verified, so no incident link is
claimed), **India CCA/NIC** (2014; no fingerprint is published and the CCA India roots are still in
use) and **Trustico** (2018; customer keys leaked, no CA certificate involved).

The list is committed, so reviewing a change is reviewing a `git diff`.

## 🛡️ Design promises

- **Never a false “clean.”** Every failure path is explicit, and no unreadable,
  unparsable or missing store can yield exit 0.
- **Dependencies are checked first.** Optional helpers (`python3`, `keytool`, `curl-config`,
  `security`) are used only when present, and their absence is stated when it matters.
- **No OpenSSL version check - a self-test.** Before auditing, the script fingerprints an embedded
  public certificate (ISRG Root X2) and compares it with the SHA-256 published by Mozilla. An
  `openssl` that cannot do that is refused (exit 2), whatever its version string says. The only
  feature needed is `openssl x509 -fingerprint -sha256`.
- **Writes nothing, not even temporary files; never touches the network.** The tests check that a
  read-only store stays unchanged, that `TMPDIR` stays empty, that no network-capable command
  appears in the code, and that the audit works in a network namespace without any interface.
- Cost: one `openssl` process per distinct certificate (the PowerShell edition has none) - a few
  seconds on a PC, minutes on a small router. Files with identical content are fingerprinted once.

## ✅ Tested on

Linux host: Ubuntu, with `dash`, `bash` and `busybox sh`, and `gawk` 5.3, `mawk` and `busybox awk`.
Containers: Ubuntu 14.04 (OpenSSL 1.0.1f, mawk 1.3.3), Ubuntu 16.04 (1.0.2g), Alpine 3.16 (1.1.1w),
Debian 12 (3.0), Alpine 3.20 (3.3), Alpine 3.8 (LibreSSL 2.7.5); `-r` on exported Alpine and
Debian images.
FreeBSD 14.2 and several Linux systems (kernels 4.4 to 7.0, NAS firmware included).

Android (Pixel 8 Pro): tested in the *Terminal* app, which is a Debian VM, so these are **not**
Android's real stores. **Not tested:** the script on Android's real stores (needs `adb` and root, or
copy the stores locally and audit the copy).

PowerShell edition: PowerShell 7.4 on Linux only (its test suite passes there; the stores are read
through the same .NET `X509Store` API).

### 🙋 Testers wanted

These have **never been run on the real system**; their store paths come from documentation only.
A report, even "works" or "crashes with this output", is valuable:

| System | What to run | What to report |
| --- | --- | --- |
| **Windows** (PowerShell 5.1 and 7) | `.\trust-audit.ps1` and `tests\test-trust-audit.ps1` | output, exit code, PowerShell version |
| **macOS** (current and old) | `./trust-audit` and `tests/test-trust-audit.sh` | output, exit code, `openssl version` (LibreSSL) |
| OpenBSD / NetBSD, Git Bash | `./trust-audit` | same |

Open an issue with the output (remove host names if you prefer), see [CONTRIBUTING.md](CONTRIBUTING.md).

## 🧑‍💻 Development

```sh
tests/test-trust-audit.sh                        # behavioural tests, throw-away certificates only
pwsh -NoProfile -File tests/test-trust-audit.ps1 # same for the PowerShell edition
shellcheck trust-audit update-list tests/*.sh    # strict, no rule disabled
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## 🙏 Inspiration

Zero Hunt's [self-check](https://github.com/ZeroHunt-org/self-check) (`trust_store_audit.py`,
MIT, © 2026 Zero Hunt) was published during the eMudhra incident and did the same job for a Python
environment. Reading it shaped several choices here: scanning the environment variables that point
at a CA bundle, covering the `certifi` copy inside `pip`, running Python without `site` so its
start-up hooks cannot execute, and auditing an exported container image. trust-audit is an
independent implementation in POSIX `sh` with a different design (no Python, explicit
unreadable-store reporting, a fingerprint list built from Mozilla's data); no code was copied.

## 📄 License and disclaimer

[MIT](LICENSE). The software is provided as is, without warranty of any kind. trust-audit is an
aid, not a guarantee: a clean result means “no listed certificate in the stores that were read”
(see *Not covered*), not that a machine is safe. The author is not liable for any damage resulting
from its use or from acting on its output.
