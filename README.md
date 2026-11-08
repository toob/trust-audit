<div align="center">

# 🔍 trust-audit

**Which certificate authorities does this machine still trust that nobody should - and which did somebody add?**

Read-only · Offline · POSIX `sh` + `openssl` (PowerShell edition for Windows) · MIT

</div>

> [!WARNING]
> **A clean result does not mean you are safe.** trust-audit finds distrusted and unknown
> certificates in the *system-wide* trust stores it can read. It does **not** cover most browsers (Firefox and Chrome
> ship their own root stores) nor software with compiled-in roots, and that is a high risk:
> **keep your browsers and applications updated.** See [what is not covered](#%EF%B8%8F-what-is-covered---and-what-is-not).

---

trust-audit reads the CA certificate stores it can find - on the machine it runs on, or inside a
container image you have unpacked - and tells you whether there is something to fix or to check:

- a certificate authority **tied to a stolen key** (eMudhra 2026, DigiNotar...);
- one **no public root program includes** - added by an administrator (internal PKI, TLS-inspection
  proxy, GPO/MDM) or by an implant: either way you should know about it;
- a store that **still holds roots Mozilla removed**, with the command that brings it up to date.

It only looks: it reads files, makes no network connection, and never modifies a store.

It exists because of incidents like the **eMudhra intermediate-CA key compromise (October 2026)**.
A host with an out-of-date trust store is exposed *passively* - it needs no open port to be
impersonated - and updating the OS is not enough, because many tools read their own store.

```text
$ ./trust-audit
trust-audit 0.2.0 - lists of 2026-11-08: 221 distrusted fingerprints, 418 known roots

VERDICT: ACT NOW - 1 unknown certificate, 1 compromised, 2 stores to update

UNKNOWN - 1 certificate that no public root program trusts
  No public root program (Apple, Chrome, Microsoft, Mozilla, nor the Android and Java
  stores) includes these: they were added to this machine. Roots recorded in
  /opt/trust-audit/known-roots.local.tsv are not reported.

  O=Example Corp, CN=Example Corp TLS Inspection CA
      sha256 8C62495F4535C93FE7CA8C7E1457FCF046AA3D0CEE6F336266A30D579D569210
      in     /usr/local/share/ca-certificates

COMPROMISED - 1 certificate tied to a stolen key

  AAA Certificate Services
      eMudhra 2026-10: Sectigo root that cross-signed the intermediates whose keys were stolen
      (its own key was not); a client that trusts it and does not check revocation (curl, Java,
      Python...) accepts certificates forged with those keys. Still included by Mozilla, Apple
      and Microsoft: removing it may break sites chaining to it
      in     /etc/ssl/certs/java/cacerts (Java keystore)

TO UPDATE - 2 stores hold roots Mozilla removed

  /etc/ssl/certs/ca-certificates.crt
      also   /etc/ssl/certs
      5 roots removed by Mozilla (this is the system store)
      roots  emSign Root CA - C1, SecureSign Root CA12, Entrust Root Certification Authority,
             ... (+2, -v lists them)

  /etc/ssl/certs/java/cacerts (Java keystore)
      24 roots removed by Mozilla, 19 of them no longer in your system store
      roots  emSign Root CA - C1, SecureSign Root CA12, Entrust Root Certification Authority,
             ... (+21, -v lists them)

FOR INFORMATION - nothing to do
  4 roots Mozilla distrusts only for certificates issued after a date (a flat bundle cannot
    express the date): Izenpe.com, Entrust Root Certification Authority - EC1, ... (+2, -v lists them)
  1 self-signed certificate of this machine itself, valid only for its own name (such as
    ssl-cert's snakeoil): CN=web01

STORES
  [FOUND]  /etc/ssl/certs/ca-certificates.crt              120  6 listed
  [FOUND]  /etc/ssl/certs                                  121  6 listed
  [FOUND]  /usr/local/share/ca-certificates                  1  1 unknown
  [FOUND]  /etc/ssl/certs/java/cacerts (Java keystore)     155  29 listed
  [ ok  ]  /home/you/.pki/nssdb (NSS database)               0  empty
  [SKIP ]  /opt/app/cacert.pem                                  NOT SCANNED - not readable

NOT EXAMINED  stores compiled into applications (Node.js, Go/Rust programs), the built-in ...
What to do about each item: README.md, section "What to do".
RESULT: ACT NOW - 1 unknown certificate, 1 compromised, 2 stores to update; some stores could not be read, see [SKIP]/[WARN]
```

The verdict comes first and again last; in between, one item per finding. The report states
facts only: what to do about each item is [below](#-what-to-do), not in the output. On a terminal it is
coloured (never with `NO_COLOR`, never when piped); `-q` keeps one line per item, `-v` adds every
certificate with its fingerprint, reason and references.

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

That is the whole installation: two scripts and their lists, nothing to build, no dependency to
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

- **`VERDICT`** - the answer, first and last:
  - `ACT NOW` - an unknown or a compromised certificate is trusted here;
  - `UPDATE NEEDED` - a store holds roots Mozilla removed;
  - `INCOMPLETE` - nothing found, but some store could not be read: **not** a clean result;
  - `NOTHING TO DO` - every store was read completely; anything left is for information.
- **`UNKNOWN`** - a certificate no public root program includes. A certificate that cannot act
  as a CA (`CA:FALSE`) is shown with the only names it can vouch for; one that names this machine
  itself (ssl-cert's "snakeoil") is listed for information only.
- **`COMPROMISED`** - a certificate tied to a stolen key, with the reason.
- **`TO UPDATE`** - one item per store, with the roots it still holds. A store that holds roots
  your system store no longer has is said to be behind it.
- **`FOR INFORMATION`** - nothing to do: roots Mozilla distrusts only after a date, roots Apple
  (or Microsoft) still ship in their own program, this machine's own self-signed certificate.
- **`[SKIP]` / `[WARN]` … NOT SCANNED** - a store exists but could not be read completely.

trust-audit changes nothing itself, and its output gives no advice: see [what to do](#-what-to-do).

In scripts and cron jobs, use the [exit status](#exit-status):

```sh
./trust-audit -k compromised || echo "compromised CA still trusted on $(hostname)"
```

### 4. Other targets

```sh
./trust-audit -r ./rootfs                 # an unpacked container image (see below)
./trust-audit -n /path/to/bundle.pem      # only what you name (a file, or a directory of PEM files)
./trust-audit -f /srv/app -f ~/venvs      # also search trees for bundle files by name
./trust-audit -q                          # quiet: one line per item
./trust-audit -v                          # every certificate, with fingerprint, reason and references
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

The PowerShell edition [`trust-audit.ps1`](trust-audit.ps1) uses the same lists and prints the same
report and exit status (`-Detail` for `-v`). It reads the machine and user *Trusted Root* and *Third-Party Root*
stores, the bundle shipped with Git for Windows, the usual environment variables, a Java
`cacerts`, and anything you name - and it reads the Windows *Disallowed* store: a listed
certificate that Windows has explicitly blocked there is shown but not counted. Roots Mozilla
removed that Microsoft still ships in the Windows root stores are reported for information.

```powershell
Expand-Archive trust-audit.zip . ; cd trust-audit
Unblock-File .\trust-audit.ps1                                   # downloaded files are marked
powershell -NoProfile -ExecutionPolicy Bypass -File .\trust-audit.ps1
$LASTEXITCODE                                                    # same codes as below
.\trust-audit.ps1 -Path C:\tools\ca-bundle.crt -NoDefault       # only what you name
.\trust-audit.ps1 -Quiet                       # one line per item
```

The report goes through `Write-Host`: redirect it with `*>` (not `>`). Several paths in one
`-File` call are not possible (`-Path a,b` stays one string) - run from a PowerShell session.

### 5. Keep the lists fresh

The audit is offline, so it cannot update itself; it tells you the lists' age and warns after 90
days. To refresh (this is the only part that uses the network, run by you, on your own machine):

```sh
./update-list --dry-run                       # what would change; writes nothing
./update-list && git diff                     # distrusted.tsv, known-roots.tsv: review, then commit
./update-list --extras                        # also known-roots-extra.tsv, when update-list says it is behind
```

## 🩹 What to do

trust-audit only reports. These are suggestions for the usual cases - check them against your
system's documentation before running anything as root, and keep a copy of what you remove.

**`UNKNOWN`** - find out who added it.

- If you run the machine, it is probably yours: an internal PKI, a TLS-inspection proxy, a CA
  pushed by GPO or MDM. Record its sha256 (and, after a TAB, a label and why) in
  `known-roots.local.tsv` next to the script - see
  [`known-roots.local.example.tsv`](known-roots.local.example.tsv). It is then no longer reported.
- If you do not run it, ask whoever does. On a company machine, the company's CAs are expected.
- If nobody can account for it, treat it as a sign of compromise: a certificate authority in a
  trust store can impersonate any site to this machine. Keep the evidence (the file, its date,
  `-v` output), audit an offline copy with `-r`, and remove it with the tool that manages the store.
- A `CA:FALSE` certificate can only impersonate the names shown: still find out why it is there.

**`COMPROMISED`** - read the reason first. A certificate whose own key was stolen should go. A
root that only signed the compromised intermediates (eMudhra 2026) is a path to the stolen keys for
every client that does not check revocation; removing it may break sites that still chain to it
(Sectigo's AAA Certificate Services), so weigh that against your clients.

**`TO UPDATE`** - by kind of store:

| store | what usually fixes it |
|-------|-----------------------|
| the system store (`/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/...`, `/etc/ssl/cert.pem`...) | update the `ca-certificates` package (or your system). If it is already current, your distribution has not shipped Mozilla's removal yet: nothing more to do, re-check after its next update |
| Java keystore `/etc/ssl/certs/java/cacerts` (Debian/Ubuntu) | rebuild it from the system store: as root, `rm /etc/ssl/certs/java/cacerts && update-ca-certificates -f`. `update-ca-certificates -f` alone adds certificates but removes none (checked on Debian 12) |
| Java keystore `/etc/pki/java/cacerts` (RHEL/Fedora) | `update-ca-trust extract`, as root |
| a JDK's own `lib/security/cacerts` | update that JDK/JRE |
| `certifi/cacert.pem` | `python -m pip install -U certifi` in that environment |
| `pip/_vendor/certifi/cacert.pem` | `python -m pip install -U pip` in that environment |
| an NSS database (browser profile, `~/.pki/nssdb`) | delete the certificate in the application's certificate manager, or with `certutil -D` |
| a macOS keychain | Apple decides what the system roots keychain holds: update macOS |
| any other bundle | update the software that ships it |

**`FOR INFORMATION`** - nothing to do.

## 🧭 What it tells you

Each certificate is identified by the SHA-256 of its DER encoding and compared with
[`distrusted.tsv`](distrusted.tsv), then with the [lists of known roots](#-the-lists):

| kind | meaning | entries | report |
|------|---------|--------:|--------|
| 🔴 `compromised` | tied to a stolen key: the CA's own key or systems were compromised (DigiNotar 2011), or it issued or cross-signed intermediates whose keys were stolen (eMudhra 2026: 4 roots, 16 intermediates and cross-signs) - a client that trusts it and does not check revocation accepts forged certificates | 25 | act now |
| 🔴 `unknown` | in no public root program (Apple, Chrome, Microsoft, Mozilla, nor the Android and Java stores) and not in your `known-roots.local.tsv`: added by someone | - | act now |
| 🟠 `removed` | distrusted or no longer in Mozilla's root store. Reasons range from misconduct (WoSign/StartCom, TURKTRUST, CNNIC, TrustCor, DarkMatter…) to plain retirement of expired or legacy roots - `-v` shows `reason` and `ref` | 191 | to update |
| 🟡 `partial` | Mozilla still includes the root but distrusts TLS certificates issued after a date | 5 | information |

`-k compromised` limits both the report and the exit status to the kinds you care about;
`-k compromised,removed,partial` leaves unknown certificates out.

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
| `0` | nothing to do: every store was read completely; what is left, if anything, is for information (`partial`, this machine's own certificate, roots Apple or Microsoft still ship) |
| `1` | something to fix or check: an unknown, compromised or removed certificate (a store that could not be read is also reported) |
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
  (“Never Trust”) are not evaluated. Roots Mozilla removed that Apple still ships in the system
  roots keychain are reported for information: Apple's own program decides there.
- **Unknown certificates** in every store above. In an NSS database only entries trusted as a CA
  count (a cached intermediate or your own certificate is not a trust anchor).
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
  “Disallowed” store, Java's `blocked.certs` and `jdk.security.caDistrustPolicies`, Chrome
  CRLSets, Firefox OneCRL, p11-kit blocklists. `[FOUND]` therefore means *present in the store*,
  and is a conservative signal where such a mechanism exists.
- **Other root programs' decisions** - the list follows **Mozilla** (plus curated incidents).
  Apple, Microsoft or Chrome may have distrusted more, or less. The CCADB marks 6 roots
  "Blocked" by Apple that Apple's own published list still shows as available (December 2025).
- **What an unknown certificate is for** - "unknown" means *in no public program as of the list's
  date*: a root added to a program after that date shows as unknown until `update-list` runs, an
  intermediate placed in a store shows as unknown, and so do legitimate private CAs until you
  record them. On macOS the system keychain may also hold non-CA certificates; on Windows, old
  Microsoft roots outside the CCADB may appear (reports welcome).
- **Java keystores with a non-default password**, other keystore formats, DER or PKCS#7 bundles
  (pass PEM), other users' NSS databases (run it as each user, or point `-f` at their home), user
  keychains.
- **Intermediates** that are not in a store (they come with the server's chain): only a *root*
  sitting in a store can be found. The eMudhra intermediates are listed for the day one turns up
  in a store or a bundle.
- **Whether a given TLS client would accept a given chain** - that depends on the client. The
  audit answers “which stores hold a listed or an unknown certificate”.
- **A compromised host** - the audit uses the host's own `sh`, `awk` and `openssl`. On a machine
  you suspect, audit an offline copy (`-r`).
</details>

## 📋 The lists

All are tab-separated, committed (reviewing a change is reviewing a `git diff`), and built by
[`update-list`](update-list); `update-list --dry-run` says which would change, without writing.

| file | what | source |
|------|------|--------|
| [`distrusted.tsv`](distrusted.tsv) | certificates not to trust: `sha256`, `kind`, `label`, `reason`, `ref` | curated incidents + Mozilla's CCADB reports |
| [`known-roots.tsv`](known-roots.tsv) | roots of the public root programs: `sha256`, `programs`, `label` | CCADB full records report: roots *Included* by Apple, Chrome, Microsoft or Mozilla (Microsoft *NotBefore* counts, noted `microsoft~`) |
| [`known-roots-extra.tsv`](known-roots-extra.tsv) | roots platforms ship outside the CCADB - Apple's own roots, Android, Java: `sha256`, `stores`, `label` | the [trust_stores_observatory](https://github.com/nabla-c0d3/trust_stores_observatory) (MIT License, © 2025 Alban Diquet), read at a pinned commit; only entries `known-roots.tsv` lacks |
| `known-roots.local.tsv` | **your** roots: `sha256`, then optionally a label and why (owner, ticket, date) | you - git-ignored, never shipped; see [`known-roots.local.example.tsv`](known-roots.local.example.tsv) |

`update-list` rebuilds the first two and says when the observatory has moved past the pinned
commit; `update-list --extras` then moves the pin and rebuilds the third.

### `distrusted.tsv`

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

## 🛡️ Design promises

- **Never a false “clean.”** Every failure path is explicit, and no unreadable,
  unparsable or missing store can yield exit 0. A missing or malformed list of known roots stops
  the audit (exit 2) rather than turn every certificate into an "unknown" - or hide one.
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

macOS: one user report - the audit runs to completion and reports findings. macOS and `openssl`
versions were not reported, and the test suite has not been run there.

PowerShell edition: PowerShell 7.4 on Linux only (its test suite passes there; the stores are read
through the same .NET `X509Store` API).

### 🙋 Testers wanted

These have **never been run on the real system** (macOS: a single report, see above); their store
paths come from documentation only. A report, even "works" or "crashes with this output", is valuable:

| System | What to run | What to report |
| --- | --- | --- |
| **Windows** (PowerShell 5.1 and 7) | `.\trust-audit.ps1` and `tests\test-trust-audit.ps1` | output, exit code, PowerShell version |
| **macOS** (current and old) | `./trust-audit` and `tests/test-trust-audit.sh` | output, exit code, `sw_vers`, `openssl version` (LibreSSL) |
| OpenBSD / NetBSD, Git Bash | `./trust-audit` | same |

Open an issue with the output (remove host names if you prefer), see [CONTRIBUTING.md](CONTRIBUTING.md).

## 🧑‍💻 Development

```sh
tests/test-trust-audit.sh                        # behavioural tests, throw-away certificates only
pwsh -NoProfile -File tests/test-trust-audit.ps1 # same for the PowerShell edition
shellcheck trust-audit update-list tests/*.sh    # strict, no rule disabled
./update-list --dry-run                          # are the lists current? (network; writes nothing)
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

The list of roots platforms ship outside the CCADB comes from Alban Diquet's
[trust_stores_observatory](https://github.com/nabla-c0d3/trust_stores_observatory) (MIT License,
© 2025 Alban Diquet): `known-roots-extra.tsv` holds the entries of its `trust_stores/*.yaml` files
that the CCADB lacks, with the commit they were read at.

## 📄 License and disclaimer

[MIT](LICENSE). The software is provided as is, without warranty of any kind. trust-audit is an
aid, not a guarantee: a clean result means “no listed certificate in the stores that were read”
(see *Not covered*), not that a machine is safe. The author is not liable for any damage resulting
from its use or from acting on its output.
