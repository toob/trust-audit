# Changelog

## 0.2.0 - 2026-11-08 (MIT licensed)

Breaking: the report and the exit status are organised around what to do.

- **Unknown certificates**, on by default: a certificate in no public root program (CCADB roots
  included by Apple, Chrome, Microsoft or Mozilla, plus the roots platforms ship outside the CCADB,
  from the trust_stores_observatory) is reported as `unknown` - added by an administrator or by an
  implant. Record your own in `known-roots.local.tsv` (git-ignored; see
  `known-roots.local.example.tsv`). A `CA:FALSE` certificate is shown with the names it can vouch
  for; this machine's own self-signed certificate (ssl-cert's snakeoil) is information only. NSS
  entries without CA trust are not trust anchors. `-k compromised,removed,partial` leaves unknown
  certificates out.
- **Report**: `VERDICT` first and last (`ACT NOW`, `UPDATE NEEDED`, `INCOMPLETE`, `NOTHING TO DO`),
  then `UNKNOWN`, `COMPROMISED`, `TO UPDATE` (one item per store; a store behind the system store
  is said so) and `FOR INFORMATION` (distrust-after roots, roots Apple or Microsoft still ship in
  their own program). The output states facts only; what to do about each item - including how to
  rebuild a Debian/Ubuntu Java keystore, which `update-ca-certificates -f` alone does not - is in
  the README's new "What to do" section. `-v` (`-Detail` in PowerShell) shows every certificate with fingerprint, reason and
  references; `-q` keeps one line per item.
- **Exit status**: 1 means something to fix or check; `partial` findings alone no longer set it.
- **Lists**: `known-roots.tsv` (CCADB) and `known-roots-extra.tsv` (observatory, MIT License,
  © 2025 Alban Diquet, read at a pinned commit). `update-list --dry-run` writes nothing and says
  which list would change; `update-list --extras` moves the pin; a plain `update-list` says when the
  observatory has changed since. A missing or malformed list of known roots stops the audit.
- **Data**: the four eMudhra roots no longer read as if their own keys were stolen: they issued or
  cross-signed the intermediates whose keys were, and the reason says what that means (and, for
  Sectigo's AAA Certificate Services, that removing it may break sites).

## 0.1.0 - 2026-11-07 (MIT licensed)

First version: read-only, offline audit of CA trust stores against a fingerprint list built from
Mozilla's removed / distrust-after roots and the eMudhra 2026 incident; host, container image
(`-r`), and tree-search (`-f`) modes; explicit exit status for unreadable stores. Each list entry
carries one or more reference links; `sources/curated.tsv` links fingerprints to DigiNotar,
TURKTRUST, ANSSI, CNNIC, WoSign/StartCom, Camerfirma, TrustCor and DarkMatter. PowerShell edition
(`trust-audit.ps1`) for Windows; identical files are fingerprinted once. NSS databases (Chrome's
shared `nssdb`, Firefox/Thunderbird profiles) are read through `certutil`. The report shows a store table, then each finding once with all stores
holding it; colour on a terminal, `-q` / `-Quiet` for a short form.
