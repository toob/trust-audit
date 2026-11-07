# Changelog

## 0.1.0 - unreleased (MIT licensed)

First version: read-only, offline audit of CA trust stores against a fingerprint list built from
Mozilla's removed / distrust-after roots and the eMudhra 2026 incident; host, container image
(`-r`), and tree-search (`-f`) modes; explicit exit status for unreadable stores. Each list entry
carries one or more reference links; `sources/curated.tsv` links fingerprints to DigiNotar,
TURKTRUST, ANSSI, CNNIC, WoSign/StartCom, Camerfirma, TrustCor and DarkMatter. PowerShell edition
(`trust-audit.ps1`) for Windows; identical files are fingerprinted once. NSS databases (Chrome's
shared `nssdb`, Firefox/Thunderbird profiles) are read through `certutil`. The report shows a store table, then each finding once with all
stores holding it; colour on a terminal, `-q` / `-Quiet` for a short form.
