# Security policy

## Reporting

Report a vulnerability, or a wrong result that could give false assurance (a distrusted
certificate that is present but not reported, or a store reported clean that was not fully read),
privately through GitHub's *Report a vulnerability* button on this repository (private advisory).
Do not open a public issue for those. You can expect an acknowledgement within a few days.

Include the command, the exit status, the output, and - for a missed certificate - its SHA-256
fingerprint and the file it sits in.

## What counts

In scope: the audit reading, writing or contacting something it must not; a path that exits `0`
without having read every store it found; a way for crafted store contents (certificates, file
names, symbolic links in an image) to make the script run code, escape `-r ROOT`, or hide a
finding.

Out of scope: certificates missing from `distrusted.tsv` (open a normal issue with the source), and
anything listed under “What is not covered” in the README.

## Supported versions

The latest release only.
