#!/bin/bash
# Behavioural tests of trust-audit. Everything runs on throw-away certificates and lists.
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
TA="$(cd "$(dirname "$0")/.." && pwd)/trust-audit"
echo "== trust-audit =="

T=$(new_tmp)
trap 'chmod -R u+rwx "$T" 2>/dev/null; rm -rf "$T"' EXIT
mkcert() { # name
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/$1.key" -out "$T/$1.pem" -subj "/CN=$1" -days 2 2>/dev/null
}
fp() { openssl x509 -in "$T/$1.pem" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g'; }
run() { bash "$TA" "$@" >"$T/out" 2>&1; echo $?; } # prints the exit status, output in $T/out

mkcert bad; mkcert good; mkcert comp
NOW=$(date +%s)
{
  printf '# generated=2026-01-01 epoch=%s\n' "$NOW"
  printf '%s\tremoved\tTest Removed CA\tremoved from test\thttps://example.test/ https://example.test/second\n' "$(fp bad)"
  printf '%s\tcompromised\tTest Compromised CA\tkey leaked\t\n' "$(fp comp)"
} >"$T/list.tsv"
LIST="$T/list.tsv"
cat "$T/good.pem" "$T/bad.pem" >"$T/bundle.pem"

echo "-- findings"
rc=$(run -n -l "$LIST" "$T/bundle.pem")
assert_rc "listed cert -> rc=1" 1 "$rc"
assert_contains "kind and label" "$T/out" "REMOVED      Test Removed CA"
assert_contains "reason" "$T/out" "removed from test"
assert_contains "fingerprint" "$T/out" "sha256 $(fp bad)"
assert_contains "reference link" "$T/out" "ref    https://example.test/"
assert_contains "second reference on its own line" "$T/out" "ref    https://example.test/second"
assert_contains "cert count and hits in the store table" "$T/out" "    2  1 listed"
assert_contains "scope disclaimer always printed" "$T/out" "NOT EXAMINED"
assert_eq "no colour codes when not on a terminal" 0 "$(grep -c "$(printf '\033')" "$T/out")"
cp "$T/bad.pem" "$T/only-bad.pem"
rc=$(run -n -l "$LIST" "$T/bundle.pem" "$T/only-bad.pem")
assert_eq "same certificate in two stores: one finding" 1 "$(grep -c 'REMOVED      Test Removed CA' "$T/out")"
assert_contains "... listing both stores" "$T/out" "      $T/only-bad.pem"
assert_contains "findings summary" "$T/out" "FINDINGS - 1 removed"
rc=$(run -q -n -l "$LIST" "$T/bundle.pem" "$T/good.pem")
assert_contains "-q keeps the finding on one line" "$T/out" "Test Removed CA  (in: $T/bundle.pem)"
assert_eq "-q hides the clean stores" 0 "$(grep -c '\[ ok  \]' "$T/out")"

rc=$(run -n -l "$LIST" "$T/good.pem")
assert_rc "clean bundle -> rc=0" 0 "$rc"
assert_contains "clean verdict" "$T/out" "RESULT: clean"

rc=$(run -n -l "$LIST" -k compromised "$T/bundle.pem")
assert_rc "-k filters out other kinds -> rc=0" 0 "$rc"

cat "$T/comp.pem" >>"$T/bundle.pem"
rc=$(run -n -l "$LIST" -k compromised "$T/bundle.pem")
assert_rc "-k compromised finds it -> rc=1" 1 "$rc"
assert_eq "-k hides the removed one" 0 "$(grep -c 'Test Removed CA' "$T/out")"

echo "-- store shapes"
mkdir "$T/dir"; cp "$T/bad.pem" "$T/dir/x.crt"; cp "$T/good.pem" "$T/dir/0a1b2c3d.0"; echo "not a cert" >"$T/dir/README"
rc=$(run -n -l "$LIST" "$T/dir")
assert_rc "directory scanned -> rc=1" 1 "$rc"
assert_contains "non-PEM file reported as skipped" "$T/out" "1 of 3 files held no PEM certificate"

cp "$T/bundle.pem" "$T/bundle-copy.pem"
rc=$(run -n -l "$LIST" "$T/bundle.pem" "$T/bundle-copy.pem")
assert_contains "identical file audited once" "$T/out" "same content as"

sed 's/$/\r/' "$T/bad.pem" >"$T/crlf.pem"
rc=$(run -n -l "$LIST" "$T/crlf.pem")
assert_rc "CRLF bundle -> rc=1" 1 "$rc"

mkdir -p "$T/root/etc/ssl/certs" "$T/root/usr/local/share/certs"
cp "$T/bundle.pem" "$T/root/etc/ssl/certs/ca-certificates.crt"
rc=$(run -r "$T/root" -l "$LIST")
assert_rc "-r ROOT -> rc=1" 1 "$rc"
assert_contains "-r reports the path inside ROOT" "$T/out" "$T/root/etc/ssl/certs/ca-certificates.crt"

# symbolic links inside an image are read inside the image, never on the host
mkdir -p "$T/img/etc/ssl/certs" "$T/img/usr/share/cas" "$T/img2/etc"
cp "$T/bad.pem" "$T/img/usr/share/cas/bad.crt"
ln -s /usr/share/cas/bad.crt "$T/img/etc/ssl/certs/bad.pem"     # absolute link, target only exists in the image
rc=$(run -r "$T/img" -l "$LIST")
assert_rc "-r follows an absolute link inside the image -> rc=1" 1 "$rc"
assert_contains "-r finds the cert through the link" "$T/out" "REMOVED      Test Removed CA"
ln -s /usr/lib/ssl "$T/img2/etc/ssl"                           # absolute link: means /usr/lib/ssl of the IMAGE
rc=$(run -r "$T/img2" -l "$LIST")
assert_rc "-r never falls back to the host (absent in image) -> rc=2" 2 "$rc"
assert_eq "-r reports no host store" 0 "$(grep -c 'PRESENT\|certs)' "$T/out")"
mkdir -p "$T/img/opt/app"; cp "$T/bad.pem" "$T/img/opt/app/cacert.pem"
rc=$(run -r "$T/img" -n -l "$LIST" /opt/app/cacert.pem)
assert_rc "-r: arguments are paths inside the image -> rc=1" 1 "$rc"
ln -s ../../../../../../../../etc/hostname "$T/img/opt/app/escape.pem"   # '..' cannot climb above ROOT
rc=$(run -r "$T/img" -n -l "$LIST" /opt/app/escape.pem)
assert_contains "-r '..' stays inside the image" "$T/out" "does not exist"

mkdir -p "$T/tree/a/b" "$T/tree/proc"
cp "$T/bad.pem" "$T/tree/a/b/cacert.pem"; cp "$T/bad.pem" "$T/tree/proc/cacert.pem"
rc=$(run -n -l "$LIST" -f "$T/tree")
assert_rc "-f finds nested bundle -> rc=1" 1 "$rc"
assert_contains "-f path reported" "$T/out" "$T/tree/a/b/cacert.pem"

echo "-- never a false 'clean'"
rc=$(run -n -l "$LIST")
assert_rc "nothing to scan -> rc=2" 2 "$rc"

rc=$(run -n -l "$LIST" "$T/does-not-exist")
assert_rc "missing explicit store -> rc=3" 3 "$rc"
assert_contains "says NOT SCANNED" "$T/out" "NOT SCANNED"

if [ "$(id -u)" != 0 ]; then
  cp "$T/good.pem" "$T/secret.pem"; chmod 000 "$T/secret.pem"
  rc=$(run -n -l "$LIST" "$T/secret.pem")
  assert_rc "unreadable store -> rc=3" 3 "$rc"
  rc=$(run -n -l "$LIST" "$T/secret.pem" "$T/bundle.pem")
  assert_rc "findings win over incomplete -> rc=1" 1 "$rc"
  assert_contains "…but incompleteness still shown" "$T/out" "some stores could not be read"
fi

{ cat "$T/good.pem"; printf -- '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n'; } >"$T/corrupt.pem"
rc=$(run -n -l "$LIST" "$T/corrupt.pem")
assert_rc "unparsable certificate -> rc=3" 3 "$rc"
assert_contains "says which store is not fully audited" "$T/out" "could not be fingerprinted"

echo "not a certificate" >"$T/empty.pem"
rc=$(run -n -l "$LIST" "$T/empty.pem")
assert_rc "file without certificate -> rc=3" 3 "$rc"

echo "-- list and tool integrity"
printf '%s\tbogus\tx\ty\t\n' "$(fp bad)" >"$T/badlist.tsv"
rc=$(run -n -l "$T/badlist.tsv" "$T/bundle.pem")
assert_rc "malformed list -> rc=2" 2 "$rc"
assert_contains "names the line" "$T/out" "line 1 is malformed"

printf '%s\tremoved\tx\ty\tnot-a-url\n' "$(fp bad)" >"$T/badref.tsv"
rc=$(run -n -l "$T/badref.tsv" "$T/bundle.pem")
assert_rc "malformed ref -> rc=2" 2 "$rc"

rc=$(run -n -l "$T/nolist" "$T/bundle.pem")
assert_rc "missing list -> rc=2" 2 "$rc"

sed 's/epoch=[0-9]*/epoch=1/' "$LIST" >"$T/oldlist.tsv"
rc=$(run -n -l "$T/oldlist.tsv" "$T/good.pem")
assert_contains "stale list warned" "$T/out" "days old"

rc=$(run -k nonsense -n "$T/good.pem")
assert_rc "unknown kind -> rc=2" 2 "$rc"

# a broken openssl must be detected by the self-test, not trusted
mkdir "$T/fakebin"
printf '#!/bin/sh\necho "sha256 Fingerprint=%s"\n' "$(printf 'AA:%.0s' $(seq 31))AA" >"$T/fakebin/openssl"
chmod +x "$T/fakebin/openssl"
PATH="$T/fakebin:$PATH" bash "$TA" -n -l "$LIST" "$T/good.pem" >"$T/out" 2>&1; rc=$?
assert_rc "wrong openssl -> rc=2" 2 "$rc"
assert_contains "self-test message" "$T/out" "self-test failed"

# a missing dependency is reported up front
mkdir "$T/nobin"
for c in openssl sed tr sort cksum cat date dirname head; do ln -s "$(command -v $c)" "$T/nobin/$c"; done
PATH="$T/nobin" "$(command -v bash)" "$TA" -n -l "$LIST" "$T/good.pem" >"$T/out" 2>&1; rc=$?
assert_rc "missing awk -> rc=2" 2 "$rc"
assert_contains "names the command" "$T/out" "required command not found: awk"

echo "-- NSS databases (certutil is stubbed: it must only be asked to list and export)"
mkdir "$T/nssbin" "$T/nss"; : >"$T/nss/cert9.db"
make_certutil() { # EXTRA_ROW  (stub that serves two certificates)
  cat >"$T/nssbin/certutil" <<EOS
#!/bin/sh
nick=
while [ \$# -gt 0 ]; do case \$1 in -n) nick=\$2; shift ;; esac; shift; done
if [ -n "\$nick" ]; then
  case "\$nick" in "my bad") cat "$T/bad.pem" ;; "good one") cat "$T/good.pem" ;; *) exit 255 ;; esac
  exit 0
fi
printf '\nCertificate Nickname                      Trust Attributes\n                                          SSL,S/MIME,JAR/XPI\n\nmy bad          C,,  \ngood one       u,u,u\n%s' "$1"
EOS
  chmod +x "$T/nssbin/certutil"
}
make_certutil ""
PATH="$T/nssbin:$PATH" bash "$TA" -n -l "$LIST" "$T/nss/cert9.db" >"$T/out" 2>&1; rc=$?
assert_rc "NSS database with a listed cert -> rc=1" 1 "$rc"
assert_contains "NSS store named" "$T/out" "(NSS database)"
assert_contains "NSS store counted" "$T/out" "    2  1 listed"
assert_contains "NSS finding" "$T/out" "REMOVED      Test Removed CA"

PATH="$T/nssbin:$PATH" bash "$TA" -n -l "$LIST" "$T/nss" >"$T/out" 2>&1; rc=$?
assert_rc "an NSS profile directory given as argument -> rc=1" 1 "$rc"
PATH="$T/nssbin:$PATH" bash "$TA" -n -l "$LIST" -f "$T" >"$T/out" 2>&1; rc=$?
assert_rc "-f finds an NSS database by name -> rc=1" 1 "$rc"

make_certutil "ghost          C,,  \n"
PATH="$T/nssbin:$PATH" bash "$TA" -n -l "$LIST" "$T/good.pem" "$T/nss/cert9.db" >"$T/out" 2>&1; rc=$?
assert_rc "a certificate that cannot be exported -> rc=3" 3 "$rc"
assert_contains "says which store is not scanned" "$T/out" "some certificates could not be exported"

printf '#!/bin/sh\nexit 1\n' >"$T/nssbin/certutil"
PATH="$T/nssbin:$PATH" bash "$TA" -n -l "$LIST" "$T/good.pem" "$T/nss/cert9.db" >"$T/out" 2>&1; rc=$?
assert_rc "certutil failing -> rc=3" 3 "$rc"
assert_contains "certutil failure reported" "$T/out" "certutil could not open it"

printf '#!/bin/sh\nprintf "Certificate Nickname   Trust Attributes\\n   SSL,S/MIME,JAR/XPI\\n\\n"\n' >"$T/nssbin/certutil"
PATH="$T/nssbin:$PATH" bash "$TA" -n -l "$LIST" "$T/good.pem" "$T/nss/cert9.db" >"$T/out" 2>&1; rc=$?
assert_rc "empty NSS database is not an error -> rc=0" 0 "$rc"
assert_contains "empty NSS database said so" "$T/out" "empty"

mkdir "$T/nocert"
for c in openssl awk sed tr sort cksum cat date dirname head; do ln -s "$(command -v $c)" "$T/nocert/$c"; done
PATH="$T/nocert" "$(command -v bash)" "$TA" -n -l "$LIST" "$T/good.pem" "$T/nss/cert9.db" >"$T/out" 2>&1; rc=$?
assert_rc "NSS database but no certutil -> rc=3" 3 "$rc"
assert_contains "names certutil" "$T/out" "certutil (nss-tools) is not installed"

if [ "$(id -u)" != 0 ]; then
  mkdir -p "$T/locked/inner"; chmod 000 "$T/locked"
  rc=$(run -n -l "$LIST" "$T/locked/inner/ca.pem" "$T/good.pem")
  chmod 755 "$T/locked"
  assert_rc "a store behind a directory we cannot enter -> rc=3" 3 "$rc"
  assert_contains "says permission denied, not 'does not exist'" "$T/out" "permission denied (a parent directory cannot be entered)"
else
  echo "  skip - running as root (cannot make a path unreachable)"
fi

echo "-- read-only and offline"
mkdir "$T/ro"; cp "$T/bundle.pem" "$T/ro/b.pem"; mkdir "$T/tmpd"
chmod a-w "$T/ro/b.pem" "$T/ro"
before=$(cksum "$T/ro/b.pem"; ls -la --time-style=full-iso "$T/ro")
TMPDIR="$T/tmpd" bash "$TA" -n -l "$LIST" "$T/ro/b.pem" >/dev/null 2>&1
after=$(cksum "$T/ro/b.pem"; ls -la --time-style=full-iso "$T/ro")
chmod u+w "$T/ro"
assert_eq "store untouched" "$before" "$after"
assert_eq "no temporary file created" "" "$(ls -A "$T/tmpd")"

assert_eq "no network tool in the executable code" "" \
  "$(grep -v '^[[:space:]]*#' "$TA" | grep -E '(^|[^-[:alnum:]_/.])(curl|wget|nc|ncat|telnet|ssh|scp|ftp)([[:space:]]|$)|/dev/(tcp|udp)' || true)"

if unshare -rn true 2>/dev/null; then
  unshare -rn bash "$TA" -n -l "$LIST" "$T/bundle.pem" >"$T/out" 2>&1; rc=$?
  assert_rc "works with no network namespace" 1 "$rc"
else
  echo "  skip - unshare -n not available"
fi

finish
