<#
.SYNOPSIS
  trust-audit for Windows (PowerShell): tell whether this machine's trust stores hold a
  certificate authority that should not be there - one tied to a stolen key, one the root
  programs have removed, or one that belongs to no public root program at all.

.DESCRIPTION
  Read-only and offline: it reads the Windows certificate stores and files, writes nothing and
  never touches the network. It uses the same lists as the POSIX edition (distrusted.tsv,
  known-roots.tsv, known-roots-extra.tsv and your own known-roots.local.tsv) and the same report
  and exit status. See README.md for what is, and is not, covered.

  Exit status: 0 nothing to do · 1 something to fix or check · 2 cannot run / bad usage
               3 nothing found but some store could not be read (NOT a clean result)

  The report is written with Write-Host: capture it with  *> file  (or  *>&1 ).
  Works in Windows PowerShell 5.1 and PowerShell 7+.

.PARAMETER Path
  Extra PEM bundle files, or directories of PEM files, to audit.

.PARAMETER Find
  Also search these trees for bundle files by well-known name (ca-bundle.crt, cacert.pem, ...).

.PARAMETER NoDefault
  Audit only what is named (-Path, -Find), not the default locations.

.PARAMETER Kinds
  Comma-separated kinds to report: compromised, removed, partial, unknown (default: all).

.PARAMETER Quiet
  Only stores with a problem and one line per item.

.PARAMETER Detail
  Every certificate with its fingerprint, reason and references.

.PARAMETER List
  Fingerprint list to use (default: distrusted.tsv next to this script).

.EXAMPLE
  .\trust-audit.ps1
  .\trust-audit.ps1 -Path C:\tools\ca-bundle.crt -NoDefault
  .\trust-audit.ps1 -Kinds compromised
#>
[CmdletBinding()]
param(
    [string[]]$Path = @(),
    [string[]]$Find = @(),
    [switch]$NoDefault,
    [switch]$Quiet,
    [switch]$Detail,
    [string]$Kinds = 'compromised,removed,partial,unknown',
    [string]$List,
    [switch]$Version
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ToolVersion = '0.2.0'
$STALE_DAYS = 90
if ($Version) { Write-Output "trust-audit.ps1 $ToolVersion"; exit 0 }

# Public self-test certificate (ISRG Root X2) and its SHA-256, published by Mozilla's CCADB.
$SELFTEST_FP = '69729B8E15A86EFC177A57AFB7171DFC64ADD28C2FCA8CF1507E34453CCB1470'
$SELFTEST_PEM = @'
-----BEGIN CERTIFICATE-----
MIICGzCCAaGgAwIBAgIQQdKd0XLq7qeAwSxs6S+HUjAKBggqhkjOPQQDAzBPMQsw
CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw00
MDA5MTcxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5ldCBT
ZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYw
EAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0HttwW
+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7AlF9
ItgKbppbd9/w+kHsOdx1ymgHDB/qo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwCgYIKoZI
zj0EAwMDaAAwZQIwe3lORlCEwkSHRhtFcP9Ymd70/aTSVaYgLXTWNLxBo1BfASdW
tL4ndQavEi51mI38AjEAi/V3bNTIZargCyzuFJ0nN6T5U6VR5CmD1/iQMVtCnwr1
/q4AaOeMSQ+2b1tbFfLn
-----END CERTIFICATE-----
'@

function Stop-Audit([string]$Message) {
    [Console]::Error.WriteLine("trust-audit: $Message")
    exit 2
}

$X509 = 'System.Security.Cryptography.X509Certificates'
$script:Sha = [System.Security.Cryptography.SHA256]::Create()

function Get-Sha256Hex([byte[]]$Bytes) {
    $h = $script:Sha.ComputeHash($Bytes)
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $h) { [void]$sb.Append($b.ToString('X2')) }
    $sb.ToString()
}

# What the report says about a certificate: subject, whether it may act as a CA (a certificate
# that says CA:FALSE can only vouch for itself) and the DNS names it is valid for.
$script:Desc = @{}
function Add-Description([string]$Fp, $Cert) {
    if ($script:Desc.ContainsKey($Fp)) { return }
    $ca = $true; $names = @()
    foreach ($ext in $Cert.Extensions) {
        if ($ext -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
            $ca = $ext.CertificateAuthority
        } elseif ($ext.Oid.Value -eq '2.5.29.17') {
            foreach ($m in [regex]::Matches($ext.Format($false), '(?:DNS Name=|DNS:)([^,\s]+)')) { $names += $m.Groups[1].Value }
        }
    }
    if ($names.Count -eq 0) {
        $cn = $Cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        if ($cn) { $names = @($cn) }
    }
    $script:Desc[$Fp] = [pscustomobject]@{ Subject = $Cert.Subject; Ca = $ca; Names = $names }
}

# A "source" is what one store yields: Fps (sorted, distinct SHA-256), Blocks (distinct
# certificates seen), Parsed (of those, how many could be fingerprinted), Files, NoPem.
# Parsed < Blocks means some certificate could not be read: the caller must say so.
function New-Source([string[]]$Fps, [int]$Blocks, [int]$Parsed, [int]$Files, [int]$NoPem) {
    $distinct = @($Fps | Sort-Object -Unique)
    [pscustomobject]@{ Fps = $distinct; Blocks = $Blocks; Parsed = $Parsed; Files = $Files; NoPem = $NoPem }
}

$PemRegex = New-Object System.Text.RegularExpressions.Regex(
    '-----BEGIN [A-Z0-9 ]*CERTIFICATE-----(?<b>[A-Za-z0-9+/=\s]*?)-----END [A-Z0-9 ]*CERTIFICATE-----',
    [System.Text.RegularExpressions.RegexOptions]::Singleline)

function Read-PemText([string[]]$Texts) {
    $seen = @{}
    $fps = New-Object System.Collections.Generic.List[string]
    $blocks = 0; $parsed = 0; $nopem = 0
    foreach ($text in $Texts) {
        $m = $PemRegex.Matches($text)
        if ($m.Count -eq 0) { $nopem++; continue }
        foreach ($x in $m) {
            $b64 = ($x.Groups['b'].Value -replace '\s', '')
            if ($seen.ContainsKey($b64)) { continue }
            $seen[$b64] = $true
            $blocks++
            try {
                $der = [Convert]::FromBase64String($b64)
                $cert = New-Object "$X509.X509Certificate2" -ArgumentList (, $der)
                $fp = Get-Sha256Hex $cert.RawData
                $fps.Add($fp)
                Add-Description $fp $cert
                $parsed++
            } catch { }
        }
    }
    New-Source $fps.ToArray() $blocks $parsed $Texts.Count $nopem
}

# ---------------------------------------------------------------- arguments, lists
$kindSet = @{}
foreach ($k in ($Kinds -split ',')) {
    if ($k -notin 'compromised', 'removed', 'partial', 'unknown') { Stop-Audit "-Kinds: unknown kind '$k'" }
    $kindSet[$k] = $true
}
if (-not $List) { $List = Join-Path $PSScriptRoot 'distrusted.tsv' }
$KnownFile = Join-Path $PSScriptRoot 'known-roots.tsv'
$ExtraFile = Join-Path $PSScriptRoot 'known-roots-extra.tsv'
$LocalFile = Join-Path $PSScriptRoot 'known-roots.local.tsv'

# self-test: this runtime must fingerprint a known certificate correctly
$st = Read-PemText @($SELFTEST_PEM)
if ($st.Blocks -ne 1 -or $st.Parsed -ne 1 -or $st.Fps.Count -ne 1 -or $st.Fps[0] -ne $SELFTEST_FP) {
    Stop-Audit "self-test failed: this runtime does not fingerprint a known certificate correctly"
}

if (-not (Test-Path -LiteralPath $List -PathType Leaf)) { Stop-Audit "cannot read the fingerprint list: $List" }
$listLines = [IO.File]::ReadAllLines($List, [Text.Encoding]::UTF8)
$entries = @{}
$epoch = $null; $gendate = $null
$lineNo = 0
foreach ($line in $listLines) {
    $lineNo++
    if ($line -match '^# generated=(\S+) epoch=(\d+)') { $gendate = $Matches[1]; $epoch = [int64]$Matches[2]; continue }
    if ($line.StartsWith('#') -or $line.Trim() -eq '') { continue }
    $f = $line.Split([char]9)
    $ok = ($f.Count -eq 5) -and ($f[0] -cmatch '^[0-9A-F]{64}$') -and ($f[1] -cin 'compromised', 'removed', 'partial')
    if ($ok -and $f[4] -ne '') {
        foreach ($r in ($f[4] -split ' ')) { if ($r -notmatch '^https?://\S+$') { $ok = $false } }
    }
    if (-not $ok) { Stop-Audit "${List}: line $lineNo is malformed" }
    $entries[$f[0]] = [pscustomobject]@{ Kind = $f[1]; Label = $f[2]; Reason = $f[3]; Refs = @($f[4] -split ' ' | Where-Object { $_ }) }
}
if ($entries.Count -eq 0) { Stop-Audit "$List holds no fingerprint" }

$notes = New-Object System.Collections.Generic.List[string]

# Roots of the public root programs. Needed (and checked) only when unknown roots are reported:
# a missing or damaged list must not turn every certificate into an "unknown" - nor hide one.
$known = @{}
$knownEpoch = $null
function Read-Known([string]$File, [int]$MinFields) {
    $n = 0; $no = 0
    foreach ($line in [IO.File]::ReadAllLines($File, [Text.Encoding]::UTF8)) {
        $no++
        if ($line.StartsWith('#') -or $line.Trim() -eq '') { continue }
        $f = $line.Split([char]9)
        $fp = $f[0].ToUpperInvariant()
        if ($f.Count -lt $MinFields -or $fp -notmatch '^[0-9A-F]{64}$') {
            Stop-Audit "${File}: line $no is malformed (expected a SHA-256 in hex, then TAB-separated fields)"
        }
        $script:known[$fp] = $true; $n++
    }
    $n
}
if ($kindSet.ContainsKey('unknown')) {
    if (-not (Test-Path -LiteralPath $KnownFile -PathType Leaf)) { Stop-Audit "cannot read the list of known roots: $KnownFile (or leave out unknown with -Kinds)" }
    if ((Read-Known $KnownFile 3) -eq 0) { Stop-Audit "$KnownFile holds no root" }
    foreach ($line in [IO.File]::ReadAllLines($KnownFile)) { if ($line -match '^# generated=\S+ epoch=(\d+)') { $knownEpoch = [int64]$Matches[1]; break } }
    if (Test-Path -LiteralPath $ExtraFile -PathType Leaf) { [void](Read-Known $ExtraFile 3) }
    else { $notes.Add("known-roots-extra.tsv is missing: roots some platforms ship outside the CCADB (Apple's own, Android, Java) will show as unknown") }
    if (Test-Path -LiteralPath $LocalFile -PathType Leaf) {
        $nlocal = Read-Known $LocalFile 1
        $notes.Add("$nlocal of your own roots accepted from $LocalFile")
    }
}

$header = "trust-audit.ps1 {0} - lists of {1}: {2} distrusted fingerprints" -f $ToolVersion, $(if ($gendate) { $gendate } else { 'unknown' }), $entries.Count
if ($kindSet.ContainsKey('unknown')) { $header += ", $($known.Count) known roots" }
Write-Host $header
$nowEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
if ($null -eq $epoch) {
    $notes.Add('the fingerprint list carries no date: cannot tell how stale it is')
} elseif ($nowEpoch - $epoch -gt $STALE_DAYS * 86400) {
    $notes.Add(("the fingerprint list is {0} days old: refresh it (update-list) and re-run" -f [math]::Floor(($nowEpoch - $epoch) / 86400)))
}
if ($null -ne $knownEpoch -and $nowEpoch - $knownEpoch -gt $STALE_DAYS * 86400) {
    $notes.Add(("the list of known roots is {0} days old: a root added since then shows as unknown; refresh it (update-list)" -f [math]::Floor(($nowEpoch - $knownEpoch) / 86400)))
}

# ---------------------------------------------------------------- checking
$script:Incomplete = $false; $script:StoreCount = 0
$script:Sigs = @{}; $script:Visited = @{}
$script:Blocked = @{}          # fingerprints present in Windows' Disallowed store
$onWindows = ($env:OS -eq 'Windows_NT')

# Results are collected and printed together at the end (see "report output").
#   Rows      one per store; Role says what kind of store it is: sys (the operating system's own
#             store), microsoft (the Windows root stores, Microsoft's own root program), other.
#   Findings  fingerprint -> kind and the stores holding it
$script:Rows = New-Object System.Collections.Generic.List[object]
$script:Findings = [ordered]@{}
$script:Role = 'other'
function Add-Row([string]$Status, [string]$Name, $Count, [string]$Note) {
    $script:Rows.Add([pscustomobject]@{ Status = $Status; Name = $Name; Count = $Count; Note = $Note; Role = $script:Role })
}

function Show-NotScanned([string]$Name, [string]$Reason) {
    Add-Row 'SKIP' $Name '' "NOT SCANNED - $Reason"
    $script:Incomplete = $true
}

function Show-Source([string]$Name, $Src, [string]$Extra = '') {
    $note = $Extra
    if ($Src.Blocks -eq 0) { Add-Row 'SKIP' $Name 0 ("no certificate found" + $(if ($note) { "; $note" })); $script:Incomplete = $true; return }
    $warn = $false
    if ($Src.Parsed -ne $Src.Blocks) {
        $note = ("{0} of {1} certificate(s) could not be fingerprinted - this store is NOT fully audited" -f ($Src.Blocks - $Src.Parsed), $Src.Blocks) + $(if ($note) { "; $note" })
        $warn = $true; $script:Incomplete = $true
    }
    if ($Src.NoPem -gt 0 -and $Src.Files -gt 1) {
        $note = $(if ($note) { "$note; " }) + ("{0} of {1} files held no PEM certificate and were skipped" -f $Src.NoPem, $Src.Files)
    }
    $sig = Get-Sha256Hex ([Text.Encoding]::UTF8.GetBytes(($Src.Fps -join "`n")))
    if ($script:Sigs.ContainsKey($sig)) {
        Add-Row $(if ($warn) { 'WARN' } else { 'same' }) $Name $Src.Blocks ("identical set to {0}, already audited above" -f $script:Sigs[$sig] + $(if ($note) { "; $note" }))
        return
    }
    $script:Sigs[$sig] = $Name
    $script:StoreCount++
    # A listed fingerprint takes its kind (even when -Kinds leaves that kind out, it is then not
    # "unknown"); a certificate Windows blocks (Disallowed store) is shown but not counted.
    $any = $false
    foreach ($fp in $Src.Fps) {
        $kind = $null
        if ($entries.ContainsKey($fp)) { if ($kindSet.ContainsKey($entries[$fp].Kind)) { $kind = $entries[$fp].Kind } }
        elseif ($kindSet.ContainsKey('unknown') -and -not $known.ContainsKey($fp)) { $kind = 'unknown' }
        if (-not $kind) { continue }
        if (-not $script:Findings.Contains($fp)) { $script:Findings[$fp] = [pscustomobject]@{ Kind = $kind; Stores = (New-Object System.Collections.Generic.List[string]) } }
        if (-not $script:Findings[$fp].Stores.Contains($Name)) { $script:Findings[$fp].Stores.Add($Name) }
        $any = $true
    }
    Add-Row $(if ($any) { 'FOUND' } elseif ($warn) { 'WARN' } else { 'ok' }) $Name $Src.Blocks $note
}

# ---------------------------------------------------------------- sources
function Test-Seen([string]$Key) {
    if ($script:Visited.ContainsKey($Key)) { return $true }
    $script:Visited[$Key] = $true
    $false
}

function Invoke-File([string]$File, [bool]$Explicit) {
    if (Test-Path -LiteralPath $File -PathType Container) { Invoke-Dir $File $Explicit; return }
    if (Test-Seen $File) { return }
    if (-not (Test-Path -LiteralPath $File -PathType Leaf)) {
        if ($Explicit) { Show-NotScanned $File 'does not exist' }
        return
    }
    if ((Split-Path -Leaf $File) -in 'cacerts', 'jssecacerts') { Invoke-Jks $File; return }
    try { $text = [IO.File]::ReadAllText($File) } catch { Show-NotScanned $File "not readable ($($_.Exception.Message))"; return }
    Show-Source $File (Read-PemText @($text))
}

function Invoke-Dir([string]$Dir, [bool]$Explicit) {
    if (Test-Seen $Dir) { return }
    if (-not (Test-Path -LiteralPath $Dir -PathType Container)) {
        if ($Explicit) { Show-NotScanned $Dir 'not a directory' }
        return
    }
    try { $files = @(Get-ChildItem -LiteralPath $Dir -File) } catch { Show-NotScanned $Dir 'directory not readable'; return }
    $texts = New-Object System.Collections.Generic.List[string]
    $unreadable = 0
    foreach ($f in $files) {
        try { $texts.Add([IO.File]::ReadAllText($f.FullName)) } catch { $unreadable++ }
    }
    if ($unreadable -gt 0) { Show-NotScanned $Dir "$unreadable file(s) could not be read" }
    if ($texts.Count -eq 0) { Add-Row 'ok' $Dir 0 'empty'; return }
    $src = Read-PemText $texts.ToArray()
    if ($src.Blocks -eq 0) { Add-Row 'ok' $Dir 0 "no certificate in $($texts.Count) files"; return }
    Show-Source $Dir $src
}

# Java keystore through keytool (default password changeit).
function Invoke-Jks([string]$File) {
    if (Test-Seen "jks:$File") { return }
    $kt = Get-Command keytool -ErrorAction SilentlyContinue
    if (-not $kt) { Show-NotScanned $File 'Java keystore and keytool is not installed (see README)'; return }
    $out = & $kt.Source '-J-Duser.language=en' '-J-Duser.country=US' -list -v -keystore $File -storepass changeit 2>$null
    if ($LASTEXITCODE -ne 0) { Show-NotScanned $File 'keytool could not open it (custom password?)'; return }
    $fps = New-Object System.Collections.Generic.List[string]
    $aliases = 0; $fp = $null; $owner = ''; $ca = $true; $names = @(); $sect = ''
    $flush = {
        if ($fp -and -not $script:Desc.ContainsKey($fp)) {
            $n = $names; if ($n.Count -eq 0 -and $owner -match 'CN=([^,]+)') { $n = @($Matches[1]) }
            $script:Desc[$fp] = [pscustomobject]@{ Subject = $owner; Ca = $ca; Names = $n }
        }
    }
    foreach ($l in $out) {
        if ($l -match '^Alias name:') { . $flush; $aliases++; $fp = $null; $owner = ''; $ca = $true; $names = @(); $sect = ''; continue }
        if ($l -match '^Owner:\s*(.*)$') { $owner = $Matches[1]; continue }
        if ($l -match '^\s*SHA256:\s*([0-9A-Fa-f:]+)\s*$') { $fp = ($Matches[1] -replace ':', '').ToUpper(); $fps.Add($fp); continue }
        if ($l -match 'BasicConstraints:\[') { $sect = 'bc'; continue }
        if ($l -match 'SubjectAlternativeName \[') { $sect = 'san'; continue }
        if ($sect -eq 'bc' -and $l -match 'CA:false') { $ca = $false }
        if ($sect -eq 'san' -and $l -match 'DNSName:\s*(\S+)') { $names += $Matches[1] }
        if ($l -match '^\]') { $sect = '' }
    }
    . $flush
    Show-Source "$File (Java keystore)" (New-Source $fps.ToArray() $aliases $fps.Count 1 0)
}

function Read-CertStore([string]$Name, [string]$Location) {
    $store = New-Object "$X509.X509Store" -ArgumentList $Name, $Location
    $flags = [Enum]::Parse([type]"$X509.OpenFlags", 'ReadOnly,OpenExistingOnly')
    $store.Open($flags)
    try {
        $fps = New-Object System.Collections.Generic.List[string]
        foreach ($c in $store.Certificates) { $fp = Get-Sha256Hex $c.RawData; $fps.Add($fp); Add-Description $fp $c }
        $fps.ToArray()
    } finally { $store.Close() }
}

function Find-Bundles([string]$Dir) {
    $names = 'ca-certificates.crt', 'ca-bundle.crt', 'cacert.pem', 'cert.pem', 'tls-ca-bundle.pem', 'curl-ca-bundle.crt', 'ca-root-nss.crt', 'cacerts', 'jssecacerts'
    $errs = $null
    $hits = @(Get-ChildItem -LiteralPath $Dir -Recurse -File -ErrorAction SilentlyContinue -ErrorVariable errs |
        Where-Object { $_.Name -in $names -or $_.Name -like 'cacert*.pem' -or $_.Name -like 'ca-bundle*' })
    if ($errs -and $errs.Count -gt 0) { Show-NotScanned $Dir 'parts of this tree could not be searched (permissions?)' }
    $hits
}

# ---------------------------------------------------------------- default stores
if (-not $NoDefault) {
    # What Windows itself blocks: certificates in the Disallowed store are not trusted, whatever the roots say.
    # (If that store cannot be read the only effect is that a blocked certificate is still reported.)
    foreach ($loc in 'LocalMachine', 'CurrentUser') {
        try { foreach ($fp in (Read-CertStore 'Disallowed' $loc)) { $script:Blocked[$fp] = $true } } catch { }
    }

    # Trust anchors: the Windows root stores (machine and user). "AuthRoot" is the cache of the
    # auto-updated third-party roots. Intermediates ("CA") are not trust anchors and are not read.
    # They follow Microsoft's root program; elsewhere .NET maps them to the system's own store.
    $stores = @('Root')
    if ($onWindows) { $stores = @('Root', 'AuthRoot'); $script:Role = 'microsoft' } else { $script:Role = 'sys' }
    foreach ($loc in 'LocalMachine', 'CurrentUser') {
        foreach ($name in $stores) {
            $label = "Windows store $loc\$name"
            try {
                $fps = @(Read-CertStore $name $loc)
                if ($fps.Count -eq 0) { Add-Row 'ok' $label 0 'empty' } else { Show-Source $label (New-Source $fps $fps.Count $fps.Count 1 0) }
            } catch {
                # An absent user-level store is normal; anything else is reported.
                if ($loc -eq 'CurrentUser' -and -not $onWindows) { continue }
                Show-NotScanned $label $_.Exception.Message
            }
        }
    }
    $script:Role = 'other'

    # What the environment points at, and the bundle shipped with Git for Windows.
    foreach ($v in 'SSL_CERT_FILE', 'CURL_CA_BUNDLE', 'REQUESTS_CA_BUNDLE', 'PIP_CERT', 'NODE_EXTRA_CA_CERTS', 'GIT_SSL_CAINFO', 'AWS_CA_BUNDLE', 'CARGO_HTTP_CAINFO', 'DENO_CERT') {
        $val = [Environment]::GetEnvironmentVariable($v)
        if ($val) { Invoke-File $val $true }
    }
    foreach ($v in 'SSL_CERT_DIR', 'GIT_SSL_CAPATH') {
        $val = [Environment]::GetEnvironmentVariable($v)
        if ($val) { foreach ($d in ($val -split [IO.Path]::PathSeparator)) { if ($d) { Invoke-Dir $d $true } } }
    }
    if ($onWindows) {
        foreach ($pf in $env:ProgramFiles, ${env:ProgramFiles(x86)}) {
            if ($pf) {
                Invoke-File (Join-Path $pf 'Git\mingw64\etc\ssl\certs\ca-bundle.crt') $false
                Invoke-File (Join-Path $pf 'Git\mingw64\ssl\certs\ca-bundle.crt') $false
            }
        }
    }

    # Java: JAVA_HOME
    $jh = [Environment]::GetEnvironmentVariable('JAVA_HOME')
    if ($jh) {
        foreach ($k in (Join-Path $jh 'lib\security\cacerts'), (Join-Path $jh 'jre\lib\security\cacerts')) {
            if (Test-Path -LiteralPath $k -PathType Leaf) { Invoke-Jks $k }
        }
    }
}

foreach ($p in $Path) { Invoke-File $p $true }
foreach ($d in $Find) {
    if (-not (Test-Path -LiteralPath $d -PathType Container)) { Show-NotScanned $d 'not a directory'; continue }
    $bundles = @(Find-Bundles $d)
    if ($bundles.Count -eq 0) { Add-Row 'ok' $d '' 'no bundle file found by name'; continue }
    foreach ($b in $bundles) { Invoke-File $b.FullName $false }
}

if ($script:StoreCount -eq 0 -and -not $script:Incomplete) {
    [Console]::Error.WriteLine('trust-audit: no trust store found; name one with -Path or -Find')
    exit 2
}

# ---------------------------------------------------------------- sort the findings by what to do
# This machine's own names: a self-signed non-CA certificate naming only them can vouch for
# nothing but this host.
$hosts = @{ 'localhost' = $true }
foreach ($h in @([Environment]::MachineName, $env:COMPUTERNAME, $env:HOSTNAME)) {
    if ($h) { $hosts[$h.ToLowerInvariant()] = $true; $hosts[($h.ToLowerInvariant() -split '\.')[0]] = $true }
}
function Test-OwnHost([string]$Fp) {
    if (-not $script:Desc.ContainsKey($Fp)) { return $false }
    $d = $script:Desc[$Fp]
    if ($d.Ca -or $d.Names.Count -eq 0) { return $false }
    foreach ($n in $d.Names) { if (-not $hosts.ContainsKey($n.ToLowerInvariant())) { return $false } }
    $true
}
function Get-Name([string]$Fp) {
    if ($entries.ContainsKey($Fp)) { return $entries[$Fp].Label }
    if ($script:Desc.ContainsKey($Fp) -and $script:Desc[$Fp].Subject) { return $script:Desc[$Fp].Subject }
    '(subject not read)'
}
function Get-Scope([string]$Fp) {
    if (-not $script:Desc.ContainsKey($Fp) -or $script:Desc[$Fp].Ca) { return '' }
    'not a CA: trusted only for ' + $(if ($script:Desc[$Fp].Names.Count) { $script:Desc[$Fp].Names -join ' ' } else { '(no name)' })
}

$roleOf = @{}; foreach ($r in $script:Rows) { $roleOf[$r.Name] = $r.Role }
$hasSys = @($script:Rows | Where-Object { $_.Role -eq 'sys' -and $_.Status -ne 'SKIP' }).Count -gt 0
$inSys = @{}
foreach ($fp in $script:Findings.Keys) { foreach ($s in $script:Findings[$fp].Stores) { if ($roleOf[$s] -eq 'sys') { $inSys[$fp] = $true } } }

$unknownL = @(); $compL = @(); $partL = @(); $ownL = @(); $msL = @(); $blockedL = @()
$upd = [ordered]@{}; $behind = @{}
foreach ($fp in $script:Findings.Keys) {
    $f = $script:Findings[$fp]
    if ($script:Blocked.ContainsKey($fp)) { $blockedL += $fp; continue }
    switch ($f.Kind) {
        'unknown' { if (Test-OwnHost $fp) { $ownL += $fp } else { $unknownL += $fp } }
        'compromised' { $compL += $fp }
        'partial' { $partL += $fp }
        'removed' {
            foreach ($s in $f.Stores) {
                if ($roleOf[$s] -eq 'microsoft') { if ($msL -notcontains $fp) { $msL += $fp }; continue }
                if (-not $upd.Contains($s)) { $upd[$s] = New-Object System.Collections.Generic.List[string] }
                $upd[$s].Add($fp)
                if ($hasSys -and $roleOf[$s] -ne 'sys' -and -not $inSys.ContainsKey($fp)) { $behind[$s] = 1 + $(if ($behind.ContainsKey($s)) { $behind[$s] } else { 0 }) }
            }
        }
    }
}
# stores of the same kind holding the same roots are one item
$items = [ordered]@{}; $also = @{}
foreach ($s in $upd.Keys) {
    $key = ($upd[$s] -join ' ') + '|' + $roleOf[$s]
    if ($items.Contains($key)) { $also[$items[$key]] += @($s) } else { $items[$key] = $s; $also[$s] = @() }
}
$nInfo = $partL.Count + $ownL.Count + $msL.Count + $blockedL.Count

# ---------------------------------------------------------------- report output
$useColor = $false
try {
    if (-not [Console]::IsOutputRedirected -and -not $env:NO_COLOR -and $Host.UI.SupportsVirtualTerminal) { $useColor = $true }
} catch { }
$E = [char]27
function Paint([string]$Text, [string]$Code) { if ($useColor) { "$E[${Code}m$Text$E[0m" } else { $Text } }
function Plural([int]$N, [string]$One, [string]$Many) { "$N " + $(if ($N -eq 1) { $One } else { $Many }) }
function Write-Wrapped([string]$First, [string]$Text, [string]$Pad) {
    $line = $First
    foreach ($w in ($Text -split ' ')) {
        if ($line.Length + $w.Length + 1 -gt 96 -and $line -ne $First -and $line -ne $Pad) { Write-Host $line; $line = $Pad }
        $line += $(if ($line -eq $First -or $line -eq $Pad) { '' } else { ' ' }) + $w
    }
    Write-Host $line
}
function Get-Names([string[]]$Fps) {
    $n = @($Fps | ForEach-Object { Get-Name $_ })
    if (-not $Detail -and $n.Count -gt 3) { return ($n[0..2] -join ', ') + ", ... (+$($n.Count - 3), -Detail lists them)" }
    $n -join ', '
}
function Write-In([string]$Fp) {
    $s = $script:Findings[$Fp].Stores
    for ($i = 0; $i -lt $s.Count; $i++) { Write-Host ("      {0} {1}" -f $(if ($i -eq 0) { 'in    ' } else { '      ' }), $s[$i]) }
}

$parts = @()
if ($unknownL.Count) { $parts += Plural $unknownL.Count 'unknown certificate' 'unknown certificates' }
if ($compL.Count) { $parts += "$($compL.Count) compromised" }
if ($items.Count) { $parts += (Plural $items.Count 'store' 'stores') + ' to update' }
$rd = $(if ($script:Incomplete) { '; some stores could not be read, see [SKIP]/[WARN]' } else { '' })
if ($unknownL.Count -or $compL.Count) { $col = '31'; $verdict = 'ACT NOW - ' + ($parts -join ', ') + $rd; $rc = 1 }
elseif ($items.Count) { $col = '33'; $verdict = 'UPDATE NEEDED - ' + ($parts -join ', ') + $rd; $rc = 1 }
elseif ($script:Incomplete) { $col = '33'; $verdict = 'INCOMPLETE - nothing found in what could be read, but see the [SKIP]/[WARN] lines: this is NOT a clean result'; $rc = 3 }
else {
    $col = '32'; $rc = 0
    $verdict = 'NOTHING TO DO - ' + (Plural $script:StoreCount 'store' 'stores') + ' read' + $(if ($nInfo) { ", $nInfo finding(s) for information only" } else { ', none holds a listed or unknown certificate' })
}
Write-Host ''
Write-Host (Paint "VERDICT: $verdict" "1;$col")

if ($unknownL.Count) {
    Write-Host ''
    Write-Host ((Paint 'UNKNOWN' '1;31') + ' - ' + (Plural $unknownL.Count 'certificate' 'certificates') + ' that no public root program trusts')
    if (-not $Quiet) {
        Write-Host '  No public root program (Apple, Chrome, Microsoft, Mozilla, nor the Android and Java'
        Write-Host '  stores) includes these: they were added to this machine. Roots recorded in'
        Write-Host "  $LocalFile are not reported."
    }
    foreach ($fp in $unknownL) {
        $sc = Get-Scope $fp
        if ($Quiet) { Write-Host ("  {0}      {1}{2}  sha256 {3}  (in: {4})" -f (Paint 'UNKNOWN' '31'), (Get-Name $fp), $(if ($sc) { " [$sc]" } else { '' }), $fp, ($script:Findings[$fp].Stores -join ', ')); continue }
        Write-Host ''
        Write-Host ('  ' + (Paint (Get-Name $fp) '1'))
        if ($sc) { Write-Host "      $sc" }
        Write-Host "      sha256 $fp"
        Write-In $fp
    }
}

if ($compL.Count) {
    Write-Host ''
    Write-Host ((Paint 'COMPROMISED' '1;31') + ' - ' + (Plural $compL.Count 'certificate' 'certificates') + ' tied to a stolen key')
    foreach ($fp in $compL) {
        if ($Quiet) { Write-Host ("  {0}  {1}  (in: {2})" -f (Paint 'COMPROMISED' '31'), (Get-Name $fp), ($script:Findings[$fp].Stores -join ', ')); continue }
        Write-Host ''
        Write-Host ('  ' + (Paint (Get-Name $fp) '1'))
        Write-Wrapped '      ' $entries[$fp].Reason '      '
        if ($Detail) { Write-Host "      sha256 $fp"; foreach ($rf in $entries[$fp].Refs) { Write-Host "      ref    $rf" } }
        Write-In $fp
    }
}

if ($items.Count) {
    Write-Host ''
    Write-Host ((Paint 'TO UPDATE' '1;33') + ' - ' + (Plural $items.Count 'store holds' 'stores hold') + ' roots Mozilla removed')
    foreach ($s in $items.Values) {
        $what = (Plural $upd[$s].Count 'root' 'roots') + ' removed by Mozilla'
        if ($behind.ContainsKey($s)) { $what += ", $($behind[$s]) of them no longer in your system store" }
        if ($roleOf[$s] -eq 'sys') { $what += ' (this is the system store)' }
        $all = @(@($s) + $also[$s])
        if ($Quiet) { Write-Host ("  {0}       {1}  ({2})" -f (Paint 'UPDATE' '33'), ($all -join ', '), $what); continue }
        Write-Host ''
        Write-Host ('  ' + (Paint $s '1'))
        if ($also[$s].Count) { Write-Host ('      also   ' + ($also[$s] -join ', ')) }
        Write-Host "      $what"
        if (-not $Detail) { Write-Wrapped '      roots  ' (Get-Names $upd[$s]) '             '; continue }
        foreach ($fp in $upd[$s]) {
            Write-Host "      - $(Get-Name $fp)"
            Write-Wrapped '        ' $entries[$fp].Reason '        '
            Write-Host "        sha256 $fp"
            foreach ($rf in $entries[$fp].Refs) { Write-Host "        ref    $rf" }
        }
    }
}

if ($nInfo) {
    Write-Host ''
    Write-Host ((Paint 'FOR INFORMATION' '1;2') + (Paint ' - nothing to do' '2'))
    $info = @(
        @($partL, 'root Mozilla distrusts only for certificates issued after a date', 'roots Mozilla distrusts only for certificates issued after a date', ' (a flat bundle cannot express the date)'),
        @($ownL, 'self-signed certificate of this machine itself', 'self-signed certificates of this machine itself', ', valid only for its own name'),
        @($msL, 'root Mozilla removed that Microsoft still ships', 'roots Mozilla removed that Microsoft still ships', " in its own root program (the Windows root stores, updated by Windows)"),
        @($blockedL, 'certificate also in the Windows Disallowed store', 'certificates also in the Windows Disallowed store', ': blocked by Windows, not counted'))
    foreach ($i in $info) {
        $l = @($i[0])
        if ($l.Count -eq 0) { continue }
        $t = Plural $l.Count $i[1] $i[2]
        if ($Quiet) { Write-Host "  INFO         $t"; continue }
        Write-Wrapped '  ' ("$t$($i[3]): " + (Get-Names $l)) '    '
    }
}

Write-Host ''
Write-Host (Paint 'STORES' '1')
$lc = @{}; $uc = @{}
foreach ($fp in $script:Findings.Keys) {
    foreach ($s in $script:Findings[$fp].Stores) {
        if ($script:Findings[$fp].Kind -ne 'unknown') { $lc[$s] = 1 + $(if ($lc.ContainsKey($s)) { $lc[$s] } else { 0 }) }
        elseif (-not (Test-OwnHost $fp)) { $uc[$s] = 1 + $(if ($uc.ContainsKey($s)) { $uc[$s] } else { 0 }) }
    }
}
$w = 0; foreach ($r in $script:Rows) { if ($r.Name.Length -gt $w) { $w = $r.Name.Length } }
$tag = @{ FOUND = @('[FOUND]', '31'); ok = @('[ ok  ]', '32'); same = @('[same ]', '2'); SKIP = @('[SKIP ]', '33'); WARN = @('[WARN ]', '33') }
foreach ($r in $script:Rows) {
    $c = @()
    if ($lc.ContainsKey($r.Name)) { $c += "$($lc[$r.Name]) listed" }
    if ($uc.ContainsKey($r.Name)) { $c += "$($uc[$r.Name]) unknown" }
    $t = $r.Status; if ($t -eq 'FOUND' -and $c.Count -eq 0) { $t = 'ok' }
    $note = $c -join ', '
    if ($r.Note) { $note = $(if ($note) { "$note; " } else { '' }) + $r.Note }
    if ($Quiet -and $t -in 'ok', 'same') { continue }
    $line = "  {0}  {1}  {2,5}" -f (Paint $tag[$t][0] $tag[$t][1]), $r.Name.PadRight($w), $r.Count
    if ($note) { $line += "  $note" }
    Write-Host $line
}

Write-Host ''
foreach ($n in $notes) { Write-Host "note: $n" }
if ($Quiet) {
    Write-Host "Not examined: compiled-in stores, browsers' built-in roots, Linux/macOS stores, override settings (see README)."
} else {
    Write-Host ((Paint 'NOT EXAMINED' '1') + "  stores compiled into applications (browsers' own stores, Firefox/NSS,")
    Write-Host '              Node.js, Go/Rust programs), Linux/macOS stores, and settings that override a'
    Write-Host '              store other than the Windows Disallowed store read above. The README lists'
    Write-Host '              what is covered.'
}
if ($rc -eq 1) { Write-Host 'What to do about each item: README.md, section "What to do".' }
Write-Host (Paint "RESULT: $verdict" "1;$col")
exit $rc
