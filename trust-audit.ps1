<#
.SYNOPSIS
  trust-audit for Windows (PowerShell): list the CA certificates that should no longer be
  trusted but are still present in this machine's trust stores.

.DESCRIPTION
  Read-only and offline: it reads the Windows certificate stores and files, writes nothing and
  never touches the network. It uses the same fingerprint list as the POSIX edition
  (distrusted.tsv) and the same output and exit status. See README.md for what is, and is not,
  covered.

  Exit status: 0 clean · 1 distrusted certificate(s) found · 2 cannot run / bad usage
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
  Comma-separated kinds to report: compromised, removed, partial (default: all).

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
    [string]$Kinds = 'compromised,removed,partial',
    [string]$List,
    [switch]$Version
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ToolVersion = '0.1.0'
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
                $fps.Add((Get-Sha256Hex $cert.RawData))
                $parsed++
            } catch { }
        }
    }
    New-Source $fps.ToArray() $blocks $parsed $Texts.Count $nopem
}

# ---------------------------------------------------------------- arguments, list
$kindSet = @{}
foreach ($k in ($Kinds -split ',')) {
    if ($k -notin 'compromised', 'removed', 'partial') { Stop-Audit "-Kinds: unknown kind '$k'" }
    $kindSet[$k] = $true
}
if (-not $List) { $List = Join-Path $PSScriptRoot 'distrusted.tsv' }

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
Write-Host ("trust-audit.ps1 {0} - list of {1} fingerprints (generated {2})" -f $ToolVersion, $entries.Count, $(if ($gendate) { $gendate } else { 'unknown' }))
if ($null -eq $epoch) {
    $notes.Add('the fingerprint list carries no date: cannot tell how stale it is')
} else {
    $age = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - $epoch
    if ($age -gt $STALE_DAYS * 86400) {
        $notes.Add(("the fingerprint list is {0} days old: refresh it (update-list) and re-run" -f [math]::Floor($age / 86400)))
    }
}

# ---------------------------------------------------------------- reporting
$script:AnyFound = $false; $script:Incomplete = $false; $script:StoreCount = 0; $script:HitStores = 0
$script:Sigs = @{}; $script:Visited = @{}
$script:Blocked = @{}          # fingerprints present in Windows' Disallowed store

# Results are collected and printed together at the end (see "report output").
$script:Rows = New-Object System.Collections.Generic.List[object]       # one per store
$script:Findings = [ordered]@{}                                         # fingerprint -> stores holding it
function Add-Row([string]$Status, [string]$Name, $Count, [string]$Note) {
    $script:Rows.Add([pscustomobject]@{ Status = $Status; Name = $Name; Count = $Count; Note = $Note })
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
    $hits = @($Src.Fps | Where-Object { $entries.ContainsKey($_) -and $kindSet.ContainsKey($entries[$_].Kind) })
    $live = @($hits | Where-Object { -not $script:Blocked.ContainsKey($_) })
    foreach ($fp in $hits) {
        if (-not $script:Findings.Contains($fp)) { $script:Findings[$fp] = New-Object System.Collections.Generic.List[string] }
        $script:Findings[$fp].Add($Name)
    }
    if ($live.Count -gt 0) {
        $script:AnyFound = $true; $script:HitStores++
        Add-Row 'FOUND' $Name $Src.Blocks ("{0} listed" -f $live.Count + $(if ($note) { "; $note" }))
    } elseif ($hits.Count -gt 0) {
        Add-Row $(if ($warn) { 'WARN' } else { 'ok' }) $Name $Src.Blocks ("{0} listed, all blocked by the Windows Disallowed store" -f $hits.Count + $(if ($note) { "; $note" }))
    } else {
        Add-Row $(if ($warn) { 'WARN' } else { 'ok' }) $Name $Src.Blocks $note
    }
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
    $fps = @($out | ForEach-Object { if ($_ -match '^\s*SHA256:\s*([0-9A-Fa-f:]+)\s*$') { ($Matches[1] -replace ':', '').ToUpper() } })
    $aliases = @($out | Where-Object { $_ -match '^Alias name:' }).Count
    Show-Source "$File (Java keystore)" (New-Source $fps $aliases $fps.Count 1 0)
}

function Read-CertStore([string]$Name, [string]$Location) {
    $store = New-Object "$X509.X509Store" -ArgumentList $Name, $Location
    $flags = [Enum]::Parse([type]"$X509.OpenFlags", 'ReadOnly,OpenExistingOnly')
    $store.Open($flags)
    try {
        $fps = New-Object System.Collections.Generic.List[string]
        foreach ($c in $store.Certificates) { $fps.Add((Get-Sha256Hex $c.RawData)) }
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
    $onWindows = ($env:OS -eq 'Windows_NT')

    # What Windows itself blocks: certificates in the Disallowed store are not trusted, whatever the roots say.
    # (If that store cannot be read the only effect is that a blocked certificate is still reported.)
    foreach ($loc in 'LocalMachine', 'CurrentUser') {
        try { foreach ($fp in (Read-CertStore 'Disallowed' $loc)) { $script:Blocked[$fp] = $true } } catch { }
    }

    # Trust anchors: the Windows root stores (machine and user). "AuthRoot" is the cache of the
    # auto-updated third-party roots. Intermediates ("CA") are not trust anchors and are not read.
    $stores = @('Root')
    if ($onWindows) { $stores = @('Root', 'AuthRoot') }
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

# ---------------------------------------------------------------- verdict
if ($script:StoreCount -eq 0 -and -not $script:Incomplete) {
    [Console]::Error.WriteLine('trust-audit: no trust store found; name one with -Path or -Find')
    exit 2
}

# ---------------------------------------------------------------- report output
$useColor = $false
try {
    if (-not [Console]::IsOutputRedirected -and -not $env:NO_COLOR -and $Host.UI.SupportsVirtualTerminal) { $useColor = $true }
} catch { }
$E = [char]27
function Paint([string]$Text, [string]$Code) { if ($useColor) { "$E[${Code}m$Text$E[0m" } else { $Text } }

Write-Host ''
Write-Host (Paint 'STORES' '1')
$w = 0; foreach ($r in $script:Rows) { if ($r.Name.Length -gt $w) { $w = $r.Name.Length } }
$tag = @{ FOUND = @('[FOUND]', '31'); ok = @('[ ok  ]', '32'); same = @('[same ]', '2'); SKIP = @('[SKIP ]', '33'); WARN = @('[WARN ]', '33') }
foreach ($r in $script:Rows) {
    if ($Quiet -and $r.Status -in 'ok', 'same') { continue }
    $line = "  {0}  {1}  {2,5}" -f (Paint $tag[$r.Status][0] $tag[$r.Status][1]), $r.Name.PadRight($w), $r.Count
    if ($r.Note) { $line += "  $($r.Note)" }
    Write-Host $line
}

if ($script:Findings.Count -gt 0) {
    Write-Host ''
    $parts = @()
    foreach ($kind in 'compromised', 'removed', 'partial') {
        $c = @($script:Findings.Keys | Where-Object { $entries[$_].Kind -eq $kind }).Count
        if ($c -gt 0) { $parts += "$c $kind" }
    }
    Write-Host ((Paint 'FINDINGS' '1') + ' - ' + ($parts -join ', '))
    $col = @{ compromised = '31'; removed = '33'; partial = '2' }
    foreach ($kind in 'compromised', 'removed', 'partial') {
        foreach ($fp in $script:Findings.Keys) {
            $e = $entries[$fp]
            if ($e.Kind -ne $kind) { continue }
            $stores = @($script:Findings[$fp] | Select-Object -Unique)
            if ($Quiet) {
                Write-Host ("  {0}  {1}  (in: {2})" -f (Paint $kind.ToUpper().PadRight(11) $col[$kind]), $e.Label, ($stores -join ', '))
                continue
            }
            Write-Host ''
            Write-Host ("  {0}  {1}" -f (Paint $kind.ToUpper().PadRight(11) $col[$kind]), (Paint $e.Label '1'))
            Write-Host "      $($e.Reason)"
            Write-Host "      sha256 $fp"
            foreach ($rf in $e.Refs) { Write-Host "      ref    $rf" }
            for ($n = 0; $n -lt $stores.Count; $n++) { Write-Host ("      {0} {1}" -f $(if ($n -eq 0) { 'in    ' } else { '      ' }), $stores[$n]) }
            if ($script:Blocked.ContainsKey($fp)) { Write-Host '      (also in the Windows Disallowed store: blocked by Windows, not counted)' }
        }
    }
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
if ($script:AnyFound) {
    $extra = ''
    if ($script:Incomplete) { $extra = '; some stores could not be read, see [SKIP]/[WARN] lines' }
    Write-Host (Paint ("RESULT: distrusted certificates present in {0} of {1} store(s){2}" -f $script:HitStores, $script:StoreCount, $extra) '31')
    exit 1
}
if ($script:Incomplete) {
    Write-Host (Paint 'RESULT: INCOMPLETE - nothing found in what could be read, but see the [SKIP]/[WARN] lines: this is NOT a clean result' '33')
    exit 3
}
Write-Host (Paint ("RESULT: clean - {0} store(s) read, none holds a listed certificate" -f $script:StoreCount) '32')
exit 0
