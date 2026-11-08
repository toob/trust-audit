# Behavioural tests of trust-audit.ps1. Everything runs on throw-away certificates and lists.
# Usage: pwsh -NoProfile -File tests/test-trust-audit.ps1      (or powershell.exe on Windows)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Src = Split-Path -Parent $PSScriptRoot
$Exe = (Get-Process -Id $PID).Path
$T = Join-Path ([IO.Path]::GetTempPath()) ("trust-audit-test." + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $T | Out-Null
$script:Pass = 0; $script:Fail = 0
Write-Host '== trust-audit.ps1 =='

function Check([string]$Desc, [bool]$Cond) {
    if ($Cond) { $script:Pass++; Write-Host "  ok  - $Desc" } else { $script:Fail++; Write-Host "  NOK - $Desc" }
}

$X = 'System.Security.Cryptography'
# A self-signed certificate: a CA by default, or (-Leaf) a CA:FALSE one valid for its name only.
function New-TestCert([string]$Name, [switch]$Leaf) {
    $rsa = [Security.Cryptography.RSA]::Create(2048)
    $req = New-Object "$X.X509Certificates.CertificateRequest" -ArgumentList "CN=$Name", $rsa,
        ([Security.Cryptography.HashAlgorithmName]::SHA256), ([Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $req.CertificateExtensions.Add((New-Object "$X.X509Certificates.X509BasicConstraintsExtension" -ArgumentList (-not $Leaf), $false, 0, $true))
    if ($Leaf) {
        $san = New-Object "$X.X509Certificates.SubjectAlternativeNameBuilder"
        $san.AddDnsName($Name)
        $req.CertificateExtensions.Add($san.Build())
    }
    $cert = $req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(2))
    $b64 = [Convert]::ToBase64String($cert.RawData, 'InsertLineBreaks')
    $sha = [Security.Cryptography.SHA256]::Create()
    $fp = (($sha.ComputeHash($cert.RawData) | ForEach-Object { $_.ToString('X2') }) -join '')
    [pscustomobject]@{ Pem = "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----`n"; Fp = $fp }
}

$bad = New-TestCert 'bad'; $good = New-TestCert 'good'; $comp = New-TestCert 'comp'; $part = New-TestCert 'part'
$extra = New-TestCert 'extra'; $stranger = New-TestCert 'stranger'
$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$tab = "`t"

# The audit runs from an installed copy whose lists of known roots are synthetic: "good" and
# "part" are known roots, "extra" comes from the observatory list, everything else is unknown.
$inst = Join-Path $T 'inst'; New-Item -ItemType Directory -Path $inst | Out-Null
Copy-Item (Join-Path $Src 'trust-audit.ps1') $inst
$TA = Join-Path $inst 'trust-audit.ps1'
[IO.File]::WriteAllLines((Join-Path $inst 'known-roots.tsv'), @("# generated=2026-01-01 epoch=$now",
    ($good.Fp + $tab + 'apple,mozilla' + $tab + 'Test Good CA'), ($part.Fp + $tab + 'mozilla' + $tab + 'Test Partial CA')))
[IO.File]::WriteAllLines((Join-Path $inst 'known-roots-extra.tsv'), @("# synced=2026-01-01 epoch=$now", ($extra.Fp + $tab + 'apple' + $tab + 'Test Extra CA')))

# Runs the audit in a child process; sets $script:Out (text) and $script:Rc.
# (Windows PowerShell 5.1 turns a child's stderr into a terminating error under 'Stop', hence 'Continue',
# and wraps error records, hence ToString() to get the raw text.)
function Invoke-Audit([string[]]$Arguments) {
    $ErrorActionPreference = 'Continue'
    $script:Out = (& $Exe -NoProfile -File $TA @Arguments *>&1 | ForEach-Object { $_.ToString() } | Out-String)
    $script:Rc = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
}
function Write-Pem([string]$Name, [string[]]$Pems) { $f = Join-Path $T $Name; [IO.File]::WriteAllText($f, ($Pems -join '')); $f }

$listFile = Join-Path $T 'list.tsv'
[IO.File]::WriteAllLines($listFile, @(
    "# generated=2026-01-01 epoch=$now",
    ($bad.Fp + $tab + 'removed' + $tab + 'Test Removed CA' + $tab + 'removed from test' + $tab + 'https://example.test/ https://example.test/second'),
    ($comp.Fp + $tab + 'compromised' + $tab + 'Test Compromised CA' + $tab + 'key leaked' + $tab),
    ($part.Fp + $tab + 'partial' + $tab + 'Test Partial CA' + $tab + 'distrusted after a date' + $tab)))
$bundle = Write-Pem 'bundle.pem' @($good.Pem, $bad.Pem)
$goodFile = Write-Pem 'good.pem' @($good.Pem)

Write-Host '-- findings'
Invoke-Audit '-NoDefault', '-List', $listFile, '-Path', $bundle
Check 'listed cert -> rc=1' ($Rc -eq 1)
Check 'verdict: update needed, one store' ($Out.Contains('VERDICT: UPDATE NEEDED - 1 store to update'))
Check 'removed roots counted per store' ($Out.Contains('1 root removed by Mozilla'))
Check 'removed roots named' ($Out.Contains('roots  Test Removed CA'))
Check 'no fingerprint by default' (-not $Out.Contains("sha256 $($bad.Fp)"))
Check 'cert count' ($Out.Contains('    2  1 listed'))
Check 'result line matches the verdict' ($Out.Contains('RESULT: UPDATE NEEDED - 1 store to update'))
Check 'no colour codes when redirected' (-not $Out.Contains([string][char]27))
Invoke-Audit '-NoDefault', '-List', $listFile, '-Detail', '-Path', $bundle
Check '-Detail: reason' ($Out.Contains('removed from test'))
Check '-Detail: fingerprint' ($Out.Contains("sha256 $($bad.Fp)"))
Check '-Detail: first reference' ($Out.Contains('ref    https://example.test/'))
Check '-Detail: second reference on its own line' ($Out.Contains('ref    https://example.test/second'))
$onlyBad = Write-Pem 'only-bad.pem' @($bad.Pem)
$ErrorActionPreference = 'Continue'; $script:Out = (& $Exe -NoProfile -Command "& '$TA' -NoDefault -List '$listFile' -Path '$bundle','$onlyBad'; exit `$LASTEXITCODE" *>&1 | ForEach-Object { $_.ToString() } | Out-String); $ErrorActionPreference = 'Stop'
Check 'two stores with the same removed roots: one item' ($Out.Contains('TO UPDATE - 1 store holds'))
Check '... naming the other store' ($Out.Contains("also   $onlyBad"))
Invoke-Audit '-NoDefault', '-List', $listFile, '-Quiet', '-Path', $bundle
Check '-Quiet: one line per item' ($Out.Contains("UPDATE       $bundle  (1 root removed by Mozilla)"))

Invoke-Audit '-NoDefault', '-List', $listFile, '-Path', $goodFile
Check 'clean bundle -> rc=0' ($Rc -eq 0)
Check 'clean verdict' ($Out.Contains('RESULT: NOTHING TO DO - 1 store read, none holds a listed or unknown certificate'))

Invoke-Audit '-NoDefault', '-List', $listFile, '-Path', (Write-Pem 'part.pem' @($part.Pem))
Check 'only a distrust-after root -> nothing to do, rc=0' ($Rc -eq 0)
Check '... but said, for information' ($Out.Contains('1 root Mozilla distrusts only for certificates issued after a date'))

Invoke-Audit '-NoDefault', '-List', $listFile, '-Kinds', 'compromised,unknown', '-Path', $bundle
Check '-Kinds filters out other kinds -> rc=0' ($Rc -eq 0)

Write-Host '-- unknown certificates'
$implant = Write-Pem 'implant.pem' @($good.Pem, $stranger.Pem)
Invoke-Audit '-NoDefault', '-List', $listFile, '-Path', $implant
Check 'a root in no public program -> rc=1' ($Rc -eq 1)
Check 'act now' ($Out.Contains('VERDICT: ACT NOW - 1 unknown certificate'))
Check 'named by its subject' ($Out.Contains('CN=stranger'))
Check 'with its fingerprint' ($Out.Contains("sha256 $($stranger.Fp)"))
Check 'counted in the store table' ($Out.Contains('1 unknown'))
Invoke-Audit '-NoDefault', '-List', $listFile, '-Path', (Write-Pem 'extra.pem' @($extra.Pem))
Check 'a root from known-roots-extra.tsv is known -> rc=0' ($Rc -eq 0)
Invoke-Audit '-NoDefault', '-List', $listFile, '-Kinds', 'compromised,removed,partial', '-Path', $implant
Check '-Kinds without unknown -> not reported, rc=0' ($Rc -eq 0)
Invoke-Audit '-NoDefault', '-List', $listFile, '-Kinds', 'compromised', '-Path', (Write-Pem 'bad.pem' @($bad.Pem))
Check "a listed root left out by -Kinds is not 'unknown' -> rc=0" ($Rc -eq 0)

$localFile = Join-Path $inst 'known-roots.local.tsv'
[IO.File]::WriteAllLines($localFile, @('# my roots', ($stranger.Fp.ToLowerInvariant() + $tab + 'Stranger' + $tab + 'ours')))
Invoke-Audit '-NoDefault', '-List', $listFile, '-Path', $implant
Check 'your own root in known-roots.local.tsv (lower case) -> rc=0' ($Rc -eq 0)
Check 'local entries loaded and counted' ($Out.Contains('1 of your own roots accepted from'))
[IO.File]::WriteAllLines($localFile, @("not-a-fingerprint${tab}x"))
Invoke-Audit '-NoDefault', '-List', $listFile, '-Path', $implant
Check 'malformed local file -> rc=2' ($Rc -eq 2)
Check 'names the line' ($Out.Contains('known-roots.local.tsv: line 1 is malformed'))
Remove-Item $localFile

Move-Item (Join-Path $inst 'known-roots.tsv') (Join-Path $inst 'kr.tsv')
Invoke-Audit '-NoDefault', '-List', $listFile, '-Path', $goodFile
Check 'no list of known roots -> rc=2, never everything unknown' ($Rc -eq 2)
Invoke-Audit '-NoDefault', '-List', $listFile, '-Kinds', 'compromised,removed,partial', '-Path', $goodFile
Check '... unless unknown is left out' ($Rc -eq 0)
Move-Item (Join-Path $inst 'kr.tsv') (Join-Path $inst 'known-roots.tsv')

$web = New-TestCert 'www.bank.test' -Leaf
Invoke-Audit '-NoDefault', '-List', $listFile, '-Path', (Write-Pem 'web.pem' @($web.Pem))
Check 'an unknown non-CA certificate for another name -> rc=1' ($Rc -eq 1)
Check 'non-CA: its DNS names are shown' ($Out.Contains('not a CA: trusted only for www.bank.test'))
$snake = New-TestCert ([Environment]::MachineName) -Leaf
Invoke-Audit '-NoDefault', '-List', $listFile, '-Path', (Write-Pem 'snake.pem' @($snake.Pem))
Check "this machine's own self-signed certificate -> nothing to do, rc=0" ($Rc -eq 0)
Check '... said, for information' ($Out.Contains('1 self-signed certificate of this machine itself'))

Write-Host '-- store shapes'
$dir = Join-Path $T 'dir'; New-Item -ItemType Directory -Path $dir | Out-Null
[IO.File]::WriteAllText((Join-Path $dir 'x.crt'), $bad.Pem)
[IO.File]::WriteAllText((Join-Path $dir '0a1b2c3d.0'), $good.Pem)
[IO.File]::WriteAllText((Join-Path $dir 'README'), 'not a cert')
Invoke-Audit '-NoDefault', '-List', $listFile, '-Path', $dir
Check 'directory scanned -> rc=1' ($Rc -eq 1)
Check 'non-PEM file reported as skipped' ($Out.Contains('1 of 3 files held no PEM certificate'))

# several paths need a real array, so this one goes through -Command (with -File, 'a,b' stays one string)
Copy-Item $bundle (Join-Path $T 'bundle-copy.pem')
$cmd = "& '$TA' -NoDefault -List '$listFile' -Path '$bundle','$(Join-Path $T 'bundle-copy.pem')'; exit `$LASTEXITCODE"
$ErrorActionPreference = 'Continue'; $script:Out = (& $Exe -NoProfile -Command $cmd *>&1 | ForEach-Object { $_.ToString() } | Out-String); $script:Rc = $LASTEXITCODE; $ErrorActionPreference = 'Stop'
Check 'two paths accepted, rc=1' ($Rc -eq 1)
Check 'same set audited once' ($Out.Contains('identical set to'))

[IO.File]::WriteAllText((Join-Path $T 'crlf.pem'), ($bad.Pem -replace "`n", "`r`n"))
Invoke-Audit '-NoDefault', '-List', $listFile, '-Path', (Join-Path $T 'crlf.pem')
Check 'CRLF bundle -> rc=1' ($Rc -eq 1)

$tree = Join-Path $T 'tree\a\b'; New-Item -ItemType Directory -Path $tree -Force | Out-Null
[IO.File]::WriteAllText((Join-Path $tree 'cacert.pem'), $bad.Pem)
Invoke-Audit '-NoDefault', '-List', $listFile, '-Find', (Join-Path $T 'tree')
Check '-Find finds nested bundle -> rc=1' ($Rc -eq 1)

Write-Host '-- never a false clean'
Invoke-Audit '-NoDefault', '-List', $listFile
Check 'nothing to scan -> rc=2' ($Rc -eq 2)

Invoke-Audit '-NoDefault', '-List', $listFile, '-Path', (Join-Path $T 'does-not-exist')
Check 'missing explicit store -> rc=3' ($Rc -eq 3)
Check 'says NOT SCANNED' ($Out.Contains('NOT SCANNED'))

[IO.File]::WriteAllText((Join-Path $T 'corrupt.pem'), $good.Pem + "-----BEGIN CERTIFICATE-----`nAAAA`n-----END CERTIFICATE-----`n")
Invoke-Audit '-NoDefault', '-List', $listFile, '-Path', (Join-Path $T 'corrupt.pem')
Check 'unparsable certificate -> rc=3' ($Rc -eq 3)
Check 'says which store is not fully audited' ($Out.Contains('could not be fingerprinted'))

[IO.File]::WriteAllText((Join-Path $T 'empty.pem'), 'not a certificate')
Invoke-Audit '-NoDefault', '-List', $listFile, '-Path', (Join-Path $T 'empty.pem')
Check 'file without certificate -> rc=3' ($Rc -eq 3)

Write-Host '-- list integrity'
[IO.File]::WriteAllLines((Join-Path $T 'badkind.tsv'), @(($bad.Fp + $tab + 'bogus' + $tab + 'x' + $tab + 'y' + $tab)))
Invoke-Audit '-NoDefault', '-List', (Join-Path $T 'badkind.tsv'), '-Path', $bundle
Check 'malformed list -> rc=2' ($Rc -eq 2)
Check 'names the line' ($Out.Contains('badkind.tsv: line 1 is malformed'))

[IO.File]::WriteAllLines((Join-Path $T 'badref.tsv'), @(($bad.Fp + $tab + 'removed' + $tab + 'x' + $tab + 'y' + $tab + 'not-a-url')))
Invoke-Audit '-NoDefault', '-List', (Join-Path $T 'badref.tsv'), '-Path', $bundle
Check 'malformed ref -> rc=2' ($Rc -eq 2)

Invoke-Audit '-NoDefault', '-List', (Join-Path $T 'nolist'), '-Path', $bundle
Check 'missing list -> rc=2' ($Rc -eq 2)

Invoke-Audit '-NoDefault', '-Kinds', 'nonsense', '-Path', $goodFile
Check 'unknown kind -> rc=2' ($Rc -eq 2)

(Get-Content $listFile) -replace 'epoch=\d+', 'epoch=1' | Set-Content (Join-Path $T 'oldlist.tsv')
Invoke-Audit '-NoDefault', '-List', (Join-Path $T 'oldlist.tsv'), '-Path', $goodFile
Check 'stale list warned' ($Out.Contains('days old'))

Write-Host '-- read-only'
$before = (Get-FileHash $bundle).Hash
Invoke-Audit '-NoDefault', '-List', $listFile, '-Path', $bundle
Check 'store untouched' ($before -eq (Get-FileHash $bundle).Hash)

Remove-Item -Recurse -Force $T
Write-Host "PASS=$script:Pass FAIL=$script:Fail"
exit $(if ($script:Fail -eq 0) { 0 } else { 1 })
