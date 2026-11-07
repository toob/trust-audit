# Behavioural tests of trust-audit.ps1. Everything runs on throw-away certificates and lists.
# Usage: pwsh -NoProfile -File tests/test-trust-audit.ps1      (or powershell.exe on Windows)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$TA = Join-Path (Split-Path -Parent $PSScriptRoot) 'trust-audit.ps1'
$Exe = (Get-Process -Id $PID).Path
$T = Join-Path ([IO.Path]::GetTempPath()) ("trust-audit-test." + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $T | Out-Null
$script:Pass = 0; $script:Fail = 0
Write-Host '== trust-audit.ps1 =='

function Check([string]$Desc, [bool]$Cond) {
    if ($Cond) { $script:Pass++; Write-Host "  ok  - $Desc" } else { $script:Fail++; Write-Host "  NOK - $Desc" }
}

$X = 'System.Security.Cryptography'
function New-TestCert([string]$Name) {
    $rsa = [Security.Cryptography.RSA]::Create(2048)
    $req = New-Object "$X.X509Certificates.CertificateRequest" -ArgumentList "CN=$Name", $rsa,
        ([Security.Cryptography.HashAlgorithmName]::SHA256), ([Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $cert = $req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(2))
    $b64 = [Convert]::ToBase64String($cert.RawData, 'InsertLineBreaks')
    $sha = [Security.Cryptography.SHA256]::Create()
    $fp = (($sha.ComputeHash($cert.RawData) | ForEach-Object { $_.ToString('X2') }) -join '')
    [pscustomobject]@{ Pem = "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----`n"; Fp = $fp }
}

# Runs the audit in a child process; sets $script:Out (text) and $script:Rc.
# (Windows PowerShell 5.1 turns a child's stderr into a terminating error under 'Stop', hence 'Continue'.)
function Invoke-Audit([string[]]$Arguments) {
    $ErrorActionPreference = 'Continue'
    $script:Out = (& $Exe -NoProfile -File $TA @Arguments *>&1 | Out-String)
    $script:Rc = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
}

$bad = New-TestCert 'bad'; $good = New-TestCert 'good'; $comp = New-TestCert 'comp'
$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$tab = "`t"
$listFile = Join-Path $T 'list.tsv'
[IO.File]::WriteAllLines($listFile, @(
    "# generated=2026-01-01 epoch=$now",
    ($bad.Fp + $tab + 'removed' + $tab + 'Test Removed CA' + $tab + 'removed from test' + $tab + 'https://example.test/ https://example.test/second'),
    ($comp.Fp + $tab + 'compromised' + $tab + 'Test Compromised CA' + $tab + 'key leaked' + $tab)))
$bundle = Join-Path $T 'bundle.pem'
[IO.File]::WriteAllText($bundle, $good.Pem + $bad.Pem)
$goodFile = Join-Path $T 'good.pem'; [IO.File]::WriteAllText($goodFile, $good.Pem)

Write-Host '-- findings'
Invoke-Audit '-NoDefault', '-List', $listFile, '-Path', $bundle
Check 'listed cert -> rc=1' ($Rc -eq 1)
Check 'kind and label' ($Out.Contains('REMOVED      Test Removed CA'))
Check 'reason' ($Out.Contains('removed from test'))
Check 'fingerprint' ($Out.Contains("sha256 $($bad.Fp)"))
Check 'first reference' ($Out.Contains('ref    https://example.test/'))
Check 'second reference on its own line' ($Out.Contains('ref    https://example.test/second'))
Check 'cert count' ($Out.Contains('    2  1 listed'))
Check 'scope disclaimer always printed' ($Out.Contains('NOT EXAMINED'))
Check 'no colour codes when redirected' (-not $Out.Contains([string][char]27))
$onlyBad = Join-Path $T 'only-bad.pem'; [IO.File]::WriteAllText($onlyBad, $bad.Pem)
Invoke-Audit '-NoDefault', '-List', $listFile, '-Path', $bundle
$ErrorActionPreference = 'Continue'; $script:Out = (& $Exe -NoProfile -Command "& '$TA' -NoDefault -List '$listFile' -Path '$bundle','$onlyBad'; exit `$LASTEXITCODE" *>&1 | Out-String); $ErrorActionPreference = 'Stop'
Check 'same certificate in two stores: one finding' (([regex]::Matches($Out, 'REMOVED      Test Removed CA')).Count -eq 1)
Check '... listing both stores' ($Out.Contains("      $onlyBad"))
Check 'findings summary' ($Out.Contains('FINDINGS - 1 removed'))
Invoke-Audit '-NoDefault', '-List', $listFile, '-Quiet', '-Path', $bundle
Check '-Quiet keeps the finding on one line' ($Out.Contains("Test Removed CA  (in: $bundle)"))

Invoke-Audit '-NoDefault', '-List', $listFile, '-Path', $goodFile
Check 'clean bundle -> rc=0' ($Rc -eq 0)
Check 'clean verdict' ($Out.Contains('RESULT: clean'))

Invoke-Audit '-NoDefault', '-List', $listFile, '-Kinds', 'compromised', '-Path', $bundle
Check '-Kinds filters out other kinds -> rc=0' ($Rc -eq 0)

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
$ErrorActionPreference = 'Continue'; $script:Out = (& $Exe -NoProfile -Command $cmd *>&1 | Out-String); $script:Rc = $LASTEXITCODE; $ErrorActionPreference = 'Stop'
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
Check 'names the line' ($Out.Contains('line 1 is malformed'))

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
