param([Parameter(Mandatory = $true)][string]$OutPath)

# Builds a Burp-style dump that carries the three shapes the noise rules exist
# for: a routing cookie that is replaced as the capture goes on, a telemetry
# body that is one container of flat flags, and a heartbeat that says the same
# thing thirty times.
#
# Deterministic. Every value comes from a seeded xorshift, so the fixture is
# reproducible from this script alone and a diff against the committed file is a
# real signal rather than a question about entropy.
#
#   powershell -ExecutionPolicy Bypass -File tests\fixtures\generate_background_noise.ps1
#
# The script is in the tree rather than in a scratch directory because a fixture
# nobody can regenerate is a fixture nobody can argue with when it breaks.

$ErrorActionPreference = 'Stop'

$host1 = 'shop.test'
$ip = '10.11.12.13'

function New-Random([int]$length, [int]$seed) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    $state = $seed
    $out = ''
    for ($i = 0; $i -lt $length; $i++) {
        # xorshift, so the value looks random to the entropy test and is
        # identical on every machine that runs this.
        $state = ($state * 1103515245 + 12345) -band 0x7fffffff
        $out += $alphabet[$state % $alphabet.Length]
    }
    return $out
}

function ConvertTo-Base64([string]$text) {
    return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($text))
}

function New-Message {
    param(
        [string]$Method,
        [string]$Path,
        [string]$Query,
        [string[]]$Headers,
        [string]$Body,
        [int]$Status
    )
    $request = "$Method $Path"
    if ($Query) { $request += "?$Query" }
    $request += " HTTP/1.1`r`nHost: $host1`r`n"
    foreach ($header in $Headers) { $request += "$header`r`n" }
    if ($Body) { $request += "Content-Type: application/json`r`n" }
    $request += "Content-Length: $([Text.Encoding]::UTF8.GetByteCount($Body))`r`n`r`n$Body"

    $statusText = switch ($Status) { 200 { 'OK' } 201 { 'Created' } 404 { 'Not Found' } default { 'OK' } }
    $response = "HTTP/1.1 $Status $statusText`r`nContent-Type: application/json`r`n"
    if ($Status -eq 201) { $response += "Set-Cookie: routing=$(New-Random 96 9001); Path=/; HttpOnly`r`n" }
    $response += "Content-Length: 0`r`n`r`n"
    return @{ Request = $request; Response = $response }
}

$items = New-Object System.Collections.Generic.List[string]
$time = 'Sat Aug 08 12:00:00 MSK 2026'

function Add-Item {
    param([string]$Method, [string]$Path, [string]$Query, [string[]]$Headers, [string]$Body, [int]$Status, [int]$ResponseLength)
    $message = New-Message -Method $Method -Path $Path -Query $Query -Headers $Headers -Body $Body -Status $Status
    # Burp carries the query inside the path element, and the parser splits it back
    # out of there. Leaving it out would make every request look byte-identical.
    $captured = if ($Query) { "$Path`?$Query" } else { $Path }
    $escaped = $captured -replace '&', '&amp;'
    $script:items.Add(
        "<item><time>$time</time><url>https://$host1$escaped</url><host ip=`"$ip`">$host1</host>" +
        "<port>443</port><protocol>https</protocol><method>$Method</method><path>$escaped</path>" +
        "<extension>null</extension><status>$Status</status><responselength>$ResponseLength</responselength>" +
        "<mimetype>JSON</mimetype><request base64=`"true`">$(ConvertTo-Base64 $message.Request)</request>" +
        "<response base64=`"true`">$(ConvertTo-Base64 $message.Response)</response></item>"
    )
}

# 1. A login that hands out a routing cookie. Everything after this is what the
#    slot looks like once it starts being replaced.
Add-Item -Method 'POST' -Path '/api/auth/session' -Query '' -Headers @('Accept: application/json') `
    -Body '{"email":"reader@shop.test","password":"correct horse battery"}' -Status 201 -ResponseLength 0

# 2. Thirty reads, each carrying a routing cookie, where the cookie is replaced
#    every two calls. That is the shape the rule is about: one name, filled
#    fifteen times over, always present.
#
#    Two calls per value, not one, because a value seen exactly once is not
#    evidence of anything. Thirty distinct values would be a capture with no
#    repeated secret in it at all, and nothing downstream could be said about
#    any of them.
#
#    The query is not decoration either, and neither half of it is. Duplicate
#    detection keys on method, path, query and body — headers are not part of
#    the key, so thirty requests differing only in their cookie would arrive as
#    one. And a group called over eight times whose *parameter names* vary in no
#    more than a fifth of its requests is sampled down to three, which would
#    leave a capture holding three exchanges and no evidence of a slot being
#    replaced. So the value varies on every request, and the names vary across
#    eight combinations: a fresh value alone is invisible to the low-variation
#    test, which counts names.
$shapes = @(
    '', '&page=2', '&sort=new', '&page=2&sort=new',
    '&filter=open', '&from=2026-01-01', '&view=compact', '&page=2&filter=open&view=compact'
)
for ($i = 1; $i -le 30; $i++) {
    $cookie = "routing=$(New-Random 96 ([math]::Floor(($i - 1) / 2)))"
    Add-Item -Method 'GET' -Path '/api/feed' -Query "cursor=$i$($shapes[$i % $shapes.Count])" `
        -Headers @("Cookie: $cookie", 'Accept: application/json') `
        -Body '' -Status 200 -ResponseLength 43
}

# 3. Sixteen telemetry posts: one container, eight flat flags, nothing back.
#
#    One flag value moves per event, so the sixteen bodies differ and survive
#    deduplication, while the shape the report shows — nine field names under one
#    root — stays exactly the same.
$deviceId = New-Random 40 424242
for ($i = 1; $i -le 16; $i++) {
    $body = '{"event":{"device_id":"' + $deviceId + '","properties":{' +
        ('"bucket":"b7","experiment":"exp-114","client_hints":"ch-2","app_version":"4.2.0",' +
        '"ab_bucket":"ab-3","sdk":"sdk-' + $i + '","platform":"web","locale":"en-GB"}}}')
    Add-Item -Method 'POST' -Path '/api/collect/events' -Query '' `
        -Headers @('Accept: application/json') `
        -Body $body -Status 200 -ResponseLength 11
}

# 4. Three reads of one order, which handle an identifier and say so.
for ($i = 1; $i -le 3; $i++) {
    Add-Item -Method 'GET' -Path '/api/orders/8891' -Query "expand=items&page=$i" `
        -Headers @('Accept: application/json') -Body '' -Status 200 -ResponseLength 57
}

$xml = '<?xml version="1.0" encoding="UTF-8"?>' + "`n" +
    '<items burpVersion="2026.5">' + "`n" +
    ($items -join "`n") + "`n" +
    '</items>' + "`n"

[IO.File]::WriteAllText($OutPath, $xml, (New-Object Text.UTF8Encoding $false))
Write-Output "wrote $($items.Count) items to $OutPath"
