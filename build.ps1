param([string]$OutputDirectory=(Join-Path $PSScriptRoot 'artifacts\unsigned'))
$ErrorActionPreference='Stop'
$project=Join-Path $PSScriptRoot 'source\Sentinella.Desktop\Sentinella.Desktop.csproj'
$buildArtifacts=Join-Path (Split-Path -Parent ([IO.Path]::GetFullPath($OutputDirectory))) 'build'
& dotnet publish $project -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -p:DebugType=None --artifacts-path $buildArtifacts -o $OutputDirectory --nologo
if($LASTEXITCODE -ne 0){throw 'Build non riuscita'}
$files=@('SentinellaFree.exe','SentinellaFree.dll','Sentinella.Core.dll')
$manifest=foreach($name in $files){
 $path=Join-Path $OutputDirectory $name
 $info=(Get-Item -LiteralPath $path).VersionInfo
 if($info.ProductName -ne 'Sentinella Free' -or $info.FileVersion -ne '0.2.0.0'){throw ('Metadati inattesi: '+$name)}
 [pscustomobject]@{Name=$name;Product=$info.ProductName;Version=$info.FileVersion;SHA256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash;SigningStatus='Unsigned; requires approved signing service'}
}
$manifest | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDirectory 'original-components.json') -Encoding utf8
Write-Output 'Build completata. Nessuna firma applicata e nessuna applicazione avviata.'

