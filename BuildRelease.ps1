<#
��;�����ɷ����档
#>

$ErrorActionPreference = "Stop"

try{

$ts = (Get-Date).ToString("yyyyMMdd-HHmmss")
$scriptDir = split-path -parent $MyInvocation.MyCommand.Definition
$releaseDir = join-path $scriptDir ("yarchk" + "-$ts")

$dirs = @(
"$releaseDir")

Write-Host "�����ļ�..."

foreach ($i in $dirs) {
   mkdir $i | Out-Null
}

Remove-Item -Path "$scriptDir\rules\all.yarc" -ErrorAction SilentlyContinue
Remove-Item -Path "$scriptDir\rules\allyar.tmp" -ErrorAction SilentlyContinue
Copy-Item "$scriptDir\rules" -Recurse -Destination "$releaseDir\"
Copy-Item "$scriptDir\yara" -Recurse -Destination "$releaseDir\"
Copy-Item "$scriptDir\README.md" -Destination "$releaseDir\README.md" 
Copy-Item "$scriptDir\scan-process.bat" -Destination "$releaseDir\scan-process.bat" 
Copy-Item "$scriptDir\suspicious-strings.txt" -Destination "$releaseDir\suspicious-strings.txt" 
Copy-Item "$scriptDir\yarchk.exe" -Destination "$releaseDir\yarchk.exe" 

$compress = @{
  Path = "$releaseDir\*"
  DestinationPath = "yarchk-$ts.zip"
}
Compress-Archive @compress
Write-Host "���"

}
catch{
  $error[0].Exception
  $_ |select -expandproperty invocationinfo
}

Write-Host "��������˳�..."
cmd /c pause | Out-Null
