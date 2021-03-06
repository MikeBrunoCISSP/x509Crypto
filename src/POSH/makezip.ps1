$version = $(Get-ChildItem -Path $args[0] -Filter X509CryptoPOSH.dll -Recurse | Select-Object Name,@{n='ProductVersion';e={$_.VersionInfo.ProductVersion}},@{n='AssemblyVersion';e={[Reflection.AssemblyName]::GetAssemblyName($_.FullName).Version}} | Select-Object ProductVersion).ProductVersion
$zipfile = "..\..\zip\X509CryptoPSModule_$version.zip"
Remove-Item $zipfile -Force
Compress-Archive -Path $args[0] -Destination $zipfile