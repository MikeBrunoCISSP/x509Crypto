$ModulePath = '..\..\bin\PSModule\X509Crypto.psd1'
$BinPath = '..\..\bin\PSModule\X509CryptoPOSH.dll'

if (Test-Path $ModulePath) {Remove-Item -Path $ModulePath}

Import-Module $BinPath -Force

$ModuleSettings =
@{
	Path = $ModulePath
	ModuleVersion = '1.1.0'
	RootModule = 'X509CryptoPOSH.dll'
	Author = 'Michael Bruno'
	CompanyName = 'X509Crypto.org'
	Copyright = '(c) 2020 X509Crypto.org. All rights reserved'
	Description = 'Lets you easily and securely encrypt and recover text expressions and files in your .NET programs using X509 digital certificates and private keys. No prior experience with certificates required!'
	DotNetFrameworkVersion = '4.6.2'
	RequiredAssemblies = $(Get-ChildItem '..\..\bin\PSModule' | Where-Object {$_.Extension -like ".dll"} | % {$_.Name})
	CmdletsToExport = "`'$([System.string]::Join("`',`'",$(Get-Command -module X509Crypto | Select -ExpandProperty Name)))`'"
}

New-ModuleManifest @ModuleSettings