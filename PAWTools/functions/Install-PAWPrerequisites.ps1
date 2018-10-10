function Install-PAWPrerequisites
{
<#
	.SYNOPSIS
		Enables all features needed to apply the PAW framework.
	
	.DESCRIPTION
		Enables all features needed to apply the PAW framework.
	
		Notably, this command ensures that:
		- ActiveDirectory module is available
		- GroupPolicy module is available
	
	.EXAMPLE
		PS C:\> Install-PAWPrerequisites
	
		Enables all features needed to apply the PAW framework.
#>
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseSingularNouns", "")]
	[CmdletBinding()]
	Param (
	
	)
	
	process
	{
		try { Assert-ActiveDirectory -ErrorAction Stop }
		catch { $null = Add-WindowsFeature RSAT-AD-PowerShell }
		Import-Module ActiveDirectory
		try { Assert-GroupPolicy -ErrorAction Stop }
		catch { $null = Add-WindowsFeature Pgmc }
		Import-Module ActiveDirectory
	}
}