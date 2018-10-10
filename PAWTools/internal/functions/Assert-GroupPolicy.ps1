function Assert-GroupPolicy
{
<#
	.SYNOPSIS
		Ensures the group policy module is available.
	
	.DESCRIPTION
		Ensures the group policy module is available.
		Will import it if needed.
		Will throw an exception if unavailable.
	
	.EXAMPLE
		PS C:\> Assert-GroupPolicy
	
		Ensures the group policy module is available.
#>
	[CmdletBinding()]
	Param (
	
	)
	
	process
	{
		if (-not (Get-Module GroupPolicy -ListAvailable))
		{
			throw "Could not find the Group Policy module. Run on computer with the module or execute 'Add-WindowsFeature Pgmc' to install it locally."
		}
		Import-Module GroupPolicy -Scope Global
	}
}