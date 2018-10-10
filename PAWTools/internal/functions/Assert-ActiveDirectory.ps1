function Assert-ActiveDirectory
{
<#
	.SYNOPSIS
		Ensures the active directory module is available.
	
	.DESCRIPTION
		Ensures the active directory module is available.
		Will import it if needed.
		Will throw an exception if unavailable.
	
	.EXAMPLE
		PS C:\> Assert-ActiveDirectory
	
		Ensures the active directory module is available.
#>
	[CmdletBinding()]
	Param (
	
	)
	
	process
	{
		if (-not (Get-Module ActiveDirectory -ListAvailable))
		{
			throw "Could not find the active directory module. Run on computer with the module or execute 'Add-WindowsFeature RSAT-AD-PowerShell' to install it locally."
		}
		Import-Module ActiveDirectory -Scope Global
	}
}