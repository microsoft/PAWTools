function Get-ADInfo
{
<#
	.SYNOPSIS
		Returns the default naming context of the current domain.
	
	.DESCRIPTION
		Returns the default naming context of the current domain.
	
	.EXAMPLE
		PS C:\> Get-ADInfo
	
		Returns the default naming context of the current domain.
#>
	[OutputType([System.String])]
	[CmdletBinding()]
	param (
		
	)
	(Get-ADRootDSE).defaultNamingContext
}
