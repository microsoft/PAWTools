function Test-XADObject
{
<#
	.SYNOPSIS
		Tests, whether an object in AD exists.
	
	.DESCRIPTION
		Tests, whether an object in AD exists.
	
	.PARAMETER Identity
		A unique identity reference, such as SamAccountName, UPN or DistinguishedName
	
	.EXAMPLE
		PS C:\> Test-XADGroupObject -Identity $Identity
	
		Returns whether the identity information offered in $Identity has a matching AD Object
#>
	[OutputType([System.Boolean])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, HelpMessage = "Identity of the AD object to verify if exists or not.")]
		[Object]
		$Identity
	)
	
	try { $auxObject = Get-ADObject -Identity $Identity -ErrorAction Stop }
	catch { return $false }
	if ($auxObject) { return $true }
	return $false
}