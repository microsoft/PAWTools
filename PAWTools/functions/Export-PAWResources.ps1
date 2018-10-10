function Export-PAWResources
{
<#
	.SYNOPSIS
		Provides additional resources needed for configuring PAWs.
	
	.DESCRIPTION
		Provides additional resources needed for configuring PAWs.
		This includes firewall and proxy rules to further lockdown the PAW.
	
		These are required for following the online guide on PAW configuration.
	
	.PARAMETER Path
		The path where to place the resources.
		by default, files are placed in the current path.
	
	.EXAMPLE
		PS C:\> Export-PAWResources
	
		Exports all additional resources needed to the current path.
#>
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseSingularNouns", "")]
	[CmdletBinding()]
	param (
		[ValidateScript({ Test-Path $_ })]
		[string]
		$Path = "."
	)
	begin
	{
		$resolvedPath = "$((Resolve-Path $Path).Path)\"
	}
	process
	{
		Get-ChildItem "$($script:ModuleRoot)\data" | Where-Object Name -NE 'groups.json' | Copy-Item -Destination $resolvedPath
	}
}