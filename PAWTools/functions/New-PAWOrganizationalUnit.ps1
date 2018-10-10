function New-PAWOrganizationalUnit
{
<#
	.SYNOPSIS
		Creates the entire OU structure used by the PAW model
	
	.DESCRIPTION
		Creates the entire OU structure used by the PAW model
	
	.PARAMETER Confirm
		If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
	
	.PARAMETER WhatIf
		If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
	
	.EXAMPLE
		PS C:\> New-PAWOrganizationalUnit
	
		Creates the entire OU structure used by the PAW model
#>
	[CmdletBinding(SupportsShouldProcess = $true)]
	param (
		
	)
	
	
	if (-not ($PSCmdlet.ShouldProcess('PAW OU Structure', 'Creating')))
	{
		return
	}
	
	try { Assert-ActiveDirectory -ErrorAction Stop }
	catch { throw }
	try { Assert-GroupPolicy -ErrorAction Stop }
	catch { throw }
	
	# Get current working directory
	$sLocation = Get-Location
	$sDSE = Get-ADInfo
	
	Write-Verbose 'Creating Top Level OUs'
	New-ADOrganizationalUnit -Name "Admin" -Path $sDSE
	New-ADOrganizationalUnit -Name "Groups" -Path $sDSE
	New-ADOrganizationalUnit -Name "Tier 1 Servers" -Path $sDSE
	New-ADOrganizationalUnit -Name "Workstations" -Path $sDSE
	New-ADOrganizationalUnit -Name "User Accounts" -Path $sDSE
	New-ADOrganizationalUnit -Name "Computer Quarantine" -Path $sDSE
	
	
	Write-Verbose 'Creating Sub OUs for Top Level Admin OU'
	New-ADOrganizationalUnit -Name "Tier 0" -Path "OU=Admin,$sDSE"
	New-ADOrganizationalUnit -Name "Tier 1" -Path "OU=Admin,$sDSE"
	New-ADOrganizationalUnit -Name "Tier 2" -Path "OU=Admin,$sDSE"
	
	Write-Verbose 'Creating Sub OUs for Admin\Tier 0 OU'
	New-ADOrganizationalUnit -Name "Accounts" -Path "OU=Tier 0,OU=Admin,$sDSE"
	New-ADOrganizationalUnit -Name "Groups" -Path "OU=Tier 0,OU=Admin,$sDSE"
	New-ADOrganizationalUnit -Name "Service Accounts" -Path "OU=Tier 0,OU=Admin,$sDSE"
	New-ADOrganizationalUnit -Name "Devices" -Path "OU=Tier 0,OU=Admin,$sDSE"
	New-ADOrganizationalUnit -Name "Tier 0 Servers" -Path "OU=Tier 0,OU=Admin,$sDSE"
	
	Write-Verbose 'Creating Sub OUs for Admin\Tier 1 OU'
	New-ADOrganizationalUnit -Name "Accounts" -Path "OU=Tier 1,OU=Admin,$sDSE"
	New-ADOrganizationalUnit -Name "Groups" -Path "OU=Tier 1,OU=Admin,$sDSE"
	New-ADOrganizationalUnit -Name "Service Accounts" -Path "OU=Tier 1,OU=Admin,$sDSE"
	New-ADOrganizationalUnit -Name "Devices" -Path "OU=Tier 1,OU=Admin,$sDSE"
	
	Write-Verbose 'Creating Sub OUs for Admin\Tier 2 OU'
	New-ADOrganizationalUnit -Name "Accounts" -Path "OU=Tier 2,OU=Admin,$sDSE"
	New-ADOrganizationalUnit -Name "Groups" -Path "OU=Tier 2,OU=Admin,$sDSE"
	New-ADOrganizationalUnit -Name "Service Accounts" -Path "OU=Tier 2,OU=Admin,$sDSE"
	New-ADOrganizationalUnit -Name "Devices" -Path "OU=Tier 2,OU=Admin,$sDSE"
	
	Write-Verbose 'Creating Sub OUs for Top Level Groups OU'
	New-ADOrganizationalUnit -Name "Security Groups" -Path "OU=Groups,$sDSE"
	New-ADOrganizationalUnit -Name "Distribution Groups" -Path "OU=Groups,$sDSE"
	New-ADOrganizationalUnit -Name "Contacts" -Path "OU=Groups,$sDSE"
	
	Write-Verbose 'Creating Sub OUs for Top Level Tier 1 Servers OU'
	New-ADOrganizationalUnit -Name "Application" -Path "OU=Tier 1 Servers,$sDSE"
	New-ADOrganizationalUnit -Name "Collaboration" -Path "OU=Tier 1 Servers,$sDSE"
	New-ADOrganizationalUnit -Name "Database" -Path "OU=Tier 1 Servers,$sDSE"
	New-ADOrganizationalUnit -Name "Messaging" -Path "OU=Tier 1 Servers,$sDSE"
	New-ADOrganizationalUnit -Name "Staging" -Path "OU=Tier 1 Servers,$sDSE"
	
	Write-Verbose 'Creating Sub OUs for Top Level Workstations OU'
	New-ADOrganizationalUnit -Name "Desktops" -Path "OU=Workstations,$sDSE"
	New-ADOrganizationalUnit -Name "Kiosks" -Path "OU=Workstations,$sDSE"
	New-ADOrganizationalUnit -Name "Laptops" -Path "OU=Workstations,$sDSE"
	New-ADOrganizationalUnit -Name "Staging" -Path "OU=Workstations,$sDSE"
	
	Write-Verbose 'Creating Sub OUs for Top Level User Accounts OU'
	New-ADOrganizationalUnit -Name "Enabled Users" -Path "OU=User Accounts,$sDSE"
	New-ADOrganizationalUnit -Name "Disabled Users" -Path "OU=User Accounts,$sDSE"
	
	Write-Verbose 'Block inheritance for PAW OUs'
	$null = Set-GpInheritance -target "OU=Devices,OU=Tier 0,OU=Admin,$sDSE" -IsBlocked Yes
	$null = Set-GpInheritance -target "OU=Devices,OU=Tier 1,OU=Admin,$sDSE" -IsBlocked Yes
	$null = Set-GpInheritance -target "OU=Devices,OU=Tier 2,OU=Admin,$sDSE" -IsBlocked Yes
	
	# Return to original working directory
	Set-Location $sLocation
}