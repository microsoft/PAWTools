function Set-PAWOUDelegation
{
<#
	.SYNOPSIS
		Sets up the delegations required for the PAW architecture.
	
	.DESCRIPTION
		Sets up the delegations required for the PAW architecture.
	
	.PARAMETER Confirm
		If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
	
	.PARAMETER WhatIf
		If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
	
	.EXAMPLE
		PS C:\> Set-PAWOUDelegation
	
		Sets up the delegations required for the PAW architecture.
	
	.NOTES
		Based on and includes the DIAD delegations by Heath Aubin and Jon Sabberton
#>
	[CmdletBinding(SupportsShouldProcess = $true)]
	param (
		
	)
	
	try { Assert-ActiveDirectory -ErrorAction Stop }
	catch { throw }
	
	#region Setup variables needed throughout the function
	$sLocation = Get-Location
	Set-Location ad:
	$rootdse = Get-ADRootDSE
	$domain = Get-ADDomain
	$configNC = $rootdse.ConfigurationNamingContext
	$schemaNC = $rootDSE.SchemaNamingContext
	$forestDnsZonesDN = "DC=ForestDnsZones," + $rootDSE.RootDomainNamingContext
	$sitesDN = "CN=Sites," + $configNC
	
	# Set variables for OUs and Containers
	$userAccountsOU = "OU=User Accounts,"
	$workstationsOU = "OU=Workstations,"
	$computerQuarantineOU = "OU=Computer Quarantine,"
	$tier1ServersOU = "OU=Tier 1 Servers,"
	$PAWDevicesOU = "OU=Devices,OU=Tier 0,OU=Admin,"
	
	# Set variables for Group objects
	$serviceDeskOperatorsGroup = "ServiceDeskOperators"
	$workstationMaintenanceGroup = "WorkstationMaintenance"
	$replicationMaintenanceGroup = "Tier0ReplicationMaintenance"
	$tier1ServerMaintenanceGroup = "Tier1ServerMaintenance"
	$PAWAdminsGroup = "PAWMaint"
	#endregion Setup variables needed throughout the function
	
	#region Create Maps for GUID lookup
	# Create a hashtable to store the GUID value of each schema class and attribute
	$guidmap = @{ }
	Get-ADObject -SearchBase $schemaNC -LDAPFilter "(schemaidguid=*)" -Properties lDAPDisplayName, schemaIDGUID |
	ForEach-Object { $guidmap[$_.lDAPDisplayName] = [System.GUID]$_.schemaIDGUID }
	
	# Create a hashtable to store the GUID value of each extended right in the forest
	$extendedrightsmap = @{ }
	Get-ADObject -SearchBase $configNC -LDAPFilter "(&(objectclass=controlAccessRight)(rightsguid=*))" -Properties displayName, rightsGuid |
	ForEach-Object { $extendedrightsmap[$_.displayName] = [System.GUID]$_.rightsGuid }
	#endregion Create Maps for GUID lookup
	
	#region Retrieve OU Info and prepare Identities
	# Get a reference to each of the OU's we want to set permissions on
	Write-Verbose "Getting OU Information"
	$userAcctsOUDN = Get-ADOrganizationalUnit -Identity ($userAccountsOU + $domain)
	$workstationsOUDN = Get-ADOrganizationalUnit -Identity ($workstationsOU + $domain)
	$computerQuarantineOUDN = Get-ADOrganizationalUnit -Identity ($computerQuarantineOU + $domain)
	$tier1ServersOUDN = Get-ADOrganizationalUnit -Identity ($tier1ServersOU + $domain)
	$PAWDevicesOUDN = Get-ADOrganizationalUnit -Identity ($PAWDevicesOU + $domain)
	
	# Get the SID values of each group (principal) we wish to delegate access to
	Write-Verbose "Getting SID values for each group for delegations"
	$serviceDeskOpsSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup $serviceDeskOperatorsGroup).SID
	$workstationMaintSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup $workstationMaintenanceGroup).SID
	$replMaintGroupSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup $replicationMaintenanceGroup).SID
	$tier1ServerMaintGroupSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup $tier1ServerMaintenanceGroup).SID
	$PAWAdminsGroupSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup $PAWAdminsGroup).SID
	#endregion Retrieve OU Info and prepare Identities
	
	#region Get a copy of the current DACL on the OU's or Containers
	Write-Verbose "Getting existing Directory ACLs"
	$userAccountsOUACL = Get-ACL -Path $userAcctsOUDN
	$workstationsOUACL = Get-ACL -Path $workstationsOUDN
	$computerQuarantineACL = Get-ACL -Path $computerQuarantineOUDN
	$topLevelDomainACL = Get-ACL -Path $domain
	$configContainerACL = Get-ACL -Path $configNC
	$schemaNCACL = Get-ACL -Path $schemaNC
	$forestDnsZonesACL = Get-ACL -Path $forestDnsZonesDN
	$sitesACL = Get-ACL -Path $sitesDN
	$tier1ServersOUACL = Get-ACL -Path $tier1ServersOUDN
	$PAWDevicesOUACL = Get-ACL -Path $PAWDevicesOUDN
	#endregion Get a copy of the current DACL on the OU's or Containers
	
	#region Create Delegation Rules
	# Set Service Desk Operators Permissions to Users
	Write-Verbose "Performing Service Desk Operators Role Delegations User Accounts OU"
	$userAccountsOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												 $serviceDeskOpsSID, "ReadProperty", "Allow", "Descendents", $guidmap["user"]))
	$userAccountsOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												 $serviceDeskOpsSID, "WriteProperty", "Allow", "Descendents", $guidmap["user"]))
	$userAccountsOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												 $serviceDeskOpsSID, "ExtendedRight", "Allow", $extendedrightsmap["Reset Password"], "Descendents", $guidmap["user"]))
	
	# Set Service Desk Operator Permissions on Computers to access BitLocker and TPM information
	Write-Verbose "Performing Service Desk Operator Role Delegations to the Workstation OU"
	$workstationsOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												 $serviceDeskOpsSID, "ReadProperty", "Allow", $guidmap["msTPM-OwnerInformation"], "Descendents", $guidmap["computer"]))
	$workstationsOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												 $serviceDeskOpsSID, "ReadProperty", "Allow", $guidmap["msFVE-KeyPackage"], "Descendents", $guidmap["msFVE-RecoveryInformation"]))
	$workstationsOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												 $serviceDeskOpsSID, "ReadProperty", "Allow", $guidmap["msFVE-RecoveryPassword"], "Descendents", $guidmap["msFVE-RecoveryInformation"]))
	$workstationsOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												 $serviceDeskOpsSID, "ReadProperty", "Allow", $guidmap["msFVE-VolumeGuid"], "Descendents", $guidmap["msFVE-RecoveryInformation"]))
	
	# Set Workstation Maintenance Permissions on Computer objects in the Computer Quarantine OU
	Write-Verbose "Performing Workstation Maintenance Role Delegations to the Computer Quarantine OU"
	$computerQuarantineACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
													 $workstationMaintSID, "CreateChild,DeleteChild", "Allow", $guidmap["computer"], "All"))
	$computerQuarantineACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
													 $workstationMaintSID, "ReadProperty", "Allow", "Descendents", $guidmap["computer"]))
	$computerQuarantineACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
													 $workstationMaintSID, "WriteProperty", "Allow", "Descendents", $guidmap["computer"]))
	
	# Set Workstation Maintenance Permissions on Computer objects in the Workstations OU
	Write-Verbose "Performing Workstation Maintenance Role Delegations to the Workstations OU"
	$workstationsOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												 $workstationMaintSID, "CreateChild,DeleteChild", "Allow", $guidmap["computer"], "All"))
	$workstationsOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												 $workstationMaintSID, "ReadProperty", "Allow", "Descendents", $guidmap["computer"]))
	$workstationsOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												 $workstationMaintSID, "WriteProperty", "Allow", "Descendents", $guidmap["computer"]))
	
	# Set PAW Admins Permissions on Computer objects in the PAW Devices OU
	Write-Verbose "Performing PAW Admins Role Delegations to the Tier 0\Devices OU"
	$PAWDevicesOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
											   $PAWAdminsGroupSID, "CreateChild,DeleteChild", "Allow", $guidmap["computer"], "All"))
	$PAWDevicesOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
											   $PAWAdminsGroupSID, "ReadProperty", "Allow", "Descendents", $guidmap["computer"]))
	$PAWDevicesOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
											   $PAWAdminsGroupSID, "WriteProperty", "Allow", "Descendents", $guidmap["computer"]))
	
	# Set Tier 0 Replication Maintenance Permissions within domain
	Write-Verbose "Performing Tier 0 Replication Maintenance Role Delegations"
	$topLevelDomainACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												 $replMaintGroupSID, "ExtendedRight", "Allow", $extendedrightsmap["Manage Replication Topology"], "Descendents"))
	$topLevelDomainACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												 $replMaintGroupSID, "ExtendedRight", "Allow", $extendedrightsmap["Replicating Directory Changes"], "Descendents"))
	$topLevelDomainACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												 $replMaintGroupSID, "ExtendedRight", "Allow", $extendedrightsmap["Replicating Directory Changes All"], "Descendents"))
	$topLevelDomainACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												 $replMaintGroupSID, "ExtendedRight", "Allow", $extendedrightsmap["Replication Synchronization"], "Descendents"))
	$configContainerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												  $replMaintGroupSID, "ExtendedRight", "Allow", $extendedrightsmap["Manage Replication Topology"], "Descendents"))
	$configContainerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												  $replMaintGroupSID, "ExtendedRight", "Allow", $extendedrightsmap["Replicating Directory Changes"], "Descendents"))
	$configContainerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												  $replMaintGroupSID, "ExtendedRight", "Allow", $extendedrightsmap["Replicating Directory Changes All"], "Descendents"))
	$configContainerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												  $replMaintGroupSID, "ExtendedRight", "Allow", $extendedrightsmap["Replication Synchronization"], "Descendents"))
	$configContainerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												  $replMaintGroupSID, "ExtendedRight", "Allow", $extendedrightsmap["Monitor active directory Replication"], "Descendents"))
	$schemaNCACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
										   $replMaintGroupSID, "ExtendedRight", "Allow", $extendedrightsmap["Manage Replication Topology"], "Descendents"))
	$schemaNCACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
										   $replMaintGroupSID, "ExtendedRight", "Allow", $extendedrightsmap["Replicating Directory Changes"], "Descendents"))
	$schemaNCACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
										   $replMaintGroupSID, "ExtendedRight", "Allow", $extendedrightsmap["Replicating Directory Changes All"], "Descendents"))
	$schemaNCACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
										   $replMaintGroupSID, "ExtendedRight", "Allow", $extendedrightsmap["Replication Synchronization"], "Descendents"))
	$schemaNCACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
										   $replMaintGroupSID, "ExtendedRight", "Allow", $extendedrightsmap["Monitor active directory Replication"], "Descendents"))
	$forestDnsZonesACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												 $replMaintGroupSID, "ExtendedRight", "Allow", $extendedrightsmap["Manage Replication Topology"], "Descendents"))
	$forestDnsZonesACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												 $replMaintGroupSID, "ExtendedRight", "Allow", $extendedrightsmap["Replicating Directory Changes"], "Descendents"))
	$forestDnsZonesACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												 $replMaintGroupSID, "ExtendedRight", "Allow", $extendedrightsmap["Replicating Directory Changes All"], "Descendents"))
	$forestDnsZonesACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												 $replMaintGroupSID, "ExtendedRight", "Allow", $extendedrightsmap["Replication Synchronization"], "Descendents"))
	$sitesACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
										$replMaintGroupSID, "CreateChild,DeleteChild", "Allow"))
	$sitesACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
										$replMaintGroupSID, "WriteProperty", "Allow"))
	
	# Set Tier 1 Server Maintenance Permissions on Computer objects in the Tier 1 Servers OU
	Write-Verbose "Performing Tier 1 Server Maintenance Role Delegations to the Tier 1 Servers OU"
	$tier1ServersOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												 $tier1ServerMaintGroupSID, "CreateChild,DeleteChild", "Allow", $guidmap["computer"], "All"))
	$tier1ServersOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												 $tier1ServerMaintGroupSID, "ReadProperty", "Allow", "Descendents", $guidmap["computer"]))
	$tier1ServersOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												 $tier1ServerMaintGroupSID, "WriteProperty", "Allow", "Descendents", $guidmap["computer"]))
	$tier1ServersOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												 $tier1ServerMaintGroupSID, "ReadProperty,WriteProperty", "Allow", $guidmap["gplink"], "All"))
	$tier1ServersOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
												 $tier1ServerMaintGroupSID, "ReadProperty", "Allow", $guidmap["gpoptions"], "All"))
	#endregion Create Delegation Rules
	
	#region Apply the modified DACL to the OU or Containers
	if ($PSCmdlet.ShouldProcess('PAW Organizational Units', 'Apply custom Delegations'))
	{
		Write-Verbose "Applying all Updated ACLs"
		Set-ACL -ACLObject $userAccountsOUACL -Path "AD:\$($userAcctsOUDN)"
		Set-ACL -ACLObject $workstationsOUACL -Path "AD:\$($workstationsOUDN)"
		Set-ACL -ACLObject $computerQuarantineACL -Path "AD:\$($computerQuarantineOUDN)"
		Set-ACL -ACLObject $topLevelDomainACL -Path "AD:\$($domain)"
		Set-ACL -ACLObject $configContainerACL -Path "AD:\$($configNC)"
		Set-ACL -ACLObject $schemaNCACL -Path "AD:\$($schemaNC)"
		Set-ACL -ACLObject $forestDnsZonesACL -Path "AD:\$($forestDnsZonesDN)"
		Set-ACL -ACLObject $sitesACL -Path "AD:\$($sitesDN)"
		Set-ACL -ACLObject $tier1ServersOUACL -Path "AD:\$($tier1ServersOUDN)"
		Set-ACL -ACLObject $PAWDevicesOUACL -Path "AD:\$($PAWDevicesOUDN)"
		Write-Verbose "--Completed PAW and DIAD Active Directory Delegations--"
	}
	#endregion Apply the modified DACL to the OU or Containers
	
	# Return to original working directory
	Set-Location $sLocation
}