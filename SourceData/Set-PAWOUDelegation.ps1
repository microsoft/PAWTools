# Delegate-PAWOURights.ps1
# Based on and includes the DIAD delegations by Heath Aubin and Jon Sabberton

#Include PS Environment
#. ..\..\Scripts\Custom\PSEnvironment.ps1
. .\\ADEnvironment.ps1
 
# Add-Log -LogEntry("--Beginning PAW and DIAD Active Directory Delegations--");
 
#Get current working directory
$sLocation = Get-Location

#Bring up an Active Directory command prompt so we can use this later on in the script
Set-Location ad:
 
#Get a reference to the RootDSE of the current domain
$rootdse = Get-ADRootDSE
 
#Get a reference to the current domain
$domain = Get-ADDomain
 
#Set the Configuration Naming Context
$configCN = $rootdse.ConfigurationNamingContext
 
#Set the Schema Naming Context
$schemaNC = $rootDSE.SchemaNamingContext
 
#Set the ForestDnsZones Naming Context
$forestDnsZonesDN = "DC=ForestDnsZones,"+$rootDSE.RootDomainNamingContext
 
#Set the Sites Naming Context
$sitesDN = "CN=Sites,"+$configCN
#Create a hashtable to store the GUID value of each schema class and attribute
$guidmap = @{}
Get-ADObject -SearchBase ($rootdse.SchemaNamingContext) -LDAPFilter `
"(schemaidguid=*)" -Properties lDAPDisplayName,schemaIDGUID | 
% {$guidmap[$_.lDAPDisplayName]=[System.GUID]$_.schemaIDGUID}
#Create a hashtable to store the GUID value of each extended right in the forest
$extendedrightsmap = @{}
Get-ADObject -SearchBase ($rootdse.ConfigurationNamingContext) -LDAPFilter `
"(&(objectclass=controlAccessRight)(rightsguid=*))" -Properties displayName,rightsGuid | 
% {$extendedrightsmap[$_.displayName]=[System.GUID]$_.rightsGuid}
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

#Get a reference to each of the OU's we want to set permissions on
#Add-Log -LogEntry("Getting OU Information");
$userAcctsOUDN = Get-ADOrganizationalUnit -Identity ($userAccountsOU+$domain)
$workstationsOUDN = Get-ADOrganizationalUnit -Identity ($workstationsOU+$domain)
$computerQuarantineOUDN = Get-ADOrganizationalUnit -Identity ($computerQuarantineOU+$domain)
$tier1ServersOUDN = Get-ADOrganizationalUnit -Identity ($tier1ServersOU+$domain)
$PAWDevicesOUDN = Get-ADOrganizationalUnit -Identity ($PAWDevicesOU+$domain)
 
#Get the SID values of each group (principal) we wish to delegate access to
#Add-Log -LogEntry("Getting SID values for each group for delegations");
$serviceDeskOpsSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup $serviceDeskOperatorsGroup).SID
$workstationMaintSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup $workstationMaintenanceGroup).SID
$replMaintGroupSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup $replicationMaintenanceGroup).SID
$tier1ServerMaintGroupSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup $tier1ServerMaintenanceGroup).SID
$PAWAdminsGroupSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup $PAWAdminsGroup).SID
 
#Get a copy of the current DACL on the OU's or Containers
#Add-Log -LogEntry("Getting existing Directory ACLs");
$userAccountsOUACL = Get-ACL -Path ($userAcctsOUDN);
$workstationsOUACL = Get-ACL -Path ($workstationsOUDN);
$computerQuarantineACL = Get-ACL -Path ($computerQuarantineOUDN)
$topLevelDomainACL = Get-ACL -Path($domain)
$configContainerACL = Get-ACL -Path($configCN)
$schemaNCACL = Get-ACL -Path($schemaNC)
$forestDnsZonesACL = Get-ACL -Path($forestDnsZonesDN)
$sitesACL = Get-ACL -Path($sitesDN)
$tier1ServersOUACL = Get-ACL -Path ($tier1ServersOUDN)
$PAWDevicesOUACL = Get-ACL -Path ($PAWDevicesOUDN)
 
#Set Service Desk Operators Permissions to Users
#Add-Log -LogEntry("Performing Service Desk Operators Role Delegations User Accounts OU");
$userAccountsOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$serviceDeskOpsSID,"ReadProperty","Allow","Descendents",$guidmap["user"]))
$userAccountsOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$serviceDeskOpsSID,"WriteProperty","Allow","Descendents",$guidmap["user"]))
$userAccountsOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$serviceDeskOpsSID,"ExtendedRight","Allow",$extendedrightsmap["Reset Password"],"Descendents",$guidmap["user"]))
 
#Set Service Desk Operator Permissions on Computers to access BitLocker and TPM information
#Add-Log -LogEntry("Performing Service Desk Operator Role Delegations to the Workstation OU");
$workstationsOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$serviceDeskOpsSID,"ReadProperty","Allow",$guidmap["msTPM-OwnerInformation"],"Descendents",$guidmap["computer"]))
$workstationsOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$serviceDeskOpsSID,"ReadProperty","Allow",$guidmap["msFVE-KeyPackage"],"Descendents",$guidmap["msFVE-RecoveryInformation"]))
$workstationsOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$serviceDeskOpsSID,"ReadProperty","Allow",$guidmap["msFVE-RecoveryPassword"],"Descendents",$guidmap["msFVE-RecoveryInformation"]))
$workstationsOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$serviceDeskOpsSID,"ReadProperty","Allow",$guidmap["msFVE-VolumeGuid"],"Descendents",$guidmap["msFVE-RecoveryInformation"]))
 
#Set Workstation Maintenance Permissions on Computer objects in the Computer Quarantine OU
#Add-Log -LogEntry("Performing Workstation Maintenance Role Delegations to the Computer Quarantine OU");
$computerQuarantineACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$workstationMaintSID,"CreateChild,DeleteChild","Allow",$guidmap["computer"],"All"))
$computerQuarantineACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$workstationMaintSID,"ReadProperty","Allow","Descendents",$guidmap["computer"]))
$computerQuarantineACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$workstationMaintSID,"WriteProperty","Allow","Descendents",$guidmap["computer"]))
 
#Set Workstation Maintenance Permissions on Computer objects in the Workstations OU
#Add-Log -LogEntry("Performing Workstation Maintenance Role Delegations to the Workstations OU");
$workstationsOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$workstationMaintSID,"CreateChild,DeleteChild","Allow",$guidmap["computer"],"All"))
$workstationsOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$workstationMaintSID,"ReadProperty","Allow","Descendents",$guidmap["computer"]))
$workstationsOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$workstationMaintSID,"WriteProperty","Allow","Descendents",$guidmap["computer"]))

#Set PAW Admins Permissions on Computer objects in the PAW Devices OU
#Add-Log -LogEntry("Performing PAW Admins Role Delegations to the Tier 0\Devices OU");
$PAWDevicesOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$PAWAdminsGroupSID,"CreateChild,DeleteChild","Allow",$guidmap["computer"],"All"))
$PAWDevicesOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$PAWAdminsGroupSID,"ReadProperty","Allow","Descendents",$guidmap["computer"]))
$PAWDevicesOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$PAWAdminsGroupSID,"WriteProperty","Allow","Descendents",$guidmap["computer"]))
 
#Set Tier 0 Replication Maintenance Permissions within domain
#Add-Log -LogEntry("Performing Tier 0 Replication Maintenance Role Delegations");
$topLevelDomainACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Manage Replication Topology"],"Descendents"))
$topLevelDomainACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Replicating Directory Changes"],"Descendents"))
$topLevelDomainACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Replicating Directory Changes All"],"Descendents"))
$topLevelDomainACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Replication Synchronization"],"Descendents"))
$configContainerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Manage Replication Topology"],"Descendents"))
$configContainerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Replicating Directory Changes"],"Descendents"))
$configContainerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Replicating Directory Changes All"],"Descendents"))
$configContainerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Replication Synchronization"],"Descendents"))
$configContainerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Monitor active directory Replication"],"Descendents"))
$schemaNCACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Manage Replication Topology"],"Descendents"))
$schemaNCACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Replicating Directory Changes"],"Descendents"))
$schemaNCACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Replicating Directory Changes All"],"Descendents"))
$schemaNCACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Replication Synchronization"],"Descendents"))
$schemaNCACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Monitor active directory Replication"],"Descendents"))
$forestDnsZonesACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Manage Replication Topology"],"Descendents"))
$forestDnsZonesACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Replicating Directory Changes"],"Descendents"))
$forestDnsZonesACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Replicating Directory Changes All"],"Descendents"))
$forestDnsZonesACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Replication Synchronization"],"Descendents"))
$sitesACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$replMaintGroupSID,"CreateChild,DeleteChild","Allow"))
$sitesACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$replMaintGroupSID,"WriteProperty","Allow"))
 
#Set Tier 1 Server Maintenance Permissions on Computer objects in the Tier 1 Servers OU
#Add-Log -LogEntry("Performing Tier 1 Server Maintenance Role Delegations to the Tier 1 Servers OU");
$tier1ServersOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$tier1ServerMaintGroupSID,"CreateChild,DeleteChild","Allow",$guidmap["computer"],"All"))
$tier1ServersOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$tier1ServerMaintGroupSID,"ReadProperty","Allow","Descendents",$guidmap["computer"]))
$tier1ServersOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$tier1ServerMaintGroupSID,"WriteProperty","Allow","Descendents",$guidmap["computer"]))
$tier1ServersOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$tier1ServerMaintGroupSID,"ReadProperty,WriteProperty","Allow",$guidmap["gplink"],"All"))
$tier1ServersOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$tier1ServerMaintGroupSID,"ReadProperty","Allow",$guidmap["gpoptions"],"All"))
 
#Apply the modified DACL to the OU or Containers
#Add-Log -LogEntry("Applying all Updated ACLs");
Set-ACL -ACLObject $userAccountsOUACL -Path ("AD:\"+($userAcctsOUDN));
Set-ACL -ACLObject $workstationsOUACL -Path ("AD:\"+($workstationsOUDN));
Set-ACL -ACLObject $computerQuarantineACL -Path ("AD:\"+($computerQuarantineOUDN));
Set-ACL -ACLObject $topLevelDomainACL -Path ("AD:\"+($domain));
Set-ACL -ACLObject $configContainerACL -Path ("AD:\"+($configCN));
Set-ACL -ACLObject $schemaNCACL -Path ("AD:\"+($schemaNC));
Set-ACL -ACLObject $forestDnsZonesACL -Path ("AD:\"+($forestDnsZonesDN));
Set-ACL -ACLObject $sitesACL -Path ("AD:\"+($sitesDN));
Set-ACL -ACLObject $tier1ServersOUACL -Path ("AD:\"+($tier1ServersOUDN));
Set-ACL -ACLObject $PAWDevicesOUACL -Path ("AD:"+($PAWDevicesOUDN));
#Add-Log -LogEntry("--Completed PAW and DIAD Active Directory Delegations--");
 
#Return to original working directory
Set-Location $sLocation
