# Create-PAWGroups.ps1

#Include PS Environment
#. ..\..\Scripts\Custom\PSEnvironment.ps1
. .\\ADEnvironment.ps1

#Configure Local Variables
$sSourceDir = Get-Location
$rootDSE = (Get-ADRootDSE).defaultNamingContext

$Groups = Import-Csv $sSourceDir"\Groups.csv"
foreach ($Group in $Groups){
    $groupName = $Group.Name
    $groupOUPrefix = $Group.OU
    $destOU = $Group.OU + "," + $rootDSE
    $groupDN = "CN=" + $groupName + "," + $destOU
    #$groupDN = $Group.OU + "," + $rootDSE
    # Check if the target group already is present.
    $checkForGroup = Test-XADGroupObject $groupDN
    If (!$checkForGroup)
    {
        # The group is not present, creating group.
#        Add-Log -LogEntry("Creating the group " + $Group.Name + " in " + $groupDN)
        New-ADGroup -Name $Group.Name -SamAccountName $Group.samAccountName -GroupCategory $Group.GroupCategory -GroupScope $Group.GroupScope -DisplayName $Group.DisplayName -Path $destOU -Description $Group.Description

        If ($Group.Membership -ne ""){
#            Add-Log -LogEntry("Adding " + $Group.Name + " to " + $Group.Membership);
            Add-ADPrincipalGroupMembership -Identity $Group.samAccountName -MemberOf $Group.Membership;
            }
        $error.Clear()
    } 
    Else
    {
        # The group is present, log a message.
#        Add-Log -LogEntry("The group name " + $Group.Name + " already exists in the " + $destOU + " OU.")        
    }
}    

