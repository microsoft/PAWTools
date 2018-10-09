#Add-Log -LogEntry(Attempting to add Windows Feature RSAT-AD-PowerShell) 
Import-Module ServerManager
Add-WindowsFeature RSAT-AD-PowerShell | out-null
Import-Module ActiveDirectory

Function Get-ADInfo(){    
    $sDSE = (Get-ADRootDSE).defaultNamingContext
    return $sDSE
}

Function Get-OU($sName){
    $sOU=(Get-ADOrganizationalUnit -Filter {Name -like $sName}).DistinguishedName
    return $sOU
}

function Test-XADGroupObject() {
   [CmdletBinding()]
   Param (
      [Parameter(Mandatory=$true,
                 Position=0,
                 ValueFromPipeline=$true,
                 HelpMessage="Identity of the AD object to verify if exists or not."
                )]
      [Object] $Identity
   )
   trap [Exception] {
      return $false
   }
   $auxObject = Get-ADObject -Identity $Identity
   if ($auxObject = $Identity){
        return $true
   }
   else
   {
        return $false
   }
}

function Test-XADObject() {
   [CmdletBinding()]
   Param (
      [Parameter(Mandatory=$true,
                 Position=0,
                 ValueFromPipeline=$true,
                 HelpMessage="Identity of the AD object to verify if exists or not."
                )]
      [Object] $Identity
   )
   trap [Exception] {
      return $false
   }
   $auxObject = Get-ADObject -Identity $Identity
   return $true
}

Function Get-User($sName){
    $sUser=(Get-ADUser -Filter {Name -like $sName}).DistinguishedName
    return $sUser
}
