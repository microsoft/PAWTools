function New-PAWGroup
{
<#
	.SYNOPSIS
		Generates the default groups needed for a PAW setup.
	
	.DESCRIPTION
		Generates the default groups needed for a PAW setup.
	
	.PARAMETER Confirm
		If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
	
	.PARAMETER WhatIf
		If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
	
	.EXAMPLE
		PS C:\> New-PAWGroup
	
		Generates the default groups needed for a PAW setup.
#>
	[CmdletBinding(SupportsShouldProcess = $true)]
	param (
		
	)
	
	try { Assert-ActiveDirectory -ErrorAction Stop }
	catch { throw }
	
	$rootDSE = Get-ADInfo
	
	$Groups = Get-Content "$($script:ModuleRoot)\data\groups.json" -Raw -Encoding UTF8 | ConvertFrom-Json
	foreach ($group in $Groups)
	{
		$destOU = '{0},{1}' -f $group.OU, $rootDSE
		
		# Check if the target group already is present.
		if (Test-XADObject $group.samAccountName)
		{
			$object = Get-ADObject -Identity $group.samAccountName
			Write-Warning "Group $($group.samAccountName) already exists as $($object.DistinguishedName)"
			continue
		}
		
		$paramNewADGroup = @{
			Name = $group.Name
			SamAccountName = $group.samAccountName
			GroupCategory = $group.GroupCategory
			GroupScope = $group.GroupScope
			DisplayName = $group.DisplayName
			Path = $destOU
			Description = $group.Description
		}
		if ($PSCmdlet.ShouldProcess($group.Name, 'Creating Group'))
		{
			Write-Verbose "Creating group: $($group.Name)"
			New-ADGroup @paramNewADGroup
		}
		
		if ($group.Membership)
		{
			if ($PSCmdlet.ShouldProcess($group.Name, 'Adding Members to it'))
			{
				Write-Verbose "Adding members: $($group.Membership -join ', ')"
				Add-ADPrincipalGroupMembership -Identity $group.samAccountName -MemberOf $group.Membership
			}
		}
	}
}