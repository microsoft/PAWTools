@{
	# Script module or binary module file associated with this manifest
	ModuleToProcess = 'PAWTools.psm1'
	
	# Version number of this module.
	ModuleVersion = '1.0.0.0'
	
	# ID used to uniquely identify this module
	GUID = 'a5ba9e8f-d1df-41ed-a40e-3f75ad2a62c5'
	
	# Author of this module
	Author = 'Friedrich Weinmann'
	
	# Company or vendor of this module
	CompanyName = 'Microsoft'
	
	# Copyright statement for this module
	Copyright = 'Copyright (c) 2018 Friedrich Weinmann'
	
	# Description of the functionality provided by this module
	Description = 'Provides tools that support implementing Privileged Access Workstations in a Active Directory Forest'
	
	# Minimum version of the Windows PowerShell engine required by this module
	PowerShellVersion = '5.0'
	
	# Modules that must be imported into the global environment prior to importing
	# this module
	# RequiredModules = @( )
	
	# Assemblies that must be loaded prior to importing this module
	# RequiredAssemblies = @('bin\PAWTools.dll')
	
	# Type files (.ps1xml) to be loaded when importing this module
	# TypesToProcess = @('xml\PAWTools.Types.ps1xml')
	
	# Format files (.ps1xml) to be loaded when importing this module
	# FormatsToProcess = @('xml\PAWTools.Format.ps1xml')
	
	# Functions to export from this module
	FunctionsToExport = @(
		'Export-PAWResources'
		'Install-PAWPrerequisites'
		'New-PAWGroup'
		'New-PAWOrganizationalUnit'
		'Set-PAWOUDelegation'
	)
	
	# Cmdlets to export from this module
	CmdletsToExport = ''
	
	# Variables to export from this module
	VariablesToExport = ''
	
	# Aliases to export from this module
	AliasesToExport = ''
	
	# List of all modules packaged with this module
	ModuleList = @()
	
	# List of all files packaged with this module
	FileList = @()
	
	# Private data to pass to the module specified in ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
	PrivateData = @{
		
		#Support for PowerShellGet galleries.
		PSData = @{
			
			# Tags applied to this module. These help with module discovery in online galleries.
			# Tags = @()
			
			# A URL to the license for this module.
			# LicenseUri = ''
			
			# A URL to the main website for this project.
			# ProjectUri = ''
			
			# A URL to an icon representing this module.
			# IconUri = ''
			
			# ReleaseNotes of this module
			# ReleaseNotes = ''
			
		} # End of PSData hashtable
		
	} # End of PrivateData hashtable
}