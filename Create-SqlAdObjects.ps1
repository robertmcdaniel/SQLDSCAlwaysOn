##########################################################################################
#
#
# This script is designed to create the needed SQL AD objects (Cluster, VNNs, etc)
#
#
##########################################################################################

Param(
    [string] $series = '',
    [string] $parametersFile = ''
)

$stagingOuPath = "OU=Staging,OU=abc,OU=Servers,OU=Azure,OU=abc,DC=mydc,DC=gov"
$keyVaultName = 'abc-mgmtkv-prod'

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if($env:AGENT_NAME)
{
    # If we are here, we're running in ADOS pipeline
    Write-Host "Running from an ADOS pipeline agent"
    $series = $env:series
    $parametersFile = $env:parametersFile
}
else
{
    Write-Host "Running manually from PS so must get the Azure Credential Context"
    $CredFileName = 'AzureCred.json'
    $CredFile = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($ENV:UserProfile, $CredFileName))
    Import-AzContext -path $CredFile
}

if([string]::IsNullOrEmpty($series))
{
    throw 'Must provide the series parameter value'
}

$parametersFile = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, $parametersFile))

# Get the deployment variables
$jsonObj = Get-Content $parametersFile | ConvertFrom-Json
$domainJoinUser = $jsonObj.parameters.domainJoinUser.value
$sqlAdminUser = $jsonObj.parameters.sqlAdminUser.value
$gMsaSqlGroupName = $jsonObj.parameters.gMsaSqlGroupName.value

$prRegion = $jsonObj.parameters.prRegion.value
$EnterpriseCloudRegionCode = 'DSCA20'
switch($prRegion)
{
    'SOUTH' {$EnterpriseCloudRegionCode = 'DSCA21'}
    'SOUTHWEST' {$EnterpriseCloudRegionCode = 'DSCA23'}
}

Write-Host "Getting domain join user creds"
[securestring]$domainJoinPassword = (Get-AzKeyVaultSecret -VaultName $keyVaultName -Name ($domainJoinUser.Split('\')[1])).SecretValue
$domainJoinCred = New-Object System.Management.Automation.PSCredential($domainJoinUser, $domainJoinPassword)

Write-Host "Getting SQL Admin user creds"
[securestring]$sqlAdminPassword = (Get-AzKeyVaultSecret -VaultName $keyVaultName -Name ($sqlAdminUser.Split('\')[1])).SecretValue
$sqlAdminCred = New-Object System.Management.Automation.PSCredential($sqlAdminUser, $sqlAdminPassword)

Write-Host "Getting a mydc.gov DC for the ps drive"

# Get a DC and map a new PS drive for AD
$domainController = (Get-ADDomainController -DomainName 'mydc.gov' -Discover -Service ADWS).Name
New-PSDrive -name AD2 -PSProvider ActiveDirectory -Root '//RootDSE/' -Server $domainController -Credential $domainJoinCred -ErrorAction SilentlyContinue

# Create the SQL Computer Objects
Write-Host "Preparing AD objects for the environment"
foreach($vmName in $jsonObj.parameters.vMsInfo.value.Name)
{
    $adObj = Get-ADComputer -Filter 'Name -eq $vmName' -Server $domainController
    if($null -eq $adObj)
    {
        Write-Host "Creating AD Object $vmName"
        $adObj = New-ADComputer -Name $vmName -path $stagingOuPath -Credential $domainJoinCred -ErrorAction Stop -Server $domainController -PassThru
    }
    
    $gmsaGroup = $jsonObj.parameters.gMsaSqlGroupName.value
    $AdGroupMember = Get-ADGroupMember -Identity $gmsaGroup -Server $domainController | Where-Object {$_.distinguishedName -eq $adObj.DistinguishedName}
    if($null -eq $AdGroupMember)
    {
        Write-Host "Adding $($($adObj).DistinguishedName) to $gmsaGroup"
        Add-ADGroupMember -Identity $gmsaGroup -Members $adObj.DistinguishedName -Server $domainController -Credential $sqlAdminCred
    }
    
}

$cnoName = $##ecPrRegionCode + 'SCLUAES' + $series
Write-Host "Checking for the existence of: $cnoName"

# Check for the existence of the Cluster and VNN AD Objects
if($null -eq (Get-ADComputer -Filter 'Name -like $cnoName' -Server $domainController))
{
    # Try to create the Cluster CNO
    Write-Host "Creating $cnoName"
    New-ADComputer -Name $cnoName -path $stagingOuPath -Enabled $false -Credential $domainJoinCred -Server $domainController
}

# Grant the domain join account full control on the CNO
Write-Host "Checking permissions on $cnoName for $domainJoinUser"
$cnoObj = Get-ADComputer -Identity $cnoName -Server $domainController -Credential $domainJoinCred
$userObj = Get-ADUser -Identity $domainJoinUser.split('\')[1] 
$path = "AD2:\$($($cnoObj).DistinguishedName)"
Write-Host "Path: $path"
$acl = Get-Acl -Path $path
$existingAce = $acl.Access | Where-Object {$_.ActiveDirectoryRights -eq 'GenericAll' -and $_.IdentityReference -like "*$domainJoinUser*" -and $_.AccessControlType -eq 'Allow'}
if($null -eq $existingAce)
{
    Write-Host "Granting permissions on $cnoName for $domainJoinUser"
    $identity = [System.Security.Principal.SecurityIdentifier]$userObj.SID
    $adRights = [System.DirectoryServices.ActiveDirectoryRights]'GenericAll'
    $type = [System.Security.AccessControl.AccessControlType]'Allow'
    $inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'All'
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $adRights, $type, $inheritance)
    Write-Host "Adding access rule"
    $acl.AddAccessRule($ace)
    Set-Acl -AclObject $acl -Path $path
    Write-Host "Granted on $cnoName"
}

# Grant the computer object Full Control on the CNO
$comp = $jsonObj.parameters.vmsInfo.value[0].Name
Write-Host "Checking permissions on $cnoName for $comp"
$cnoObj = Get-ADComputer -Identity $cnoName -Server $domainController -Credential $domainJoinCred
$compObj = Get-ADComputer -Identity $comp -Server $domainController -Credential $domainJoinCred
$path = "AD2:\$($($cnoObj).DistinguishedName)"
Write-Host "Path: $path"
$acl = Get-Acl -Path $path
$existingAce = $acl.Access | Where-Object {$_.ActiveDirectoryRights -eq 'GenericAll' -and $_.IdentityReference -like "*$comp*" -and $_.AccessControlType -eq 'Allow'}
if($null -eq $existingAce)
{
    Write-Host "Granting permissions on $cnoName for $comp"
    $identity = [System.Security.Principal.SecurityIdentifier]$compObj.SID
    $adRights = [System.DirectoryServices.ActiveDirectoryRights]'GenericAll'
    $type = [System.Security.AccessControl.AccessControlType]'Allow'
    $inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'All'
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $adRights, $type, $inheritance)
    Write-Host "Adding access rule"
    $acl.AddAccessRule($ace)
    Set-Acl -AclObject $acl -Path $path
    Write-Host "Granted on $cnoName"
}

foreach($ag in $jsonObj.parameters.agsInfo.value)
{
    if($ag.ListenerName -like '*vnn*')
    {
        $vnnName = $ag.ListenerName
        if($null -eq (Get-ADComputer -Filter 'Name -like $vnnName'))
        {
            # Try to create the vnn
            Write-Host "Creating $vnnName"
            try
            {
                New-ADComputer -Name $vnnName -path $stagingOUPath -Enabled $false -ManagedBy "$cnoName$" -Credential $domainJoinCred -Server $domainController
            }
            catch
            {
                if($_.Exception.Message -notlike "*The specified account already exists*")
                {
                    throw $_.Exception.Message
                }
            }
        }

        # Grant the CNO full control
        Write-Host "Checking permissions on $vnnName for $cnoName"
        $comp = Get-ADComputer -Identity $cnoName -Server $domainController -Credential $domainJoinCred
        $vnnObj = Get-ADComputer -Identity $vnnName -Server $domainController -Credential $domainJoinCred
        $path = "AD2:\$($($vnnObj).DistinguishedName)"
        Write-Host "Path: $path"
        $acl = Get-Acl -Path $path
        $existingAce = $acl.Access | Where-Object {$_.ActiveDirectoryRights -eq 'GenericAll' -and $_.IdentityReference -like "*$cnoName*" -and $_.AccessControlType -eq 'Allow'}
        if($null -eq $existingAce)
        {
            Write-Host "Granting permissions on $vnnName for $cnoName"
            $identity = [System.Security.Principal.SecurityIdentifier]$comp.SID
            $adRights = [System.DirectoryServices.ActiveDirectoryRights]'GenericAll'
            $type = [System.Security.AccessControl.AccessControlType]'Allow'
            $inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'All'
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $adRights, $type, $inheritance)
            Write-Host "Adding access rule"
            $acl.AddAccessRule($ace)
            Set-Acl -AclObject $acl -Path $path
            Write-Host "Granted on $vnnName"
        }
    }
}