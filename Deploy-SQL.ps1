#Requires -Version 3.0

Param(
    [ValidateSet("DEV","TEST","DEVTEST","PREPROD","PROD")][string] $EnterpriseCloudEnvironment = '',
    [string] $ParametersFile = '',
    [string] $Series = '',
    [bool] $DscOnly = $false,
    [bool] $ValidateOnly = $false
)
Function Convert-CIDRToNetMask {
    [CmdletBinding()]
    Param(
        [ValidateRange(0,32)]
        [int16]$PrefixLength=0
    )
    $bitString=('1' * $PrefixLength).PadRight(32,'0')

    $strBuilder=New-Object -TypeName Text.StringBuilder

    for($i=0;$i -lt 32;$i+=8){
        $8bitString=$bitString.Substring($i,8)
        [void]$strBuilder.Append("$([Convert]::ToInt32($8bitString,2)).")
    }

    $strBuilder.ToString().TrimEnd('.')
}

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

[string] $ArtifactStagingDirectory = '.'
[string] $CredFileName = "AzureCred.json"
[string] $DSCSourceFolder = 'DSC'
[string] $TemplateFile = '.\sqlDeploy.json'
[string] $abcOuPath = ",OU=abc,OU=Servers,OU=Azure,OU=abc,DC=mydc,DC=gov"
[string] $GenericStorageAccountName = "abcdeveaststorgeneric"
[string] $GenericStorageContainerName = "provisioningfiles"
[string] $DeploymentStorageContainerName = "abcdeploymentartifacts"
[string] $AutomationAccountName = "abc-prod-int-east-automation"
[string] $AutomationAccountResourceGroup = "abc-prod-int-east-mgmt-rg"

$RegionsDev = @{
    EAST       = [pscustomobject]@('EAST', '20', 'USGovVirginia', 'ABC-DEVTEST-INT-EAST-ABC-RG', 'N73C-Subnet-02', 'ABC-DEVTEST-INT-EAST-NETWORK-RG', 'ABC-GOV-DEVTEST-EAST')
    SOUTH      = [pscustomobject]@('SOUTH', '21', 'USGovTexas', 'ABC-DEVTEST-INT-SOUTH-ABC-RG', 'N75C-Subnet-02', 'ABC-DEVTEST-INT-SOUTH-NETWORK-RG', 'ABC-GOV-DEVTEST-SOUTH') 
}
$RegionsTest = @{
    EAST       = [pscustomobject]@('EAST', '20', 'USGovVirginia', 'ABC-DEVTEST-INT-EAST-ABC-RG', 'N73C-Subnet-01', 'ABC-DEVTEST-INT-EAST-NETWORK-RG', 'ABC-GOV-DEVTEST-EAST')
    SOUTH      = [pscustomobject]@('SOUTH', '21', 'USGovTexas', 'ABC-DEVTEST-INT-SOUTH-ABC-RG', 'N75C-Subnet-01', 'ABC-DEVTEST-INT-SOUTH-NETWORK-RG', 'ABC-GOV-DEVTEST-SOUTH') 
}
$RegionsPreProd = @{
    EAST       = [pscustomobject]@('EAST', '20', 'USGovVirginia', 'ABC-PREPROD-INT-EAST-ABC-RG', 'N73CA-Subnet-01', 'ABC-PREPROD-INT-EAST-NETWORK-RG', 'ABC-GOV-PREPROD-EAST')
    SOUTH      = [pscustomobject]@('SOUTH', '21', 'USGovTexas', 'ABC-PREPROD-INT-SOUTH-ABC-RG', 'N75CA-Subnet-01', 'ABC-PREPROD-INT-SOUTH-NETWORK-RG', 'ABC-GOV-PREPROD-SOUTH') 
}
$RegionsProd = @{
    EAST       = [pscustomobject]@('EAST', '20', 'USGovVirginia', 'ABC-PROD-INT-EAST-ABC-RG', 'N73CB-Subnet-03', 'ABC-PROD-INT-EAST-NETWORK-RG', 'ABC-GOV-PROD-EAST')
    SOUTH      = [pscustomobject]@('SOUTH', '21', 'USGovTexas', 'ABC-PROD-INT-SOUTH-ABC-RG', 'N75CB-Subnet-01', 'ABC-PROD-INT-SOUTH-NETWORK-RG', 'ABC-GOV-PROD-SOUTH') 
}

if($env:AGENT_NAME)
{
    # If we are here, we're running in ADOS pipeline
    Write-Output "Running from an ADOS pipeline agent"
    $Series = $env:Series
    $EnterpriseCloudEnvironment = $env:EnterpriseCloudEnvironment
    $ParametersFile = $env:ParametersFile
    $ValidateOnly = [System.Convert]::ToBoolean($env:ValidateOnly)
    $DscOnly = [System.Convert]::ToBoolean($env:DscOnly)
}
else
{
    Write-Output "Running manually from PS so must get the Azure Credential Context"
    $CredFileName = 'AzureCred.json'
    $CredFile = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($ENV:UserProfile, $CredFileName))
    Import-AzContext -path $CredFile
}

if([string]::IsNullOrEmpty($Series))
{
    throw "Series parameter must be passed in at runtime"
}

if([string]::IsNullOrEmpty($EnterpriseCloudEnvironment))
{
    throw "EnterpriseCloudEnvironment parameter must be passed in at runtime"
}

if([string]::IsNullOrEmpty($ParametersFile))
{
    throw "ParametersFile parameter must be passed in at runtime"
}

# Convert relative paths to absolute paths
$TemplateFile = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, $TemplateFile))
$ParametersFile = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, $ParametersFile))
$ArtifactStagingDirectory = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, $ArtifactStagingDirectory))
$DSCSourceFolder = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, $DSCSourceFolder))

Write-Output "TemplateFile: $TemplateFile"
Write-Output "ParametersFile: $ParametersFile"
Write-Output "ArtifactStagingDirectory: $ArtifactStagingDirectory"
Write-Output "DSCSourceFolder: $DSCSourceFolder"

# Get the parameters from JSON
$jsonObj = Get-Content $ParametersFile | ConvertFrom-Json

# Get environment mapping
$prRegion = $null
$drRegion = $null
$ouTargetName = $EnterpriseCloudEnvironment

if($EnterpriseCloudEnvironment -eq 'DEV')
{
    $prRegion = $RegionsDev[$jsonObj.parameters.prRegion.value]
    $drRegion = $RegionsDev[$jsonObj.parameters.drRegion.value]
    $ouTargetName = 'DEV'
    # Now that subnet lookup is complete (because dev and test are different) we need to combine devtest
    $EnterpriseCloudEnvironment = 'DEVTEST'
}
elseif($EnterpriseCloudEnvironment -eq 'TEST')
{
    $prRegion = $RegionsTest[$jsonObj.parameters.prRegion.value]
    $drRegion = $RegionsTest[$jsonObj.parameters.drRegion.value]
    $ouTargetName = 'DEV'
    # Now that subnet lookup is complete (because dev and test are different) we need to combine devtest
    $EnterpriseCloudEnvironment = 'DEVTEST'
}
elseif($EnterpriseCloudEnvironment -eq 'PREPROD')
{
    $prRegion = $RegionsPreProd[$jsonObj.parameters.prRegion.value]
    $drRegion = $RegionsPreProd[$jsonObj.parameters.drRegion.value]
    $ouTargetName = 'NPROD'
}
elseif($EnterpriseCloudEnvironment -eq 'PROD')
{
    $prRegion = $RegionsProd[$jsonObj.parameters.prRegion.value]
    $drRegion = $RegionsProd[$jsonObj.parameters.drRegion.value]
    $ouTargetName = 'PROD'
}

# Remap the parameters
$ResourceGroupName = $prRegion[3]
Write-Host "Primary resource group: $ResourceGroupName"

# Update the AG owners, this isnt ideal, but so far we are fixed to two AGs
[PSCustomObject]$agsInfo = @{} 
$agsInfo = $jsonObj.parameters.agsInfo.value
$vMsInfo = $jsonObj.parameters.vMsInfo.value
$agsInfo[0].primaryReplicaName = $vMsInfo[0].name
$agsInfo[1].primaryReplicaName = $vMsInfo[1].name

$sqlVmNames = @()
$seriesCheck = $false

foreach($vmInfo in $vMsInfo)
{
    $sqlVmNames += $vmInfo.name

    if($vmInfo.drNode -eq 'false')
    {
        $vmInfo.location = $prRegion[2]
    }
    else {
        $vmInfo.location = $drRegion[2]
    }

    # Check to make sure the parameters files and series match
    if($vmInfo.name -like "*$($series)")
    {
        $seriesCheck = $true;
    }
}

if(-not $seriesCheck)
{
    throw "Series and VM Names do not match, did you edit the parameters file correctly?"
}

Write-Host "Getting Resource Group location"
$ResourceGroupLocation = (Get-AzResourceGroup -Name $ResourceGroupName).Location
Write-Host "Resource Group location: $ResourceGroupLocation"

# Create the deployment storage account name
$DeploymentStorageAccountName = ("###" + $EnterpriseCloudEnvironment + $prRegion[0] + "stor" + $Series).ToLower()

# Used to store additional\optional parameters
$OptionalParameters = New-Object -TypeName Hashtable
$OptionalParameters['series'] = $Series
$OptionalParameters['dscOnly'] = $DscOnly
$OptionalParameters['EnterpriseCloudEnvironment'] = $EnterpriseCloudEnvironment
$OptionalParameters['prRegion'] = $prRegion
$OptionalParameters['drRegion'] = $drRegion
$OptionalParameters['targetOuPath'] = ("OU=$ouTargetName" + $###OuPath)

# Get the subnet masks for the subnets
$prVnet = Get-AzVirtualNetwork -Name $prRegion[6]
$drVnet = Get-AzVirtualNetwork -Name $prRegion[6]
[int32]$prMaskLength = (Get-AzVirtualNetworkSubnetConfig -Name $prRegion[4] -VirtualNetwork $prVnet).AddressPrefix.split('/')[1]
[int32]$drMaskLength = (Get-AzVirtualNetworkSubnetConfig -Name $prRegion[4] -VirtualNetwork $drVnet).AddressPrefix.split('/')[1]

$OptionalParameters['sqlListenerSubnet'] = Convert-CIDRToNetMask $prMaskLength
$OptionalParameters['drSqlListenerSubnet'] = Convert-CIDRToNetMask $drMaskLength

Write-Host "Primary Region SQL Subnet Mask: $($OptionalParameters['sqlListenerSubnet'])"
Write-Host "DR Region SQL Subnet Mask: $($OptionalParameters['drSqlListenerSubnet'])"

Write-Host "Getting Deployment Storage Account"
$StorageSku = $jsonObj.parameters.storageAccountType.value

if($EnterpriseCloudEnvironment -eq 'PROD')
{
    $StorageSku = 'Standard_GRS'
}

# Get the deployment storage account (deployment artifacts get uploaded here)
$DeploymentStorageAccount = (Get-AzStorageAccount | Where-Object {$_.StorageAccountName -eq $DeploymentStorageAccountName})

# Create the storage account if it doesn't already exist
if ($null -eq $DeploymentStorageAccount) {
    Write-Host "Creating storage account: $DeploymentStorageAccountName"
    $DeploymentStorageAccount = New-AzStorageAccount -StorageAccountName $DeploymentStorageAccountName -Type $StorageSku `
        -ResourceGroupName $ResourceGroupName -Location $ResourceGroupLocation -Kind "StorageV2" -AllowBlobPublicAccess $false

    New-AzStorageContainer -Name $DeploymentStorageContainerName.ToLower() -Context $DeploymentStorageAccount.Context -Permission Off -ErrorAction SilentlyContinue *>&1
}

if($null -eq $DeploymentStorageAccount)
{
    throw "Could not create the storage account: $DeploymentStorageAccountName"
}

$OptionalParameters['deploymentStorageAccountName'] = $DeploymentStorageAccount.StorageAccountName

Write-Output "Deployment Storage Account: $DeploymentStorageAccountName"

# Generate a 20 year SAS token for the artifacts location if one was not provided in the parameters file
$DeploymentStorageAccountSasTokenParameterName = 'deploymentStorageAccountSasToken'
$OptionalParameters[$DeploymentStorageAccountSasTokenParameterName] = ConvertTo-SecureString -AsPlainText -Force `
   (New-AzStorageContainerSASToken -Container $DeploymentStorageContainerName -Context $DeploymentStorageAccount.Context -Permission r -ExpiryTime (Get-Date).AddYears(20))

Write-Output "DeploymentStorageAccountSasToken: ", $OptionalParameters[$DeploymentStorageAccountSasTokenParameterName]

# Copy deployment content (DSC, nested templates, etc) to deployment storage account
[string[]]$uploadPaths = @($DSCSourceFolder, [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, 'nested')))
$ArtifactFilePaths = (Get-ChildItem $uploadPaths).FullName
foreach ($SourcePath in $ArtifactFilePaths) {
    Write-Output "Copying $SourcePath to $DeploymentStorageContainerName"
    Set-AzStorageBlobContent -File $SourcePath -Blob $SourcePath.Substring($ArtifactStagingDirectory.length + 1) `
        -Container $DeploymentStorageContainerName.ToLower() -Context $DeploymentStorageAccount.Context -Force
}

# Get the generic storage account
$GenericStorageAccount = (Get-AzStorageAccount | Where-Object{$_.StorageAccountName -eq $GenericStorageAccountName})

Write-Output "Generic Storage Account: $GenericStorageAccountName"

# Generate a 20 year SAS token for the generic storage account (needed for the installation files)
$GenericStorageAccountSasTokenParameterName = 'genericStorageAccountSasToken'
$OptionalParameters[$GenericStorageAccountSasTokenParameterName] = ConvertTo-SecureString -AsPlainText -Force `
   (New-AzStorageContainerSASToken -Container $GenericStorageContainerName -Context $GenericStorageAccount.Context -Permission r -ExpiryTime (Get-Date).AddYears(20))

Write-Output "GenericStorageAccountSasToken: ", $OptionalParameters[$GenericStorageAccountSasTokenParameterName]

if ($ValidateOnly) {
    $ErrorMessages = Test-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName `
                                                    -TemplateFile $TemplateFile `
                                                    -TemplateParameterFile $ParametersFile `
                                                    @OptionalParameters
    if ($ErrorMessages) {
        Write-Output '', 'Validation returned the following errors:', @($ErrorMessages), '', 'Template is invalid.'
    }
    else {
        Write-Output '', 'Template is valid.'
    }
}
else {
    New-AzResourceGroupDeployment -Name ((Get-ChildItem $TemplateFile).BaseName + "_$Series") `
        -ResourceGroupName $ResourceGroupName `
        -TemplateFile $TemplateFile `
        -TemplateParameterFile $ParametersFile `
        @OptionalParameters `
        -ErrorVariable ErrorMessages `
        -ErrorAction SilentlyContinue `
        -Force -Verbose
}                         

$deploymentFailed = $false

if ($ErrorMessages)
{

    Write-Host "Deployment errors occurred.  Checking criticality."
    
    foreach($sqlVM in $sqlVmNames)
    {
        Write-Host "Checking $sqlVM"
        
        # See if the VM was created
        $vmObj = Get-AzVM -Name $sqlVM | Where-Object {$_.ProvisioningState -eq 'Succeeded'}
        if($vmObj)
        {
            Write-Host "$sqlVM VM provisioned successfully!" -ForegroundColor Green

            # Check to see if the VM is registered into the Automation Account

            $dscNode = Get-AzAutomationDscNode -ResourceGroupName $AutomationAccountResourceGroup -AutomationAccountName $AutomationAccountName -Name $sqlVM
            if($dscNode)
            {
                Write-Host "  $sqlVM registered with DSC!" -ForegroundColor Green
            }
            else 
            {
                $deploymentFailed = $true
            }
        }
        else
        {
            $deploymentFailed = $true
        }

    }

    if($deploymentFailed)
    {
        throw "Template deployment returned the errors.  Check the deployments section of the Resource Group to get the error details"
    }

    # Check if the CNO is enabled
    $cnoName = 'DSC' + $prRegion[1] + 'SCLU###' + $series
    Write-Host "Checking for the existence of: $cnoName"
    if((Get-ADComputer -Identity $cnoName).Enabled -eq $false)
    {
        throw "Template deployment returned the errors.  Check the deployments section of the Resource Group to get the error details"
    }
    
}

# If the deployment worked, create the SQL VM Resources
if($deploymentFailed -eq $false)
{
    foreach($sqlVM in $sqlVmNames)
    {
        
        Write-Host "Checking the VM resource for $sqlVM"
        $vm = Get-AzVM -Name $sqlVM -ResourceGroupName $ResourceGroupName
        if($vm)
        {
            $sqlSku = 'Developer'
            $licenseType = 'PAYG'
            # Determine the SKU to deploy
            if($jsonObj.parameters.sqlSku.value -ne 'SQLDEV')
            {
                $sqlSku = 'Enterprise'
                $licenseType = 'AHUB'
                if($vMsInfo.length -eq 3)
                {
                    if($sqlVM -eq $vMsInfo[2].name)
                    {
                        $licenseType = 'DR'
                    }
                }
            }

            Write-Host "Checking the SQL VM resource for $sqlVM"
            if(-not (Get-AzSqlVM -Name $vm.Name -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue))
            {
                Write-Host "Registering the SQL VM resource on $sqlVM"
                Write-Host "SQL licensing will be Sku: $sqlSku, LicenseType: $licenseType"
                New-AzSqlVM -Name $vm.Name -ResourceGroupName $ResourceGroupName -Location $vm.Location -LicenseType $licenseType -Sku $sqlSku -SqlManagementType Full
            }
            else 
            {
                Write-Host "SQL VM Resource already exist"
            }
        }
        else
        {
            Write-Host "$sqlVM does not exist as a VM"
        }
    }
}

# If we are here, the ARM template provisioning should have worked
Write-Host "ARM deployment succeeded" -ForegroundColor Green