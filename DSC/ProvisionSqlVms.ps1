Configuration ProvisionSqlVms
{

    Import-DscResource -ModuleName StorageDsc
    Import-DscResource -ModuleName SqlServerDSC
    Import-DscResource -ModuleName xFailoverCluster
    Import-DscResource -ModuleName cUserRightsAssignment

    # Credentials from Azure Automation Account (these are considered global)
    $domainJoinCred              = Get-AutomationPSCredential -Name domainJoinCred
    $sqlAdminCred                = Get-AutomationPSCredential -Name sqlAdminCred
    $localAdminCred              = Get-AutomationPSCredential -Name localAdminCred

    # Variables from Azure Automation Account (these are considered global)
    #$genericStorageUrl           = Get-AutomationVariable -Name genericStorageUrl
    #$genericStorageSasToken      = Get-AutomationVariable -Name genericStorageSasToken
    $stagingOuPath               = Get-AutomationVariable -Name stagingOuPath
    $aesAdminGroup               = Get-AutomationVariable -Name aesAdminGroup
    $sqlAgentUser                = Get-AutomationVariable -Name sqlAgentUser
    $sqlSvcUser                  = Get-AutomationVariable -Name sqlSvcUser
    $gMsaSqlGroupName            = Get-AutomationVariable -Name gMsaSqlGroupName

    # Parameters that come from ConfigurationData (these are considered per-deployment)
    $witnessStorageBlobEndpoint  = $CONFIGURATIONDATA.NonNodeData.witnessStorageBlobEndpoint
    $witnessStorageAccountKey    = $CONFIGURATIONDATA.NonNodeData.witnessStorageAccountKey
    $agsInfoWithIps              = $CONFIGURATIONDATA.NonNodeData.agsInfoWithIps
    $clusterName                 = $CONFIGURATIONDATA.NonNodeData.clusterName
    $targetOuPath                = $CONFIGURATIONDATA.NonNodeData.targetOuPath
    $sqlVmNames                  = $CONFIGURATIONDATA.NonNodeData.sqlVmNames
    $drSqlListenerSubnet         = $CONFIGURATIONDATA.NonNodeData.drSqlListenerSubnet
    $sqlListenerSubnet           = $CONFIGURATIONDATA.NonNodeData.sqlListenerSubnet

    # Other variables
    $volumeLetters               = @('E','F','G','D')
    $prodVolumeLetters           = @('E','F','G','D','H',"I")
    $appDrive                    = 'D:'
    $tempFolder                  = "$appDrive\temp"
    $logDir                      = 'F:\SQL\LOG'
    $tempDataDir                 = 'S:\SQL\TEMPDB\DATA'
    $tempLogDir                  = 'S:\SQL\TEMPDB\LOG'
    $data0Dir                    = 'E:\SQL\DATA'   
    $data1Dir                    = 'H:\SQL\DATA'
    $data2Dir                    = 'I:\SQL\DATA'
    $data3Dir                    = 'G:\SQL\DATA'
    $sqlInstanceName             = 'MSSQLSERVER'
    $domainNetbiosName           = '##'
    $agGroupName                 = 'SQLAGNodes'
    $HostRecordTTL               = 300
    $basicAG                     = $false
    $dnToMsaAccounts             = "CN=Managed Service Accounts,DC=##,DC=gov"
    $clusterNetworkName          = 'Cluster Network 1'
    $ProdEnv                     = $false
    $ProdVMCheckRegex            = [RegEx] '[2][0-9][0-9]$' 




    # Needed for local admin group
    $localAdmins = @($($sqlAdminCred).UserName, $($domainJoinCred).UserName, $aesAdminGroup)

    # Remove duplicates
    $localAdmins = $localAdmins | Select-Object -uniq

    # Used for cloud storage
    $suri = [System.uri]$witnessStorageBlobEndpoint
    $uricomp = $suri.Host.split('.')
    $witnessStorageAccount = $uriComp[0]
    $witnessEndpoint = $uricomp[-3] + "." + $uricomp[-2] + "." + $uricomp[-1]

    Node $AllNodes.NodeName
    {
        if($AllNodes.NodeName -match $ProdVMCheckRegex)
        {
            $ProdEnv = $true
            $volumeLetters = $prodVolumeLetters

        }

        $sqlServerInstance = $Node.NodeName
        if($sqlInstanceName -ne 'MSSQLSERVER')
        {
            $sqlServerInstance = "$($Node.NodeName)\$sqlInstanceName"
        }
        
        Script SetTlsValue
        {
            GetScript = {
            }

            SetScript = {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            }

            TestScript = {
                return ([Net.ServicePointManager]::SecurityProtocol -like '*tls12*')
            }
        }
        
        Script InitializePsModules
        {
            GetScript = {
            }

            SetScript = {
                Install-Module -Name PackageManagement
                Install-PackageProvider -Name NuGet -Force
                Install-Module Az -Force -AllowClobber -Scope AllUsers
                Install-Module -Name SqlServer -Force -AllowClobber
                Install-Module -Name cUserRightsAssignment -Force -Scope AllUsers
            }

            TestScript = {
                $Status = (Get-PackageProvider -Name "NuGet" -errorAction SilentlyContinue) -and (Get-InstalledModule -Name Az.Storage -errorAction SilentlyContinue) `
                -and (Get-InstalledModule -Name SqlServer -errorAction SilentlyContinue) -and (Get-InstalledModule -Name cUserRightsAssignment -errorAction SilentlyContinue)
                $Status -eq $True
            }

            DependsOn = '[Script]SetTlsValue'
        }        

        # Region Initialize Disks
        Script InitializeDisk 
        {
            GetScript = {
                # Not Implemented
            }

            SetScript = {
                
                $drv = $null
                $drv = Get-WmiObject win32_volume -filter 'DriveLetter = "E:" and FileSystem <> "NTFS"'   

                if($drv)
                {
                    Write-Host "Reassigning the DVD drive letter"
                    $drv.DriveLetter = "V:"
                    $drv.Put() | out-null
                }

                $drv = $null
                $drv = Get-WmiObject win32_volume -filter 'DriveLetter = "D:"'
                if($drv)
                {
                    # We may have to reassign the pagefile to rename the d: drive
                    if($drv.Properties['Label'].Value -eq 'Temporary Storage')
                    {
                        $pageFile = Get-WmiObject Win32_PageFileSetting | Where-Object {$_.Name -like 'D:\*'}
                        if($pageFile)
                        {
                            Write-Host "Moving the pagefile"
                            $pageFile.Name = 'c:\pagefile.sys'
                            $pageFile.InitialSize = 0
                            $pageFile.MaximumSize = 0
                            $pageFile.Put()

                            $oldPageFile = Get-WmiObject Win32_PageFileSetting | Where-Object {$_.Name -like 'D:\*'}
                            if($oldPageFile)
                            {
                                Write-Host "Deleting the old pagefile"
                                $oldPageFile.Delete()
                            }
                            
                            $global:DSCMachineStatus = 1
                            return
                        }
                        Write-Host "Reassigning the Temp Storage drive letter"
                        $drv.DriveLetter = "S:"
                        $drv.Put() | out-null
                    }
                    
                  
                }
                
                $disks = $null
                while($disks -eq $null)
                {
                    Write-Host "Getting the raw disks"
                    $disks = Get-Disk | Where-Object partitionstyle -eq 'raw'
                    Start-Sleep -Seconds 15
                }

                foreach ($disk in $disks)
                {

                    Write-Host "Operating on disk: $($($disk).Number)"
                    
                    $driveLetter = $null
                    $label = $null

                    switch (($disk.Location).Split(':')[4].TrimStart(' '))
                    {

                        "LUN 0" {
                            $driveLetter = 'E'
                            $label = "DATA0"
                        }
                        "LUN 1"{
                            $driveLetter = 'G'
                            $label = "DATA3"
                        }
                        "LUN 2"{
                            $driveLetter = 'D'
                            $label = "APPS"
                        }
                        "LUN 3"{
                            $driveLetter = 'F'
                            $label = "LOG"
                        }
                        "LUN 4" {
                            $driveLetter = 'H'
                            $label = "DATA1"
                        }
                        "LUN 5" {
                            $driveLetter = 'I'
                            $label = "DATA2"
                        }

                    }
                    
                    if($label)
                    {
                        Write-Host "Initializing disk $driveLetter"
                        $disk | Initialize-Disk -PartitionStyle GPT -PassThru |
                        New-Partition -UseMaximumSize -DriveLetter $driveLetter |
                        Format-Volume -FileSystem NTFS -NewFileSystemLabel $label -Confirm:$false -AllocationUnitSize 65536 -Force
                        Start-Sleep -Seconds 15
                    }
                    {
                        Write-Warning "Label is null for disk $($($disk).DiskNumber)"
                    }
                }
            }

            TestScript = {
                If((Get-Disk | Where-Object partitionstyle -eq 'raw').Count -gt 0)
                {
                    return $false
                }
                if(Get-Volume -FileSystemLabel 'Temporary Storage' | Where-Object {$_.DriveLetter -eq 'D'})
                {
                    return $false
                }
                
                return $true
            }
            
            DependsOn = '[Script]InitializePsModules'

        }

        # Region Configure Pagefile
        Script ConfigurePagefile 
        {
            GetScript = {
                # Not Implemented
            }

            SetScript = {
                $pf = Get-Volume -FileSystemLabel 'Temporary Storage' -ErrorAction SilentlyContinue
                if($pf)
                {
                    #$pfSize = ($pf.Size | Measure-Object -Sum).Sum/1MB
                    $pageFile = Get-WmiObject Win32_PageFileSetting | Where-Object {$_.Name -notlike 'S:\*'} | Select-Object -First 1
                    if($pageFile)
                    {
                        Write-Host "Setting the correct PageFile properties"
                        $pageFile.Name = 'S:\pagefile.sys'
                        $pageFile.InitialSize = 102400 #[math]::Floor($pfSize - ($pfSize * .1))
                        $pageFile.MaximumSize = 102400 #[math]::Floor($pfSize - ($pfSize * .1))
                        $pageFile.Put()

                        $oldPageFile = Get-WmiObject Win32_PageFileSetting | Where-Object {$_.Name -notlike 'S:\*'} | Select-Object -First 1
                        if($oldPageFile)
                        {
                            Write-Host "Removing the old PageFile"
                            $oldPageFile.Delete()
                        }
                                        
                        $global:DSCMachineStatus = 1
                    }
                }
            }

            TestScript = {
                if(Get-WmiObject Win32_PageFileSetting | Where-Object {$_.Name -notlike 'S:\*'})
                {
                    Write-Host "The PageFile is on the wrong volume"
                    return $false
                }
                $pf = Get-Volume -FileSystemLabel 'Temporary Storage' -ErrorAction SilentlyContinue
                if($pf)
                {
                    #$pfSize = ($pf.Size | Measure-Object -Sum).Sum/1MB
                    $pageFile = Get-WmiObject Win32_PageFileSetting
                    if($pageFile)
                    {
                        $bConfigured = $false
                        #if(([math]::Floor($pfSize - ($pfSize * .1)) -eq $pageFile.InitialSize) -and (([math]::Floor($pfSize - ($pfSize * .1)) -eq $pageFile.MaximumSize)))
                        if((102400 -eq $pageFile.InitialSize) -and (102400 -eq $pageFile.MaximumSize))
                        {
                            return $true
                        }

                    }

                    Write-Host "The PageFile is not configured correctly"
                }
                return $false
            }

            DependsOn = '[Script]InitializeDisk'
        }
        # Endregion Configure Pagefile

        foreach($volumeLetter in $volumeLetters)
        {
            WaitForVolume "WaitForVolume_$volumeLetter"
            {
                DriveLetter      = $volumeLetter
                RetryIntervalSec = 5
                RetryCount       = 20
                DependsOn        = '[Script]InitializeDisk'
            }
        }
        # Endregion Initialize Disks

        # Region Add Local Users to Admins Group (using a script resource because the Group resource cannot handle spaces
        # in usernames.  The SqlIaasExtension adds a account with the 'NT AUTHORITY' prefix causing the resource to error out.)
        Script AddUsersToAdmins 
        {
            GetScript = {
                # Not Implemented
            }

            SetScript = {
                foreach($localadmin in $using:localadmins)
                {
                    Write-Host "Adding $localadmin"
                    Add-LocalGroupMember -Group 'Administrators' -Member $localadmin -ErrorAction SilentlyContinue
                }
            }

            TestScript = {
                Write-Host "Checking the local administrators group"
                $members = (Get-LocalGroup -Name 'Administrators' | Get-LocalGroupMember).Name
                $trues = @()
                foreach($member in $members)
                {
                    Write-Host "Member: $member"
                    if($using:localadmins -contains $member)
                    {
                        Write-Host "Member matched"
                        $trues += $true
                    }
                }
                if($trues.Count -eq $using:localadmins.Count)
                {
                    return $true
                }
                else
                {
                    return $false
                }
            }

        }
        # Endregion Add Local Users to Admins Group
        
        # Region Disable Firewall
        Script DisableFirewall 
        {
            GetScript = {
                # Not Implemented
            }

            SetScript = {
                Set-NetFirewallProfile -Name 'Domain' -Enabled False -Verbose
            }

            TestScript = {
                $Status = -not('True' -in (Get-NetFirewallProfile -Name 'Domain').Enabled)
                $Status -eq $True
            }

            DependsOn = '[Script]InitializeDisk'
        }
        # Endregion Disable Firewall
        
        WindowsFeature AdPosh
        {
            Name      = 'RSAT-AD-PowerShell'
            Ensure    = 'Present'
            DependsOn = '[Script]DisableFirewall'
        }

        # Region Install Cluster
        WindowsFeature FC
        {
            Name      = 'Failover-Clustering'
            Ensure    = 'Present'
            DependsOn = '[WindowsFeature]AdPosh'
        }

        WindowsFeature FCMGMT
        {
            Name      = 'RSAT-Clustering-Mgmt'
            Ensure    = 'Present'
            DependsOn = '[WindowsFeature]FC'
        }

        WindowsFeature FCPS
        {
            Name      = 'RSAT-Clustering-PowerShell'
            Ensure    = 'Present'
            DependsOn = '[WindowsFeature]FC'
        }

        WindowsFeature FCCI
        {
            Ensure    = 'Present'
            Name      = 'RSAT-Clustering-CmdInterface'
            DependsOn = '[WindowsFeature]FCPS'
        }
        # Endregion Install Cluster

        # Region Install prerequisites for SQL Server
        WindowsFeature NetFramework35
        {
            Name      = 'NET-Framework-Core'
            Ensure    = 'Present'
            DependsOn = '[WindowsFeature]FCCI'
        }

        WindowsFeature NetFramework45
        {
            Name      = 'NET-Framework-45-Core'
            Ensure    = 'Present'
            DependsOn = '[WindowsFeature]NetFramework35'
        }
        # Endregion Install prerequisites for SQL Server

        File TempFolder
        {
            Type            = 'Directory'
            DestinationPath = $tempFolder
            Ensure          = "Present"
            DependsOn       = '[WaitForVolume]WaitForVolume_D'
        }

        File DataDbFolder0
        {
            Type            = 'Directory'
            DestinationPath = $data0Dir
            Ensure          = "Present"
            DependsOn       = '[WaitForVolume]WaitForVolume_E'
        }

        if ($ProdEnv)
        {
            File DataDbFolder1
            {
                Type            = 'Directory'
                DestinationPath = $data1Dir
                Ensure          = "Present"
                DependsOn       = '[WaitForVolume]WaitForVolume_H'
            }

            File DataDbFolder2
            {
                Type            = 'Directory'
                DestinationPath = $data2Dir
                Ensure          = "Present"
                DependsOn       = '[WaitForVolume]WaitForVolume_I'
            }
        }

        File LogDbFolder
        {
            Type            = 'Directory'
            DestinationPath = $logDir
            Ensure          = "Present"
            DependsOn       = '[WaitForVolume]WaitForVolume_F'
        }

        File DataDbFolder3
        {
            Type            = 'Directory'
            DestinationPath = $data3Dir
            Ensure          = "Present"
            DependsOn       = '[WaitForVolume]WaitForVolume_G'
        }

        # Make sure the servers in the gMSA AD Groups
        Script AddServerToGmsaGroup 
        {
            GetScript = {
                # Not Implemented
            }

            SetScript = {
                $serverName = $using:Node.NodeName + '$'
                Write-Host "Adding $serverName to $using:gMsaSqlGroupName"
                Add-ADGroupMember -Identity $using:gMsaSqlGroupName -Members $serverName
                # Allowing time for replication
                Start-Sleep -seconds 300
                $global:DSCMachineStatus = 1
            }

            TestScript = {
                $serverName = $using:Node.NodeName
                Write-Host "Checking for $serverName in group $using:gMsaSqlGroupName"
                $members = Get-ADGroup -Identity $using:gMsaSqlGroupName | Get-ADGroupMember
                if($members)
                {
                    return ($members.Name -contains $serverName)
                }
                return $false

            }

            PsDscRunAsCredential = $domainJoinCred
            DependsOn            = '[WindowsFeature]AdPosh'
        }

        # Install the gMSA accounts
        Script InstallGmsaAccounts 
        {
            GetScript = {
                # Not Implemented
            }

            SetScript = {
                $SqlSvcDn = 'CN=' + (($using:sqlSvcUser).Split('\')[1]).Trim('$') + ',' + $using:dnToMsaAccounts
                $SqlAgtDn = 'CN=' + (($using:sqlAgentUser).Split('\')[1]).Trim('$') + ',' + $using:dnToMsaAccounts
                Install-ADServiceAccount -Identity $SqlSvcDn
                Install-ADServiceAccount -Identity $SqlAgtDn
            }

            TestScript = {
                $SqlSvcDn = 'CN=' + (($using:sqlSvcUser).Split('\')[1]).Trim('$') + ',' + $using:dnToMsaAccounts
                Write-Host "SqlSvc account= $SqlSvcDn"
                $SqlAgtDn = 'CN=' + (($using:sqlAgentUser).Split('\')[1]).Trim('$') + ',' + $using:dnToMsaAccounts
                Write-Host "SqlAgt account= $SqlAgtDn"
                return ((Test-AdServiceAccount -Identity $SqlSvcDn) -and (Test-AdServiceAccount -Identity $SqlAgtDn))
            }

            DependsOn = '[WindowsFeature]AdPosh', '[Script]AddServerToGmsaGroup'

        }

        # Make sure the SQL Service account can manage the volumes for Instant File Initialization in SQL
        cUserRight GrantSqlServiceManageVolumePrivilege
        {
            Ensure = 'Present'
            Constant = 'SeManageVolumePrivilege'
            Principal = $sqlSvcUser
        }

        cUserRight GrantSqlServiceLockPagesPrivilege
        {
            Ensure = 'Present'
            Constant = 'SeLockMemoryPrivilege'
            Principal = $sqlSvcUser
        }

        # Check to see if SQL Service is running, this fixes a startup issue with gMSA service accounts
        Script CheckSqlService {
            GetScript = {
            }

            SetScript = {
                Write-Host "Starting the SQL Service"
                Start-Service -Name MSSQLSERVER -ErrorAction SilentlyContinue
            }

            TestScript = {
                Write-Host "Checking to ensure the SQL service is running"
                $service = Get-Service -Name MSSQLSERVER -ErrorAction SilentlyContinue
                if($service.Status -ne 'Running')
                {
                    # The service should be running
                    return $false
                }
                
                # will default to returning true for now as this is a optional and limited scenario check
                return $true
            }

            DependsOn = "[WindowsFeature]NetFramework45"
        }

        Script ChangeSqlServicesToGmsa {
            GetScript = {
            }

            SetScript = {
                Write-Host "Getting the SQL services"
                $sqlSvc = Get-WmiObject win32_service -filter "name=`'MSSQLSERVER`'" -ComputerName .
                $agtSvc = Get-WmiObject win32_service -filter "name=`'SQLSERVERAGENT`'" -ComputerName .
                Write-Host "Reconfiguring the SQL services"
                $sqlSvc.Change($null, $null, $null, $null, $null, $null, "$($using:sqlSvcUser)", "", $null, $null, $null)
                $agtSvc.Change($null, $null, $null, $null, $null, $null, "$($using:sqlAgentUser)", "", $null, $null, $null)
                Write-Host "Restarting the SQL services"
                Stop-Service -Name SQLSERVERAGENT -Force
                Stop-Service -Name MSSQLSERVER -Force
                Start-Sleep -Seconds 15
                Start-Service -Name MSSQLSERVER
                Start-Service -Name SQLSERVERAGENT
            }

            TestScript = {
                Write-Host "Checking the SQL service accounts"
                $sqlSvcStartName = (Get-WmiObject win32_service -filter "name=`'MSSQLSERVER`'" -ComputerName .).StartName
                $agtSvcStartName = (Get-WmiObject win32_service -filter "name=`'SQLSERVERAGENT`'" -ComputerName .).StartName
                if(($sqlSvcStartName -eq $using:sqlSvcUser) -and ($agtSvcStartName -eq $using:sqlAgentUser))
                {
                    return $true
                }
                return $false
            }

            DependsOn = '[Script]CheckSqlService', '[Script]InstallGmsaAccounts'
        }

        Script CheckSqlEngineService {
            GetScript = {
            }

            SetScript = {
                Write-Host "Starting the SQL Engine Service"
                sc.exe config MSSQLSERVER start= delayed-auto
                Start-Service -Name MSSQLSERVER -ErrorAction SilentlyContinue
            }

            TestScript = {
                Write-Host "Checking to ensure the SQL Engine service is running"
                $service = Get-Service -Name MSSQLSERVER -ErrorAction SilentlyContinue
                if($service.Status -ne 'Running')
                {
                    # The service should be running
                    return $false
                }
                try
                {
                    Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Services\MSSQLSERVER -Name DelayedAutoStart
                }
                catch
                {
                    #DelayedAutoStart value does not exist
                    return $false
                }
                if((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\MSSQLSERVER).DelayedAutoStart -eq 0)
                {
                    # The service is not configured for delay start
                    return $false
                }
                
                # will default to returning true for now as this is a optional and limited scenario check
                return $true
            }

            DependsOn = '[Script]ChangeSqlServicesToGmsa'
        }

        Script CheckSqlAgentService {
            GetScript = {
            }

            SetScript = {
                Write-Host "Starting the SQL Agent Service"
                sc.exe config SQLSERVERAGENT start= delayed-auto
                Start-Service -Name SQLSERVERAGENT -ErrorAction SilentlyContinue
            }

            TestScript = {
                Write-Host "Checking to ensure the SQL Agent service is running"
                $service = Get-Service -Name SQLSERVERAGENT -ErrorAction SilentlyContinue
                if($service.Status -ne 'Running')
                {
                    # The service should be running
                    return $false
                }
                try
                {
                    Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Services\SQLSERVERAGENT -Name DelayedAutoStart
                }
                catch
                {
                    #DelayedAutoStart value does not exist
                    return $false
                }
                if((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\SQLSERVERAGENT).DelayedAutoStart -eq 0)
                {
                    # The service is not configured for delay start
                    return $false
                }
                
                # will default to returning true for now as this is a optional and limited scenario check
                return $true
            }

            DependsOn = '[Script]ChangeSqlServicesToGmsa'
        }

        # Ensure SQL registers its SPNs
        Script "RegisterSPN_$($($Node).NodeName)"
        {

            GetScript = {
                # Not Implemented
            }

            SetScript = {
                Write-Host "Setting SPN registration on $($($using:Node).NodeName)"
                try
                {
                    Write-Host "Enabling xp_cmd"
                    $sqlCmd = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
                    Invoke-Sqlcmd -Query $sqlCmd
                    Write-Host "Registering NetBios with port"
                    $sqlCmd = "exec master.dbo.xp_cmdshell 'setspn -s MSSQLSvc/$($($using:Node).NodeName):1433 $using:sqlSvcUser'"
                    Invoke-Sqlcmd -Query $sqlCmd
                    Write-Host "Registering NetBios without port"
                    $sqlCmd = "exec master.dbo.xp_cmdshell 'setspn -s MSSQLSvc/$($($using:Node).NodeName) $using:sqlSvcUser'"
                    Invoke-Sqlcmd -Query $sqlCmd
                    Write-Host "Registering FQDN with port"
                    $sqlCmd = "exec master.dbo.xp_cmdshell 'setspn -s MSSQLSvc/$($($using:Node).NodeName).mydc.gov:1433 $using:sqlSvcUser'"
                    Invoke-Sqlcmd -Query $sqlCmd
                    Write-Host "Registering FQDN without port"
                    $sqlCmd = "exec master.dbo.xp_cmdshell 'setspn -s MSSQLSvc/$($($using:Node).NodeName).mydc.gov $using:sqlSvcUser'"
                    Invoke-Sqlcmd -Query $sqlCmd
                    Write-Host "Disabling xp_cmd"
                    $sqlCmd = "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE; EXEC sp_configure 'show advanced options', 0; RECONFIGURE;"
                    Invoke-Sqlcmd -Query $sqlCmd
                }
                catch
                {
                    Write-Host "An error occurred while attempting SPN registration"
                }
            }

            TestScript = {
                Write-Host "Checking for SPN registration on $($($using:Node).NodeName)"
                $results = setspn -l $using:sqlSvcUser
                $fqdnListener = $false
                $netbiosListener = $false
                $fqdnListenerNoPort = $false
                $netbiosListenerNoPort = $false
                foreach($result in $results)
                { 
                    if($result -like "*MSSQLSvc/$($($using:Node).NodeName):1433*")
                    {
                        Write-Host "Found NetBios with port"
                        $netbiosListener = $true
                    }
                    if($result -like "*MSSQLSvc/$($($using:Node).NodeName).mydc.gov:1433*")
                    {
                        Write-Host "Found FQDN with port"
                        $fqdnListener = $true
                    }
                    if($result -like "*MSSQLSvc/$($($using:Node).NodeName)*" -and $result -notLike "*:*")
                    {
                        Write-Host "Found NetBios without port"
                        $netbiosListenerNoPort = $true
                    }
                    if($result -like "*MSSQLSvc/$($($using:Node).NodeName).mydc.gov*" -and $result -notLike "*:*")
                    {
                        Write-Host "Found FQDN without port"
                        $fqdnListenerNoPort = $true
                    }
                }
                if(($fqdnListener -eq $true) -and ($netbiosListener -eq $true) -and ($fqdnListenerNoPort -eq $true) -and ($netbiosListenerNoPort -eq $true))
                {
                    return $true
                }
                return $false
            }

            PsDscRunAsCredential = $sqlAdminCred
            DependsOn            = "[Script]CheckSqlEngineService"
        }

        # Ensure there are no system service account registered SPNs
        Script "CheckForStaleSPNs_$($($Node).NodeName)"
        {

            GetScript = {
                # Not Implemented
            }

            SetScript = {
                Write-Host "Checking SPN registration on $($($using:Node).NodeName)"
                try
                {
                    $results = setspn -l $($($using:Node).NodeName) | findstr /i /s "MSSQLSvc/"
                    if($results.Count -gt 0)
                    {
                        foreach($result in $results)
                        {
                            Write-Host "Cleaning up SPN: $result"
                            $spnString = $result.Trim()
                            setspn -D $spnString $($($using:Node).NodeName)
                        }                        
                    }
                }
                catch
                {
                    Write-Host "An error occurred while attempting cleanup of SPNs"
                }
            }

            TestScript = {
                Write-Host "Checking for SPN registration on $($($using:Node).NodeName)"
                $results = setspn -l $($($using:Node).NodeName) | findstr /i /s "MSSQLSvc/"
                if($results.Count -gt 0)
                {
                    Write-Host "Found: $results"
                    return $false
                }
                return $true
            }

            DependsOn = "[Script]RegisterSPN_$($($Node).NodeName)"
        }

        # Enable SQL to listen on TCP
        Script "EnableTcpIp"
        {
            GetScript = {
                # Not Implemented
            }

            SetScript = {
                [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SqlWmiManagement')
                $wmi = New-Object 'Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer' localhost
                $tcp = $wmi.ServerInstances['MSSQLSERVER'].ServerProtocols['Tcp']
                $tcp.IsEnabled = $true
                $tcp.Alter()
                Restart-Service -Name MSSQLSERVER -Force
            }

            TestScript = {
                [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SqlWmiManagement')
                $wmi = New-Object 'Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer' localhost
                $tcp = $wmi.ServerInstances['MSSQLSERVER'].ServerProtocols['Tcp']
                return ($tcp.IsEnabled)
            }

            PsDscRunAsCredential = $localAdminCred
            DependsOn            = '[Script]CheckSqlService'
        }

        # Change SQL to mixed mode auth
        Script SetSqlAuthenticationMixed
        {
            GetScript = {
                # Not Implemented
            }

            SetScript = {
                $instanceKey = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL\').MSSQLSERVER
                if($instanceKey)
                {
                    Write-Host "Configuring SQL to use mixed mode authentication"
                    Set-ItemProperty -Path ("HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\" + $instanceKey + "\MSSQLSERVER") -Name LoginMode -Value 2
                    Write-Host "Restarting the SQL Service"
                    Stop-Service -Name MSSQLSERVER -Force
                    Start-Service -Name MSSQLSERVER
                }
                else
                {
                    Write-Host "SQL Instance registry key not found"
                }
            }

            TestScript = {
                $instanceKey = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL\').MSSQLSERVER
                if($instanceKey)
                {
                    $loginMode = (Get-ItemProperty -Path ("HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\" + $instanceKey + "\MSSQLSERVER")).LoginMode

                    if($loginMode)
                    {
                        if($loginMode -eq 2)
                        {
                            return $true
                        }
                    }
                    else
                    {
                        Write-Host "SQL Instance registry key not found"
                    }
                    
                    return $false
                }
            }

            DependsOn = '[Script]CheckSqlService'
        }

        # Region Set SQL Paths
        Script SetSqlPaths 
        {
            GetScript = {
                # Not Implemented
            }

            SetScript = {
                $instanceKey = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL\').MSSQLSERVER
                if($instanceKey)
                {
                    Set-ItemProperty -Path ("HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\" + $instanceKey + "\MSSQLSERVER") -Name DefaultData -Value $using:data0Dir
                    Set-ItemProperty -Path ("HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\" + $instanceKey + "\MSSQLSERVER") -Name DefaultLog -Value $using:logDir
                }
                Stop-Service -Name MSSQLSERVER -Force
                Start-Service -Name MSSQLSERVER
            }

            TestScript = {
                $instanceKey = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL\').MSSQLSERVER
                if($instanceKey)
                {
                    $dataPath = (Get-ItemProperty -Path ("HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\" + $instanceKey + "\MSSQLSERVER")).DefaultData
                    $logPath = (Get-ItemProperty -Path ("HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\" + $instanceKey + "\MSSQLSERVER")).DefaultLog

                    if($dataPath)
                    {
                        if($dataPath -ne $using:data0Dir)
                        {
                            return $false
                        }
                    }
                    else
                    {
                        return $false
                    }
                    if($logPath)
                    {
                        if($logPath -ne $using:logDir)
                        {
                            return $false
                        }
                    }
                    else
                    {
                        return $false
                    }

                    return $true
                }
            }

            DependsOn = '[Script]EnableTcpIp', '[File]LogDbFolder', '[File]DataDbFolder0'
        }
        # Endregion Set SQL Paths

        # Region Configure Temp DBs
        Script MoveSqlTempDb
        {
            GetScript = {
            }

            SetScript = {
                $tempDevPath = $using:tempDataDir + '\tempdb.mdf'
                $tempLogPath = $using:tempLogDir + '\templog.ldf'
                $temp2Path = $using:tempDataDir + '\temp2.ndf'
                Invoke-Sqlcmd -query "USE MASTER `
                    ALTER DATABASE TempDB MODIFY FILE (NAME = tempdev, SIZE = 25600MB, FILEGROWTH = 512MB, FILENAME = `'$tempDevPath`') `
                    ALTER DATABASE TempDB MODIFY FILE (NAME = templog, SIZE = 512MB, FILEGROWTH = 512MB, FILENAME = `'$tempLogPath`') `
                    ALTER DATABASE TempDB MODIFY FILE (NAME = temp2, SIZE = 25600MB, FILEGROWTH = 512MB, FILENAME = `'$temp2Path`')"
                Stop-Service -Name MSSQLSERVER -Force
                Start-Service -Name MSSQLSERVER
                }

            TestScript = {
                $tempDevPath = $using:tempDataDir + '\tempdb.mdf'
                $tempLogPath = $using:tempLogDir + '\templog.ldf'
                $temp2Path = $using:tempDataDir + '\temp2.ndf'
                $i = 0
                $results = Invoke-Sqlcmd -query "select name, physical_name, size, growth from sys.master_files where name like 'temp%'"
                foreach($result in $results)
                {
                    if($result.name -eq 'tempdev')
                    {
                        if(($result.physical_name -ne $tempDevPath) -and ($result.size -ne 65536) -and ($result.growth -ne 65536))
                        {
                            Write-Host "tempdev not configured correctly"
                            return $false
                        }
                        else 
                        {
                            $i++    
                        }
                    }
                    if($result.name -eq 'templog')
                    {
                        if(($result.physical_name -ne $tempLogPath) -and ($result.size -ne 65536) -and ($result.growth -ne 65536))
                        {
                            Write-Host "templog not configured correctly"
                            return $false
                        }
                        else 
                        {
                            $i++    
                        }
                    }
                    if($result.name -eq 'temp2')
                    {
                        if(($result.physical_name -ne $temp2Path) -and ($result.size -ne 65536) -and ($result.growth -ne 65536))
                        {
                            Write-Host "temp2 not configured correctly"
                            return $false
                        }
                        else 
                        {
                            $i++    
                        }
                    }
                }

                return $true
            }

            DependsOn = '[Script]EnableTcpIp', '[File]DataDbFolder3'
        }

        Script CleanupSqlTempDbFiles
        {
            GetScript = {
            }

            SetScript = {
                $instanceVal = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL\').MSSQLSERVER
                $sqlPath = $null

                if($instanceVal)
                {
                    Write-Host "Found SQL instance: $instanceVal"
                    $sqlPath = (Get-ItemProperty -Path ("HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\" + $instanceVal + "\Setup")).SQLPath
                }

                if($sqlPath)
                {
                    Write-Host "Found SQL installed at $sqlPath"
                    
                    if(Test-Path $sqlPath)
                    {
                        Write-Host "$sqlPath is valid"

                        if(Test-Path(Join-Path -Path $sqlPath -ChildPath "\DATA\tempdev.mdf"))
                        {
                            Write-Host "Deleting tempdev"
                            Remove-Item -Path (Join-Path -Path $sqlPath -ChildPath "\DATA\tempdev.mdf") -Force
                        }
                        if(Test-Path(Join-Path -Path $sqlPath -ChildPath "\DATA\templog.mdf"))
                        {
                            Write-Host "Deleting templog"
                            Remove-Item -Path (Join-Path -Path $sqlPath -ChildPath "\DATA\templog.mdf") -Force
                        }
                        if(Test-Path(Join-Path -Path $sqlPath -ChildPath "\DATA\tempdb_mssql_2.ndf"))
                        {
                            Write-Host "Deleting temp2"
                            Remove-Item -Path (Join-Path -Path $sqlPath -ChildPath "\DATA\tempdb_mssql_2.ndf") -Force
                        }
                        if(Test-Path(Join-Path -Path $sqlPath -ChildPath "\DATA\tempdb.mdf"))
                        {
                            Write-Host "Deleting tempdb"
                            Remove-Item -Path (Join-Path -Path $sqlPath -ChildPath "\DATA\tempdb.mdf") -Force
                        }
                        if(Test-Path(Join-Path -Path $sqlPath -ChildPath "\DATA\templog.ldf"))
                        {
                            Write-Host "Deleting templog"
                            Remove-Item -Path (Join-Path -Path $sqlPath -ChildPath "\DATA\templog.ldf") -Force
                        }
                    }
                }
            }

            TestScript = {
                $instanceVal = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL\').MSSQLSERVER
                $sqlPath = $null

                if($instanceVal)
                {
                    Write-Host "Found SQL instance: $instanceVal"
                    $sqlPath = (Get-ItemProperty -Path ("HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\" + $instanceVal + "\Setup")).SQLPath
                }

                if($sqlPath)
                {
                    Write-Host "Found SQL installed at $sqlPath"

                    if(Test-Path $sqlPath)
                    {
                        if(Test-Path(Join-Path -Path $sqlPath -ChildPath "\DATA\tempdev.mdf"))
                        {
                            Write-Host "tempdev DB found in old location"
                            return $false
                        }
                        if(Test-Path(Join-Path -Path $sqlPath -ChildPath "\DATA\templog.mdf"))
                        {
                            Write-Host "templog DB found in old location"
                            return $false
                        }
                        if(Test-Path(Join-Path -Path $sqlPath -ChildPath "\DATA\tempdb_mssql_2.ndf"))
                        {
                            Write-Host "temp2 DB found in old location"
                            return $false
                        }
                        if(Test-Path(Join-Path -Path $sqlPath -ChildPath "\DATA\tempdb.mdf"))
                        {
                            Write-Host "tempdb found in old location"
                            return $false
                        }
                        if(Test-Path(Join-Path -Path $sqlPath -ChildPath "\DATA\templog.ldf"))
                        {
                            Write-Host "templog found in old location"
                            return $false
                        }
                    }
                }

                return $true
            }

            DependsOn = '[Script]EnableTcpIp', '[File]DataDbFolder3', '[Script]MoveSqlTempDb'
        }

        Script CreateAdditionalTempDbs
        {
            GetScript = {
            }

            SetScript = {
                $temp3Path = $using:tempDataDir + '\temp3.ndf'
                $temp4Path = $using:tempDataDir + '\temp4.ndf'
                $temp5Path = $using:tempDataDir + '\temp5.ndf'
                $temp6Path = $using:tempDataDir + '\temp6.ndf'
                $temp7Path = $using:tempDataDir + '\temp7.ndf'
                $temp8Path = $using:tempDataDir + '\temp8.ndf'
                Invoke-Sqlcmd -query "USE MASTER `
                    IF NOT EXISTS(SELECT name FROM tempdb.sys.database_files WHERE name = 'temp3') `
                    BEGIN `
                        ALTER DATABASE [tempdb] ADD FILE (NAME = temp3, FILENAME = `'$temp3Path`' , SIZE = 25600MB , FILEGROWTH = 512MB) `
                    END `
                    IF NOT EXISTS(SELECT name FROM tempdb.sys.database_files WHERE name = 'temp4') `
                    BEGIN `
                        ALTER DATABASE [tempdb] ADD FILE (NAME = temp4, FILENAME = `'$temp4Path`' , SIZE = 25600MB , FILEGROWTH = 512MB) `
                    END `
                    IF NOT EXISTS(SELECT name FROM tempdb.sys.database_files WHERE name = 'temp5') `
                    BEGIN `
                        ALTER DATABASE [tempdb] ADD FILE (NAME = temp5, FILENAME = `'$temp5Path`' , SIZE = 25600MB , FILEGROWTH = 512MB) `
                    END `
                    IF NOT EXISTS(SELECT name FROM tempdb.sys.database_files WHERE name = 'temp6') `
                    BEGIN `
                        ALTER DATABASE [tempdb] ADD FILE (NAME = temp6, FILENAME = `'$temp6Path`' , SIZE = 25600MB , FILEGROWTH = 512MB) `
                    END `
                    IF NOT EXISTS(SELECT name FROM tempdb.sys.database_files WHERE name = 'temp7') `
                    BEGIN `
                        ALTER DATABASE [tempdb] ADD FILE (NAME = temp7, FILENAME = `'$temp7Path`' , SIZE = 25600MB , FILEGROWTH = 512MB) `
                    END `
                    IF NOT EXISTS(SELECT name FROM tempdb.sys.database_files WHERE name = 'temp8') `
                    BEGIN `
                        ALTER DATABASE [tempdb] ADD FILE (NAME = temp8, FILENAME = `'$temp8Path`' , SIZE = 25600MB , FILEGROWTH = 512MB) `
                    END"
                Stop-Service -Name MSSQLSERVER -Force
                Start-Service -Name MSSQLSERVER
                }

            TestScript = {
                $temp3Path = $using:tempDataDir + '\temp3.ndf'
                $temp4Path = $using:tempDataDir + '\temp4.ndf'
                $temp5Path = $using:tempDataDir + '\temp5.ndf'
                $temp6Path = $using:tempDataDir + '\temp6.ndf'
                $temp7Path = $using:tempDataDir + '\temp7.ndf'
                $temp8Path = $using:tempDataDir + '\temp8.ndf'
                $i = 0
                $results = Invoke-Sqlcmd -query "select name, physical_name from tempdb.sys.database_files"
                foreach($result in $results)
                {
                    if($result.name -eq 'temp3')
                    {
                        if($result.physical_name -ne $temp3Path)
                        {
                            Write-Host "temp3 DB does not have the correct file path"
                            return $false
                        }
                        else 
                        {
                            $i++    
                        }
                    }
                    if($result.name -eq 'temp4')
                    {
                        if($result.physical_name -ne $temp4Path)
                        {
                            Write-Host "temp4 DB does not have the correct file path"
                            return $false
                        }
                        else 
                        {
                            $i++    
                        }
                    }
                    if($result.name -eq 'temp5')
                    {
                        if($result.physical_name -ne $temp5Path)
                        {
                            Write-Host "temp5 DB does not have the correct file path"
                            return $false
                        }
                        else 
                        {
                            $i++    
                        }
                    }
                    if($result.name -eq 'temp6')
                    {
                        if($result.physical_name -ne $temp6Path)
                        {
                            Write-Host "temp6 DB does not have the correct file path"
                            return $false
                        }
                        else 
                        {
                            $i++    
                        }
                    }
                    if($result.name -eq 'temp7')
                    {
                        if($result.physical_name -ne $temp7Path)
                        {
                            Write-Host "temp7 DB does not have the correct file path"
                            return $false
                        }
                        else 
                        {
                            $i++    
                        }
                    }
                    if($result.name -eq 'temp8')
                    {
                        if($result.physical_name -ne $temp8Path)
                        {
                            Write-Host "temp8 DB does not have the correct file path"
                            return $false
                        }
                        else 
                        {
                            $i++    
                        }
                    }
                }

                if($i -eq 6)
                {
                    return $true
                }
                else
                {
                    Write-Host "Total number of configured DBs does not match expected value"
                }
                
                return $false
                
            }

            DependsOn = '[Script]EnableTcpIp', '[File]DataDbFolder3', '[Script]MoveSqlTempDb'
        }
        # Endregion Configure Temp DBs

        # Region Configure SQL
        $sqlNodesToInclude = @()
        Foreach ($sqlVmName in $sqlVmNames)
        {
            $sqlNodesToInclude += "$domainNetbiosName\$sqlVmName"
        }

        Group AddSqlNodesToLocalSecurityGroup
        {
            GroupName        = $agGroupName
            Ensure           = 'Present'
            MembersToInclude = $sqlNodesToInclude
            Credential       = $domainJoinCred
            DependsOn        = '[Script]CheckSqlService'
        }

        SqlLogin AddBobbyLogin
        {
            Ensure               = 'Present'
            Name                 = '##'
            LoginType            = 'WindowsUser'
            ServerName           = $Node.NodeName
            InstanceName         = $sqlInstanceName
            PsDscRunAsCredential = $localAdminCred
            DependsOn            = '[Script]EnableTcpIp'
        }

        SqlLogin AddJoeLogin
        {
            Ensure               = 'Present'
            Name                 = '##'
            LoginType            = 'WindowsUser'
            ServerName           = $Node.NodeName
            InstanceName         = $sqlInstanceName
            PsDscRunAsCredential = $localAdminCred
            DependsOn            = '[Script]EnableTcpIp'
        }

        

        SqlLogin AddSqlAdminLogin
        {
            Ensure               = 'Present'
            Name                 = $sqlAdminCred.UserName
            LoginType            = 'WindowsUser'
            ServerName           = $Node.NodeName
            InstanceName         = $sqlInstanceName
            PsDscRunAsCredential = $localAdminCred
            DependsOn            = '[Script]EnableTcpIp'
        }

        SqlLogin AddAesGroupCldWinLogin
        {
            Ensure               = 'Present'
            Name                 = $aesAdminGroup
            LoginType            = 'WindowsGroup'
            ServerName           = $Node.NodeName
            InstanceName         = $sqlInstanceName
            PsDscRunAsCredential = $localAdminCred
            DependsOn            = '[Script]EnableTcpIp'
        }

        SqlLogin AddAGGroupLogin
        {
            Ensure               = 'Present'
            Name                 = "$($Node.NodeName)\$agGroupName"
            LoginType            = 'WindowsGroup'
            ServerName           = $Node.NodeName
            InstanceName         = $sqlInstanceName
            PsDscRunAsCredential = $localAdminCred
            DependsOn            = '[Group]AddSqlNodesToLocalSecurityGroup'
        }

        SqlLogin AddSqlSvcLogin
        {
            Ensure               = 'Present'
            Name                 = $sqlSvcUser
            LoginType            = 'WindowsUser'
            ServerName           = $Node.NodeName
            InstanceName         = $sqlInstanceName
            PsDscRunAsCredential = $localAdminCred
            DependsOn            = '[Script]CheckSqlService','[Script]ChangeSqlServicesToGmsa'
        }

        SqlRole AddSqlSysAdminUsers
        {
            Ensure               = 'Present'
            ServerRoleName       = 'sysadmin'
            ServerName           = $Node.NodeName
            InstanceName         = $sqlInstanceName
            MembersToInclude     = $localAdmins
            PsDscRunAsCredential = $localAdminCred
            DependsOn            = '[SqlLogin]AddAesGroupCldWinLogin','[SqlLogin]AddSqlAdminLogin','[SqlLogin]AddSonjaLogin','[SqlLogin]AddJoeLogin'
        }

        SqlMemory SetSQLServerMemory
        {
            Ensure               = 'Present'
            DynamicAlloc         = $true
            ServerName           = $Node.NodeName
            InstanceName         = $sqlInstanceName
            PsDscRunAsCredential = $sqlAdminCred
            DependsOn            = '[Script]CheckSqlService'
        }

        SqlPermission ConfigureAgGroupPermissions
        {
            Ensure               = 'Present'
            ServerName           = $Node.NodeName
            InstanceName         = $sqlInstanceName
            Principal            = "$($Node.NodeName)\$agGroupName"
            Permission           = 'AlterAnyAvailabilityGroup', 'ViewServerState', 'ConnectSql'
            PsDscRunAsCredential = $sqlAdminCred
            DependsOn            = '[SqlLogin]AddAGGroupLogin'
        }

        SqlPermission AddNTSystemPermissions
        {
            Ensure               = 'Present'
            ServerName           = $Node.NodeName
            InstanceName         = $sqlInstanceName
            Principal            = 'NT AUTHORITY\SYSTEM'
            Permission           = 'AlterAnyAvailabilityGroup', 'ViewServerState', 'ConnectSql'
            PsDscRunAsCredential = $sqlAdminCred
            DependsOn            = '[SqlMemory]SetSQLServerMemory'
        }

        SqlPermission AddSqlSvcPermissions
        {
            Ensure               = 'Present'
            ServerName           = $Node.NodeName
            InstanceName         = $sqlInstanceName
            Principal            = $sqlSvcUser
            Permission           = 'AlterAnyAvailabilityGroup', 'ViewServerState'
            PsDscRunAsCredential = $sqlAdminCred
            DependsOn            = '[SqlEndpoint]HADREndpoint','[Script]ChangeSqlServicesToGmsa'
        }

        SqlEndpoint HADREndpoint
        {
            EndPointName         = 'HADR'
            EndpointType         = 'DatabaseMirroring' 
            Ensure               = 'Present'
            Port                 = 5022
            ServerName           = $Node.NodeName
            InstanceName         = $sqlInstanceName
            PsDscRunAsCredential = $sqlAdminCred
            DependsOn            = '[SqlMemory]SetSQLServerMemory'
        }

        SqlEndpointPermission SQLConfigureEndpointPermission
        {
            Ensure               = 'Present'
            ServerName           = $Node.NodeName
            InstanceName         = $sqlInstanceName
            Name                 = 'HADR'
            Principal            = 'NT AUTHORITY\SYSTEM'
            Permission           = 'CONNECT'
            PsDscRunAsCredential = $sqlAdminCred
            DependsOn            = '[SqlEndpoint]HADREndpoint'
        }

        SqlEndpointPermission SQLSvcConfigureEndpointPermission
        {
            Ensure               = 'Present'
            ServerName           = $Node.NodeName
            InstanceName         = $sqlInstanceName
            Name                 = 'HADR'
            Principal            = $sqlSvcUser
            Permission           = 'CONNECT'
            PsDscRunAsCredential = $sqlAdminCred
            DependsOn            = '[SqlEndpoint]HADREndpoint','[Script]ChangeSqlServicesToGmsa'
        }

        SqlEndpointPermission SQLAgNodesConfigureEndpointPermission
        {
            Ensure               = 'Present'
            ServerName           = $Node.NodeName
            InstanceName         = $sqlInstanceName
            Name                 = 'HADR'
            Principal            = ($Node.NodeName + '\' + $agGroupName)
            Permission           = 'CONNECT'
            PsDscRunAsCredential = $sqlAdminCred
            DependsOn            = '[SqlEndpoint]HADREndpoint'
        }

        SqlConfiguration ConfigureClrEnabled
        {
            ServerName           = $Node.NodeName
            InstanceName         = $sqlInstanceName
            OptionName           = 'clr enabled'
            OptionValue          = 1
            PsDscRunAsCredential = $sqlAdminCred
            DependsOn            = '[SqlMemory]SetSQLServerMemory'
        }

       SqlConfiguration ConfigureClrStrictSecurity
        {
            ServerName           = $Node.NodeName
            InstanceName         = $sqlInstanceName
            OptionName           = 'clr strict security'
            OptionValue          = 0
            PsDscRunAsCredential = $sqlAdminCred
            DependsOn            = '[SqlMemory]SetSQLServerMemory'
        }

    }

    Node $AllNodes.Where{$_.Role -eq 'PrimaryNode1'}.NodeName
    {

        $sqlServerInstance = $Node.NodeName
        if($sqlInstanceName -ne 'MSSQLSERVER')
        {
            $sqlServerInstance = "$($Node.NodeName)\$sqlInstanceName"
        }

        Script CreateCluster
        {
            GetScript = {
                # Not Implemented
            }

            SetScript = {
                Write-Host "Creating Cluster with Name=$using:clusterName"
                New-Cluster -Name $using:clusterName -Node $using:sqlVmNames -ManagementPointNetworkType Distributed
            }

            TestScript = {
                $Status = ($null -ne (Get-Cluster -ErrorAction SilentlyContinue))
                return $Status
            }

            PsDscRunAsCredential = $domainJoinCred
            DependsOn            = '[WindowsFeature]FCPS'
        }

        # This is helpful in rebuild scenarios
        Script JoinCluster
        {
            GetScript = {
                # Not Implemented
            }

            SetScript = {
                Write-Host "Joining the cluster $using:clusterName"
                Add-ClusterNode -Name $using:Node.NodeName -Cluster $using:clusterName
            }

            TestScript = {
                $Status = ($null -ne (Get-ClusterNode -Name $using:Node.NodeName -ErrorAction SilentlyContinue))
                return $Status
            }

            PsDscRunAsCredential = $domainJoinCred
            DependsOn            = '[Script]CreateCluster'
        }

        # Beginregion Configure Cluster
        Script ConfigureClusterAll
        {
            GetScript = {
                # Not Implemented
            }

            SetScript = {
                Write-Host "Configuring the Cluster"
                (Get-Cluster).ClusterLogSize = 500
                (Get-Cluster).SameSubnetDelay = 1000
                (Get-Cluster).SameSubnetThreshold = 20
                (Get-Cluster).CrossSubnetDelay = 1000
                (Get-Cluster).CrossSubnetThreshold = 20
            }

            TestScript = {
                if((Get-Cluster).ClusterLogSize -ne 500){return $false}
                if((Get-Cluster).SameSubnetDelay -ne 1000){return $false}
                if((Get-Cluster).SameSubnetThreshold -ne 20){return $false}
                if((Get-Cluster).CrossSubnetDelay -ne 1000){return $false}
                if((Get-Cluster).CrossSubnetThreshold -ne 20){return $false}
                return $true
            }

            PsDscRunAsCredential = $domainJoinCred
            DependsOn            = '[WindowsFeature]FCPS', '[Script]JoinCluster'
        }

        Script SetCloudWitness
        {
            GetScript = { 
                # Not Implemented
            }

            SetScript = {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Write-Host "Configuring Cloud Witness using the following values. Storage Account: $using:witnessStorageAccount, `
                    Key: $using:witnessStorageAccountKey, Endpoint: $using:witnessEndpoint"
                Set-ClusterQuorum -CloudWitness -AccountName $using:witnessStorageAccount -AccessKey $using:witnessStorageAccountKey -Endpoint $using:witnessEndpoint
            }

            TestScript = {
                $(Get-ClusterQuorum).QuorumResource.ResourceType -eq "Cloud Witness"
            }

            PsDscRunAsCredential = $domainJoinCred
            DependsOn = "[Script]JoinCluster"
        }

        SqlAlwaysOnService EnableAlwaysOn
        {
            Ensure               = 'Present'
            ServerName           = $Node.NodeName
            InstanceName         = $sqlInstanceName
            RestartTimeout       = 120
            PsDscRunAsCredential = $sqlAdminCred
            DependsOn            = '[Script]JoinCluster'
        }

        foreach($agInfo in $agsInfoWithIps)
        {
            
            if($agInfo.primaryReplicaName -eq $Node.NodeName)
            {
            
                SqlAG "AddAG_$($($agInfo).agName)"
                {
                    Ensure                        = 'Present'
                    Name                          = $agInfo.agName
                    ServerName                    = $Node.NodeName
                    InstanceName                  = $sqlInstanceName
                    ProcessOnlyOnActiveNode       = $true
                    AutomatedBackupPreference     = 'Primary'
                    AvailabilityMode              = 'SynchronousCommit'
                    BackupPriority                = 50
                    ConnectionModeInPrimaryRole   = 'AllowAllConnections'
                    ConnectionModeInSecondaryRole = 'AllowAllConnections'
                    FailoverMode                  = 'Automatic'
                    HealthCheckTimeout            = 15000
                    BasicAvailabilityGroup        = $basicAG
                    DatabaseHealthTrigger         = $true
                    DtcSupportEnabled             = $true
                    PsDscRunAsCredential          = $sqlAdminCred
                    DependsOn                     = '[SqlAlwaysOnService]EnableAlwaysOn'
                }

                Script "CreateListener_$($($agInfo).listenerName)"
                {
                    GetScript  = {
                        # Not implemented
                    }
            
                    SetScript  = {
                        $agName = $using:agInfo.agName
                        $listenerName = $using:agInfo.listenerName
                        $port = $using:agInfo.sqlPort
                        $ipAddress = $using:agInfo.ipAddress
                        $drIpAddress = $using:agInfo.drIpAddress
                        $subnetMask = $using:sqlListenerSubnet
                        $drsubnetMask = $using:drSqlListenerSubnet
                        $i = 0
                        $drQuery = "ALTER AVAILABILITY GROUP [$agName] `
                            ADD LISTENER N`'$listenerName`' ( `
                            WITH IP `
                            ((N`'$ipAddress`', N`'$subnetMask`'), `
                            (N`'$drIpAddress`', N`'$drsubnetMask`') `
                            ) `
                            , PORT=$port);"
                        $prOnlyQuery = "ALTER AVAILABILITY GROUP [$agName] `
                            ADD LISTENER N`'$listenerName`' ( `
                            WITH IP `
                            ((N`'$ipAddress`', N`'$subnetMask`')) `
                            , PORT=$port);"
                        $query = $drQuery
                        if($drIpAddress -eq '')
                        {
                            $query = $prOnlyQuery 
                        }
                        Write-Host "Creating the SQL listener using query: $query"
                        while($i -lt 3)
                        {
                            Set-Location "SQLSERVER:\SQL\$using:sqlServerInstance"
                            try
                            {
                                Invoke-SqlCmd -Query $query -OutputSqlErrors $true -IncludeSqlUserErrors -ErrorAction Stop
                                Write-Host "Listener created!"
                                return $true
                            }
                            catch
                            {
                                Write-Warning "Error: $($($($_).Exception).Message)"
                                $owningNode = (Get-ClusterResource $agName).OwnerNode.Name
                                if($owningNode -ne $using:sqlServerInstance)
                                {
                                    Write-Host "Moving cluster resource to correct owner"
                                    Move-ClusterGroup -Name $agName -Node $($using:sqlServerInstance).Split('\')[0]
                                }
                                if($_.Exception.Message -like '*already has a listener with DNS name*')
                                {
                                    # Check to ensure the listener really exists (see work item #76463)
                                    $query = "SELECT COUNT(*) as count FROM sys.availability_group_listeners WHERE dns_name = `'$listenerName`'"
                                    $ds = Invoke-Sqlcmd -Query $query
                                    if ($ds.count -gt 0)
                                    {
                                        Write-Host "Listener created succesfully!"
                                        return $true
                                    }
                                }   
                                $i++
                                if($i -lt 3)
                                {
                                    Write-Host 'Will retry in 15 seconds...'
                                    Start-Sleep -Seconds 15
                                }
                            }
                        }
                        # If we are here, the Listener failed
                        Write-Error "Error: Failed to create the listener!"
                        return $false
                    }

                    TestScript = {
                        $agName = $using:agInfo.agName
                        $listenerName = $using:agInfo.listenerName
                        $port = $using:agInfo.sqlPort
                        $prOnlyQuery = "SELECT COUNT (*) `
                            FROM sys.availability_group_listeners `
                            WHERE dns_name = N`'$listenerName`' AND port = $port AND `
                            (ip_configuration_string_from_cluster LIKE N`'%$($($using:agInfo).ipAddress)%`'"
                        $drQuery = "SELECT COUNT (*) `
                            FROM sys.availability_group_listeners `
                            WHERE dns_name = N`'$listenerName`' AND port = $port AND `
                            (ip_configuration_string_from_cluster LIKE N`'%$($($using:agInfo).ipAddress)%`' AND `
                            ip_configuration_string_from_cluster LIKE N`'%$($($using:agInfo).drIpAddress)%`')"
                        $query = $drQuery
                        if($drIpAddress -eq '')
                        {
                            $query = $prOnlyQuery 
                        }
                        Write-Host "Checking for $listenerName on $agName listening on port $port"
                        $count = (Invoke-SqlCmd -ServerInstance $using:sqlServerInstance -Query $query).Column1
                        if($count -gt 0)
                        {
                            return $true
                        }

                        return $false

                    }

                    PsDscRunAsCredential = $sqlAdminCred
                    DependsOn = "[SqlAG]AddAG_$($($agInfo).agName)"
                }

                Script "EnableAutoSeeding_$($($agInfo).agName)"
                {
                    GetScript  = {
                    }
            
                    SetScript  = {
                        $agName = $using:agInfo.agName
                        Invoke-SqlCmd -ServerInstance $using:sqlServerInstance -Query "ALTER AVAILABILITY GROUP [$agName] `
                            MODIFY REPLICA ON `'$using:sqlServerInstance`' `
                            WITH (SEEDING_MODE = AUTOMATIC)"
                    }

                    TestScript = {
                        $agName = $using:agInfo.agName
                        $count = (Invoke-SqlCmd -ServerInstance $using:sqlServerInstance -Query "SELECT Count(*) `
                            FROM sys.dm_hadr_automatic_seeding autos `
                            JOIN sys.availability_groups ag `
                            ON autos.ag_id = ag.group_id `
	                        JOIN sys.availability_replicas ar `
		                    ON autos.ag_id = ar.group_id `
                            WHERE performed_seeding = 1 AND name = `'$agName`' `
                            AND replica_server_name = `'$using:sqlServerInstance`' AND seeding_mode = 0").Column1
                        if($count -gt 0)
                        {
                            return $true
                        }
                        else
                        {
                            return $false
                        }
                    }

                    PsDscRunAsCredential = $sqlAdminCred
                    DependsOn = "[SqlAG]AddAG_$($($agInfo).agName)"
                }

                Script "RegisterSPN_$($($agInfo).listenerName)"
                {

                    GetScript = {
                        # Not Implemented
                    }

                    SetScript = {
                        Write-Host "Setting SPN registration on $($($using:agInfo).listenerName)"
                        try
                        {
                            Write-Host "Enabling xp_cmd"
                            $sqlCmd = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
                            Invoke-Sqlcmd -Query $sqlCmd
                            Write-Host "Registering the SPNs"
                            $sqlCmd = "exec master.dbo.xp_cmdshell 'setspn -s MSSQLSvc/$($($using:agInfo).listenerName):$($($using:agInfo).sqlPort) $using:sqlSvcUser'"
                            Invoke-Sqlcmd -Query $sqlCmd
                            $sqlCmd = "exec master.dbo.xp_cmdshell 'setspn -s MSSQLSvc/$($($using:agInfo).listenerName).mydc.gov:$($($using:agInfo).sqlPort) $using:sqlSvcUser'"
                            Invoke-Sqlcmd -Query $sqlCmd
                            Write-Host "Disabling xp_cmd"
                            $sqlCmd = "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE; EXEC sp_configure 'show advanced options', 0; RECONFIGURE;"
                            Invoke-Sqlcmd -Query $sqlCmd
                        }
                        catch
                        {
                            Write-Host "An error occurred while attempting SPN registration"
                        }
                    }

                    TestScript = {
                        Write-Host "Checking for SPN registration on $($($using:agInfo).listenerName)"
                        $results = setspn -l $using:sqlSvcUser
                        $fqdnListener = $false
                        $netbiosListener = $false
                        foreach($result in $results)
                        { 
                            if($result -like "*MSSQLSvc/$($($using:agInfo).listenerName):$($($using:agInfo).sqlPort)*")
                            {
                                $netbiosListener = $true
                            }
                            if($result -like "*MSSQLSvc/$($($using:agInfo).listenerName).mydc.gov:$($($using:agInfo).sqlPort)*")
                            {
                                $fqdnListener = $true
                            }
                        }
                        if(($fqdnListener -eq $true) -and ($netbiosListener -eq $true))
                        {
                            return $true
                        }
                        return $false
                    }

                    PsDscRunAsCredential = $sqlAdminCred
                    DependsOn            = "[Script]CreateListener_$($($agInfo).listenerName)"
                }

                Script "ConfigureClusterResource_$($($agInfo).agName)"
                {

                    GetScript = {
                        # Not Implemented
                    }

                    SetScript = {
                        $agName = $using:agInfo.agName
                        $cg = Get-ClusterGroup $agName
                        $cg.AutoFailbackType = 0
                    }

                    TestScript = {
                        $agName = $using:agInfo.agName
                        $cg = Get-ClusterGroup $agName
                        if($cg.AutoFailbackType -ne 0){return $false}
                        return $true
                    }

                    PsDscRunAsCredential = $domainJoinCred
                    DependsOn            = '[WindowsFeature]FCPS','[Script]JoinCluster'
                }

                [string[]]$listenerIPs = @($agInfo.ipAddress)
                if(-not [string]::IsNullOrEmpty($agInfo.drIpAddress))
                {
                    $listenerIPs += $agInfo.drIpAddress
                }

                foreach($listenerIP in $listenerIPs)
                {

                    $sqlAgIpResourceName = $agInfo.agName + "_" + $listenerIP
                    $sqlAgListenerResourceName = $agInfo.agName + "_" + $agInfo.listenerName
                    $sqlListenerIPAddress = $listenerIP
                    $sqlAGHealthProbePort = $agInfo.probePort

                    Script "ConfigureSqlListenerResource_$sqlAgIpResourceName"
                    {

                        GetScript = {
                            # Not Implemented
                        }

                        SetScript = {
                            # Get the Cluster Network Name
                            $sep = $($using:listenerIP).LastIndexOf('.')
                            $subnet = $($using:listenerIP).Substring(0,$sep)
                            $clusterNetworkName = (Get-ClusterNetwork | Where-Object {$_.Address -like "$subnet*"}).Name
                            Write-Host "Setting $($($using:agInfo).agName) configuration. Address=$using:sqlListenerIPAddress, ProbePort=$using:sqlAGHealthProbePort, Network=$clusterNetworkName"
                            Get-ClusterResource $using:sqlAgIpResourceName | Set-ClusterParameter -Multiple @{"Address"=$using:sqlListenerIPAddress;"ProbePort"=$using:sqlAGHealthProbePort;"SubnetMask"='255.255.255.255';"Network"=$clusterNetworkName;"EnableDhcp"=0}
                            Get-ClusterResource $using:sqlAgListenerResourceName | Set-ClusterParameter -Name HostRecordTTL $using:HostRecordTTL
                            try
                            {
                                Write-Host "Restarting resource: $($($using:agInfo).agName)"
                                Stop-ClusterResource $using:sqlAgIpResourceName -ErrorAction Stop
                                Start-ClusterResource $using:sqlAgIpResourceName -ErrorAction Stop
                                Start-ClusterResource $using:agInfo.agName -ErrorAction Stop
                            }
                            catch
                            {
                                return $false
                            }
                            return $true
                        }

                        TestScript = {
                            # Get the Cluster Network Name
                            $sep = $($using:listenerIP).LastIndexOf('.')
                            $subnet = $($using:listenerIP).Substring(0,$sep)
                            $clusterNetworkName = (Get-ClusterNetwork | Where-Object {$_.Address -like "$subnet*"}).Name
                            Write-Host "Checking $($($using:agInfo).agName) configuration. Address=$using:sqlListenerIPAddress, ProbePort=$using:sqlAGHealthProbePort, Network=$clusterNetworkName, HostRecordTTL=$using:HostRecordTTL"
                            $address = $false
                            $ProbePort = $false
                            $Network = $false
                            $HRTTL = $false
                            $params = Get-ClusterResource $using:sqlAgIpResourceName | Get-ClusterParameter *
                            $params += Get-ClusterResource $using:sqlAgListenerResourceName | Get-ClusterParameter *
                            foreach ($param in $params)
                            {
                                if($param.Name -eq 'Address')
                                {
                                    if($param.Value -eq $using:sqlListenerIPAddress)
                                    {
                                        Write-Host "Address correct"
                                        $address = $true
                                    }
                                }
                                if($param.Name -eq 'ProbePort')
                                {
                                    if($param.Value -eq $using:sqlAGHealthProbePort)
                                    {
                                        Write-Host "ProbePort correct"
                                        $ProbePort = $true
                                    }
                                }
                                if($param.Name -eq 'Network')
                                {
                                    if($param.Value -eq $clusterNetworkName)
                                    {
                                        Write-Host "Network correct"
                                        $Network = $true
                                    }
                                }
                                if($param.Name -eq 'HostRecordTTL')
                                {
                                    if($param.Value -eq $using:HostRecordTTL)
                                    {
                                        Write-Host "HostRecordTTL correct"
                                        $HRTTL = $true
                                    }
                                }
                            }
                            $Status = $address -and $ProbePort -and $Network -and $HRTTL
                            $Status -eq $True
                        }

                        PsDscRunAsCredential = $domainJoinCred
                        DependsOn            = '[WindowsFeature]FCPS','[Script]JoinCluster',"[Script]CreateListener_$($($agInfo).listenerName)"
                    }

                }
            }
            else
            {
                
                if(($agInfo.primaryReplicaName -ne '') -and ($agInfo.secondaryReplicaName -ne ''))
                {
                    # If we are here, we just need to add the replica to the AG
                    SqlAGReplica "AddReplica_$($($agInfo).agName)"
                    {
                        Ensure                        = 'Present'
                        Name                          = $sqlServerInstance
                        AvailabilityGroupName         = $agInfo.agName
                        ServerName                    = $Node.NodeName
                        InstanceName                  = $sqlInstanceName
                        AvailabilityMode              = 'SynchronousCommit'
                        ConnectionModeInSecondaryRole = 'AllowAllConnections'
                        FailoverMode                  = 'Automatic'
                        PrimaryReplicaServerName      = ( $AllNodes | Where-Object { $_.Role -eq 'PrimaryNode2' } ).NodeName
                        PrimaryReplicaInstanceName    = $sqlInstanceName
                        ProcessOnlyOnActiveNode       = $true
                        DependsOn                     = "[SqlAlwaysOnService]EnableAlwaysOn"
                    }

                    Script "EnableAutoSeeding_$($($agInfo).agName)"
                    {
                        GetScript  = {
                        }
                
                        SetScript  = {
                            $agName = $using:agInfo.agName
                            $secondaryServer = $using:sqlServerInstance
                            $primaryServer = $using:agInfo.primaryReplicaName
                            Write-Host "Running command against: $secondaryServer"
                            Invoke-SqlCmd -ServerInstance $secondaryServer -Query "ALTER AVAILABILITY GROUP [$agName] GRANT CREATE ANY DATABASE"
                            Write-Host "Running command against: $primaryServer"
                            Invoke-SqlCmd -ServerInstance $primaryServer -Query "ALTER AVAILABILITY GROUP [$agName] `
                                MODIFY REPLICA ON `'$secondaryServer`' `
                                WITH (SEEDING_MODE = AUTOMATIC)"
                        }
        
                        TestScript = {
                            $agName = $using:agInfo.agName
                            $secondaryServer = $using:sqlServerInstance
                            $count = (Invoke-SqlCmd -ServerInstance $secondaryServer -Query "SELECT Count(*) `
                                FROM sys.dm_hadr_automatic_seeding autos `
                                JOIN sys.availability_groups ag `
                                ON autos.ag_id = ag.group_id `
                                JOIN sys.availability_replicas ar `
                                ON autos.ag_id = ar.group_id `
                                WHERE performed_seeding = 1 AND name = `'$agName`' `
                                AND replica_server_name = `'$secondaryServer`' AND seeding_mode = 0").Column1
                            if($count -gt 0)
                            {
                                return $true
                            }
                            else
                            {
                                return $false
                            }
                        }

                        PsDscRunAsCredential = $sqlAdminCred
                        DependsOn = "[SqlAGReplica]AddReplica_$($($agInfo).agName)"
                    }
                }
            }
        }

        # Move the computer object, cluster name object and listerner name objects to the final OU
        Script "MoveComputerObjectsToTargetOU"{
                
            GetScript = {
            }

            SetScript = {
                $computerMoved = $false
                [string[]]$adObjectsToMove = @()
                $adObjectsToMove += $using:Node.NodeName
                $adObjectsToMove += $using:clusterName
                $adObjectsToMove += $using:agsInfoWithIps[0].listenerName
                foreach($adObject in $adObjectsToMove)
                {
                    Write-Host "Moving $adObject object to $using:targetOuPath"
                    Get-ADComputer -Filter "Name -eq `"$adObject`"" -SearchBase ($using:stagingOuPath) | Move-ADObject -TargetPath $using:targetOuPath
                    $adComputer = Get-ADComputer -Filter "Name -eq `"$adObject`"" -SearchBase $using:targetOuPath
                    if($adComputer)
                    {
                        Write-Host "Computer object has been moved"
                        $computerMoved = $true
                    }
                }
                if($computerMoved)
                {
                    $global:DSCMachineStatus = 1
                }
            }

            TestScript = {
                [string[]]$adObjectsToMove = @()
                $adObjectsToMove += $using:Node.NodeName
                $adObjectsToMove += $using:clusterName
                $adObjectsToMove += $using:agsInfoWithIps[0].listenerName
                foreach($adObject in $adObjectsToMove)
                {
                    $filter = "Name -eq `"$adObject`""
                    Write-Host "Using filter ($filter) and searching in $using:targetOuPath"
                    $adComputer = Get-ADComputer -Filter $filter -SearchBase $using:targetOuPath
                    if($null -eq $adComputer)
                    {
                        Write-Host "Object is not in the correct OU"
                        return $false
                    }
                    return $true
                }
            }

            DependsOn = '[Script]JoinCluster', "[Script]ConfigureSqlListenerResource_$sqlAgIpResourceName"
            PsDscRunAsCredential = $domainJoinCred
        }

    }

    Node $AllNodes.Where{$_.Role -eq 'PrimaryNode2'}.NodeName
    {

        $sqlServerInstance = $Node.NodeName
        if($sqlInstanceName -ne 'MSSQLSERVER')
        {
            $sqlServerInstance = "$($Node.NodeName)\$sqlInstanceName"
        }

        Script JoinCluster
        {
            GetScript = {
                # Not Implemented
            }

            SetScript = {
                Write-Host "Joining the cluster $using:clusterName"
                Add-ClusterNode -Name $using:Node.NodeName -Cluster $using:clusterName
            }

            TestScript = {
                $Status = $false
                Write-Host "Looking for $using:clusterName"
                if(Get-Cluster -Name $using:clusterName -ErrorAction SilentlyContinue)
                {
                    Write-Host "Checking Active Directory for $using:clusterName"
                    if((Get-ADComputer -Identity $using:clusterName -ErrorAction SilentlyContinue).Enabled)
                    {
                        $Status = ($null -ne (Get-ClusterNode -Name $using:Node.NodeName -Cluster $using:clusterName -ErrorAction SilentlyContinue))
                    }
                    else
                    {
                        Write-Host "$using:clusterName not found in AD!"
                    }
                }
                else
                {
                    Write-Host "$using:clusterName cluster not found!"
                }
                
                return $Status
            }

            PsDscRunAsCredential = $domainJoinCred
        }

        SqlAlwaysOnService "EnableAlwaysOn"
        {
            Ensure               = 'Present'
            ServerName           = $Node.NodeName
            InstanceName         = $sqlInstanceName
            RestartTimeout       = 120
            PsDscRunAsCredential = $sqlAdminCred
            DependsOn            = "[Script]JoinCluster"
        }

        foreach($agInfo in $agsInfoWithIps)
        {
            
            if($agInfo.primaryReplicaName -eq $Node.NodeName)
            {
            
                SqlAG "AddAG_$($($agInfo).agName)"
                {
                    Ensure                        = 'Present'
                    Name                          = $agInfo.agName
                    ServerName                    = $Node.NodeName
                    InstanceName                  = $sqlInstanceName
                    ProcessOnlyOnActiveNode       = $true
                    AutomatedBackupPreference     = 'Primary'
                    AvailabilityMode              = 'SynchronousCommit'
                    BackupPriority                = 50
                    ConnectionModeInPrimaryRole   = 'AllowAllConnections'
                    ConnectionModeInSecondaryRole = 'AllowAllConnections'
                    FailoverMode                  = 'Automatic'
                    HealthCheckTimeout            = 15000
                    BasicAvailabilityGroup        = $basicAG
                    DatabaseHealthTrigger         = $true
                    DtcSupportEnabled             = $true
                    PsDscRunAsCredential          = $sqlAdminCred
                    DependsOn                     = '[SqlAlwaysOnService]EnableAlwaysOn'
                }

                Script "CreateListener_$($($agInfo).listenerName)"
                {
                    GetScript  = {
                        # Not implemented
                    }
            
                    SetScript  = {
                        $agName = $using:agInfo.agName
                        $listenerName = $using:agInfo.listenerName
                        $port = $using:agInfo.sqlPort
                        $ipAddress = $using:agInfo.ipAddress
                        $drIpAddress = $using:agInfo.drIpAddress
                        $subnetMask = $using:sqlListenerSubnet
                        $drsubnetMask = $using:drSqlListenerSubnet
                        $i = 0
                        $drQuery = "ALTER AVAILABILITY GROUP [$agName] `
                            ADD LISTENER N`'$listenerName`' ( `
                            WITH IP `
                            ((N`'$ipAddress`', N`'$subnetMask`'), `
                            (N`'$drIpAddress`', N`'$drsubnetMask`') `
                            ) `
                            , PORT=$port);"
                        $prOnlyQuery = "ALTER AVAILABILITY GROUP [$agName] `
                            ADD LISTENER N`'$listenerName`' ( `
                            WITH IP `
                            ((N`'$ipAddress`', N`'$subnetMask`')) `
                            , PORT=$port);"
                        $query = $drQuery
                        if($drIpAddress -eq '')
                        {
                            $query = $prOnlyQuery 
                        }
                        Write-Host "Creating the SQL listener using query: $query"
                        while($i -lt 3)
                        {
                            Set-Location "SQLSERVER:\SQL\$using:sqlServerInstance"
                            try
                            {
                                Invoke-SqlCmd -Query $query -OutputSqlErrors $true -IncludeSqlUserErrors -ErrorAction Stop
                                Write-Host "Listener created!"
                                return $true
                            }
                            catch
                            {
                                Write-Warning "Error: $($($($_).Exception).Message)"
                                $owningNode = (Get-ClusterResource $agName).OwnerNode.Name
                                if($owningNode -ne $using:sqlServerInstance)
                                {
                                    Write-Host "Moving cluster resource to correct owner"
                                    Move-ClusterGroup -Name $agName -Node $($using:sqlServerInstance).Split('\')[0]
                                }
                                if($_.Exception.Message -like '*already has a listener with DNS name*')
                                {
                                    # Check to ensure the listener really exists (see work item #76463)
                                    $query = "SELECT COUNT(*) as count FROM sys.availability_group_listeners WHERE dns_name = `'$listenerName`'"
                                    $ds = Invoke-Sqlcmd -Query $query
                                    if ($ds.count -gt 0)
                                    {
                                        Write-Host "Listener created succesfully!"
                                        return $true
                                    }
                                }   
                                $i++
                                if($i -lt 3)
                                {
                                    Write-Host 'Will retry in 15 seconds...'
                                    Start-Sleep -Seconds 15
                                }
                            }
                        }
                        # If we are here, the Listener failed
                        Write-Error "Error: Failed to create the listener!"
                        return $false
                    }

                    TestScript = {
                        $agName = $using:agInfo.agName
                        $listenerName = $using:agInfo.listenerName
                        $port = $using:agInfo.sqlPort
                        $prOnlyQuery = "SELECT COUNT (*) `
                            FROM sys.availability_group_listeners `
                            WHERE dns_name = N`'$listenerName`' AND port = $port AND `
                            (ip_configuration_string_from_cluster LIKE N`'%$($($using:agInfo).ipAddress)%`'"
                        $drQuery = "SELECT COUNT (*) `
                            FROM sys.availability_group_listeners `
                            WHERE dns_name = N`'$listenerName`' AND port = $port AND `
                            (ip_configuration_string_from_cluster LIKE N`'%$($($using:agInfo).ipAddress)%`' AND `
                            ip_configuration_string_from_cluster LIKE N`'%$($($using:agInfo).drIpAddress)%`')"
                        $query = $drQuery
                        if($drIpAddress -eq '')
                        {
                            $query = $prOnlyQuery 
                        }
                        Write-Host "Checking for $listenerName on $agName listening on port $port"
                        $count = (Invoke-SqlCmd -ServerInstance $using:sqlServerInstance -Query $query).Column1
                        if($count -gt 0)
                        {
                            return $true
                        }
                        return $false
                    }

                    PsDscRunAsCredential = $sqlAdminCred
                    DependsOn = "[SqlAG]AddAG_$($($agInfo).agName)"
                }

                Script "EnableAutoSeeding_$($($agInfo).agName)"
                {
                    GetScript  = {
                    }
            
                    SetScript  = {
                        $agName = $using:agInfo.agName
                        Invoke-SqlCmd -ServerInstance $using:sqlServerInstance -Query "ALTER AVAILABILITY GROUP [$agName] `
                            MODIFY REPLICA ON `'$using:sqlServerInstance`' `
                            WITH (SEEDING_MODE = AUTOMATIC)"
                    }

                    TestScript = {
                        $agName = $using:agInfo.agName
                        $count = (Invoke-SqlCmd -ServerInstance $using:sqlServerInstance -Query "SELECT Count(*) `
                            FROM sys.dm_hadr_automatic_seeding autos `
                            JOIN sys.availability_groups ag `
                            ON autos.ag_id = ag.group_id `
	                        JOIN sys.availability_replicas ar `
		                    ON autos.ag_id = ar.group_id `
                            WHERE performed_seeding = 1 AND name = `'$agName`' `
                            AND replica_server_name = `'$using:sqlServerInstance`' AND seeding_mode = 0").Column1
                        if($count -gt 0)
                        {
                            return $true
                        }
                        else
                        {
                            return $false
                        }
                    }

                    PsDscRunAsCredential = $sqlAdminCred
                    DependsOn = "[SqlAG]AddAG_$($($agInfo).agName)"
                }

                Script "RegisterSPN_$($($agInfo).listenerName)"
                {

                    GetScript = {
                        # Not Implemented
                    }

                    SetScript = {
                        Write-Host "Setting SPN registration on $($($using:agInfo).listenerName)"
                        try
                        {
                            Write-Host "Enabling xp_cmd"
                            $sqlCmd = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
                            Invoke-Sqlcmd -Query $sqlCmd
                            Write-Host "Registering the SPNs"
                            $sqlCmd = "exec master.dbo.xp_cmdshell 'setspn -s MSSQLSvc/$($($using:agInfo).listenerName):$($($using:agInfo).sqlPort) $using:sqlSvcUser'"
                            Invoke-Sqlcmd -Query $sqlCmd
                            $sqlCmd = "exec master.dbo.xp_cmdshell 'setspn -s MSSQLSvc/$($($using:agInfo).listenerName).mydc.gov:$($($using:agInfo).sqlPort) $using:sqlSvcUser'"
                            Invoke-Sqlcmd -Query $sqlCmd
                            Write-Host "Disabling xp_cmd"
                            $sqlCmd = "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE; EXEC sp_configure 'show advanced options', 0; RECONFIGURE;"
                            Invoke-Sqlcmd -Query $sqlCmd
                        }
                        catch
                        {
                            Write-Host "An error occurred while attempting SPN registration"
                        }
                    }

                    TestScript = {
                        Write-Host "Checking for SPN registration on $($($using:agInfo).listenerName)"
                        $results = setspn -l $using:sqlSvcUser
                        $fqdnListener = $false
                        $netbiosListener = $false
                        foreach($result in $results)
                        { 
                            if($result -like "*MSSQLSvc/$($($using:agInfo).listenerName):$($($using:agInfo).sqlPort)*")
                            {
                                $netbiosListener = $true
                            }
                            if($result -like "*MSSQLSvc/$($($using:agInfo).listenerName).mydc.gov:$($($using:agInfo).sqlPort)*")
                            {
                                $fqdnListener = $true
                            }
                        }
                        if(($fqdnListener -eq $true) -and ($netbiosListener -eq $true))
                        {
                            return $true
                        }
                        return $false
                    }

                    PsDscRunAsCredential = $sqlAdminCred
                    DependsOn            = "[Script]CreateListener_$($($agInfo).listenerName)"
                }

                Script "ConfigureClusterResource_$($($agInfo).agName)"
                {

                    GetScript = {
                        # Not Implemented
                    }

                    SetScript = {
                        $agName = $using:agInfo.agName
                        $cg = Get-ClusterGroup $agName
                        $cg.AutoFailbackType = 0
                    }

                    TestScript = {
                        $agName = $using:agInfo.agName
                        $cg = Get-ClusterGroup $agName
                        if($cg.AutoFailbackType -ne 0){return $false}
                        return $true
                    }

                    PsDscRunAsCredential = $domainJoinCred
                    DependsOn            = '[WindowsFeature]FCPS','[Script]JoinCluster'
                }

                [string[]]$listenerIPs = @($agInfo.ipAddress)
                if(-not [string]::IsNullOrEmpty($agInfo.drIpAddress))
                {
                    $listenerIPs += $agInfo.drIpAddress
                }

                foreach($listenerIP in $listenerIPs)
                {

                    $sqlAgIpResourceName = $agInfo.agName + "_" + $listenerIP
                    $sqlAgListenerResourceName = $agInfo.agName + "_" + $agInfo.listenerName
                    $sqlListenerIPAddress = $listenerIP
                    $sqlAGHealthProbePort = $agInfo.probePort

                    Script "ConfigureSqlListenerResource_$sqlAgIpResourceName"
                    {

                        GetScript = {
                            # Not Implemented
                        }

                        SetScript = {
                            # Get the Cluster Network Name
                            $sep = $($using:listenerIP).LastIndexOf('.')
                            $subnet = $($using:listenerIP).Substring(0,$sep)
                            $clusterNetworkName = (Get-ClusterNetwork | Where-Object {$_.Address -like "$subnet*"}).Name
                            Write-Host "Setting $($($using:agInfo).agName) configuration. Address=$using:sqlListenerIPAddress, ProbePort=$using:sqlAGHealthProbePort, Network=$clusterNetworkName"
                            Get-ClusterResource $using:sqlAgIpResourceName | Set-ClusterParameter -Multiple @{"Address"=$using:sqlListenerIPAddress;"ProbePort"=$using:sqlAGHealthProbePort;"SubnetMask"='255.255.255.255';"Network"=$clusterNetworkName;"EnableDhcp"=0}
                            Get-ClusterResource $using:sqlAgListenerResourceName | Set-ClusterParameter -Name HostRecordTTL $using:HostRecordTTL
                            try
                            {
                                Write-Host "Restarting resource: $($($using:agInfo).agName)"
                                Stop-ClusterResource $using:sqlAgIpResourceName -ErrorAction Stop
                                Start-ClusterResource $using:sqlAgIpResourceName -ErrorAction Stop
                                Start-ClusterResource $using:agInfo.agName -ErrorAction Stop
                            }
                            catch
                            {
                                return $false
                            }
                            return $true
                        }

                        TestScript = {
                            # Get the Cluster Network Name
                            $sep = $($using:listenerIP).LastIndexOf('.')
                            $subnet = $($using:listenerIP).Substring(0,$sep)
                            $clusterNetworkName = (Get-ClusterNetwork | Where-Object {$_.Address -like "$subnet*"}).Name
                            Write-Host "Checking $($($using:agInfo).agName) configuration. Address=$using:sqlListenerIPAddress, ProbePort=$using:sqlAGHealthProbePort, Network=$clusterNetworkName, HostRecordTTL=$using:HostRecordTTL"
                            $address = $false
                            $ProbePort = $false
                            $Network = $false
                            $HRTTL = $false
                            $params = Get-ClusterResource $using:sqlAgIpResourceName | Get-ClusterParameter *
                            $params += Get-ClusterResource $using:sqlAgListenerResourceName | Get-ClusterParameter *
                            foreach ($param in $params)
                            {
                                if($param.Name -eq 'Address')
                                {
                                    if($param.Value -eq $using:sqlListenerIPAddress)
                                    {
                                        Write-Host "Address correct"
                                        $address = $true
                                    }
                                }
                                if($param.Name -eq 'ProbePort')
                                {
                                    if($param.Value -eq $using:sqlAGHealthProbePort)
                                    {
                                        Write-Host "ProbePort correct"
                                        $ProbePort = $true
                                    }
                                }
                                if($param.Name -eq 'Network')
                                {
                                    if($param.Value -eq $clusterNetworkName)
                                    {
                                        Write-Host "Network correct"
                                        $Network = $true
                                    }
                                }
                                if($param.Name -eq 'HostRecordTTL')
                                {
                                    if($param.Value -eq $using:HostRecordTTL)
                                    {
                                        Write-Host "HostRecordTTL correct"
                                        $HRTTL = $true
                                    }
                                }
                            }
                            $Status = $address -and $ProbePort -and $Network -and $HRTTL
                            $Status -eq $True
                        }

                        PsDscRunAsCredential = $domainJoinCred
                        DependsOn            = '[WindowsFeature]FCPS','[Script]JoinCluster',"[Script]CreateListener_$($($agInfo).listenerName)"
                    }

                }
            }
            else
            {
                if($agInfo.secondaryReplicaName -eq $Node.NodeName)
                {
                    # If we are here, we just need to add the replica to the AG
                    SqlAGReplica "AddReplica_$($($agInfo).agName)"
                    {
                        Ensure                        = 'Present'
                        Name                          = $sqlServerInstance
                        AvailabilityGroupName         = $agInfo.agName
                        ServerName                    = $Node.NodeName
                        InstanceName                  = $sqlInstanceName
                        AvailabilityMode              = 'SynchronousCommit'
                        ConnectionModeInSecondaryRole = 'AllowAllConnections'
                        FailoverMode                  = 'Automatic'
                        PrimaryReplicaServerName      = ( $AllNodes | Where-Object { $_.Role -eq 'PrimaryNode1' } ).NodeName
                        PrimaryReplicaInstanceName    = $sqlInstanceName
                        ProcessOnlyOnActiveNode       = $true
                        DependsOn                     = "[SqlAlwaysOnService]EnableAlwaysOn"
                    }

                    Script "EnableAutoSeeding_$($($agInfo).agName)"
                    {
                        GetScript  = {
                        }
                
                        SetScript  = {
                            $agName = $using:agInfo.agName
                            $secondaryServer = $using:sqlServerInstance
                            $primaryServer = $using:agInfo.primaryReplicaName
                            Write-Host "Running command against: $secondaryServer"
                            Invoke-SqlCmd -ServerInstance $secondaryServer -Query "ALTER AVAILABILITY GROUP [$agName] GRANT CREATE ANY DATABASE"
                            Write-Host "Running command against: $primaryServer"
                            Invoke-SqlCmd -ServerInstance $primaryServer -Query "ALTER AVAILABILITY GROUP [$agName] `
                                MODIFY REPLICA ON `'$secondaryServer`' `
                                WITH (SEEDING_MODE = AUTOMATIC)"
                        }
        
                        TestScript = {
                            $agName = $using:agInfo.agName
                            $secondaryServer = $using:sqlServerInstance
                            $count = (Invoke-SqlCmd -ServerInstance $secondaryServer -Query "SELECT Count(*) `
                                FROM sys.dm_hadr_automatic_seeding autos `
                                JOIN sys.availability_groups ag `
                                ON autos.ag_id = ag.group_id `
                                JOIN sys.availability_replicas ar `
                                ON autos.ag_id = ar.group_id `
                                WHERE performed_seeding = 1 AND name = `'$agName`' `
                                AND replica_server_name = `'$secondaryServer`' AND seeding_mode = 0").Column1
                            if($count -gt 0)
                            {
                                return $true
                            }
                            else
                            {
                                return $false
                            }
                        }

                        PsDscRunAsCredential = $sqlAdminCred
                        DependsOn = "[SqlAGReplica]AddReplica_$($($agInfo).agName)"
                    }
                }
            }
        }

        Script MoveComputerToTargetOU{
            
            GetScript = {
            }

            SetScript = {
                [string[]]$adObjectsToMove = @()
                $adObjectsToMove += $using:Node.NodeName
                $adObjectsToMove += $using:agsInfoWithIps[1].listenerName
                foreach($adObject in $adObjectsToMove)
                {
                    Write-Host "Moving AD computer to $using:targetOuPath"
                    Get-ADComputer -Filter "Name -eq `"$adObject`"" -SearchBase ($using:stagingOuPath) | Move-ADObject -TargetPath $using:targetOuPath
                    $adComputer = Get-ADComputer -Filter "Name -eq `"$adObject`"" -SearchBase $using:targetOuPath
                    if($adComputer)
                    {
                        Write-Host "Computer object has been moved"
                    }
                }
                $global:DSCMachineStatus = 1
            }

            TestScript = {
                [string[]]$adObjectsToMove = @()
                $adObjectsToMove += $using:Node.NodeName
                $adObjectsToMove += $using:agsInfoWithIps[1].listenerName
                foreach($adObject in $adObjectsToMove)
                {
                    $filter = "Name -eq `"$adObject`""
                    Write-Host "Using filter ($filter) and searching in $using:targetOuPath"
                    $adComputer = Get-ADComputer -Filter $filter -SearchBase $using:targetOuPath
                    if(-not $adComputer)
                    {
                        Write-Host "Computer is NOT in the correct OU"
                        return $false
                    }
                }
                return $true
            }

            DependsOn = '[Script]JoinCluster', "[Script]ConfigureSqlListenerResource_$sqlAgIpResourceName"
            PsDscRunAsCredential = $domainJoinCred
        }

    }

    Node $AllNodes.Where{$_.Role -eq 'HaNode1'}.NodeName
    {

        $sqlServerInstance = $Node.NodeName
        if($sqlInstanceName -ne 'MSSQLSERVER')
        {
            $sqlServerInstance = "$($Node.NodeName)\$sqlInstanceName"
        }

        Script JoinCluster
        {
            GetScript = {
                # Not Implemented
            }

            SetScript = {
                Write-Host "Joining the cluster $using:clusterName"
                Add-ClusterNode -Name $using:Node.NodeName -Cluster $using:clusterName
            }

            TestScript = {
                $Status = $false
                Write-Host "Looking for $using:clusterName"
                if(Get-Cluster -Name $using:clusterName -ErrorAction SilentlyContinue)
                {
                    Write-Host "Checking Active Directory for $using:clusterName"
                    if((Get-ADComputer -Identity $using:clusterName -ErrorAction SilentlyContinue).Enabled)
                    {
                        $Status = ($null -ne (Get-ClusterNode -Name $using:Node.NodeName -Cluster $using:clusterName -ErrorAction SilentlyContinue))
                    }
                    else
                    {
                        Write-Host "$using:clusterName not found in AD!"
                    }
                }
                else
                {
                    Write-Host "$using:clusterName cluster not found!"
                }
                
                return $Status
            }

            PsDscRunAsCredential = $domainJoinCred
        }

        SqlAlwaysOnService "EnableAlwaysOn"
        {
            Ensure               = 'Present'
            ServerName           = $Node.NodeName
            InstanceName         = $sqlInstanceName
            RestartTimeout       = 120
            PsDscRunAsCredential = $sqlAdminCred
            DependsOn            = "[Script]JoinCluster"
        }

        foreach($agInfo in $agsInfoWithIps)
        {
            
            # If we are here, we just need to add the replica to the AG
            SqlAGReplica "AddReplica_$($($agInfo).agName)"
            {
                Ensure                        = 'Present'
                Name                          = $sqlServerInstance
                AvailabilityGroupName         = $agInfo.agName
                ServerName                    = $Node.NodeName
                InstanceName                  = $sqlInstanceName
                AvailabilityMode              = 'SynchronousCommit'
                ConnectionModeInSecondaryRole = 'AllowAllConnections'
                FailoverMode                  = 'Automatic'
                PrimaryReplicaServerName      = $agInfo.primaryReplicaName
                PrimaryReplicaInstanceName    = $sqlInstanceName
                ProcessOnlyOnActiveNode       = $true
                DependsOn                     = "[SqlAlwaysOnService]EnableAlwaysOn"
            }

            Script "EnableAutoSeeding_$($($agInfo).agName)"
            {
                GetScript  = {
                }
        
                SetScript  = {
                    $agName = $using:agInfo.agName
                    $secondaryServer = $using:sqlServerInstance
                    $primaryServer = $using:agInfo.primaryReplicaName
                    Write-Host "Running command against: $secondaryServer"
                    Invoke-SqlCmd -ServerInstance $secondaryServer -Query "ALTER AVAILABILITY GROUP [$agName] GRANT CREATE ANY DATABASE"
                    Write-Host "Running command against: $primaryServer"
                    Invoke-SqlCmd -ServerInstance $primaryServer -Query "ALTER AVAILABILITY GROUP [$agName] `
                        MODIFY REPLICA ON `'$secondaryServer`' `
                        WITH (SEEDING_MODE = AUTOMATIC)"
                }

                TestScript = {
                    $agName = $using:agInfo.agName
                    $secondaryServer = $using:sqlServerInstance
                    $count = (Invoke-SqlCmd -ServerInstance $secondaryServer -Query "SELECT Count(*) `
                        FROM sys.dm_hadr_automatic_seeding autos `
                        JOIN sys.availability_groups ag `
                        ON autos.ag_id = ag.group_id `
                        JOIN sys.availability_replicas ar `
                        ON autos.ag_id = ar.group_id `
                        WHERE performed_seeding = 1 AND name = `'$agName`' `
                        AND replica_server_name = `'$secondaryServer`' AND seeding_mode = 0").Column1
                    if($count -gt 0)
                    {
                        return $true
                    }
                    else
                    {
                        return $false
                    }
                }

                PsDscRunAsCredential = $sqlAdminCred
                DependsOn = "[SqlAGReplica]AddReplica_$($($agInfo).agName)"
            }
        
        }

        Script MoveComputerToTargetOU{
            
            GetScript = {
            }

            SetScript = {
                [string[]]$adObjectsToMove = @()
                $adObjectsToMove += $using:Node.NodeName
                $adObjectsToMove += $using:agsInfoWithIps[1].listenerName
                foreach($adObject in $adObjectsToMove)
                {
                    Write-Host "Moving AD computer to $using:targetOuPath"
                    Get-ADComputer -Filter "Name -eq `"$adObject`"" -SearchBase ($using:stagingOuPath) | Move-ADObject -TargetPath $using:targetOuPath
                    $adComputer = Get-ADComputer -Filter "Name -eq `"$adObject`"" -SearchBase $using:targetOuPath
                    if($adComputer)
                    {
                        Write-Host "Computer object has been moved"
                    }
                }
                $global:DSCMachineStatus = 1
            }

            TestScript = {
                [string[]]$adObjectsToMove = @()
                $adObjectsToMove += $using:Node.NodeName
                $adObjectsToMove += $using:agsInfoWithIps[1].listenerName
                foreach($adObject in $adObjectsToMove)
                {
                    $filter = "Name -eq `"$adObject`""
                    Write-Host "Using filter ($filter) and searching in $using:targetOuPath"
                    $adComputer = Get-ADComputer -Filter $filter -SearchBase $using:targetOuPath
                    if(-not $adComputer)
                    {
                        Write-Host "Computer is NOT in the correct OU"
                        return $false
                    }
                }
                return $true
            }

            DependsOn = '[Script]JoinCluster', "[SqlAGReplica]AddReplica_$($($agInfo).agName)"
            PsDscRunAsCredential = $domainJoinCred
        }

    }

    Node $AllNodes.Where{$_.Role -eq 'DrNode1'}.NodeName
    {

        $sqlServerInstance = $Node.NodeName
        if($sqlInstanceName -ne 'MSSQLSERVER')
        {
            $sqlServerInstance = "$($Node.NodeName)\$sqlInstanceName"
        }

        Script JoinCluster
        {
            GetScript = {
                # Not Implemented
            }

            SetScript = {
                Write-Host "Joining the cluster $using:clusterName"
                Add-ClusterNode -Name $using:Node.NodeName -Cluster $using:clusterName
            }

            TestScript = {
                $Status = ($null -ne (Get-ClusterNode -Name $using:Node.NodeName -Cluster $using:clusterName -ErrorAction SilentlyContinue))
                return $Status
            }

            PsDscRunAsCredential = $domainJoinCred
        }

        SqlAlwaysOnService "EnableAlwaysOn"
        {
            Ensure               = 'Present'
            ServerName           = $Node.NodeName
            InstanceName         = $sqlInstanceName
            RestartTimeout       = 120
            PsDscRunAsCredential = $sqlAdminCred
            DependsOn            = "[Script]JoinCluster"
        }

        foreach($agInfo in $agsInfoWithIps)
        {
            
            if($agInfo.primaryReplicaName -ne '')
            {

                SqlAGReplica "AddReplica_$($($agInfo).agName)"
                {
                    Ensure                        = 'Present'
                    Name                          = $Node.NodeName
                    AvailabilityGroupName         = $agInfo.agName
                    ServerName                    = $Node.NodeName
                    InstanceName                  = $sqlInstanceName
                    AvailabilityMode              = 'AsynchronousCommit'
                    ConnectionModeInSecondaryRole = 'AllowAllConnections'
                    FailoverMode                  = 'Manual'
                    PrimaryReplicaServerName      = $agInfo.primaryReplicaName
                    PrimaryReplicaInstanceName    = $sqlInstanceName
                    ProcessOnlyOnActiveNode       = $true
                    DependsOn                     = '[SqlAlwaysOnService]EnableAlwaysOn'
                }

                Script "EnableAutoSeeding_$($($agInfo).agName)"
                {
                    GetScript  = {
                    }
            
                    SetScript  = {
                        $agName = $using:agInfo.agName
                        $secondaryServer = $using:sqlServerInstance
                        $primaryServer = $using:agInfo.primaryReplicaName
                        Write-Host "Running command against: $secondaryServer"
                        Invoke-SqlCmd -ServerInstance $secondaryServer -Query "ALTER AVAILABILITY GROUP [$agName] GRANT CREATE ANY DATABASE"
                        Write-Host "Running command against: $primaryServer"
                        Invoke-SqlCmd -ServerInstance $primaryServer -Query "ALTER AVAILABILITY GROUP [$agName] `
                            MODIFY REPLICA ON `'$secondaryServer`' `
                            WITH (SEEDING_MODE = AUTOMATIC)"
                    }
    
                    TestScript = {
                        $agName = $using:agInfo.agName
                        $secondaryServer = $using:sqlServerInstance
                        $count = (Invoke-SqlCmd -ServerInstance $secondaryServer -Query "SELECT Count(*) `
                            FROM sys.dm_hadr_automatic_seeding autos `
                            JOIN sys.availability_groups ag `
                            ON autos.ag_id = ag.group_id `
                            JOIN sys.availability_replicas ar `
                            ON autos.ag_id = ar.group_id `
                            WHERE performed_seeding = 1 AND name = `'$agName`' `
                            AND replica_server_name = `'$secondaryServer`' AND seeding_mode = 0").Column1
                        if($count -gt 0)
                        {
                            return $true
                        }
                        else
                        {
                            return $false
                        }
                    }

                    PsDscRunAsCredential = $sqlAdminCred
                    DependsOn = "[SqlAGReplica]AddReplica_$($($agInfo).agName)"
                }

            }
        }

        WaitForSome ClusterCreated
        {
            ResourceName      = '[Script]ConfigureClusterAll'
            NodeCount         = 1
            NodeName          = ( $AllNodes | Where-Object { $_.Role -eq 'PrimaryNode1' } ).NodeName
            RetryIntervalSec  = 30
            RetryCount        = 60
        }

        # Change the DR server to have a quorum vote to 0
        Script ConfigureClusterSecondary
        {
            GetScript = {
                # Not Implemented
            }

            SetScript = {
                Write-Host "Configuring the Cluster"
                $drNode = $using:Node.NodeName
                (Get-ClusterNode $drNode).NodeWeight = 0
            }

            TestScript = {
                $drNode = $using:Node.NodeName
                if(((Get-ClusterNode $drNode).NodeWeight) -ne 0){return $false}
                return $true
            }

            PsDscRunAsCredential = $domainJoinCred
            DependsOn            = '[WaitForSome]ClusterCreated','[WindowsFeature]FCPS'
        }

        Script MoveComputerToTargetOU{
            
            GetScript = {
            }

            SetScript = {
                Write-Host "Moving AD computer to $using:targetOuPath"
                Get-ADComputer -Filter "Name -eq `"$($using:Node.NodeName)`"" -SearchBase ($using:stagingOuPath) | Move-ADObject -TargetPath $using:targetOuPath
                $adComputer = Get-ADComputer -Filter "Name -eq `"$($using:Node.NodeName)`"" -SearchBase $using:targetOuPath
                if($adComputer)
                {
                    Write-Host "Computer object has been moved"
                    $global:DSCMachineStatus = 1
                }
            }

            TestScript = {
                $filter = "Name -eq `"$($using:Node.NodeName)`""
                Write-Host "Using filter ($filter) and searching in $using:targetOuPath"
                $adComputer = Get-ADComputer -Filter $filter -SearchBase $using:targetOuPath
                if($adComputer)
                {
                    Write-Host "Computer is in the correct OU"
                    return $true
                }
                return $false
            }

            DependsOn = '[Script]JoinCluster', "[Script]ConfigureClusterSecondary"
            PsDscRunAsCredential = $domainJoinCred
        }
    }
}