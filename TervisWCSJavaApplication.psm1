﻿function Invoke-WCSJavaApplicationProvision {
    param (
        [Parameter(Mandatory)]$EnvironmentName,
        [Parameter(Mandatory)]$WCSJavaApplicationGitRepositoryPath
    )
    Invoke-ApplicationProvision -ApplicationName WCSJavaApplication -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName WCSJavaApplication -EnvironmentName $EnvironmentName
    $Nodes | Add-Member -MemberType NoteProperty -Name WCSJavaApplicationGitRepositoryPath -Value $WCSJavaApplicationGitRepositoryPath
    $Nodes | Add-WCSODBCDSN -ODBCDSNTemplateName Tervis
    $Nodes | Set-WCSEnvironmentVariables
    $Nodes | Expand-QCSoftwareZipPackage
    $Nodes | Invoke-ProcessWCSTemplateFiles
    $Nodes | New-QCSoftwareShare
    $Nodes | New-WCSShortcut
    $Nodes | Set-WCSBackground
    $Nodes | Install-WCSServiceManager
    $Nodes | Start-WCSServiceManagerService
    $Nodes | New-WCSJavaApplicationFirewallRules
    $Nodes | Install-WCSPrinters -PrintEngineOrientationRelativeToLabel Top
    $Nodes | Install-WCSPrinters -PrintEngineOrientationRelativeToLabel Bottom
    $Nodes | Install-WCSScheduledTasks
}

function Update-QcSoftwareFiles {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(ValueFromPipelineByPropertyName)]$EnvironmentName,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$WCSJavaApplicationGitRepositoryPath
    )
    process {
        Stop-WCSServiceManagerService -ComputerName $ComputerName
        Remove-QCSoftwareShare -ComputerName $ComputerName
        $QCSoftwarePathRemote = Get-WCSJavaApplicationRootDirectory -RemotePath -ComputerName $ComputerName
        $ArchivePath = "$($QCSoftwarePathRemote | Split-Path)\Archive"
        New-Item -ItemType Directory -Force -Path $ArchivePath 
        Move-Item -Path $QCSoftwarePathRemote -Destination "$($QCSoftwarePathRemote | Split-Path)\Archive"
        Remove-QCSoftwareZipPackage -ComputerName $ComputerName
        Expand-QCSoftwareZipPackage -ComputerName $ComputerName -WCSJavaApplicationGitRepositoryPath $WCSJavaApplicationGitRepositoryPath
        Invoke-ProcessWCSTemplateFiles -ComputerName $ComputerName -EnvironmentName $EnvironmentName -WCSJavaApplicationGitRepositoryPath $WCSJavaApplicationGitRepositoryPath
        New-QCSoftwareShare -ComputerName $ComputerName
        New-WCSShortcut -ComputerName $ComputerName
        Set-WCSBackground -ComputerName $ComputerName -EnvironmentName $EnvironmentName -WCSJavaApplicationGitRepositoryPath $WCSJavaApplicationGitRepositoryPath
        Start-WCSServiceManagerService -ComputerName $ComputerName
    }
}

function Set-WCSSystemParameterCS_ServerBasedOnNode {
    param (       
        [Parameter(ValueFromPipelineByPropertyName)]$EnvironmentName
    )
    begin {
        $ADDomain = Get-ADDomain
    }
    process {
        $WCSEnvironmentState = Get-WCSEnvironmentState -EnvironmentName $EnvironmentName
        Set-TervisWCSSystemParameterCS_Server -CS_Server "Progistics.$EnvironmentName.$($ADDomain.DNSRoot)" -PasswordID $WCSEnvironmentState.SybaseQCUserPasswordEntryID
    }
}

function New-WCSJavaApplicationFirewallRules {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName,
        [Switch]$Force
    )
    process {
        New-TervisFirewallRule -ComputerName $ComputerName -DisplayName "WCS Control" -Group WCS -LocalPort 26000-26100 -Name "WCSControl" -Direction Inbound -Action Allow -Protocol tcp -Force:$Force
        New-TervisFirewallRule -ComputerName $ComputerName -DisplayName "WCS RMI" -Group WCS -LocalPort 26300-26400 -Name "WCSRMI" -Direction Inbound -Action Allow -Protocol tcp -Force:$Force
        New-TervisFirewallRule -ComputerName $ComputerName -DisplayName "WCS RF Scanner" -Group WCS -LocalPort 26299 -Name "WCSRFScanner" -Direction Inbound -Action Allow -Protocol tcp -Force:$Force
    }
}

function Get-WCSJavaApplicationGitRepositoryPath {
    $ADDomain = Get-ADDomain -Current LocalComputer
    "\\$($ADDomain.DNSRoot)\applications\GitRepository\WCSJavaApplication"
}

function Start-WCSServiceManagerService {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Start-Service -Name servicemgr
        }
    }
}

function Stop-WCSServiceManagerService {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        $Force
    )
    process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Stop-Service -Name servicemgr -Force:$Force
        }
    }
}

function Set-WCSBackground {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$EnvironmentName,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$WCSJavaApplicationGitRepositoryPath
    )
    begin {
        $BackGroundSourcePath = "$WCSJavaApplicationGitRepositoryPath\Background"
        $BackGroundPathLocal = "$(Get-WCSJavaApplicationRootDirectory)\Gif"
    }
    process {
        $BackGroundPathRemote = $BackGroundPathLocal | ConvertTo-RemotePath -ComputerName $ComputerName
        Copy-Item -Force -Path "$BackGroundSourcePath\backgroundQC.$EnvironmentName.png" -Destination $BackGroundPathRemote\backgroundQC.png
    }
}

function New-WCSShortcut {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName,
        $Path,
        [Switch]$ExcludeComputerNameVariable
    )
    begin {
        $WCSJavaApplicationRootDirectory = Get-WCSJavaApplicationRootDirectory
    }
    process {
        $WCSShortcutPath = if ($Path) { 
            $Path
        } else { 
            $WCSJavaApplicationRootDirectory | 
            ConvertTo-RemotePath -ComputerName $ComputerName
        }
        Set-Shortcut -LinkPath "$WCSShortcutPath\WCS ($ComputerName).lnk" -IconLocation "\\$ComputerName\QcSoftware\Gif\tfIcon.ico,0" -TargetPath "\\$ComputerName\QcSoftware\Bin\runScreens.cmd" -Arguments "-q -p \\$ComputerName\QcSoftware$(if(-not $ExcludeComputerNameVariable) {" -n %COMPUTERNAME%"})"
    }
}

function New-QCSoftwareShare {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    begin {
        $WCSJavaApplicationRootDirectory = Get-WCSJavaApplicationRootDirectory
    }
    process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            if (-not (Get-SmbShare -Name QcSoftware -ErrorAction SilentlyContinue)) {
                New-SmbShare -Name QcSoftware -Path $Using:WCSJavaApplicationRootDirectory -ChangeAccess "Everyone" | Out-Null
                $ACL = Get-Acl -Path $Using:WCSJavaApplicationRootDirectory
                $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "Modify","ContainerInherit,ObjectInherit", "None", "Allow")
                $ACL.SetAccessRule($AccessRule)
                Set-Acl -path $Using:WCSJavaApplicationRootDirectory -AclObject $Acl
            }
        }
    }  
}

function Remove-QCSoftwareShare {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Get-SmbShare -Name QcSoftware | Remove-SmbShare -Force
        }
    }  
}

function Get-WCSJavaApplicationRootDirectory {
    param (
        [Parameter(ParameterSetName="RemotePath")][Switch]$RemotePath,
        [Parameter(ParameterSetName="RemotePath")]$ComputerName
    )
    $Path = "C:\QcSoftware"
    if ($RemotePath) {
        $Path | ConvertTo-RemotePath -ComputerName $ComputerName
    } else {
        $Path
    }
}

function Set-WCSEnvironmentVariables {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    begin {
        $WCSJavaApplicationRootDirectory = Get-WCSJavaApplicationRootDirectory

        $EnvironmentVariables = [PSCustomObject]@{
            Name = "CONFIG_DIR"
            Value = "$WCSJavaApplicationRootDirectory\config"
        },
        [PSCustomObject]@{
            Name = "JSWAT"
            Value = "$WCSJavaApplicationRootDirectory\jswat"
        },
        [PSCustomObject]@{
            Name = "JSWAT_HOME"
            Value = "$WCSJavaApplicationRootDirectory\jswat"
        },
        [PSCustomObject]@{
            Name = "PROJECT_BASE"
            Value = "$WCSJavaApplicationRootDirectory"
        }

        $PathsToAddToEnvironmentVariablePath = @(
            "$WCSJavaApplicationRootDirectory\lib",
            "$WCSJavaApplicationRootDirectory\Bin"
        )
    }
    process {
        $EnvironmentVariablesResult = $EnvironmentVariables | 
            Set-EnvironmentVariable -ComputerName $ComputerName -Target Machine -ReturnTrueIfSet
        $PathsResult = $PathsToAddToEnvironmentVariablePath | 
            Add-PathToEnvironmentVariablePath -ComputerName $ComputerName -Target Machine -ReturnTrueIfSet
        if ($EnvironmentVariablesResult -or $PathsResult) {
            Restart-Computer -ComputerName $ComputerName
            Wait-ForNodeRestart -ComputerName $ComputerName
        }
    }
}

function Set-EnvironmentVariable {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$Name,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$Value,
        [Parameter(Mandatory)][ValidateSet("Machine","Process","User")]$Target,
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName,
        [Switch]$Force,
        [Switch]$ReturnTrueIfSet
    )
    process {
        if ($ComputerName) {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                if ( -not (Get-Item -Path Env:\$Using:Name -ErrorAction SilentlyContinue) -or $Using:Force) {
                    [Environment]::SetEnvironmentVariable($Using:Name, $Using:Value, $Using:Target)
                    if ($Using:ReturnTrueIfSet) { $true }
                }
            }
        } else {
            if ( -not (Get-Item -Path Env:\$Name -ErrorAction SilentlyContinue) -or $Force) {
                [Environment]::SetEnvironmentVariable($Name, $Value, $Target)
                if ($ReturnTrueIfSet) { $true }
            }
        }
    }
}

function Add-PathToEnvironmentVariablePath {
    param (
        [Parameter(Mandatory,ValueFromPipeline)]$Path,
        [Parameter(Mandatory)][ValidateSet("Machine","Process","User")]$Target,
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName,
        [Switch]$ReturnTrueIfSet
    )
    process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {            
            if ( -not ($env:Path -split ";" -contains $Using:Path)) {
                [Environment]::SetEnvironmentVariable("PATH", "$env:Path;$Using:Path", $Using:Target)
                if ($Using:ReturnTrueIfSet) { $true }
            }
        }
    }
}

function Compress-QCSoftwarePath {
    param (
        [Parameter(Mandatory)]$Path,
        [Parameter(Mandatory)]$WCSJavaApplicationGitRepositoryPath
    )
    $ZipFileName = "QcSoftware.zip"
    $ZipFilePathRemote = "$WCSJavaApplicationGitRepositoryPath\$ZipFileName"
    Compress-Archive -Path $Path -DestinationPath $ZipFilePathRemote

    #$QCSoftwareFilesAndDirectoriesToZip = Get-ChildItem -Path $Path -Recurse |
    #where {
    #    -not ($_.FullName -match "QcSoftware\\Tmp" -and -not $_.PsIsContainer)
    #} |
    #where {
    #    -not ($_.FullName -match "QcSoftware\\Log\\Tmp\\Backup" -and -not $_.PsIsContainer)
    #} |
    #where Name -NE "WCS (wcs01).lnk"
    #$progressPreference = 'silentlyContinue'
    #Compress-Archive -Path $QCSoftwareFilesAndDirectoriesToZip.FullName -DestinationPath $ZipFilePathRemote
    #$progressPreference = 'Continue'
}

function Expand-QCSoftwareZipPackage {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$WCSJavaApplicationGitRepositoryPath
    )
    begin {
        $ZipFileName = "QcSoftware.zip"
        $ZipFilePathRemote = "$WCSJavaApplicationGitRepositoryPath\$ZipFileName"
        $ZipFileCopyPathLocal = "C:\ProgramData\TervisWCS\"
        $ExtractPath = Get-WCSJavaApplicationRootDirectory        
    }
    process {
        $ZipFileCopyPathRemote = $ZipFileCopyPathLocal | ConvertTo-RemotePath -ComputerName $ComputerName
        New-Item -Force -ItemType Directory -Path $ZipFileCopyPathRemote | Out-Null
        if (-not (Test-Path $ZipFileCopyPathRemote\$ZipFileName)) {
            Copy-Item -Path $ZipFilePathRemote -Destination $ZipFileCopyPathRemote
        }
        
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            if (-not (Test-Path $Using:ExtractPath)) {
                Expand-Archive -Path "$Using:ZipFileCopyPathLocal\$Using:ZipFileName" -DestinationPath $Using:ExtractPath -Force
            }
        }
    }
}

function Remove-QCSoftwareZipPackage {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName        
    )
    begin {
        $ZipFileName = "QcSoftware.zip"
        $ZipFileCopyPathLocal = "C:\ProgramData\TervisWCS\"
    }
    process {
        $ZipFileCopyPathRemote = $ZipFileCopyPathLocal | ConvertTo-RemotePath -ComputerName $ComputerName
        Remove-Item -Path $ZipFileCopyPathRemote\$ZipFileName
    }
}

function Install-WCSServiceManager {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName        
    )
    begin {
        $RootDirectory = Get-WCSJavaApplicationRootDirectory
    }
    process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Set-Location -Path $Using:RootDirectory\bin
            cmd /c "..\profile.bat && servicemgr -i"
            Set-Service -Name servicemgr -StartupType Automatic
        }
    }
}

function Remove-WCSServiceManager {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName        
    )
    begin {
        $RootDirectory = Get-WCSJavaApplicationRootDirectory
    }
    process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Set-Location -Path $Using:RootDirectory\bin
            cmd /c "..\profile.bat && servicemgr -r"
        }
    }
}

function Get-QCPatcherUpdateZip {
    param (
        [Parameter(Mandatory)]$UpdateFileName,
        [Parameter(Mandatory)]$WCSJavaApplicationGitRepositoryPath
    )
    $UpdatesPath = "$WCSJavaApplicationGitRepositoryPath\Updates"
    
    $ZipFile = Get-ChildItem -Filter "*.zip" -Path $UpdatesPath |
    Where Name -Match $UpdateFileName

    if ($ZipFile | Measure | Where Count -gt 1) {
        Throw "More than one zip file with `"$UpdateFileName`" in the name"
    }

    $ZipFile
}

function Invoke-QCPatcher {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(Mandatory)]$UpdateFileName,
        [switch]$AcknowledgeWarning
    )
    begin {
        Write-Warning "DO NOT BEGIN PATCHING PROCESS RIGHT BEFORE SCHEDULED MAINTENANCE OF SERVERS"
        if (-not $AcknowledgeWarning) {
            Read-Host "Press Enter to acknowledge"
        }
        $UpdatesPendingPath = "$(Get-WCSJavaApplicationRootDirectory)\Updates\Pending"
    }
    process {
        $UpdatesPendingPathRemote =  $UpdatesPendingPath | ConvertTo-RemotePath -ComputerName $ComputerName
        $ZipFileRemote = Get-QCPatcherUpdateZip -UpdateFileName $UpdateFileName
        Copy-Item -Path $ZipFileRemote.FullName -Destination $UpdatesPendingPathRemote

        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Set-Location -Path $Using:UpdatesPendingPath
            $ZipFileLocal = Get-ChildItem -Filter "*.zip"
            cmd /V:ON /C "..\..\profile.bat && qcpatcher $($ZipFileLocal.Name)"
        }
    }
    end {
        Write-Warning "Run Invoke-TervisDBUnloadToWCSGitRepository to generate SQL rebuild script and commit it with Git."
    }
}

function Invoke-ProcessWCSTemplateFiles {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$EnvironmentName,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$WCSJavaApplicationGitRepositoryPath
    )
    begin {
        $RootDirectory = Get-WCSJavaApplicationRootDirectory
        $TemplateFilesPath = "$WCSJavaApplicationGitRepositoryPath\QcSoftware"
    }
    process {
        $WCSEnvironmentState = Get-WCSEnvironmentState -EnvironmentName $EnvironmentName
        $SybaseDatabaseEntryDetails = Get-PasswordstateSybaseDatabaseEntryDetails -PasswordID $WCSEnvironmentState.SybaseQCUserPasswordEntryID
        $TemplateVariables = @{
            DATABASE_MACHINE = $SybaseDatabaseEntryDetails.Host
            DATABASE_NAME = $SybaseDatabaseEntryDetails.DatabaseName
            QCCS_DB_NAME = $SybaseDatabaseEntryDetails.DatabaseName
            DATABASE_PORT = $SybaseDatabaseEntryDetails.Port
            ComputerName = $ComputerName
            EnvironmentName = $EnvironmentName
            WCSJavaApplicationRootDirectory = $RootDirectory
        }

        $RootDirectoryRemote = $RootDirectory | ConvertTo-RemotePath -ComputerName $ComputerName
        Invoke-ProcessTemplatePath -Path $TemplateFilesPath -DestinationPath $RootDirectoryRemote -TemplateVariables $TemplateVariables
    }
}

function Get-WCSLogFileTail {
    param (
        $ComputerName,
        $Tail = 100
    )
    $WCSJavaApplicationRootDirectoryRemote = Get-WCSJavaApplicationRootDirectory | ConvertTo-RemotePath -ComputerName $ComputerName
    $LogFilePath = "$WCSJavaApplicationRootDirectoryRemote\log\tmp"
    $LogFiles = Get-ChildItem -Path $LogFilePath -File | where name -NotMatch ".lnk"
    $LogFiles | ForEach-Object { 
        $_.FullName
        Get-Content -Tail $Tail -Path $_.FullName 
    }
}

function Install-WCSScheduledTasks {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    begin {
        $WCSScheduledProgramsDirectory = "$(Get-WCSJavaApplicationRootDirectory)\Bin"
        $SystemCredential = New-Object System.Management.Automation.PSCredential ('System',(New-Object System.Security.SecureString))        
    }
    process {
        Install-TervisScheduledTask -Credential $SystemCredential `
            -TaskName "Nightly Cleanup" `
            -Execute $WCSScheduledProgramsDirectory\nightlyCleanup.cmd `
            -RepetitionIntervalName "EveryDayAt2AM" `
            -ComputerName $ComputerName
        Install-TervisScheduledTask -Credential $SystemCredential `
            -TaskName "Reopen Daily Logs" `
            -Execute $WCSScheduledProgramsDirectory\dailyLogsReopen.cmd `
            -RepetitionIntervalName "EveryDayAt5amEvery3HoursFor18Hours" `
            -ComputerName $ComputerName
    }
}

function Install-WCSJavaRemoteAppClient {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    begin {
        $ADDomain = Get-ADDomain -Current LocalComputer | select -ExpandProperty DNSRoot
        $TemplateVariables = @{
            DLTWCSJavaApplicationServer = "WCSJavaApplication.Delta.$ADDomain"
            EPSWCSJavaApplicationServer = "WCSJavaApplication.Epsilon.$ADDomain"
            PRDWCSJavaApplicationServer = "WCSJavaApplication.Production.$ADDomain"
        }
    }
    process {
        Invoke-ProcessTemplatePath -Path $PSScriptRoot\Templates -DestinationPath \\$ComputerName\C$ -TemplateVariables $TemplateVariables
    }
}

function Install-TervisWCSShortcutOnShippingComputers {
    param (
        [Parameter(Mandatory)]$ServerName
    )
    
    $ShippingComputers = Get-ADComputer -Filter {Name -like "Ship*"}
    foreach ($Computer in $ShippingComputers) {
        try {
            $RemotePublicDesktopWCSLink = "C:\Users\Public\Desktop\WCS ($ServerName).lnk" | ConvertTo-RemotePath -ComputerName $Computer.Name
            if (Test-Path -Path $RemotePublicDesktopWCSLink) {
                Remove-Item -Path $RemotePublicDesktopWCSLink -Force
            }
            Set-Shortcut -LinkPath $RemotePublicDesktopWCSLink -IconLocation "\\$ServerName\QcSoftware\Gif\tfIcon.ico,0" -TargetPath "\\$ServerName\QcSoftware\Bin\runScreens.cmd" -Arguments "-q -p \\$ServerName\QcSoftware -n %COMPUTERNAME%"
            $Result = "Success"
        } catch { $Result = "Fail" }
        [PSCustomObject][Ordered]@{
            ComputerName = $Computer.Name
            Result = $Result
        }
    }
}

function Remove-TervisWCSShortcutOnShippingComputers {
    param (
        [Parameter(Mandatory)]$ServerName
    )
    
    $ShippingComputers = Get-ADComputer -Filter {Name -like "Ship*"}
    foreach ($Computer in $ShippingComputers) {
        try {
            $RemotePublicDesktopWCSLink = "C:\Users\Public\Desktop\WCS ($ServerName).lnk" | ConvertTo-RemotePath -ComputerName $Computer.Name
            if (Test-Path -Path $RemotePublicDesktopWCSLink -ErrorAction Stop) {
                Remove-Item -Path $RemotePublicDesktopWCSLink -Force
            }
        $Result = "Success"
        } catch { $Result = "Fail" }
        [PSCustomObject][Ordered]@{
            ComputerName = $Computer.Name
            Result = $Result
        }
    }
}

function Invoke-WCSJavaApplicationCutover {
    param (
        $ComputerName,
        $OldComputerName,
        $EnvironmentName
    )

    Stop-WCSServiceManagerService -ComputerName $OldComputerName
    $OldService = Get-Service -Name servicemgr -ComputerName $OldComputerName
    $OldService | Set-Service -StartupType Disabled

    $OldComputerIPAddress = Resolve-DnsName $OldComputerName | select -ExpandProperty IPAddress
    $Connections = Get-TervisSQLAnywhereConnection -EnvironmentName $EnvironmentName
    
    $Connections |
    where NodAddr -EQ $OldComputerIPAddress |
    Remove-TervisSQLAnywhereConnection -EnvironmentName $EnvironmentName
    
    Update-TervisWCSReferencesToComputerName -ComputerName $ComputerName -OldComputerName $OldComputerName -PasswordID 3459

    $Service = Get-Service -Name servicemgr -ComputerName $ComputerName
    $Service | Set-Service -StartupType Automatic
    $Service | Start-Service
}


