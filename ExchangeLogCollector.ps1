<#
    MIT License

    Copyright (c) Microsoft Corporation.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE
#>

# Version 22.02.05.1629

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Value is used')]
[CmdletBinding()]
Param (
    [string]$FilePath = "C:\MS_Logs_Collection",
    [array]$Servers = @($env:COMPUTERNAME),
    [switch]$ADDriverLogs,
    [bool]$AppSysLogs = $true,
    [bool]$AppSysLogsToXml = $true,
    [switch]$AutoDLogs,
    [switch]$CollectFailoverMetrics,
    [switch]$DAGInformation,
    [switch]$DailyPerformanceLogs,
    [switch]$DefaultTransportLogging,
    [switch]$EASLogs,
    [switch]$ECPLogs,
    [switch]$EWSLogs,
    [Alias("ExchangeServerInfo")]
    [switch]$ExchangeServerInformation,
    [switch]$Exmon,
    [switch]$Experfwiz,
    [switch]$FrontEndConnectivityLogs,
    [switch]$FrontEndProtocolLogs,
    [switch]$GetVdirs,
    [switch]$HighAvailabilityLogs,
    [switch]$HubConnectivityLogs,
    [switch]$HubProtocolLogs,
    [switch]$IISLogs,
    [switch]$ImapLogs,
    [switch]$MailboxConnectivityLogs,
    [switch]$MailboxDeliveryThrottlingLogs,
    [switch]$MailboxProtocolLogs,
    [Alias("ManagedAvailability")]
    [switch]$ManagedAvailabilityLogs,
    [switch]$MapiLogs,
    [switch]$MessageTrackingLogs,
    [switch]$MitigationService,
    [switch]$OABLogs,
    [switch]$OrganizationConfig,
    [switch]$OWALogs,
    [switch]$PopLogs,
    [switch]$PowerShellLogs,
    [switch]$QueueInformation,
    [switch]$ReceiveConnectors,
    [switch]$RPCLogs,
    [switch]$SearchLogs,
    [switch]$SendConnectors,
    [Alias("ServerInfo")]
    [switch]$ServerInformation,
    [switch]$TransportConfig,
    [switch]$WindowsSecurityLogs,
    [switch]$AcceptEULA,
    [switch]$AllPossibleLogs,
    [bool]$CollectAllLogsBasedOnDaysWorth = $true,
    [switch]$DatabaseFailoverIssue,
    [int]$DaysWorth = 3,
    [int]$HoursWorth = 0,
    [switch]$DisableConfigImport,
    [string]$ExmonLogmanName = "Exmon_Trace",
    [array]$ExperfwizLogmanName = @("Exchange_Perfwiz", "ExPerfwiz"),
    [switch]$ConnectivityLogs,
    [switch]$OutlookConnectivityIssues,
    [switch]$PerformanceIssues,
    [switch]$PerformanceMailflowIssues,
    [switch]$ProtocolLogs,
    [switch]$ScriptDebug,
    [bool]$SkipEndCopyOver
)

$BuildVersion = "22.02.05.1629"

$Script:VerboseEnabled = $false

if ($PSBoundParameters["Verbose"]) { $Script:VerboseEnabled = $true }


#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/Common/Confirm-Administrator/Confirm-Administrator.ps1
#v21.01.22.2212
Function Confirm-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )

    if ($currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )) {
        return $true
    } else {
        return $false
    }
}


Function Invoke-CatchActionError {
    [CmdletBinding()]
    param(
        [scriptblock]$CatchActionFunction
    )

    if ($null -ne $CatchActionFunction) {
        & $CatchActionFunction
    }
}

Function Invoke-CatchActionErrorLoop {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [int]$CurrentErrors,
        [Parameter(Mandatory = $false, Position = 1)]
        [scriptblock]$CatchActionFunction
    )
    process {
        if ($null -ne $CatchActionFunction -and
            $Error.Count -ne $CurrentErrors) {
            $i = 0
            while ($i -lt ($Error.Count - $currentErrors)) {
                & $CatchActionFunction $Error[$i]
                $i++
            }
        }
    }
}

Function Confirm-ExchangeShell {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Identity,

        [Parameter(Mandatory = $false)]
        [bool]$LoadExchangeShell = $true,

        [Parameter(Mandatory = $false)]
        [bool]$IgnoreToolsIdentity = $false,

        [Parameter(Mandatory = $false)]
        [scriptblock]$CatchActionFunction
    )

    begin {
        Function Test-GetExchangeServerCmdletError {
            param(
                [Parameter(Mandatory = $true)]
                [object]$ThisError
            )

            if ($ThisError.FullyQualifiedErrorId -ne "CommandNotFoundException") {
                Write-Warning "Failed to find '$Identity' as an Exchange Server."
                return $true
            }
            return $false
        }
        $currentErrors = $Error.Count
        $passed = $false
        $edgeTransportKey = 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\EdgeTransportRole'
        $setupKey = 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup'
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose "Passed: LoadExchangeShell: $LoadExchangeShell | Identity: $Identity | IgnoreToolsIdentity: $IgnoreToolsIdentity"
        $params = @{
            Identity    = $Identity
            ErrorAction = "Stop"
        }

        $toolsServer = (Test-Path $setupKey) -and (!(Test-Path $edgeTransportKey)) -and `
        ($null -eq (Get-ItemProperty -Path $setupKey -Name "Services" -ErrorAction SilentlyContinue))

        if ($toolsServer) {
            Write-Verbose "Tools Server: $env:ComputerName"
            if ($env:ComputerName -eq $Identity -and
                $IgnoreToolsIdentity) {
                Write-Verbose "Removing Identity from Get-ExchangeServer cmdlet"
                $params.Remove("Identity")
            } else {
                Write-Verbose "Didn't remove Identity"
            }
        }

        Invoke-CatchActionErrorLoop $currentErrors $CatchActionFunction
    }
    process {
        try {
            $currentErrors = $Error.Count
            Get-ExchangeServer @params | Out-Null
            Write-Verbose "Exchange PowerShell Module already loaded."
            $passed = $true
            Invoke-CatchActionErrorLoop $currentErrors $CatchActionFunction
        } catch {
            Write-Verbose "Failed to run Get-ExchangeServer"
            Invoke-CatchActionError $CatchActionFunction
            if (Test-GetExchangeServerCmdletError $_) { return }
            if (-not ($LoadExchangeShell)) { return }

            #Test 32 bit process, as we can't see the registry if that is the case.
            if (-not ([System.Environment]::Is64BitProcess)) {
                Write-Warning "Open a 64 bit PowerShell process to continue"
                return
            }

            if (Test-Path "$setupKey") {
                $currentErrors = $Error.Count
                Write-Verbose "We are on Exchange 2013 or newer"

                try {
                    if (Test-Path $edgeTransportKey) {
                        Write-Verbose "We are on Exchange Edge Transport Server"
                        [xml]$PSSnapIns = Get-Content -Path "$env:ExchangeInstallPath\Bin\exshell.psc1" -ErrorAction Stop

                        foreach ($PSSnapIn in $PSSnapIns.PSConsoleFile.PSSnapIns.PSSnapIn) {
                            Write-Verbose "Trying to add PSSnapIn: {0}" -f $PSSnapIn.Name
                            Add-PSSnapin -Name $PSSnapIn.Name -ErrorAction Stop
                        }

                        Import-Module $env:ExchangeInstallPath\bin\Exchange.ps1 -ErrorAction Stop
                    } else {
                        Import-Module $env:ExchangeInstallPath\bin\RemoteExchange.ps1 -ErrorAction Stop
                        Connect-ExchangeServer -Auto -ClientApplication:ManagementShell
                    }

                    Write-Verbose "Imported Module. Trying Get-Exchange Server Again"
                    try {
                        Get-ExchangeServer @params | Out-Null
                        $passed = $true
                        Write-Verbose "Successfully loaded Exchange Management Shell"
                        Invoke-CatchActionErrorLoop $currentErrors $CatchActionFunction
                    } catch {
                        Write-Verbose "Failed to run Get-ExchangeServer again"
                        Invoke-CatchActionError $CatchActionFunction
                        if (Test-GetExchangeServerCmdletError $_) { return }
                    }
                } catch {
                    Write-Warning "Failed to Load Exchange PowerShell Module..."
                    Invoke-CatchActionError $CatchActionFunction
                }
            } else {
                Write-Verbose "Not on an Exchange or Tools server"
            }
        }
    }
    end {

        $currentErrors = $Error.Count
        $returnObject = [PSCustomObject]@{
            ShellLoaded = $passed
            Major       = ((Get-ItemProperty -Path $setupKey -Name "MsiProductMajor" -ErrorAction SilentlyContinue).MsiProductMajor)
            Minor       = ((Get-ItemProperty -Path $setupKey -Name "MsiProductMinor" -ErrorAction SilentlyContinue).MsiProductMinor)
            Build       = ((Get-ItemProperty -Path $setupKey -Name "MsiBuildMajor" -ErrorAction SilentlyContinue).MsiBuildMajor)
            Revision    = ((Get-ItemProperty -Path $setupKey -Name "MsiBuildMinor" -ErrorAction SilentlyContinue).MsiBuildMinor)
            EdgeServer  = $passed -and (Test-Path $setupKey) -and (Test-Path $edgeTransportKey)
            ToolsOnly   = $passed -and $toolsServer
            RemoteShell = $passed -and (!(Test-Path $setupKey))
        }

        Invoke-CatchActionErrorLoop $currentErrors $CatchActionFunction

        return $returnObject
    }
}

#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/Common/Enter-YesNoLoopAction/Enter-YesNoLoopAction.ps1
#v21.01.22.2234
Function Enter-YesNoLoopAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Question,
        [Parameter(Mandatory = $true)][scriptblock]$YesAction,
        [Parameter(Mandatory = $true)][scriptblock]$NoAction
    )
    #Function Version #v21.01.22.2234

    Write-VerboseWriter("Calling: Enter-YesNoLoopAction")
    Write-VerboseWriter("Passed: [string]Question: {0}" -f $Question)

    do {
        $answer = Read-Host ("{0} ('y' or 'n')" -f $Question)
        Write-VerboseWriter("Read-Host answer: {0}" -f $answer)
    }while ($answer -ne 'n' -and $answer -ne 'y')

    if ($answer -eq 'y') {
        &$YesAction
    } else {
        &$NoAction
    }
}

#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/Common/Import-ScriptConfigFile/Import-ScriptConfigFile.ps1
#v21.02.07.1240
Function Import-ScriptConfigFile {
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true
        )]
        [string]$ScriptConfigFileLocation
    )
    #Function Version #v21.02.07.1240

    Write-VerboseWriter("Calling: Import-ScriptConfigFile")
    Write-VerboseWriter("Passed: [string]ScriptConfigFileLocation: '$ScriptConfigFileLocation'")

    if (!(Test-Path $ScriptConfigFileLocation)) {
        throw [System.Management.Automation.ParameterBindingException] "Failed to provide valid ScriptConfigFileLocation"
    }

    try {
        $content = Get-Content $ScriptConfigFileLocation -ErrorAction Stop
        $jsonContent = $content | ConvertFrom-Json
    } catch {
        throw "Failed to convert ScriptConfigFileLocation from a json type object."
    }

    $jsonContent |
        Get-Member |
        Where-Object { $_.Name -ne "Method" } |
        ForEach-Object {
            Write-VerboseWriter("Adding variable $($_.Name)")
            Set-Variable -Name $_.Name -Value ($jsonContent.$($_.Name)) -Scope Script
        }
}

#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/Common/Start-JobManager/Start-JobManager.ps1
#v21.01.22.2234
Function Start-JobManager {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'I prefer Start here')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][array]$ServersWithArguments,
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [Parameter(Mandatory = $false)][string]$JobBatchName,
        [Parameter(Mandatory = $false)][bool]$DisplayReceiveJob = $true,
        [Parameter(Mandatory = $false)][bool]$DisplayReceiveJobInVerboseFunction,
        [Parameter(Mandatory = $false)][bool]$DisplayReceiveJobInCorrectFunction,
        [Parameter(Mandatory = $false)][bool]$NeedReturnData = $false
    )
    #Function Version #v21.01.22.2234
    <#
        [array]ServersWithArguments
            [string]ServerName
            [object]ArgumentList #customized for your scriptblock
    #>

    Function Write-ReceiveJobData {
        param(
            [Parameter(Mandatory = $true)][array]$ReceiveJobData
        )
        $returnJob = [string]::Empty
        foreach ($job in $ReceiveJobData) {
            if ($job["Verbose"]) {
                Write-VerboseWriter($job["Verbose"])
            } elseif ($job["Host"]) {
                Write-HostWriter($job["Host"])
            } elseif ($job["ReturnObject"]) {
                $returnJob = $job["ReturnObject"]
            } else {
                Write-VerboseWriter("Unable to determine the key for the return type.")
            }
        }
        return $returnJob
    }

    Function Start-Jobs {
        Write-VerboseWriter("Calling Start-Jobs")
        foreach ($serverObject in $ServersWithArguments) {
            $server = $serverObject.ServerName
            $argumentList = $serverObject.ArgumentList
            Write-VerboseWriter("Starting job on server {0}" -f $server)
            Invoke-Command -ComputerName $server -ScriptBlock $ScriptBlock -ArgumentList $argumentList -AsJob -JobName $server | Out-Null
        }
    }

    Function Confirm-JobsPending {
        $jobs = Get-Job
        if ($null -ne $jobs) {
            return $true
        }
        return $false
    }

    Function Wait-JobsCompleted {
        Write-VerboseWriter("Calling Wait-JobsCompleted")
        [System.Diagnostics.Stopwatch]$timer = [System.Diagnostics.Stopwatch]::StartNew()
        $returnData = @{}
        while (Confirm-JobsPending) {
            $completedJobs = Get-Job | Where-Object { $_.State -ne "Running" }
            if ($null -eq $completedJobs) {
                Start-Sleep 1
                continue
            }

            foreach ($job in $completedJobs) {
                $receiveJobNull = $false
                $jobName = $job.Name
                Write-VerboseWriter("Job {0} received. State: {1} | HasMoreData: {2}" -f $job.Name, $job.State, $job.HasMoreData)
                if ($NeedReturnData -eq $false -and $DisplayReceiveJob -eq $false -and $job.HasMoreData -eq $true) {
                    Write-VerboseWriter("This job has data and you provided you didn't want to return it or display it.")
                }
                $receiveJob = Receive-Job $job
                Remove-Job $job
                if ($null -eq $receiveJob) {
                    $receiveJobNull = $True
                    Write-VerboseWriter("Job {0} didn't have any receive job data" -f $jobName)
                }
                if ($DisplayReceiveJobInVerboseFunction -and (-not($receiveJobNull))) {
                    Write-VerboseWriter("[JobName: {0}] : {1}" -f $jobName, $receiveJob)
                } elseif ($DisplayReceiveJobInCorrectFunction -and (-not ($receiveJobNull))) {
                    $returnJobData = Write-ReceiveJobData -ReceiveJobData $receiveJob
                    if ($null -ne $returnJobData) {
                        $returnData.Add($jobName, $returnJobData)
                    }
                } elseif ($DisplayReceiveJob -and (-not($receiveJobNull))) {
                    Write-HostWriter $receiveJob
                }
                if ($NeedReturnData -and (-not($DisplayReceiveJobInCorrectFunction))) {
                    $returnData.Add($job.Name, $receiveJob)
                }
            }
        }
        $timer.Stop()
        Write-VerboseWriter("Waiting for jobs to complete took {0} seconds" -f $timer.Elapsed.TotalSeconds)
        if ($NeedReturnData) {
            return $returnData
        }
        return $null
    }

    [System.Diagnostics.Stopwatch]$timerMain = [System.Diagnostics.Stopwatch]::StartNew()
    Write-VerboseWriter("Calling Start-JobManager")
    Write-VerboseWriter("Passed: [bool]DisplayReceiveJob: {0} | [string]JobBatchName: {1} | [bool]DisplayReceiveJobInVerboseFunction: {2} | [bool]NeedReturnData:{3}" -f $DisplayReceiveJob,
        $JobBatchName,
        $DisplayReceiveJobInVerboseFunction,
        $NeedReturnData)

    Start-Jobs
    $data = Wait-JobsCompleted
    $timerMain.Stop()
    Write-VerboseWriter("Exiting: Start-JobManager | Time in Start-JobManager: {0} seconds" -f $timerMain.Elapsed.TotalSeconds)
    if ($NeedReturnData) {
        return $data
    }
    return $null
}

Function Get-DAGInformation {
    param(
        [Parameter(Mandatory = $true)][string]$DAGName
    )

    try {
        $dag = Get-DatabaseAvailabilityGroup $DAGName -Status -ErrorAction Stop
    } catch {
        Write-ScriptDebug("Failed to run Get-DatabaseAvailabilityGroup on $DAGName")
        Invoke-CatchBlockActions
    }

    try {
        $dagNetwork = Get-DatabaseAvailabilityGroupNetwork $DAGName -ErrorAction Stop
    } catch {
        Write-ScriptDebug("Failed to run Get-DatabaseAvailabilityGroupNetwork on $DAGName")
        Invoke-CatchBlockActions
    }

    #Now to get the Mailbox Database Information for each server in the DAG.
    $cacheDBCopyStatus = @{}
    $mailboxDatabaseInformationPerServer = @{}

    foreach ($server in $dag.Servers) {
        $serverName = $server.ToString()
        $getMailboxDatabases = Get-MailboxDatabase -Server $serverName -Status

        #Foreach of the mailbox databases on this server, we want to know the copy status
        #but we don't want to duplicate this work a lot, so we have a cache feature.
        $getMailboxDatabaseCopyStatusPerDB = @{}
        $getMailboxDatabases |
            ForEach-Object {
                $dbName = $_.Name

                if (!($cacheDBCopyStatus.ContainsKey($dbName))) {
                    $copyStatusForDB = Get-MailboxDatabaseCopyStatus $dbName\* -ErrorAction SilentlyContinue
                    $cacheDBCopyStatus.Add($dbName, $copyStatusForDB)
                } else {
                    $copyStatusForDB = $cacheDBCopyStatus[$dbName]
                }

                $getMailboxDatabaseCopyStatusPerDB.Add($dbName, $copyStatusForDB)
            }

        $serverDatabaseInformation = [PSCustomObject]@{
            MailboxDatabases                = $getMailboxDatabases
            MailboxDatabaseCopyStatusPerDB  = $getMailboxDatabaseCopyStatusPerDB
            MailboxDatabaseCopyStatusServer = (Get-MailboxDatabaseCopyStatus *\$serverName -ErrorAction SilentlyContinue)
        }

        $mailboxDatabaseInformationPerServer.Add($serverName, $serverDatabaseInformation)
    }

    return [PSCustomObject]@{
        DAGInfo             = $dag
        DAGNetworkInfo      = $dagNetwork
        MailboxDatabaseInfo = $mailboxDatabaseInformationPerServer
    }
}

Function Get-ExchangeBasicServerObject {
    param(
        [Parameter(Mandatory = $true)][string]$ServerName,
        [Parameter(Mandatory = $false)][bool]$AddGetServerProperty = $false
    )
    Write-ScriptDebug("Function Enter: Get-ExchangeBasicServerObject")
    Write-ScriptDebug("Passed: [string]ServerName: {0}" -f $ServerName)
    try {
        $getExchangeServer = Get-ExchangeServer $ServerName -Status -ErrorAction Stop
    } catch {
        Write-ScriptHost -WriteString ("Failed to detect server {0} as an Exchange Server" -f $ServerName) -ShowServer $false -ForegroundColor "Red"
        Invoke-CatchBlockActions
        return $null
    }

    $exchAdminDisplayVersion = $getExchangeServer.AdminDisplayVersion
    $exchServerRole = $getExchangeServer.ServerRole
    Write-ScriptDebug("AdminDisplayVersion: {0} | ServerRole: {1}" -f $exchAdminDisplayVersion.ToString(), $exchServerRole.ToString())
    if ($exchAdminDisplayVersion.GetType().Name -eq "string") {
        $start = $exchAdminDisplayVersion.IndexOf(" ")
        $split = $exchAdminDisplayVersion.Substring( $start + 1, 4).split('.')
        [int]$major = $split[0]
        [int]$minor = $split[1]
    }
    if ($exchAdminDisplayVersion.Major -eq 14 -or $major -eq 14) {
        $exchVersion = 14
    } elseif ($exchAdminDisplayVersion.Major -eq 15 -or $major -eq 15) {
        #determine if 2013/2016/2019
        if ($exchAdminDisplayVersion.Minor -eq 0 -or $minor -eq 0) {
            $exchVersion = 15
        } elseif ($exchAdminDisplayVersion.Minor -eq 1 -or $minor -eq 1) {
            $exchVersion = 16
        } else {
            $exchVersion = 19
        }
    } else {
        Write-ScriptHost -WriteString ("Failed to determine what version server {0} is. AdminDisplayVersion: {1}." -f $ServerName, $exchAdminDisplayVersion.ToString()) -ShowServer $false -ForegroundColor "Red"
        return $true
    }

    Function Confirm-MailboxServer {
        param([string]$Value)
        if ($value -like "*Mailbox*" -and (-not(Confirm-EdgeServer -Value $Value))) {
            return $true
        } else {
            return $false
        }
    }

    Function Confirm-CASServer {
        param([string]$Value, [int]$Version)
        if ((-not(Confirm-EdgeServer -Value $Value)) -and (($Version -ge 16) -or ($Value -like "*ClientAccess*"))) {
            return $true
        } else {
            return $false
        }
    }

    Function Confirm-CASOnlyServer {
        param([string]$Value)
        if ($Value -eq "ClientAccess") {
            return $true
        } else {
            return $false
        }
    }

    Function Confirm-MailboxOnlyServer {
        param([string]$Value)
        if ($Value -eq "Mailbox") {
            return $true
        } else {
            return $false
        }
    }

    Function Confirm-HubServer {
        param([string]$Value, [int]$Version)
        if ((($Version -ge 15) -and (-not (Confirm-CASOnlyServer -Value $Value))) -or ($Value -like "*HubTransport*")) {
            return $true
        } else {
            return $false
        }
    }

    Function Confirm-EdgeServer {
        param([string]$Value)
        if ($Value -eq "Edge") {
            return $true
        } else {
            return $false
        }
    }

    $exchServerObject = New-Object PSCustomObject
    $exchServerObject | Add-Member -MemberType NoteProperty -Name ServerName -Value ($getExchangeServer.Name.ToUpper())
    $exchServerObject | Add-Member -MemberType NoteProperty -Name Mailbox -Value (Confirm-MailboxServer -Value $exchServerRole)
    $exchServerObject | Add-Member -MemberType NoteProperty -Name CAS -Value (Confirm-CASServer -Value $exchServerRole -version $exchVersion)
    $exchServerObject | Add-Member -MemberType NoteProperty -Name Hub -Value (Confirm-HubServer -Value $exchServerRole -version $exchVersion)
    $exchServerObject | Add-Member -MemberType NoteProperty -Name CASOnly -Value (Confirm-CASOnlyServer -Value $exchServerRole)
    $exchServerObject | Add-Member -MemberType NoteProperty -Name MailboxOnly -Value (Confirm-MailboxOnlyServer -Value $exchServerRole)
    $exchServerObject | Add-Member -MemberType NoteProperty -Name Edge -Value (Confirm-EdgeServer -Value $exchServerRole)
    $exchServerObject | Add-Member -MemberType NoteProperty -Name Version -Value $exchVersion

    if ($exchServerObject.Mailbox) {
        $getMailboxServer = Get-MailboxServer $ServerName
        $exchServerObject | Add-Member -MemberType NoteProperty -Name DAGMember -Value (![string]::IsNullOrEmpty($getMailboxServer.DatabaseAvailabilityGroup))

        if ($exchServerObject.DAGMember) {
            $exchServerObject | Add-Member -MemberType NoteProperty -Name DAGName -Value ($getMailboxServer.DatabaseAvailabilityGroup.ToString())
        }
    } else {
        $exchServerObject | Add-Member -MemberType NoteProperty -Name DAGMember -Value $false
    }

    if ($AddGetServerProperty) {
        $exchServerObject | Add-Member -MemberType NoteProperty -Name ExchangeServer -Value $getExchangeServer
    }

    Write-ScriptDebug("Mailbox: {0} | CAS: {1} | Hub: {2} | CASOnly: {3} | MailboxOnly: {4} | Edge: {5} | DAGMember {6} | Version: {7} | AnyTransportSwitchesEnabled: {8} | DAGName: {9}" -f $exchServerObject.Mailbox,
        $exchServerObject.CAS,
        $exchServerObject.Hub,
        $exchServerObject.CASOnly,
        $exchServerObject.MailboxOnly,
        $exchServerObject.Edge,
        $exchServerObject.DAGMember,
        $exchServerObject.Version,
        $Script:AnyTransportSwitchesEnabled,
        $exchServerObject.DAGName
    )

    return $exchServerObject
}

Function Get-ServerObjects {
    param(
        [Parameter(Mandatory = $true)][Array]$ValidServers
    )

    Write-ScriptDebug ("Function Enter: Get-ServerObjects")
    Write-ScriptDebug ("Passed: {0} number of Servers" -f $ValidServers.Count)
    $svrsObject = @()
    $validServersList = @()
    foreach ($svr in $ValidServers) {
        Write-ScriptDebug ("Working on Server {0}" -f $svr)

        $sobj = Get-ExchangeBasicServerObject -ServerName $svr
        if ($sobj -eq $true) {
            Write-ScriptHost -WriteString ("Removing Server {0} from the list" -f $svr) -ForegroundColor "Red" -ShowServer $false
            continue
        } else {
            $validServersList += $svr
        }

        if ($Script:AnyTransportSwitchesEnabled -and ($sobj.Hub -or $sobj.Version -ge 15)) {
            $sobj | Add-Member -Name TransportInfoCollect -MemberType NoteProperty -Value $true
            $sobj | Add-Member -Name TransportInfo -MemberType NoteProperty -Value `
            (Get-TransportLoggingInformationPerServer -Server $svr `
                    -version $sobj.Version `
                    -EdgeServer $sobj.Edge `
                    -CASOnly $sobj.CASOnly `
                    -MailboxOnly $sobj.MailboxOnly)
        } else {
            $sobj | Add-Member -Name TransportInfoCollect -MemberType NoteProperty -Value $false
        }

        if ($PopLogs -and
            !$Script:EdgeRoleDetected) {
            $sobj | Add-Member -Name PopLogsLocation -MemberType NoteProperty -Value ((Get-PopSettings -Server $svr).LogFileLocation)
        }

        if ($ImapLogs -and
            !$Script:EdgeRoleDetected) {
            $sobj | Add-Member -Name ImapLogsLocation -MemberType NoteProperty -Value ((Get-ImapSettings -Server $svr).LogFileLocation)
        }

        $svrsObject += $sobj
    }

    if (($null -eq $svrsObject) -or
        ($svrsObject.Count -eq 0)) {
        Write-ScriptHost -WriteString ("Something wrong happened in Get-ServerObjects stopping script") -ShowServer $false -ForegroundColor "Red"
        exit
    }
    #Set the valid servers
    $Script:ValidServers = $validServersList
    Write-ScriptDebug("Function Exit: Get-ServerObjects")
    Return $svrsObject
}

Function Get-TransportLoggingInformationPerServer {
    param(
        [string]$Server,
        [int]$Version,
        [bool]$EdgeServer,
        [bool]$CASOnly,
        [bool]$MailboxOnly
    )
    Write-ScriptDebug("Function Enter: Get-TransportLoggingInformationPerServer")
    Write-ScriptDebug("Passed: [string]Server: {0} | [int]Version: {1} | [bool]EdgeServer: {2} | [bool]CASOnly: {3} | [bool]MailboxOnly: {4}" -f $Server, $Version, $EdgeServer, $CASOnly, $MailboxOnly)
    $transportLoggingObject = New-Object PSCustomObject

    if ($Version -ge 15) {

        if (-not($CASOnly)) {
            #Hub Transport Layer
            $data = Get-TransportService -Identity $Server
            $hubObject = [PSCustomObject]@{
                ConnectivityLogPath    = $data.ConnectivityLogPath.ToString()
                MessageTrackingLogPath = $data.MessageTrackingLogPath.ToString()
                PipelineTracingPath    = $data.PipelineTracingPath.ToString()
                ReceiveProtocolLogPath = $data.ReceiveProtocolLogPath.ToString()
                SendProtocolLogPath    = $data.SendProtocolLogPath.ToString()
                WlmLogPath             = $data.WlmLogPath.ToString()
            }

            if (![string]::IsNullOrEmpty($data.QueueLogPath)) {
                $hubObject | Add-Member -MemberType NoteProperty -Name "QueueLogPath" -Value ($data.QueueLogPath.ToString())
            }

            $transportLoggingObject | Add-Member -MemberType NoteProperty -Name HubLoggingInfo -Value $hubObject
        }

        if (-not ($EdgeServer)) {
            #Front End Transport Layer
            if (($Version -eq 15 -and (-not ($MailboxOnly))) -or $Version -ge 16) {
                $data = Get-FrontendTransportService -Identity $Server

                $FETransObject = [PSCustomObject]@{
                    ConnectivityLogPath    = $data.ConnectivityLogPath.ToString()
                    ReceiveProtocolLogPath = $data.ReceiveProtocolLogPath.ToString()
                    SendProtocolLogPath    = $data.SendProtocolLogPath.ToString()
                    AgentLogPath           = $data.AgentLogPath.ToString()
                }
                $transportLoggingObject | Add-Member -MemberType NoteProperty -Name FELoggingInfo -Value $FETransObject
            }

            if (($Version -eq 15 -and (-not ($CASOnly))) -or $Version -ge 16) {
                #Mailbox Transport Layer
                $data = Get-MailboxTransportService -Identity $Server
                $mbxObject = [PSCustomObject]@{
                    ConnectivityLogPath              = $data.ConnectivityLogPath.ToString()
                    ReceiveProtocolLogPath           = $data.ReceiveProtocolLogPath.ToString()
                    SendProtocolLogPath              = $data.SendProtocolLogPath.ToString()
                    PipelineTracingPath              = $data.PipelineTracingPath.ToString()
                    MailboxDeliveryThrottlingLogPath = $data.MailboxDeliveryThrottlingLogPath.ToString()
                }
                $transportLoggingObject | Add-Member -MemberType NoteProperty -Name MBXLoggingInfo -Value $mbxObject
            }
        }
    } elseif ($Version -eq 14) {
        $data = Get-TransportServer -Identity $Server
        $hubObject = New-Object PSCustomObject #TODO Remove because we shouldn't support 2010 any longer
        $hubObject | Add-Member -MemberType NoteProperty -Name ConnectivityLogPath -Value ($data.ConnectivityLogPath.PathName)
        $hubObject | Add-Member -MemberType NoteProperty -Name MessageTrackingLogPath -Value ($data.MessageTrackingLogPath.PathName)
        $hubObject | Add-Member -MemberType NoteProperty -Name PipelineTracingPath -Value ($data.PipelineTracingPath.PathName)
        $hubObject | Add-Member -MemberType NoteProperty -Name ReceiveProtocolLogPath -Value ($data.ReceiveProtocolLogPath.PathName)
        $hubObject | Add-Member -MemberType NoteProperty -Name SendProtocolLogPath -Value ($data.SendProtocolLogPath.PathName)
        $transportLoggingObject | Add-Member -MemberType NoteProperty -Name HubLoggingInfo -Value $hubObject
    } else {
        Write-ScriptHost -WriteString ("trying to determine transport information for server {0} and wasn't able to determine the correct version type" -f $Server) -ShowServer $false
        return
    }

    Write-ScriptDebug("Function Exit: Get-TransportLoggingInformationPerServer")
    return $transportLoggingObject
}

Function Get-VirtualDirectoriesLdap {

    $authTypeEnum = @"
    namespace AuthMethods
    {
        using System;
        [Flags]
        public enum AuthenticationMethodFlags
        {
            None = 0,
            Basic = 1,
            Ntlm = 2,
            Fba = 4,
            Digest = 8,
            WindowsIntegrated = 16,
            LiveIdFba = 32,
            LiveIdBasic = 64,
            WSSecurity = 128,
            Certificate = 256,
            NegoEx = 512,
            // Exchange 2013
            OAuth = 1024,
            Adfs = 2048,
            Kerberos = 4096,
            Negotiate = 8192,
            LiveIdNegotiate = 16384,
        }
    }
"@

    Write-ScriptHost -WriteString "Collecting Virtual Directory Information..." -ShowServer $false
    Add-Type -TypeDefinition $authTypeEnum -Language CSharp

    $objRootDSE = [ADSI]"LDAP://rootDSE"
    $strConfigurationNC = $objRootDSE.configurationNamingContext
    $objConfigurationNC = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$strConfigurationNC")
    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.filter = "(&(objectClass=msExchVirtualDirectory)(!objectClass=container))"
    $searcher.SearchRoot = $objConfigurationNC
    $searcher.CacheResults = $false
    $searcher.SearchScope = "Subtree"
    $searcher.PageSize = 1000

    # Get all the results
    $colResults = $searcher.FindAll()
    $objects = @()

    # Loop through the results and
    foreach ($objResult in $colResults) {
        $objItem = $objResult.getDirectoryEntry()
        $objProps = $objItem.Properties

        $place = $objResult.Path.IndexOf("CN=Protocols,CN=")
        $ServerDN = [ADSI]("LDAP://" + $objResult.Path.SubString($place, ($objResult.Path.Length - $place)).Replace("CN=Protocols,", ""))
        [string]$Site = $serverDN.Properties.msExchServerSite.ToString().Split(",")[0].Replace("CN=", "")
        [string]$server = $serverDN.Properties.adminDisplayName.ToString()
        [string]$version = $serverDN.Properties.serialNumber.ToString()

        $obj = New-Object PSObject
        $obj | Add-Member -MemberType NoteProperty -Name Server -Value $server
        $obj | Add-Member -MemberType NoteProperty -Name Version -Value $version
        $obj | Add-Member -MemberType NoteProperty -Name Site -Value $Site
        [string]$var = $objProps.DistinguishedName.ToString().Split(",")[0].Replace("CN=", "")
        $obj | Add-Member -MemberType NoteProperty -Name VirtualDirectory -Value $var
        [string]$var = $objProps.msExchInternalHostName
        $obj | Add-Member -MemberType NoteProperty -Name InternalURL -Value $var

        if (-not [string]::IsNullOrEmpty($objProps.msExchInternalAuthenticationMethods)) {
            $obj | Add-Member -MemberType NoteProperty -Name InternalAuthenticationMethods -Value ([AuthMethods.AuthenticationMethodFlags]$objProps.msExchInternalAuthenticationMethods)
        } else {
            $obj | Add-Member -MemberType NoteProperty -Name InternalAuthenticationMethods -Value $null
        }

        [string]$var = $objProps.msExchExternalHostName
        $obj | Add-Member -MemberType NoteProperty -Name ExternalURL -Value $var

        if (-not [string]::IsNullOrEmpty($objProps.msExchExternalAuthenticationMethods)) {
            $obj | Add-Member -MemberType NoteProperty -Name ExternalAuthenticationMethods -Value ([AuthMethods.AuthenticationMethodFlags]$objProps.msExchExternalAuthenticationMethods)
        } else {
            $obj | Add-Member -MemberType NoteProperty -Name ExternalAuthenticationMethods -Value $null
        }

        if (-not [string]::IsNullOrEmpty($objProps.msExch2003Url)) {
            [string]$var = $objProps.msExch2003Url
            $obj | Add-Member -MemberType NoteProperty -Name Exchange2003URL  -Value $var
        } else {
            $obj | Add-Member -MemberType NoteProperty -Name Exchange2003URL -Value $null
        }

        [Array]$objects += $obj
    }

    return $objects
}

Function Get-WritersToAddToScriptBlock {

    $writersString = "Function Write-InvokeCommandReturnHostWriter { " + (${Function:Write-InvokeCommandReturnHostWriter}).ToString() + " } `n`n Function Write-InvokeCommandReturnVerboseWriter { " + (${Function:Write-InvokeCommandReturnVerboseWriter}).ToString() + " } `n`n#"
    return $writersString
}

Function Write-DataOnlyOnceOnMasterServer {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseUsingScopeModifierInNewRunspaces', '', Justification = 'Can not use using for an env variable')]
    param()
    Write-ScriptDebug("Enter Function: Write-DataOnlyOnceOnMasterServer")
    Write-ScriptDebug("Writing only once data")

    if (!$Script:MasterServer.ToUpper().Contains($env:COMPUTERNAME.ToUpper())) {
        $serverName = Invoke-Command -ComputerName $Script:MasterServer -ScriptBlock { return $env:COMPUTERNAME }
        $RootCopyToDirectory = "\\{0}\{1}" -f $Script:MasterServer, (("{0}{1}" -f $Script:RootFilePath, $serverName).Replace(":", "$"))
    } else {
        $RootCopyToDirectory = "{0}{1}" -f $Script:RootFilePath, $env:COMPUTERNAME
    }

    if ($GetVdirs -and (-not($Script:EdgeRoleDetected))) {
        $target = $RootCopyToDirectory + "\ConfigNC_msExchVirtualDirectory_All.CSV"
        $data = (Get-VirtualDirectoriesLdap)
        $data | Sort-Object -Property Server | Export-Csv $target -NoTypeInformation
    }

    if ($OrganizationConfig) {
        $target = $RootCopyToDirectory + "\OrganizationConfig"
        $data = Get-OrganizationConfig
        Save-DataInfoToFile -dataIn (Get-OrganizationConfig) -SaveToLocation $target -AddServerName $false
    }

    if ($SendConnectors) {
        $create = $RootCopyToDirectory + "\Connectors"
        New-Folder -NewFolder $create -IncludeDisplayCreate $true
        $saveLocation = $create + "\Send_Connectors"
        Save-DataInfoToFile -dataIn (Get-SendConnector) -SaveToLocation $saveLocation -AddServerName $false
    }

    if ($TransportConfig) {
        $target = $RootCopyToDirectory + "\TransportConfig"
        $data = Get-TransportConfig
        Save-DataInfoToFile -dataIn $data -SaveToLocation $target -AddServerName $false
    }

    if ($Error.Count -ne 0) {
        Save-DataInfoToFile -DataIn $Error -SaveToLocation ("$RootCopyToDirectory\AllErrors")
        Save-DataInfoToFile -DataIn $Script:ErrorsHandled -SaveToLocation ("$RootCopyToDirectory\HandledErrors")
    } else {
        Write-ScriptDebug ("No errors occurred within the script")
    }

    Write-ScriptDebug("Exiting Function: Write-DataOnlyOnceOnMasterServer")
}

#This function job is to write out the Data that is too large to pass into the main script block
#This is for mostly Exchange Related objects.
#To handle this, we export the data locally and copy the data over the correct server.
Function Write-LargeDataObjectsOnMachine {

    Write-ScriptDebug("Function Enter Write-LargeDataObjectsOnMachine")

    [array]$serverNames = $Script:ArgumentList.ServerObjects |
        ForEach-Object {
            return $_.ServerName
        }

    #Collect the Exchange Data that resides on their own machine.
    Function Invoke-ExchangeResideDataCollectionWrite {
        param(
            [Parameter(Mandatory = $true)][object]$PassedInfo
        )

        $location = $PassedInfo.SaveToLocation
        $exchBin = "{0}\Bin" -f $PassedInfo.InstallDirectory
        $configFiles = Get-ChildItem $exchBin | Where-Object { $_.Name -like "*.config" }
        $copyTo = "{0}\Config" -f $location
        $configFiles | ForEach-Object { Copy-Item $_.VersionInfo.FileName $copyTo }

        $copyServerComponentStatesRegistryTo = "{0}\regServerComponentStates.TXT" -f $location
        reg query HKLM\SOFTWARE\Microsoft\ExchangeServer\v15\ServerComponentStates /s > $copyServerComponentStatesRegistryTo

        Get-Command exsetup | ForEach-Object { $_.FileVersionInfo } > ("{0}\{1}_GCM.txt" -f $location, $env:COMPUTERNAME)

        #Exchange Web App Pools
        $windir = $env:windir
        $appCmd = "{0}\system32\inetsrv\appcmd.exe" -f $windir
        if (Test-Path $appCmd) {
            $appPools = &$appCmd list apppool
            $sites = &$appCmd list sites

            $exchangeAppPools = $appPools |
                ForEach-Object {
                    $startIndex = $_.IndexOf('"') + 1
                    $appPoolName = $_.Substring($startIndex,
                        ($_.Substring($startIndex).IndexOf('"')))
                    return $appPoolName
                } |
                Where-Object {
                    $_.StartsWith("MSExchange")
                }

            $sitesContent = @{}
            $sites |
                ForEach-Object {
                    $startIndex = $_.IndexOf('"') + 1
                    $siteName = $_.Substring($startIndex,
                        ($_.Substring($startIndex).IndexOf('"')))
                    $sitesContent.Add($siteName, (&$appCmd list site $siteName /text:*))
                }

            $webAppPoolsSaveRoot = "{0}\WebAppPools" -f $location
            $cacheConfigFileListLocation = @()
            $exchangeAppPools |
                ForEach-Object {
                    $config = &$appCmd list apppool $_ /text:CLRConfigFile
                    $allInfo = &$appCmd list apppool $_ /text:*

                    if (![string]::IsNullOrEmpty($config) -and
                        (Test-Path $config) -and
                        (!($cacheConfigFileListLocation.Contains($config.ToLower())))) {

                        $cacheConfigFileListLocation += $config.ToLower()
                        $saveConfigLocation = "{0}\{1}_{2}" -f $webAppPoolsSaveRoot, $env:COMPUTERNAME,
                        $config.Substring($config.LastIndexOf("\") + 1)
                        #Copy item to keep the date modify time
                        Copy-Item $config -Destination $saveConfigLocation
                    }
                    $saveAllInfoLocation = "{0}\{1}_{2}.txt" -f $webAppPoolsSaveRoot, $env:COMPUTERNAME, $_
                    $allInfo | Format-List * > $saveAllInfoLocation
                }

            $sitesContent.Keys |
                ForEach-Object {
                    $sitesContent[$_] > ("{0}\{1}_{2}_Site.config" -f $webAppPoolsSaveRoot, $env:COMPUTERNAME, ($_.Replace(" ", "")))
                    $slsResults = $sitesContent[$_] | Select-String applicationPool:, physicalPath:
                    $appPoolName = [string]::Empty
                    foreach ($matchInfo in $slsResults) {
                        $line = $matchInfo.Line

                        if ($line.Trim().StartsWith("applicationPool:")) {
                            $correctAppPoolSection = $false
                        }

                        if ($line.Trim().StartsWith("applicationPool:`"MSExchange")) {
                            $correctAppPoolSection = $true
                            $startIndex = $line.IndexOf('"') + 1
                            $appPoolName = $line.Substring($startIndex,
                                ($line.Substring($startIndex).IndexOf('"')))
                        }

                        if ($correctAppPoolSection -and
                            (!($line.Trim() -eq 'physicalPath:""')) -and
                            $line.Trim().StartsWith("physicalPath:")) {
                            $startIndex = $line.IndexOf('"') + 1
                            $path = $line.Substring($startIndex,
                                ($line.Substring($startIndex).IndexOf('"')))
                            $fullPath = "{0}\web.config" -f $path

                            if ((Test-Path $path) -and
                                (Test-Path $fullPath)) {
                                $saveFileName = "{0}\{1}_{2}_{3}_web.config" -f $webAppPoolsSaveRoot, $env:COMPUTERNAME, $appPoolName, ($_.Replace(" ", ""))
                                #Use Copy-Item to keep date modified
                                Copy-Item $fullPath -Destination $saveFileName
                                $bakFullPath = "$fullPath.bak"

                                if (Test-Path $bakFullPath) {
                                    Copy-Item $bakFullPath -Destination ("$saveFileName.bak")
                                }
                            }
                        }
                    }
                }

            $machineConfig = [System.Runtime.InteropServices.RuntimeEnvironment]::SystemConfigurationFile

            if (Test-Path $machineConfig) {
                Copy-Item $machineConfig -Destination ("{0}\{1}_machine.config" -f $webAppPoolsSaveRoot, $env:COMPUTERNAME)
            }
        }
    }

    #Write the Exchange Object Information locally first to then allow it to be copied over to the remote machine.
    #Exchange objects can be rather large preventing them to be passed within an Invoke-Command -ArgumentList
    #In order to get around this and to avoid going through a loop of doing an Invoke-Command per server per object,
    #Write the data out locally, copy that directory over to the remote location.
    Function Write-ExchangeObjectDataLocal {
        param(
            [object]$ServerData,
            [string]$Location
        )
        $tempLocation = "{0}\{1}" -f $Location, $ServerData.ServerName
        Save-DataToFile -DataIn $ServerData.ExchangeServer -SaveToLocation ("{0}_ExchangeServer" -f $tempLocation)
        Save-DataToFile -DataIn $ServerData.HealthReport -SaveToLocation ("{0}_HealthReport" -f $tempLocation)
        Save-DataToFile -DataIn $ServerData.ServerComponentState -SaveToLocation ("{0}_ServerComponentState" -f $tempLocation)
        Save-DataToFile -DataIn $ServerData.ServerMonitoringOverride -SaveToLocation ("{0}_serverMonitoringOverride" -f $tempLocation)
        Save-DataToFile -DataIn $ServerData.ServerHealth -SaveToLocation ("{0}_ServerHealth" -f $tempLocation)

        if ($ServerData.Hub) {
            Save-DataToFile -DataIn $ServerData.TransportServerInfo -SaveToLocation ("{0}_TransportServer" -f $tempLocation)
            Save-DataToFile -DataIn $ServerData.ReceiveConnectors -SaveToLocation ("{0}_ReceiveConnectors" -f $tempLocation)
            Save-DataToFile -DataIn $ServerData.QueueData -SaveToLocation ("{0}_InstantQueueInfo" -f $tempLocation)
        }

        if ($ServerData.CAS) {
            Save-DataToFile -DataIn $ServerData.CAServerInfo -SaveToLocation ("{0}_ClientAccessServer" -f $tempLocation)
            Save-DataToFile -DataIn $ServerData.FrontendTransportServiceInfo -SaveToLocation ("{0}_FrontendTransportService" -f $tempLocation)
        }

        if ($ServerData.Mailbox) {
            Save-DataToFile -DataIn $ServerData.MailboxServerInfo -SaveToLocation ("{0}_MailboxServer" -f $tempLocation)
            Save-DataToFile -DataIn $ServerData.MailboxTransportServiceInfo -SaveToLocation ("{0}_MailboxTransportService" -f $tempLocation)
        }
    }

    Function Write-DatabaseAvailabilityGroupDataLocal {
        param(
            [object]$DAGWriteInfo
        )
        $dagName = $DAGWriteInfo.DAGInfo.Name
        $serverName = $DAGWriteInfo.ServerName
        $rootSaveToLocation = $DAGWriteInfo.RootSaveToLocation
        $mailboxDatabaseSaveToLocation = "{0}\MailboxDatabase\" -f $rootSaveToLocation
        $copyStatusSaveToLocation = "{0}\MailboxDatabaseCopyStatus\" -f $rootSaveToLocation
        New-Folder -NewFolders @($mailboxDatabaseSaveToLocation, $copyStatusSaveToLocation)
        Save-DataToFile -DataIn $DAGWriteInfo.DAGInfo -SaveToLocation ("{0}{1}_DatabaseAvailabilityGroup" -f $rootSaveToLocation, $dagName)
        Save-DataToFile -DataIn $DAGWriteInfo.DAGNetworkInfo -SaveToLocation ("{0}{1}_DatabaseAvailabilityGroupNetwork" -f $rootSaveToLocation, $dagName)
        Save-DataToFile -DataIn $DAGWriteInfo.MailboxDatabaseCopyStatusServer -SaveToLocation ("{0}{1}_MailboxDatabaseCopyStatus" -f $copyStatusSaveToLocation, $serverName)

        $DAGWriteInfo.MailboxDatabases |
            ForEach-Object {
                Save-DataToFile -DataIn $_ -SaveToLocation ("{0}{1}_MailboxDatabase" -f $mailboxDatabaseSaveToLocation, $_.Name)
            }

        $DAGWriteInfo.MailboxDatabaseCopyStatusPerDB.Keys |
            ForEach-Object {
                $data = $DAGWriteInfo.MailboxDatabaseCopyStatusPerDB[$_]
                Save-DataToFile -DataIn $data -SaveToLocation ("{0}{1}_MailboxDatabaseCopyStatus" -f $copyStatusSaveToLocation, $_)
            }
    }

    $dagNameGroup = $argumentList.ServerObjects |
        Group-Object DAGName |
        Where-Object { ![string]::IsNullOrEmpty($_.Name) }

    if ($DAGInformation -and
        !$Script:EdgeRoleDetected -and
        $null -ne $dagNameGroup -and
        $dagNameGroup.Count -ne 0) {

        $dagWriteInformation = @()
        $dagNameGroup |
            ForEach-Object {
                $dagName = $_.Name
                $getDAGInformation = Get-DAGInformation -DAGName $dagName
                $_.Group |
                    ForEach-Object {
                        $dagWriteInformation += [PSCustomObject]@{
                            ServerName                      = $_.ServerName
                            DAGInfo                         = $getDAGInformation.DAGInfo
                            DAGNetworkInfo                  = $getDAGInformation.DAGNetworkInfo
                            MailboxDatabaseCopyStatusServer = $getDAGInformation.MailboxDatabaseInfo[$_.ServerName].MailboxDatabaseCopyStatusServer
                            MailboxDatabases                = $getDAGInformation.MailboxDatabaseInfo[$_.ServerName].MailboxDatabases
                            MailboxDatabaseCopyStatusPerDB  = $getDAGInformation.MailboxDatabaseInfo[$_.ServerName].MailboxDatabaseCopyStatusPerDB
                        }
                    }
                }

        $localServerTempLocation = "{0}{1}\Exchange_DAG_Temp\" -f $Script:RootFilePath, $env:COMPUTERNAME
        $dagWriteInformation |
            ForEach-Object {
                $location = "{0}{1}" -f $Script:RootFilePath, $_.ServerName
                Write-ScriptDebug("Location of the data should be at: $location")
                $remoteLocation = "\\{0}\{1}" -f $_.ServerName, $location.Replace(":", "$")
                Write-ScriptDebug("Remote Copy Location: $remoteLocation")
                $rootTempLocation = "{0}{1}\{2}_Exchange_DAG_Information\" -f $localServerTempLocation, $_.ServerName, $_.DAGInfo.Name
                Write-ScriptDebug("Local Root Temp Location: $rootTempLocation")
                New-Folder -NewFolders $rootTempLocation
                $_ | Add-Member -MemberType NoteProperty -Name RootSaveToLocation -Value $rootTempLocation
                Write-DatabaseAvailabilityGroupDataLocal -DAGWriteInfo $_

                $zipCopyLocation = Compress-Folder -Folder $rootTempLocation -ReturnCompressedLocation $true
                try {
                    Copy-Item $zipCopyLocation $remoteLocation
                } catch {
                    Write-ScriptDebug("Failed to copy data to $remoteLocation. This is likely due to file sharing permissions.")
                    Invoke-CatchBlockActions
                }
            }
        #Remove the temp data location
        Remove-Item $localServerTempLocation -Force -Recurse
    }

    # Can not invoke CollectOverMetrics.ps1 script inside of a script block against a different machine.
    if ($CollectFailoverMetrics -and
        !$Script:LocalExchangeShell.RemoteShell -and
        !$Script:EdgeRoleDetected -and
        $null -ne $dagNameGroup -and
        $dagNameGroup.Count -ne 0) {

        $localServerTempLocation = "{0}{1}\Temp_Exchange_Failover_Reports" -f $Script:RootFilePath, $env:COMPUTERNAME
        $argumentList.ServerObjects |
            Group-Object DAGName |
            Where-Object { ![string]::IsNullOrEmpty($_.Name) } |
            ForEach-Object {
                $failed = $false
                $reportPath = "{0}\{1}_FailoverMetrics" -f $localServerTempLocation, $_.Name
                New-Folder -NewFolders $reportPath

                try {
                    Write-ScriptHost("Attempting to run CollectOverMetrics.ps1 against $($_.Name)")
                    &"$Script:localExInstall\Scripts\CollectOverMetrics.ps1" -DatabaseAvailabilityGroup $_.Name `
                        -IncludeExtendedEvents `
                        -GenerateHtmlReport `
                        -ReportPath $reportPath
                } catch {
                    Write-ScriptDebug("Failed to collect failover metrics")
                    Invoke-CatchBlockActions
                    $failed = $true
                }

                if (!$failed) {
                    $zipCopyLocation = Compress-Folder -Folder $reportPath -ReturnCompressedLocation $true
                    $_.Group |
                        ForEach-Object {
                            $location = "{0}{1}" -f $Script:RootFilePath, $_.ServerName
                            Write-ScriptDebug("Location of the data should be at: $location")
                            $remoteLocation = "\\{0}\{1}" -f $_.ServerName, $location.Replace(":", "$")
                            Write-ScriptDebug("Remote Copy Location: $remoteLocation")

                            try {
                                Copy-Item $zipCopyLocation $remoteLocation
                            } catch {
                                Write-ScriptDebug("Failed to copy data to $remoteLocation. This is likely due to file sharing permissions.")
                                Invoke-CatchBlockActions
                            }
                        }
                    } else {
                        Write-ScriptDebug("Not compressing or copying over this folder.")
                    }
                }

        Remove-Item $localServerTempLocation -Recurse -Force
    } elseif ($null -eq $dagNameGroup -or
        $dagNameGroup.Count -eq 0) {
        Write-ScriptDebug("No DAGs were found. Didn't run CollectOverMetrics.ps1")
    } elseif ($Script:EdgeRoleDetected) {
        Write-ScriptHost("Unable to run CollectOverMetrics.ps1 script from an edge server") -ForegroundColor Yellow
    } elseif ($CollectFailoverMetrics) {
        Write-ScriptHost("Unable to run CollectOverMetrics.ps1 script from a remote shell session not on an Exchange Server or Tools box.") -ForegroundColor Yellow
    }

    if ($ExchangeServerInformation) {

        #Create a list that contains all the information that we need to dump out locally then copy over to each respective server within "Exchange_Server_Data"
        $exchangeServerData = @()
        foreach ($server in $serverNames) {
            $basicServerObject = Get-ExchangeBasicServerObject -ServerName $server -AddGetServerProperty $true

            if ($basicServerObject.Hub) {
                $basicServerObject | Add-Member -MemberType NoteProperty -Name "TransportServerInfo" -Value (Get-TransportService $server)
                $basicServerObject | Add-Member -MemberType NoteProperty -Name "ReceiveConnectors" -Value (Get-ReceiveConnector -Server $server)
                $basicServerObject | Add-Member -MemberType NoteProperty -Name "QueueData" -Value (Get-Queue -Server $server)
            }

            if ($basicServerObject.CAS) {

                if ($basicServerObject.Version -ge 16) {
                    $getClientAccessService = Get-ClientAccessService $server -IncludeAlternateServiceAccountCredentialStatus
                } else {
                    $getClientAccessService = Get-ClientAccessServer $server -IncludeAlternateServiceAccountCredentialStatus
                }
                $basicServerObject | Add-Member -MemberType NoteProperty -Name "CAServerInfo" -Value $getClientAccessService
                $basicServerObject | Add-Member -MemberType NoteProperty -Name "FrontendTransportServiceInfo" -Value (Get-FrontendTransportService -Identity $server)
            }

            if ($basicServerObject.Mailbox) {
                $basicServerObject | Add-Member -MemberType NoteProperty -Name "MailboxServerInfo" -Value (Get-MailboxServer $server)
                $basicServerObject | Add-Member -MemberType NoteProperty -Name "MailboxTransportServiceInfo" -Value (Get-MailboxTransportService -Identity $server)
            }

            $basicServerObject | Add-Member -MemberType NoteProperty -Name "HealthReport" -Value (Get-HealthReport $server)
            $basicServerObject | Add-Member -MemberType NoteProperty -Name "ServerComponentState" -Value (Get-ServerComponentState $server)
            $basicServerObject | Add-Member -MemberType NoteProperty -Name "ServerMonitoringOverride" -Value (Get-ServerMonitoringOverride -Server $server -ErrorAction SilentlyContinue)
            $basicServerObject | Add-Member -MemberType NoteProperty -Name "ServerHealth" -Value (Get-ServerHealth $server)

            $exchangeServerData += $basicServerObject
        }

        #if single server or Exchange 2010 where invoke-command doesn't work
        if (!($serverNames.count -eq 1 -and
                $serverNames[0].ToUpper().Contains($env:COMPUTERNAME.ToUpper()))) {

            <#
            To pass an action to Start-JobManager, need to create objects like this.
                Where ArgumentList is the arguments for the scriptblock that we are running
            [array]
                [PSCustom]
                    [string]ServerName
                    [object]ArgumentList

            Need to do the following:
                Collect Exchange Install Directory Location
                Create directories where data is being stored with the upcoming requests
                Write out the Exchange Server Object Data and copy them over to the correct server
            #>

            #Setup all the Script blocks that we are going to use.
            Write-ScriptDebug("Getting Get-ExchangeInstallDirectory string to create Script Block")
            $getExchangeInstallDirectoryString = (${Function:Get-ExchangeInstallDirectory}).ToString().Replace("#Function Version", (Get-WritersToAddToScriptBlock))
            Write-ScriptDebug("Creating Script Block")
            $getExchangeInstallDirectoryScriptBlock = [scriptblock]::Create($getExchangeInstallDirectoryString)

            Write-ScriptDebug("Getting New-Folder string to create Script Block")
            $newFolderString = (${Function:New-Folder}).ToString().Replace("#Function Version", (Get-WritersToAddToScriptBlock))
            Write-ScriptDebug("Creating script block")
            $newFolderScriptBlock = [scriptblock]::Create($newFolderString)

            $serverArgListExchangeInstallDirectory = @()
            $serverArgListDirectoriesToCreate = @()
            $serverArgListExchangeResideData = @()
            $localServerTempLocation = "{0}{1}\Exchange_Server_Data_Temp\" -f $Script:RootFilePath, $env:COMPUTERNAME

            #Need to do two loops as both of these actions are required before we can do actions in the next loop.
            foreach ($serverData in $exchangeServerData) {
                $serverName = $serverData.ServerName

                $serverArgListExchangeInstallDirectory += [PSCustomObject]@{
                    ServerName   = $serverName
                    ArgumentList = $true
                }

                $serverArgListDirectoriesToCreate += [PSCustomObject]@{
                    ServerName   = $serverName
                    ArgumentList = [PSCustomObject]@{
                        NewFolders = (@(
                                ("{0}{1}\Exchange_Server_Data\Config" -f $Script:RootFilePath, $serverName),
                                ("{0}{1}\Exchange_Server_Data\WebAppPools" -f $Script:RootFilePath, $serverName)
                            ))
                    }
                }
            }

            Write-ScriptDebug ("Calling job for Get Exchange Install Directory")
            $serverInstallDirectories = Start-JobManager -ServersWithArguments $serverArgListExchangeInstallDirectory -ScriptBlock $getExchangeInstallDirectoryScriptBlock `
                -NeedReturnData $true `
                -DisplayReceiveJobInCorrectFunction $true `
                -JobBatchName "Exchange Install Directories for Write-LargeDataObjectsOnMachine"

            Write-ScriptDebug("Calling job for folder creation")
            Start-JobManager -ServersWithArguments $serverArgListDirectoriesToCreate -ScriptBlock $newFolderScriptBlock `
                -DisplayReceiveJobInCorrectFunction $true `
                -JobBatchName "Creating folders for Write-LargeDataObjectsOnMachine"

            #Now do the rest of the actions
            foreach ($serverData in $exchangeServerData) {
                $serverName = $serverData.ServerName

                $saveToLocation = "{0}{1}\Exchange_Server_Data" -f $Script:RootFilePath, $serverName
                $serverArgListExchangeResideData += [PSCustomObject]@{
                    ServerName   = $serverName
                    ArgumentList = [PSCustomObject]@{
                        SaveToLocation   = $saveToLocation
                        InstallDirectory = $serverInstallDirectories[$serverName]
                    }
                }

                #Write out the Exchange object data locally as a temp and copy it over to the remote server
                $location = "{0}{1}\Exchange_Server_Data" -f $Script:RootFilePath, $serverName
                Write-ScriptDebug("Location of data should be at: {0}" -f $location)
                $remoteLocation = "\\{0}\{1}" -f $serverName, $location.Replace(":", "$")
                Write-ScriptDebug("Remote Copy Location: {0}" -f $remoteLocation)
                $rootTempLocation = "{0}{1}" -f $localServerTempLocation, $serverName
                Write-ScriptDebug("Local Root Temp Location: {0}" -f $rootTempLocation)
                #Create the temp location and write out the data
                New-Folder -NewFolders $rootTempLocation
                Write-ExchangeObjectDataLocal -ServerData $serverData -Location $rootTempLocation
                Get-ChildItem $rootTempLocation |
                    ForEach-Object {
                        try {
                            Copy-Item $_.VersionInfo.FileName $remoteLocation
                        } catch {
                            Write-ScriptDebug("Failed to copy data to $remoteLocation. This is likely due to file sharing permissions.")
                            Invoke-CatchBlockActions
                        }
                    }
            }

            #Remove the temp data location right away
            Remove-Item $localServerTempLocation -Force -Recurse

            Write-ScriptDebug("Calling Invoke-ExchangeResideDataCollectionWrite")
            Start-JobManager -ServersWithArguments $serverArgListExchangeResideData -ScriptBlock ${Function:Invoke-ExchangeResideDataCollectionWrite} `
                -DisplayReceiveJob $false `
                -JobBatchName "Write the data for Write-LargeDataObjectsOnMachine"
        } else {

            if ($null -eq $ExInstall) {
                $ExInstall = Get-ExchangeInstallDirectory
            }
            $location = "{0}{1}\Exchange_Server_Data" -f $Script:RootFilePath, $exchangeServerData.ServerName
            [array]$createFolders = @(("{0}\Config" -f $location), ("{0}\WebAppPools" -f $location))
            New-Folder -NewFolders $createFolders -IncludeDisplayCreate $true
            Write-ExchangeObjectDataLocal -Location $location -ServerData $exchangeServerData

            $passInfo = [PSCustomObject]@{
                SaveToLocation   = $location
                InstallDirectory = $ExInstall
            }

            Write-ScriptDebug("Writing out the Exchange data")
            Invoke-ExchangeResideDataCollectionWrite -PassedInfo $passInfo
        }
    }
}

Function Get-ArgumentList {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'TODO: Change this')]
    param(
        [Parameter(Mandatory = $true)][array]$Servers
    )

    #First we need to verify if the local computer is in the list or not. If it isn't we need to pick a master server to store
    #the additional information vs having a small amount of data dumped into the local directory.
    $localServerInList = $false
    $Script:MasterServer = $env:COMPUTERNAME
    foreach ($server in $Servers) {

        if ($server.ToUpper().Contains($env:COMPUTERNAME.ToUpper())) {
            $localServerInList = $true
            break
        }
    }

    if (!$localServerInList) {
        $Script:MasterServer = $Servers[0]
    }

    $obj = New-Object PSCustomObject
    $obj | Add-Member -Name FilePath -MemberType NoteProperty -Value $FilePath
    $obj | Add-Member -Name RootFilePath -MemberType NoteProperty -Value $Script:RootFilePath
    $obj | Add-Member -Name ServerObjects -MemberType NoteProperty -Value (Get-ServerObjects -ValidServers $Servers)
    $obj | Add-Member -Name ManagedAvailabilityLogs -MemberType NoteProperty -Value $ManagedAvailabilityLogs
    $obj | Add-Member -Name AppSysLogs -MemberType NoteProperty -Value $AppSysLogs
    $obj | Add-Member -Name AppSysLogsToXml -MemberType NoteProperty -Value $AppSysLogsToXml
    $obj | Add-Member -Name EWSLogs -MemberType NoteProperty -Value $EWSLogs
    $obj | Add-Member -Name DailyPerformanceLogs -MemberType NoteProperty -Value $DailyPerformanceLogs
    $obj | Add-Member -Name RPCLogs -MemberType NoteProperty -Value $RPCLogs
    $obj | Add-Member -Name EASLogs -MemberType NoteProperty -Value $EASLogs
    $obj | Add-Member -Name ECPLogs -MemberType NoteProperty -Value $ECPLogs
    $obj | Add-Member -Name AutoDLogs -MemberType NoteProperty -Value $AutoDLogs
    $obj | Add-Member -Name OWALogs -MemberType NoteProperty -Value $OWALogs
    $obj | Add-Member -Name ADDriverLogs -MemberType NoteProperty -Value $ADDriverLogs
    $obj | Add-Member -Name SearchLogs -MemberType NoteProperty -Value $SearchLogs
    $obj | Add-Member -Name HighAvailabilityLogs -MemberType NoteProperty -Value $HighAvailabilityLogs
    $obj | Add-Member -Name MapiLogs -MemberType NoteProperty -Value $MapiLogs
    $obj | Add-Member -Name MessageTrackingLogs -MemberType NoteProperty -Value $MessageTrackingLogs
    $obj | Add-Member -Name HubProtocolLogs -MemberType NoteProperty -Value $HubProtocolLogs
    $obj | Add-Member -Name HubConnectivityLogs -MemberType NoteProperty -Value $HubConnectivityLogs
    $obj | Add-Member -Name FrontEndConnectivityLogs -MemberType NoteProperty -Value $FrontEndConnectivityLogs
    $obj | Add-Member -Name FrontEndProtocolLogs -MemberType NoteProperty -Value $FrontEndProtocolLogs
    $obj | Add-Member -Name MailboxConnectivityLogs -MemberType NoteProperty -Value $MailboxConnectivityLogs
    $obj | Add-Member -Name MailboxProtocolLogs -MemberType NoteProperty -Value $MailboxProtocolLogs
    $obj | Add-Member -Name MailboxDeliveryThrottlingLogs -MemberType NoteProperty -Value $MailboxDeliveryThrottlingLogs
    $obj | Add-Member -Name QueueInformation -MemberType NoteProperty -Value $QueueInformation
    $obj | Add-Member -Name SendConnectors -MemberType NoteProperty -Value $SendConnectors
    $obj | Add-Member -Name DAGInformation -MemberType NoteProperty -Value $DAGInformation
    $obj | Add-Member -Name GetVdirs -MemberType NoteProperty -Value $GetVdirs
    $obj | Add-Member -Name TransportConfig -MemberType NoteProperty -Value $TransportConfig
    $obj | Add-Member -Name DefaultTransportLogging -MemberType NoteProperty -Value $DefaultTransportLogging
    $obj | Add-Member -Name ServerInformation -MemberType NoteProperty -Value $ServerInformation
    $obj | Add-Member -Name CollectAllLogsBasedOnDaysWorth -MemberType NoteProperty -Value $CollectAllLogsBasedOnDaysWorth
    $obj | Add-Member -Name TimeSpan -MemberType NoteProperty -Value (New-TimeSpan -Days $DaysWorth -Hours $HoursWorth)
    $obj | Add-Member -Name IISLogs -MemberType NoteProperty -Value $IISLogs
    $obj | Add-Member -Name AnyTransportSwitchesEnabled -MemberType NoteProperty -Value $script:AnyTransportSwitchesEnabled
    $obj | Add-Member -Name HostExeServerName -MemberType NoteProperty -Value ($env:COMPUTERNAME)
    $obj | Add-Member -Name Experfwiz -MemberType NoteProperty -Value $Experfwiz
    $obj | Add-Member -Name ExperfwizLogmanName -MemberType NoteProperty -Value $ExperfwizLogmanName
    $obj | Add-Member -Name Exmon -MemberType NoteProperty -Value $Exmon
    $obj | Add-Member -Name ExmonLogmanName -MemberType NoteProperty -Value $ExmonLogmanName
    $obj | Add-Member -Name ScriptDebug -MemberType NoteProperty -Value $ScriptDebug
    $obj | Add-Member -Name ExchangeServerInformation -MemberType NoteProperty -Value $ExchangeServerInformation
    $obj | Add-Member -Name StandardFreeSpaceInGBCheckSize -MemberType NoteProperty $Script:StandardFreeSpaceInGBCheckSize
    $obj | Add-Member -Name PopLogs -MemberType NoteProperty -Value $PopLogs
    $obj | Add-Member -Name ImapLogs -MemberType NoteProperty -Value $ImapLogs
    $obj | Add-Member -Name OABLogs -MemberType NoteProperty -Value $OABLogs
    $obj | Add-Member -Name PowerShellLogs -MemberType NoteProperty -Value $PowerShellLogs
    $obj | Add-Member -Name WindowsSecurityLogs -MemberType NoteProperty $WindowsSecurityLogs
    $obj | Add-Member -Name MasterServer -MemberType NoteProperty -Value $Script:MasterServer
    $obj | Add-Member -Name MitigationService -MemberType NoteProperty -Value $MitigationService

    return $obj
}

#This function is to handle all root zipping capabilities and copying of the data over.
Function Invoke-ServerRootZipAndCopy {
    param(
        [bool]$RemoteExecute = $true
    )

    $serverNames = $Script:ArgumentList.ServerObjects |
        ForEach-Object {
            return $_.ServerName
        }

    Function Write-CollectFilesFromLocation {
        Write-ScriptHost -ShowServer $false -WriteString (" ")
        Write-ScriptHost -ShowServer $false -WriteString ("Please collect the following files from these servers and upload them: ")
        $LogPaths |
            ForEach-Object {
                Write-ScriptHost -ShowServer $false -WriteString ("Server: {0} Path: {1}" -f $_.ServerName, $_.ZipFolder)
            }
    }

    if ($RemoteExecute) {
        $Script:ErrorsFromStartOfCopy = $Error.Count
        $Script:Logger = New-LoggerObject -LogDirectory $Script:RootFilePath -LogName "ExchangeLogCollector-ZipAndCopy-Debug" `
            -HostFunctionCaller $Script:HostFunctionCaller `
            -VerboseFunctionCaller $Script:VerboseFunctionCaller

        Write-ScriptDebug("Getting Compress-Folder string to create Script Block")
        $compressFolderString = (${Function:Compress-Folder}).ToString().Replace("#Function Version", (Get-WritersToAddToScriptBlock))
        Write-ScriptDebug("Creating script block")
        $compressFolderScriptBlock = [scriptblock]::Create($compressFolderString)

        $serverArgListZipFolder = @()

        foreach ($serverName in $serverNames) {

            $folder = "{0}{1}" -f $Script:RootFilePath, $serverName
            $serverArgListZipFolder += [PSCustomObject]@{
                ServerName   = $serverName
                ArgumentList = [PSCustomObject]@{
                    Folder                = $folder
                    IncludeMonthDay       = $true
                    IncludeDisplayZipping = $true
                }
            }
        }

        Write-ScriptDebug("Calling Compress-Folder")
        Start-JobManager -ServersWithArguments $serverArgListZipFolder -ScriptBlock $compressFolderScriptBlock `
            -DisplayReceiveJobInCorrectFunction $true `
            -JobBatchName "Zipping up the data for Invoke-ServerRootZipAndCopy"

        $LogPaths = Invoke-Command -ComputerName $serverNames -ScriptBlock {

            $item = $Using:RootFilePath + (Get-ChildItem $Using:RootFilePath |
                    Where-Object { $_.Name -like ("*-{0}*.zip" -f (Get-Date -Format Md)) } |
                    Sort-Object CreationTime -Descending |
                    Select-Object -First 1)

            return [PSCustomObject]@{
                ServerName = $env:COMPUTERNAME
                ZipFolder  = $item
                Size       = ((Get-Item $item).Length)
            }
        }

        if (!($SkipEndCopyOver)) {
            #Check to see if we have enough free space.
            $LogPaths |
                ForEach-Object {
                    $totalSizeToCopyOver += $_.Size
                }

            $freeSpace = Get-FreeSpace -FilePath $Script:RootFilePath
            $totalSizeGB = $totalSizeToCopyOver / 1GB

            if ($freeSpace -gt ($totalSizeGB + $Script:StandardFreeSpaceInGBCheckSize)) {
                Write-ScriptHost -ShowServer $true -WriteString ("Looks like we have enough free space at the path to copy over the data")
                Write-ScriptHost -ShowServer $true -WriteString ("FreeSpace: {0} TestSize: {1} Path: {2}" -f $freeSpace, ($totalSizeGB + $Script:StandardFreeSpaceInGBCheckSize), $RootPath)
                Write-ScriptHost -ShowServer $false -WriteString (" ")
                Write-ScriptHost -ShowServer $false -WriteString ("Copying over the data may take some time depending on the network")

                $LogPaths |
                    ForEach-Object {
                        if ($_.ServerName -ne $env:COMPUTERNAME) {
                            $remoteCopyLocation = "\\{0}\{1}" -f $_.ServerName, ($_.ZipFolder.Replace(":", "$"))
                            Write-ScriptHost -ShowServer $false -WriteString ("[{0}] : Copying File {1}...." -f $_.ServerName, $remoteCopyLocation)
                            Copy-Item -Path $remoteCopyLocation -Destination $Script:RootFilePath
                            Write-ScriptHost -ShowServer $false -WriteString ("[{0}] : Done copying file" -f $_.ServerName)
                        }
                    }
            } else {
                Write-ScriptHost -ShowServer $true -WriteString("Looks like we don't have enough free space to copy over the data") -ForegroundColor "Yellow"
                Write-ScriptHost -ShowServer $true -WriteString("FreeSpace: {0} TestSize: {1} Path: {2}" -f $FreeSpace, ($totalSizeGB + $Script:StandardFreeSpaceInGBCheckSize), $RootPath)
                Write-CollectFilesFromLocation
            }
        } else {
            Write-CollectFilesFromLocation
        }
    } else {
        Invoke-ZipFolder -Folder $Script:RootCopyToDirectory -ZipItAll $true -AddCompressedSize $false
    }
}

Function Test-DiskSpace {
    param(
        [Parameter(Mandatory = $true)][array]$Servers,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$CheckSize
    )
    Write-ScriptDebug("Function Enter: Test-DiskSpace")
    Write-ScriptDebug("Passed: [string]Path: {0} | [int]CheckSize: {1}" -f $Path, $CheckSize)
    Write-ScriptHost -WriteString ("Checking the free space on the servers before collecting the data...") -ShowServer $false
    if (-not ($Path.EndsWith("\"))) {
        $Path = "{0}\" -f $Path
    }

    Function Test-ServerDiskSpace {
        param(
            [Parameter(Mandatory = $true)][string]$Server,
            [Parameter(Mandatory = $true)][int]$FreeSpace,
            [Parameter(Mandatory = $true)][int]$CheckSize
        )
        Write-ScriptDebug("Calling Test-ServerDiskSpace")
        Write-ScriptDebug("Passed: [string]Server: {0} | [int]FreeSpace: {1} | [int]CheckSize: {2}" -f $Server, $FreeSpace, $CheckSize)

        if ($FreeSpace -gt $CheckSize) {
            Write-ScriptHost -WriteString ("[Server: {0}] : We have more than {1} GB of free space." -f $Server, $CheckSize) -ShowServer $false
            return $true
        } else {
            Write-ScriptHost -WriteString ("[Server: {0}] : We have less than {1} GB of free space." -f $Server, $CheckSize) -ShowServer $false
            return $false
        }
    }

    if ($Servers.Count -eq 1 -and $Servers[0] -eq $env:COMPUTERNAME) {
        Write-ScriptDebug("Local server only check. Not going to invoke Start-JobManager")
        $freeSpace = Get-FreeSpace -FilePath $Path
        if (Test-ServerDiskSpace -Server $Servers[0] -FreeSpace $freeSpace -CheckSize $CheckSize) {
            return $Servers[0]
        } else {
            return $null
        }
    }

    $serverArgs = @()
    foreach ($server in $Servers) {
        $obj = New-Object PSCustomObject
        $obj | Add-Member -MemberType NoteProperty -Name ServerName -Value $server
        $obj | Add-Member -MemberType NoteProperty -Name ArgumentList -Value $Path
        $serverArgs += $obj
    }

    Write-ScriptDebug("Getting Get-FreeSpace string to create Script Block")
    $getFreeSpaceString = (${Function:Get-FreeSpace}).ToString().Replace("#Function Version", (Get-WritersToAddToScriptBlock))
    Write-ScriptDebug("Creating Script Block")
    $getFreeSpaceScriptBlock = [scriptblock]::Create($getFreeSpaceString)
    $serversData = Start-JobManager -ServersWithArguments $serverArgs -ScriptBlock $getFreeSpaceScriptBlock `
        -NeedReturnData $true `
        -DisplayReceiveJobInCorrectFunction $true `
        -JobBatchName "Getting the free space for test disk space"
    $passedServers = @()
    foreach ($server in $Servers) {

        $freeSpace = $serversData[$server]
        if (Test-ServerDiskSpace -Server $server -FreeSpace $freeSpace -CheckSize $CheckSize) {
            $passedServers += $server
        }
    }

    if ($passedServers.Count -eq 0) {
        Write-ScriptHost -WriteString("Looks like all the servers didn't pass the disk space check.") -ShowServer $false
        Write-ScriptHost -WriteString("Because there are no servers left, we will stop the script.") -ShowServer $false
        exit
    } elseif ($passedServers.Count -ne $Servers.Count) {
        Write-ScriptHost -WriteString ("Looks like all the servers didn't pass the disk space check.") -ShowServer $false
        Write-ScriptHost -WriteString ("We will only collect data from these servers: ") -ShowServer $false
        foreach ($svr in $passedServers) {
            Write-ScriptHost -ShowServer $false -WriteString ("{0}" -f $svr)
        }
        Enter-YesNoLoopAction -Question "Are yu sure you want to continue?" -YesAction {} -NoAction { exit }
    }
    Write-ScriptDebug("Function Exit: Test-DiskSpace")
    return $passedServers
}

Function Test-NoSwitchesProvided {
    if ($EWSLogs -or
        $IISLogs -or
        $DailyPerformanceLogs -or
        $ManagedAvailabilityLogs -or
        $Experfwiz -or
        $RPCLogs -or
        $EASLogs -or
        $ECPLogs -or
        $AutoDLogs -or
        $SearchLogs -or
        $OWALogs -or
        $ADDriverLogs -or
        $HighAvailabilityLogs -or
        $MapiLogs -or
        $Script:AnyTransportSwitchesEnabled -or
        $DAGInformation -or
        $GetVdirs -or
        $OrganizationConfig -or
        $Exmon -or
        $ServerInformation -or
        $PopLogs -or
        $ImapLogs -or
        $OABLogs -or
        $PowerShellLogs -or
        $WindowsSecurityLogs -or
        $ExchangeServerInformation -or
        $MitigationService
    ) {
        return
    } else {
        Write-ScriptHost -WriteString "`r`nWARNING: Doesn't look like any parameters were provided, are you sure you are running the correct command? This is ONLY going to collect the Application and System Logs." -ShowServer $false -ForegroundColor "Yellow"
        Enter-YesNoLoopAction -Question "Would you like to continue?" -YesAction { Write-Host "Okay moving on..." } -NoAction { exit }
    }
}

Function Test-PossibleCommonScenarios {

    #all possible logs
    if ($AllPossibleLogs) {
        $Script:EWSLogs = $true
        $Script:IISLogs = $true
        $Script:DailyPerformanceLogs = $true
        $Script:ManagedAvailabilityLogs = $true
        $Script:RPCLogs = $true
        $Script:EASLogs = $true
        $Script:AutoDLogs = $true
        $Script:OWALogs = $true
        $Script:ADDriverLogs = $true
        $Script:SearchLogs = $true
        $Script:HighAvailabilityLogs = $true
        $Script:ServerInformation = $true
        $Script:GetVdirs = $true
        $Script:DAGInformation = $true
        $Script:DefaultTransportLogging = $true
        $Script:MapiLogs = $true
        $Script:OrganizationConfig = $true
        $Script:ECPLogs = $true
        $Script:ExchangeServerInformation = $true
        $Script:PopLogs = $true
        $Script:ImapLogs = $true
        $Script:Experfwiz = $true
        $Script:OABLogs = $true
        $Script:PowerShellLogs = $true
        $Script:WindowsSecurityLogs = $true
        $Script:CollectFailoverMetrics = $true
        $Script:ConnectivityLogs = $true
        $Script:ProtocolLogs = $true
        $Script:MitigationService = $true
    }

    if ($DefaultTransportLogging) {
        $Script:HubConnectivityLogs = $true
        $Script:MessageTrackingLogs = $true
        $Script:QueueInformation = $true
        $Script:SendConnectors = $true
        $Script:ReceiveConnectors = $true
        $Script:TransportConfig = $true
        $Script:FrontEndConnectivityLogs = $true
        $Script:MailboxConnectivityLogs = $true
        $Script:FrontEndProtocolLogs = $true
        $Script:MailboxDeliveryThrottlingLogs = $true
    }

    if ($ConnectivityLogs) {
        $Script:FrontEndConnectivityLogs = $true
        $Script:HubConnectivityLogs = $true
        $Script:MailboxConnectivityLogs = $true
    }

    if ($ProtocolLogs) {
        $Script:FrontEndProtocolLogs = $true
        $Script:HubProtocolLogs = $true
        $Script:MailboxProtocolLogs = $true
    }

    if ($DatabaseFailoverIssue) {
        $Script:DailyPerformanceLogs = $true
        $Script:HighAvailabilityLogs = $true
        $Script:ManagedAvailabilityLogs = $true
        $Script:DAGInformation = $true
        $Script:Experfwiz = $true
        $Script:ServerInformation = $true
        $Script:CollectFailoverMetrics = $true
    }

    if ($PerformanceIssues) {
        $Script:DailyPerformanceLogs = $true
        $Script:ManagedAvailabilityLogs = $true
        $Script:Experfwiz = $true
    }

    if ($PerformanceMailflowIssues) {
        $Script:DailyPerformanceLogs = $true
        $Script:Experfwiz = $true
        $Script:MessageTrackingLogs = $true
        $Script:QueueInformation = $true
        $Script:TransportConfig = $true
    }

    if ($OutlookConnectivityIssues) {
        $Script:DailyPerformanceLogs = $true
        $Script:Experfwiz = $true
        $Script:IISLogs = $true
        $Script:MapiLogs = $true
        $Script:RPCLogs = $true
        $Script:AutoDLogs = $true
        $Script:EWSLogs = $true
        $Script:ServerInformation = $true
    }

    #Because we right out our Receive Connector information in Exchange Server Info now
    if ($ReceiveConnectors -or
        $QueueInformation) {
        $Script:ExchangeServerInformation = $true
    }

    #See if any transport logging is enabled.
    $Script:AnyTransportSwitchesEnabled = $false
    if ($HubProtocolLogs -or
        $HubConnectivityLogs -or
        $MessageTrackingLogs -or
        $QueueInformation -or
        $SendConnectors -or
        $ReceiveConnectors -or
        $TransportConfig -or
        $FrontEndConnectivityLogs -or
        $FrontEndProtocolLogs -or
        $MailboxConnectivityLogs -or
        $MailboxProtocolLogs -or
        $MailboxDeliveryThrottlingLogs -or
        $DefaultTransportLogging) {
        $Script:AnyTransportSwitchesEnabled = $true
    }

    if ($ServerInformation -or $ManagedAvailabilityLogs) {
        $Script:ExchangeServerInformation = $true
    }
}

Function Test-RemoteExecutionOfServers {
    param(
        [Parameter(Mandatory = $true)][Array]$ServerList
    )
    Write-ScriptDebug("Function Enter: Test-RemoteExecutionOfServers")
    Write-ScriptHost -WriteString "Checking to see if the servers are up in this list:" -ShowServer $false
    $ServerList | ForEach-Object { Write-ScriptHost -WriteString $_ -ShowServer $false }
    #Going to just use Invoke-Command to see if the servers are up. As ICMP might be disabled in the environment.
    Write-ScriptHost " " -ShowServer $false
    Write-ScriptHost -WriteString "For all the servers in the list, checking to see if Invoke-Command will work against them." -ShowServer $false
    #shouldn't need to test if they are Exchange servers, as we should be doing that locally as well.
    $validServers = @()
    foreach ($server in $ServerList) {

        try {
            Write-ScriptHost -WriteString ("Checking Server {0}....." -f $server) -ShowServer $false -NoNewLine $true
            Invoke-Command -ComputerName $server -ScriptBlock { Get-Process | Out-Null } -ErrorAction Stop
            #if that doesn't fail, we should be okay to add it to the working list
            Write-ScriptHost -WriteString ("Passed") -ShowServer $false -ForegroundColor "Green"
            $validServers += $server
        } catch {
            Write-ScriptHost -WriteString "Failed" -ShowServer $false -ForegroundColor "Red"
            Write-ScriptHost -WriteString ("Removing Server {0} from the list to collect data from" -f $server) -ShowServer $false
            Invoke-CatchBlockActions
        }
    }

    if ($validServers.Count -gt 0) {
        $validServers = Test-DiskSpace -Servers $validServers -Path $FilePath -CheckSize $Script:StandardFreeSpaceInGBCheckSize
    }

    #all servers in teh list weren't able to do Invoke-Command or didn't have enough free space. Try to do against local server.
    if ($null -ne $validServers -and
        $validServers.Count -eq 0) {

        #Can't do this on a tools or remote shell
        if ($Script:LocalExchangeShell.ToolsOnly -or
            $Script:LocalExchangeShell.RemoteShell) {
            Write-ScriptHost -WriteString "Failed to invoke against the machines to do remote collection from a tools box or a remote machine." -ForegroundColor "Red"
            exit
        }

        Write-ScriptHost -ShowServer $false -WriteString ("Failed to do remote collection for all the servers in the list...") -ForegroundColor "Yellow"

        if ((Enter-YesNoLoopAction -Question "Do you want to collect from the local server only?" -YesAction { return $true } -NoAction { return $false })) {
            $validServers = @($env:COMPUTERNAME)
        } else {
            exit
        }

        #want to test local server's free space first before moving to just collecting the data
        if ($null -eq (Test-DiskSpace -Servers $validServers -Path $FilePath -CheckSize $Script:StandardFreeSpaceInGBCheckSize)) {
            Write-ScriptHost -ShowServer $false -WriteString ("Failed to have enough space available locally. We can't continue with the data collection") -ForegroundColor "Yellow"
            exit
        }
    }

    Write-ScriptDebug("Function Exit: Test-RemoteExecutionOfServers")
    return $validServers
}

Function Invoke-RemoteFunctions {
    param(
        [Parameter(Mandatory = $true)][object]$PassedInfo
    )


#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/Common/Compress-Folder/Compress-Folder.ps1
#v21.01.22.2234
Function Compress-Folder {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '', Justification = 'Because it returns different types that needs to be addressed')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][string]$Folder,
        [Parameter(Mandatory = $false)][bool]$IncludeMonthDay = $false,
        [Parameter(Mandatory = $false)][bool]$IncludeDisplayZipping = $true,
        [Parameter(Mandatory = $false)][bool]$ReturnCompressedLocation = $false,
        [Parameter(Mandatory = $false, Position = 1)][object]$PassedObjectParameter
    )
    #Function Version #v21.01.22.2234

    Function Get-DirectorySize {
        param(
            [Parameter(Mandatory = $true)][string]$Directory,
            [Parameter(Mandatory = $false)][bool]$IsCompressed = $false
        )
        Write-InvokeCommandReturnVerboseWriter("Calling: Get-DirectorySize")
        Write-InvokeCommandReturnVerboseWriter("Passed: [string]Directory: {0} | [bool]IsCompressed: {1}" -f $Directory, $IsCompressed)
        $itemSize = 0
        if ($IsCompressed) {
            $itemSize = (Get-Item $Directory).Length
        } else {
            $childItems = Get-ChildItem $Directory -Recurse | Where-Object { -not($_.Mode.StartsWith("d-")) }
            foreach ($item in $childItems) {
                $itemSize += $item.Length
            }
        }
        return $itemSize
    }
    Function Enable-IOCompression {
        $successful = $true
        Write-InvokeCommandReturnVerboseWriter("Calling: Enable-IOCompression")
        try {
            Add-Type -AssemblyName System.IO.Compression.Filesystem -ErrorAction Stop
        } catch {
            Write-InvokeCommandReturnHostWriter("Failed to load .NET Compression assembly. Unable to compress up the data.")
            $successful = $false
        }
        Write-InvokeCommandReturnVerboseWriter("Returned: [bool]{0}" -f $successful)
        return $successful
    }
    Function Confirm-IOCompression {
        Write-InvokeCommandReturnVerboseWriter("Calling: Confirm-IOCompression")
        $assemblies = [Appdomain]::CurrentDomain.GetAssemblies()
        $successful = $false
        foreach ($assembly in $assemblies) {
            if ($assembly.Location -like "*System.IO.Compression.Filesystem*") {
                $successful = $true
                break
            }
        }
        Write-InvokeCommandReturnVerboseWriter("Returned: [bool]{0}" -f $successful)
        return $successful
    }

    Function Compress-Now {
        Write-InvokeCommandReturnVerboseWriter("Calling: Compress-Now ")
        $zipFolder = Get-ZipFolderName -Folder $Folder -IncludeMonthDay $IncludeMonthDay
        if ($IncludeDisplayZipping) {
            Write-InvokeCommandReturnHostWriter("Compressing Folder {0}" -f $Folder)
        }
        $sizeBytesBefore = Get-DirectorySize -Directory $Folder
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        [System.IO.Compression.ZipFile]::CreateFromDirectory($Folder, $zipFolder)
        $timer.Stop()
        $sizeBytesAfter = Get-DirectorySize -Directory $zipFolder -IsCompressed $true
        Write-InvokeCommandReturnVerboseWriter("Compressing directory size of {0} MB down to the size of {1} MB took {2} seconds." -f ($sizeBytesBefore / 1MB), ($sizeBytesAfter / 1MB), $timer.Elapsed.TotalSeconds)
        if ((Test-Path -Path $zipFolder)) {
            Write-InvokeCommandReturnVerboseWriter("Compress successful, removing folder.")
            Remove-Item $Folder -Force -Recurse
        }
        if ($ReturnCompressedLocation) {
            Set-Variable -Name compressedLocation -Value $zipFolder -Scope 1
        }
    }

    Function Get-ZipFolderName {
        param(
            [Parameter(Mandatory = $true)][string]$Folder,
            [Parameter(Mandatory = $false)][bool]$IncludeMonthDay = $false
        )
        Write-InvokeCommandReturnVerboseWriter("Calling: Get-ZipFolderName")
        Write-InvokeCommandReturnVerboseWriter("Passed - [string]Folder:{0} | [bool]IncludeMonthDay:{1}" -f $Folder, $IncludeMonthDay)
        if ($IncludeMonthDay) {
            $zipFolderNoEXT = "{0}-{1}" -f $Folder, (Get-Date -Format Md)
        } else {
            $zipFolderNoEXT = $Folder
        }
        Write-InvokeCommandReturnVerboseWriter("[string]zipFolderNoEXT: {0}" -f $zipFolderNoEXT)
        $zipFolder = "{0}.zip" -f $zipFolderNoEXT
        if (Test-Path $zipFolder) {
            [int]$i = 1
            do {
                $zipFolder = "{0}-{1}.zip" -f $zipFolderNoEXT, $i
                $i++
            }while (Test-Path $zipFolder)
        }
        Write-InvokeCommandReturnVerboseWriter("Returned: [string]zipFolder {0}" -f $zipFolder)
        return $zipFolder
    }

    $Script:stringArray = @()
    if ($null -ne $PassedObjectParameter) {
        if ($null -ne $PassedObjectParameter.Folder) {
            $Folder = $PassedObjectParameter.Folder
            if ($null -ne $PassedObjectParameter.IncludeDisplayZipping) {
                $IncludeDisplayZipping = $PassedObjectParameter.IncludeDisplayZipping
            }
            if ($null -ne $PassedObjectParameter.ReturnCompressedLocation) {
                $ReturnCompressedLocation = $PassedObjectParameter.ReturnCompressedLocation
            }
            if ($null -ne $PassedObjectParameter.IncludeMonthDay) {
                $IncludeMonthDay = $PassedObjectParameter.IncludeMonthDay
            }
        } else {
            $Folder = $PassedObjectParameter
        }
        $InvokeCommandReturnWriteArray = $true
    }
    if ($Folder.EndsWith("\")) {
        $Folder = $Folder.TrimEnd("\")
    }
    Write-InvokeCommandReturnVerboseWriter("Calling: Compress-Folder")
    Write-InvokeCommandReturnVerboseWriter("Passed - [string]Folder: {0} | [bool]IncludeDisplayZipping: {1} | [bool]ReturnCompressedLocation: {2}" -f $Folder,
        $IncludeDisplayZipping,
        $ReturnCompressedLocation)

    $compressedLocation = [string]::Empty
    if (Test-Path $Folder) {
        if (Confirm-IOCompression) {
            Compress-Now
        } else {
            if (Enable-IOCompression) {
                Compress-Now
            } else {
                Write-InvokeCommandReturnHostWriter("Unable to compress folder {0}" -f $Folder)
                Write-InvokeCommandReturnVerboseWriter("Unable to enable IO compression on this system")
            }
        }
    } else {
        Write-InvokeCommandReturnHostWriter("Failed to find the folder {0}" -f $Folder)
    }
    if ($InvokeCommandReturnWriteArray) {
        if ($ReturnCompressedLocation) {
            Write-InvokeCommandReturnVerboseWriter("Returning: {0}" -f $compressedLocation)
            $hashTable = @{"ReturnObject" = $compressedLocation }
            $Script:stringArray += $hashTable
            return $Script:stringArray
        } else {
            return $Script:stringArray
        }
    }
    if ($ReturnCompressedLocation) {
        Write-InvokeCommandReturnVerboseWriter("Returning: {0}" -f $compressedLocation)
        return $compressedLocation
    }
}

#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/ComputerInformation/Get-ClusterNodeFileVersions/Get-ClusterNodeFileVersions.ps1
#v21.01.22.2212
Function Get-ClusterNodeFileVersions {
    [CmdletBinding()]
    param(
        [string]$ClusterDirectory = "C:\Windows\Cluster"
    )

    $fileHashes = @{}

    Get-ChildItem $ClusterDirectory |
        Where-Object {
            $_.Name.EndsWith(".dll") -or
            $_.Name.EndsWith(".exe")
        } |
        ForEach-Object {
            $item = [PSCustomObject]@{
                FileName        = $_.Name
                FileMajorPart   = $_.VersionInfo.FileMajorPart
                FileMinorPart   = $_.VersionInfo.FileMinorPart
                FileBuildPart   = $_.VersionInfo.FileBuildPart
                FilePrivatePart = $_.VersionInfo.FilePrivatePart
                ProductVersion  = $_.VersionInfo.ProductVersion
                LastWriteTime   = $_.LastWriteTimeUtc
            }
            $fileHashes.Add($_.Name, $item)
        }

    return [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        Files        = $fileHashes
    }
}

#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/ExchangeInformation/Get-ExchangeInstallDirectory/Get-ExchangeInstallDirectory.ps1
#v21.01.22.2234
Function Get-ExchangeInstallDirectory {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '', Justification = 'Different types returned')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][bool]$InvokeCommandReturnWriteArray
    )
    #Function Version #v21.01.22.2234

    $stringArray = @()
    Write-InvokeCommandReturnVerboseWriter("Calling: Get-ExchangeInstallDirectory")
    Write-InvokeCommandReturnVerboseWriter("Passed: [bool]InvokeCommandReturnWriteArray: {0}" -f $InvokeCommandReturnWriteArray)

    $installDirectory = [string]::Empty
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup') {
        Write-InvokeCommandReturnVerboseWriter("Detected v14")
        $installDirectory = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup).MsiInstallPath
    } elseif (Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup') {
        Write-InvokeCommandReturnVerboseWriter("Detected v15")
        $installDirectory = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup).MsiInstallPath
    } else {
        Write-InvokeCommandReturnHostWriter -WriteString ("Something went wrong trying to find Exchange Install path on this server: {0}" -f $env:COMPUTERNAME)
    }
    Write-InvokeCommandReturnVerboseWriter("Returning: {0}" -f $installDirectory)
    if ($InvokeCommandReturnWriteArray) {
        $hashTable = @{"ReturnObject" = $installDirectory }
        $stringArray += $hashTable
        return $stringArray
    }
    return $installDirectory
}

#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/ComputerInformation/Get-FreeSpace/Get-FreeSpace.ps1
#v21.01.22.2234
Function Get-FreeSpace {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '', Justification = 'Different types returned')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Different types returned')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][ValidateScript( { $_.ToString().EndsWith("\") })][string]$FilePath,
        [Parameter(Mandatory = $false, Position = 1)][object]$PassedObjectParameter
    )
    #Function Version #v21.01.22.2234

    if ($null -ne $PassedObjectParameter) {
        if ($null -ne $PassedObjectParameter.FilePath) {
            $FilePath = $PassedObjectParameter.FilePath
        } else {
            $FilePath = $PassedObjectParameter
        }
        $InvokeCommandReturnWriteArray = $true
    }
    $stringArray = @()
    Write-InvokeCommandReturnVerboseWriter("Calling: Get-FreeSpace")
    Write-InvokeCommandReturnVerboseWriter("Passed: [string]FilePath: {0}" -f $FilePath)

    Function Update-TestPath {
        param(
            [Parameter(Mandatory = $true)][string]$FilePath
        )
        $updateFilePath = $FilePath.Substring(0, $FilePath.LastIndexOf("\", $FilePath.Length - 2) + 1)
        return $updateFilePath
    }

    Function Get-MountPointItemTarget {
        param(
            [Parameter(Mandatory = $true)][string]$FilePath
        )
        $itemTarget = [string]::Empty
        if (Test-Path $testPath) {
            $item = Get-Item $FilePath
            if ($item.Target -like "Volume{*}\") {
                Write-InvokeCommandReturnVerboseWriter("File Path appears to be a mount point target: {0}" -f $item.Target)
                $itemTarget = $item.Target
            } else {
                Write-InvokeCommandReturnVerboseWriter("Path didn't appear to be a mount point target")
            }
        } else {
            Write-InvokeCommandReturnVerboseWriter("Path isn't a true path yet.")
        }
        return $itemTarget
    }

    Function Invoke-ReturnValue {
        param(
            [Parameter(Mandatory = $true)][int]$FreeSpaceSize
        )
        if ($InvokeCommandReturnWriteArray) {
            $hashTable = @{"ReturnObject" = $freeSpaceSize }
            Set-Variable stringArray -Value ($stringArray += $hashTable) -Scope 1
            return $stringArray
        }
        return $FreeSpaceSize
    }

    $drivesList = Get-WmiObject Win32_Volume -Filter "drivetype = 3"
    $testPath = $FilePath
    $freeSpaceSize = -1
    while ($true) {
        if ($testPath -eq [string]::Empty) {
            Write-InvokeCommandReturnHostWriter("Unable to fine a drive that matches the file path: {0}" -f $FilePath)
            return (Invoke-ReturnValue -FreeSpaceSize $freeSpaceSize)
        }
        Write-InvokeCommandReturnVerboseWriter("Trying to find path that matches path: {0}" -f $testPath)
        foreach ($drive in $drivesList) {
            if ($drive.Name -eq $testPath) {
                Write-InvokeCommandReturnVerboseWriter("Found a match")
                $freeSpaceSize = $drive.FreeSpace / 1GB
                Write-InvokeCommandReturnVerboseWriter("Have {0}GB of Free Space" -f $freeSpaceSize)
                return (Invoke-ReturnValue -FreeSpaceSize $freeSpaceSize)
            }
            Write-InvokeCommandReturnVerboseWriter("Drive name: '{0}' didn't match" -f $drive.Name)
        }

        $itemTarget = Get-MountPointItemTarget -FilePath $testPath
        if ($itemTarget -ne [string]::Empty) {
            foreach ($drive in $drivesList) {
                if ($drive.DeviceID.Contains($itemTarget)) {
                    $freeSpaceSize = $drive.FreeSpace / 1GB
                    Write-InvokeCommandReturnVerboseWriter("Have {0}GB of Free Space" -f $freeSpaceSize)
                    return (Invoke-ReturnValue -FreeSpaceSize $freeSpaceSize)
                }
                Write-InvokeCommandReturnVerboseWriter("DeviceID didn't appear to match: {0}" -f $drive.DeviceID)
            }
            if ($freeSpaceSize -eq -1) {
                Write-InvokeCommandReturnHostWriter("Unable to fine a drive that matches the file path: {0}" -f $FilePath)
                Write-InvokeCommandReturnHostWriter("This shouldn't have happened.")
                return (Invoke-ReturnValue -FreeSpaceSize $freeSpaceSize)
            }
        }
        $testPath = Update-TestPath -FilePath $testPath
    }
}

#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/Common/New-Folder/New-Folder.ps1
#v21.01.22.2234
Function New-Folder {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'I prefer New here')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '', Justification = 'Multiple output types')]
    [CmdletBinding()]
    param(
        [Alias("NewFolder")]
        [Parameter(Mandatory = $false)][array]$NewFolders,
        [Parameter(Mandatory = $false)][bool]$IncludeDisplayCreate,
        [Parameter(Mandatory = $false, Position = 1)][object]$PassedParametersObject
    )
    #Function Version #v21.01.22.2234

    Function New-Directory {
        param(
            [Parameter(Mandatory = $false)][string]$NewFolder
        )
        if (-not (Test-Path -Path $NewFolder)) {
            if ($IncludeDisplayCreate -or $InvokeCommandReturnWriteArray) {
                Write-InvokeCommandReturnHostWriter("Creating Directory: {0}" -f $NewFolder)
            }
            [System.IO.Directory]::CreateDirectory($NewFolder) | Out-Null
        } else {
            if ($IncludeDisplayCreate -or $InvokeCommandReturnWriteArray) {
                Write-InvokeCommandReturnHostWriter("Directory {0} is already created!" -f $NewFolder)
            }
        }
    }

    $Script:stringArray = @()
    if ($null -ne $PassedParametersObject) {
        if ($null -ne $PassedParametersObject.NewFolders) {
            $NewFolders = $PassedParametersObject.NewFolders
        } else {
            $NewFolders = $PassedParametersObject
        }
        $InvokeCommandReturnWriteArray = $true
    }
    if ($NewFolders.Count -gt 1) {
        $verboseDisplayNewFolders = "Multiple ('{0}') Folders Passed" -f $NewFolders.Count
    } else {
        $verboseDisplayNewFolders = $NewFolders[0]
    }
    Write-InvokeCommandReturnVerboseWriter("Calling: New-Folder")
    Write-InvokeCommandReturnVerboseWriter("Passed: [string]NewFolders: {0} | [bool]IncludeDisplayCreate: {1}" -f $verboseDisplayNewFolders,
        $IncludeDisplayCreate)

    foreach ($newFolder in $NewFolders) {
        New-Directory -NewFolder $newFolder
    }

    if ($InvokeCommandReturnWriteArray) {
        return $Script:stringArray
    }
}

#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/Common/New-LoggerObject/New-LoggerObject.ps1
#v21.01.22.2234
Function New-LoggerObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'I prefer New here')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][string]$LogDirectory = ".",
        [Parameter(Mandatory = $false)][string]$LogName = "Script_Logging",
        [Parameter(Mandatory = $false)][bool]$EnableDateTime = $true,
        [Parameter(Mandatory = $false)][bool]$IncludeDateTimeToFileName = $true,
        [Parameter(Mandatory = $false)][int]$MaxFileSizeInMB = 10,
        [Parameter(Mandatory = $false)][int]$CheckSizeIntervalMinutes = 10,
        [Parameter(Mandatory = $false)][int]$NumberOfLogsToKeep = 10,
        [Parameter(Mandatory = $false)][bool]$VerboseEnabled,
        [Parameter(Mandatory = $false)][scriptblock]$HostFunctionCaller,
        [Parameter(Mandatory = $false)][scriptblock]$VerboseFunctionCaller
    )
    #Function Version #v21.01.22.2234

    ########################
    #
    # Template Functions
    #
    ########################

    Function Write-ToLog {
        param(
            [object]$WriteString,
            [string]$LogLocation
        )
        $WriteString | Out-File ($LogLocation) -Append
    }

    ########################
    #
    # End Template Functions
    #
    ########################

    ########## Parameter Binding Exceptions ##############
    if ($LogDirectory -eq ".") {
        $LogDirectory = (Get-Location).Path
    }

    if ([string]::IsNullOrWhiteSpace($LogName)) {
        throw [System.Management.Automation.ParameterBindingException] "Failed to provide valid LogName"
    }

    if (!(Test-Path $LogDirectory)) {

        try {
            New-Item -Path $LogDirectory -ItemType Directory | Out-Null
        } catch {
            throw [System.Management.Automation.ParameterBindingException] "Failed to provide valid LogDirectory"
        }
    }

    $loggerObject = New-Object PSCustomObject
    $loggerObject | Add-Member -MemberType NoteProperty -Name "FileDirectory" -Value $LogDirectory
    $loggerObject | Add-Member -MemberType NoteProperty -Name "FileName" -Value $LogName
    $loggerObject | Add-Member -MemberType NoteProperty -Name "FullPath" -Value $fullLogPath
    $loggerObject | Add-Member -MemberType NoteProperty -Name "InstanceBaseName" -Value ([string]::Empty)
    $loggerObject | Add-Member -MemberType NoteProperty -Name "EnableDateTime" -Value $EnableDateTime
    $loggerObject | Add-Member -MemberType NoteProperty -Name "IncludeDateTimeToFileName" -Value $IncludeDateTimeToFileName
    $loggerObject | Add-Member -MemberType NoteProperty -Name "MaxFileSizeInMB" -Value $MaxFileSizeInMB
    $loggerObject | Add-Member -MemberType NoteProperty -Name "CheckSizeIntervalMinutes" -Value $CheckSizeIntervalMinutes
    $loggerObject | Add-Member -MemberType NoteProperty -Name "NextFileCheckTime" -Value ((Get-Date).AddMinutes($CheckSizeIntervalMinutes))
    $loggerObject | Add-Member -MemberType NoteProperty -Name "InstanceNumber" -Value 1
    $loggerObject | Add-Member -MemberType NoteProperty -Name "NumberOfLogsToKeep" -Value $NumberOfLogsToKeep
    $loggerObject | Add-Member -MemberType NoteProperty -Name "WriteVerboseData" -Value $VerboseEnabled
    $loggerObject | Add-Member -MemberType NoteProperty -Name "PreventLogCleanup" -Value $false
    $loggerObject | Add-Member -MemberType NoteProperty -Name "LoggerDisabled" -Value $false
    $loggerObject | Add-Member -MemberType ScriptMethod -Name "ToLog" -Value ${Function:Write-ToLog}
    $loggerObject | Add-Member -MemberType ScriptMethod -Name "WriteHostWriter" -Value ${Function:Write-ScriptMethodHostWriter}
    $loggerObject | Add-Member -MemberType ScriptMethod -Name "WriteVerboseWriter" -Value ${Function:Write-ScriptMethodVerboseWriter}

    if ($null -ne $HostFunctionCaller) {
        $loggerObject | Add-Member -MemberType ScriptMethod -Name "HostFunctionCaller" -Value $HostFunctionCaller
    }

    if ($null -ne $VerboseFunctionCaller) {
        $loggerObject | Add-Member -MemberType ScriptMethod -Name "VerboseFunctionCaller" -Value $VerboseFunctionCaller
    }

    $loggerObject | Add-Member -MemberType ScriptMethod -Name "WriteHost" -Value {
        param(
            [object]$LoggingString
        )

        if ($this.LoggerDisabled) {
            return
        }

        if ($null -eq $LoggingString) {
            throw [System.Management.Automation.ParameterBindingException] "Failed to provide valid LoggingString"
        }

        if ($this.EnableDateTime) {
            $LoggingString = "[{0}] : {1}" -f [System.DateTime]::Now, $LoggingString
        }

        $this.WriteHostWriter($LoggingString)
        $this.ToLog($LoggingString, $this.FullPath)
        $this.LogUpKeep()
    }

    $loggerObject | Add-Member -MemberType ScriptMethod -Name "WriteVerbose" -Value {
        param(
            [object]$LoggingString
        )

        if ($this.LoggerDisabled) {
            return
        }

        if ($null -eq $LoggingString) {
            throw [System.Management.Automation.ParameterBindingException] "Failed to provide valid LoggingString"
        }

        if ($this.EnableDateTime) {
            $LoggingString = "[{0}] : {1}" -f [System.DateTime]::Now, $LoggingString
        }
        $this.WriteVerboseWriter($LoggingString)
        $this.ToLog($LoggingString, $this.FullPath)
        $this.LogUpKeep()
    }

    $loggerObject | Add-Member -MemberType ScriptMethod -Name "WriteToFileOnly" -Value {
        param(
            [object]$LoggingString
        )

        if ($this.LoggerDisabled) {
            return
        }

        if ($null -eq $LoggingString) {
            throw [System.Management.Automation.ParameterBindingException] "Failed to provide valid LoggingString"
        }

        if ($this.EnableDateTime) {
            $LoggingString = "[{0}] : {1}" -f [System.DateTime]::Now, $LoggingString
        }
        $this.ToLog($LoggingString, $this.FullPath)
        $this.LogUpKeep()
    }

    $loggerObject | Add-Member -MemberType ScriptMethod -Name "UpdateFileLocation" -Value {

        if ($this.LoggerDisabled) {
            return
        }

        if ($null -eq $this.FullPath) {

            if ($this.IncludeDateTimeToFileName) {
                $this.InstanceBaseName = "{0}_{1}" -f $this.FileName, ((Get-Date).ToString('yyyyMMddHHmmss'))
                $this.FullPath = "{0}\{1}.txt" -f $this.FileDirectory, $this.InstanceBaseName
            } else {
                $this.InstanceBaseName = "{0}" -f $this.FileName
                $this.FullPath = "{0}\{1}.txt" -f $this.FileDirectory, $this.InstanceBaseName
            }
        } else {

            do {
                $this.FullPath = "{0}\{1}_{2}.txt" -f $this.FileDirectory, $this.InstanceBaseName, $this.InstanceNumber
                $this.InstanceNumber++
            }while (Test-Path $this.FullPath)
            $this.WriteVerbose("Updated to New Log")
        }
    }

    $loggerObject | Add-Member -MemberType ScriptMethod -Name "LogUpKeep" -Value {

        if ($this.LoggerDisabled) {
            return
        }

        if ($this.NextFileCheckTime -gt [System.DateTime]::Now) {
            return
        }
        $this.NextFileCheckTime = (Get-Date).AddMinutes($this.CheckSizeIntervalMinutes)
        $this.CheckFileSize()
        $this.CheckNumberOfFiles()
        $this.WriteVerbose("Did Log Object Up Keep")
    }

    $loggerObject | Add-Member -MemberType ScriptMethod -Name "CheckFileSize" -Value {

        if ($this.LoggerDisabled) {
            return
        }

        $item = Get-ChildItem $this.FullPath

        if (($item.Length / 1MB) -gt $this.MaxFileSizeInMB) {
            $this.UpdateFileLocation()
        }
    }

    $loggerObject | Add-Member -MemberType ScriptMethod -Name "CheckNumberOfFiles" -Value {

        if ($this.LoggerDisabled) {
            return
        }

        $filter = "{0}*" -f $this.InstanceBaseName
        $items = Get-ChildItem -Path $this.FileDirectory | Where-Object { $_.Name -like $filter }

        if ($items.Count -gt $this.NumberOfLogsToKeep) {
            do {
                $items | Sort-Object LastWriteTime | Select-Object -First 1 | Remove-Item -Force
                $items = Get-ChildItem -Path $this.FileDirectory | Where-Object { $_.Name -like $filter }
            }while ($items.Count -gt $this.NumberOfLogsToKeep)
        }
    }

    $loggerObject | Add-Member -MemberType ScriptMethod -Name "RemoveLatestLogFile" -Value {

        if ($this.LoggerDisabled) {
            return
        }

        if (!$this.PreventLogCleanup) {
            $item = Get-ChildItem $this.FullPath
            Remove-Item $item -Force
        }
    }

    $loggerObject | Add-Member -MemberType ScriptMethod -Name "DisableLogger" -Value {
        $this.LoggerDisabled = $true
    }

    $loggerObject | Add-Member -MemberType ScriptMethod -Name "EnableLogger" -Value {
        $this.LoggerDisabled = $false
    }

    $loggerObject.UpdateFileLocation()
    try {
        "[{0}] : Creating a new logger instance" -f [System.DAteTime]::Now | Out-File ($loggerObject.FullPath) -Append
    } catch {
        throw
    }

    return $loggerObject
}

#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/Common/Save-DataToFile/Save-DataToFile.ps1
#v21.01.22.2234
Function Save-DataToFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][object]$DataIn,
        [Parameter(Mandatory = $true)][string]$SaveToLocation,
        [Parameter(Mandatory = $false)][bool]$FormatList = $true,
        [Parameter(Mandatory = $false)][bool]$SaveTextFile = $true,
        [Parameter(Mandatory = $false)][bool]$SaveXMLFile = $true
    )
    #Function Version #v21.01.22.2234

    Write-VerboseWriter("Calling: Save-DataToFile")
    Write-VerboseWriter("Passed: [string]SaveToLocation: {0} | [bool]FormatList: {1} | [bool]SaveTextFile: {2} | [bool]SaveXMLFile: {3}" -f $SaveToLocation,
        $FormatList,
        $SaveTextFile,
        $SaveXMLFile)

    $xmlSaveLocation = "{0}.xml" -f $SaveToLocation
    $txtSaveLocation = "{0}.txt" -f $SaveToLocation

    if ($DataIn -ne [string]::Empty -and
        $null -ne $DataIn) {
        if ($SaveXMLFile) {
            $DataIn | Export-Clixml $xmlSaveLocation -Encoding UTF8
        }
        if ($SaveTextFile) {
            if ($FormatList) {
                $DataIn | Format-List * | Out-File $txtSaveLocation
            } else {
                $DataIn | Format-Table -AutoSize | Out-File $txtSaveLocation
            }
        }
    } else {
        Write-VerboseWriter("DataIn was an empty string. Not going to save anything.")
    }
    Write-VerboseWriter("Returning from Save-DataToFile")
}

Function Write-HostWriter {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Need to use Write Host')]
    param(
        [Parameter(Mandatory = $true)][string]$WriteString
    )
    if ($null -ne $Script:Logger) {
        $Script:Logger.WriteHost($WriteString)
    } elseif ($null -eq $HostFunctionCaller) {
        Write-Host $WriteString
    } else {
        &$HostFunctionCaller $WriteString
    }
}

#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/Common/Write-HostWriters/Write-InvokeCommandReturnHostWriter.ps1
#v21.01.22.2212
Function Write-InvokeCommandReturnHostWriter {
    param(
        [Parameter(Mandatory = $true)][string]$WriteString
    )
    if ($InvokeCommandReturnWriteArray) {
        $hashTable = @{"Host" = ("[Remote Server: {0}] : {1}" -f $env:COMPUTERNAME, $WriteString) }
        Set-Variable stringArray -Value ($Script:stringArray += $hashTable) -Scope Script
    } else {
        Write-HostWriter $WriteString
    }
}

#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/Common/Write-VerboseWriters/Write-InvokeCommandReturnVerboseWriter.ps1
#v21.01.22.2212
Function Write-InvokeCommandReturnVerboseWriter {
    param(
        [Parameter(Mandatory = $true)][string]$WriteString
    )
    if ($InvokeCommandReturnWriteArray) {
        $hashTable = @{"Verbose" = ("[Remote Server: {0}] : {1}" -f $env:COMPUTERNAME, $WriteString) }
        Set-Variable stringArray -Value ($Script:stringArray += $hashTable) -Scope Script
    } else {
        Write-VerboseWriter($WriteString)
    }
}

#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/Common/Write-HostWriters/Write-ScriptMethodHostWriter.ps1
#v21.01.22.2212
Function Write-ScriptMethodHostWriter {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Need to use Write Host')]
    param(
        [Parameter(Mandatory = $true)][string]$WriteString
    )
    if ($null -ne $this.LoggerObject) {
        $this.LoggerObject.WriteHost($WriteString)
    } elseif ($null -eq $this.HostFunctionCaller) {
        Write-Host $WriteString
    } else {
        $this.HostFunctionCaller($WriteString)
    }
}

#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/Common/Write-VerboseWriters/Write-ScriptMethodVerboseWriter.ps1
#v21.01.22.2212
Function Write-ScriptMethodVerboseWriter {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Need to use Write Host')]
    param(
        [Parameter(Mandatory = $true)][string]$WriteString
    )
    if ($null -ne $this.LoggerObject) {
        $this.LoggerObject.WriteVerbose($WriteString)
    } elseif ($null -eq $this.VerboseFunctionCaller -and
        $this.WriteVerboseData) {
        Write-Host $WriteString -ForegroundColor Cyan
    } elseif ($this.WriteVerboseData) {
        $this.VerboseFunctionCaller($WriteString)
    }
}

Function Write-VerboseWriter {
    param(
        [Parameter(Mandatory = $true)][string]$WriteString
    )
    if ($null -ne $Script:Logger) {
        $Script:Logger.WriteVerbose($WriteString)
    } elseif ($null -eq $VerboseFunctionCaller) {
        Write-Verbose $WriteString
    } else {
        &$VerboseFunctionCaller $WriteString
    }
}

Function Add-ServerNameToFileName {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath
    )
    Write-ScriptDebug("Calling: Add-ServerNameToFileName")
    Write-ScriptDebug("Passed: [string]FilePath: {0}" -f $FilePath)
    $fileName = "{0}_{1}" -f $env:COMPUTERNAME, ($name = $FilePath.Substring($FilePath.LastIndexOf("\") + 1))
    $filePathWithServerName = $FilePath.Replace($name, $fileName)
    Write-ScriptDebug("Returned: {0}" -f $filePathWithServerName)
    return $filePathWithServerName
}

Function Get-ItemsSize {
    param(
        [Parameter(Mandatory = $true)][array]$FilePaths
    )
    Write-ScriptDebug("Calling: Get-ItemsSize")
    $totalSize = 0
    $hashSizes = @{}
    foreach ($file in $FilePaths) {
        if (Test-Path $file) {
            $totalSize += ($fileSize = (Get-Item $file).Length)
            Write-ScriptDebug("File: {0} | Size: {1} MB" -f $file, ($fileSizeMB = $fileSize / 1MB))
            $hashSizes.Add($file, ("{0}" -f $fileSizeMB))
        } else {
            Write-ScriptDebug("File no longer exists: {0}" -f $file)
        }
    }
    Set-Variable -Name ItemSizesHashed -Value $hashSizes -Scope Script
    Write-ScriptDebug("Returning: {0}" -f $totalSize)
    return $totalSize
}

Function Get-StringDataForNotEnoughFreeSpaceFile {
    param(
        [Parameter(Mandatory = $true)][hashtable]$hasher
    )
    Write-ScriptDebug("Calling: Get-StringDataForNotEnoughFreeSpaceFile")
    $reader = [string]::Empty
    $totalSizeMB = 0
    foreach ($key in $hasher.Keys) {
        $reader += ("File: {0} | Size: {1} MB`r`n" -f $key, ($keyValue = $hasher[$key]).ToString())
        $totalSizeMB += $keyValue
    }
    $reader += ("`r`nTotal Size Attempted To Copy Over: {0} MB`r`nCurrent Available Free Space: {1} GB" -f $totalSizeMB, $Script:CurrentFreeSpaceGB)
    return $reader
}

Function Get-IISLogDirectory {
    Write-ScriptDebug("Function Enter: Get-IISLogDirectory")

    Function Get-IISDirectoryFromGetWebSite {
        Write-ScriptDebug("Get-WebSite command exists")
        return Get-WebSite |
            ForEach-Object {
                $logFile = "$($_.LogFile.Directory)\W3SVC$($_.id)".Replace("%SystemDrive%", $env:SystemDrive)
                Write-ScriptDebug("Found Directory: $logFile")
                return $logFile
            }
    }

    if ((Test-CommandExists -command "Get-WebSite")) {
        [array]$iisLogDirectory = Get-IISDirectoryFromGetWebSite
    } else {
        #May need to load the module
        try {
            Write-ScriptDebug("Going to attempt to load the WebAdministration Module")
            Import-Module WebAdministration -ErrorAction Stop
            Write-ScriptDebug("Successful loading the module")

            if ((Test-CommandExists -command "Get-WebSite")) {
                [array]$iisLogDirectory = Get-IISDirectoryFromGetWebSite
            }
        } catch {
            Invoke-CatchBlockActions
            [array]$iisLogDirectory = "C:\inetpub\logs\LogFiles\" #Default location for IIS Logs
            Write-ScriptDebug("Get-WebSite command doesn't exists. Set IISLogDirectory to: {0}" -f $iisLogDirectory)
        }
    }

    Write-ScriptDebug("Function Exit: Get-IISLogDirectory")
    return $iisLogDirectory
}

Function Test-CommandExists {
    param(
        [string]$command
    )

    try {
        if (Get-Command $command -ErrorAction Stop) {
            return $true
        }
    } catch {
        Invoke-CatchBlockActions
        return $false
    }
}

Function Test-FreeSpace {
    param(
        [Parameter(Mandatory = $false)][array]$FilePaths
    )
    Write-ScriptDebug("Calling: Test-FreeSpace")

    if ($null -eq $FilePaths -or
        $FilePaths.Count -eq 0) {
        Write-ScriptDebug("Null FilePaths provided returning true.")
        return $true
    }

    $passed = $true
    $currentSizeCopy = Get-ItemsSize -FilePaths $FilePaths
    #It is better to be safe than sorry, checking against probably a value way higher than needed.
    if (($Script:FreeSpaceMinusCopiedAndCompressedGB - ($currentSizeCopy / 1GB)) -lt $Script:AdditionalFreeSpaceCushionGB) {
        Write-ScriptDebug("Estimated free space is getting low, going to recalculate.")
        Write-ScriptDebug("Current values: [double]FreeSpaceMinusCopiedAndCompressedGB: {0} | [double]currentSizeCopy: {1} | [double]AdditionalFreeSpaceCushionGB: {2} | [double]CurrentFreeSpaceGB: {3}" -f $Script:FreeSpaceMinusCopiedAndCompressedGB,
            ($currentSizeCopy / 1GB),
            $Script:AdditionalFreeSpaceCushionGB,
            $Script:CurrentFreeSpaceGB)
        $freeSpace = Get-FreeSpace -FilePath ("{0}\" -f $Script:RootCopyToDirectory)
        Write-ScriptDebug("True current free space: {0}" -f $freeSpace)

        if ($freeSpace -lt ($Script:CurrentFreeSpaceGB - .5)) {
            #If we off by .5GB, we need to know about this and look at the data to determine if we might have some logical errors. It is possible that the disk is that active, but that wouldn't be good either for this script.
            Write-ScriptDebug("CRIT: Disk Space logic is off. CurrentFreeSpaceGB: {0} | ActualFreeSpace: {1}" -f $Script:CurrentFreeSpaceGB, $freeSpace)
        }

        $Script:CurrentFreeSpaceGB = $freeSpace
        $Script:FreeSpaceMinusCopiedAndCompressedGB = $freeSpace
        $passed = $freeSpace -gt ($addSize = $Script:AdditionalFreeSpaceCushionGB + ($currentSizeCopy / 1GB))

        if (!($passed)) {
            Write-ScriptHost("Free space on the drive has appear to be used up past recommended thresholds. Going to stop this execution of the script. If you feel this is an Error, please notify ExToolsFeedback@microsoft.com") -ShowServer $true -ForegroundColor "Red"
            Write-ScriptHost("FilePath: {0} | FreeSpace: {1} | Looking for: {2}" -f $Script:RootCopyToDirectory, $freeSpace, ($freeSpace + $addSize)) -ShowServer $true -ForegroundColor "Red"
            return $passed
        }
    }

    $Script:TotalBytesSizeCopied += $currentSizeCopy
    $Script:FreeSpaceMinusCopiedAndCompressedGB = $Script:FreeSpaceMinusCopiedAndCompressedGB - ($currentSizeCopy / 1GB)

    Write-ScriptDebug("Current values [double]FreeSpaceMinusCopiedAndCompressedGB: {0} | [double]TotalBytesSizeCopied: {1}" -f $Script:FreeSpaceMinusCopiedAndCompressedGB, $Script:TotalBytesSizeCopied)
    Write-ScriptDebug("Returning: {0}" -f $passed)
    return $passed
}

Function Invoke-ZipFolder {
    param(
        [string]$Folder,
        [bool]$ZipItAll,
        [bool]$AddCompressedSize = $true
    )

    if ($ZipItAll) {
        Write-ScriptDebug("Disabling Logger before zipping up the directory")
        $Script:Logger.DisableLogger()
        Compress-Folder -Folder $Folder -IncludeMonthDay $true
    } else {
        $compressedLocation = Compress-Folder -Folder $Folder -ReturnCompressedLocation $AddCompressedSize
        if ($AddCompressedSize -and ($compressedLocation -ne [string]::Empty)) {
            $Script:TotalBytesSizeCompressed += ($size = Get-ItemsSize -FilePaths $compressedLocation)
            $Script:FreeSpaceMinusCopiedAndCompressedGB -= ($size / 1GB)
            Write-ScriptDebug("Current Sizes after compression: [double]TotalBytesSizeCompressed: {0} | [double]FreeSpaceMinusCopiedAndCompressedGB: {1}" -f $Script:TotalBytesSizeCompressed,
                $Script:FreeSpaceMinusCopiedAndCompressedGB)
        }
    }
}

Function Copy-BulkItems {
    param(
        [string]$CopyToLocation,
        [Array]$ItemsToCopyLocation
    )
    if (-not(Test-Path $CopyToLocation)) {
        New-Folder -NewFolder $CopyToLocation -IncludeDisplayCreate $true
    }

    if (Test-FreeSpace -FilePaths $ItemsToCopyLocation) {
        foreach ($item in $ItemsToCopyLocation) {
            Copy-Item -Path $item -Destination $CopyToLocation -ErrorAction SilentlyContinue
        }
    } else {
        Write-ScriptHost("Not enough free space to copy over this data set.")
        New-Item -Path ("{0}\NotEnoughFreeSpace.txt" -f $CopyToLocation) -ItemType File -Value (Get-StringDataForNotEnoughFreeSpaceFile -hasher $Script:ItemSizesHashed) | Out-Null
    }
}

Function Copy-FullLogFullPathRecurse {
    param(
        [Parameter(Mandatory = $true)][string]$LogPath,
        [Parameter(Mandatory = $true)][string]$CopyToThisLocation
    )
    Write-ScriptDebug("Function Enter: Copy-FullLogFullPathRecurse")
    Write-ScriptDebug("Passed: [string]LogPath: {0} | [string]CopyToThisLocation: {1}" -f $LogPath, $CopyToThisLocation)
    New-Folder -NewFolder $CopyToThisLocation -IncludeDisplayCreate $true
    if (Test-Path $LogPath) {
        $childItems = Get-ChildItem $LogPath -Recurse
        $items = @()
        foreach ($childItem in $childItems) {
            if (!($childItem.Mode.StartsWith("d-"))) {
                $items += $childItem.VersionInfo.FileName
            }
        }

        if ($null -ne $items -and
            $items.Count -gt 0) {
            if (Test-FreeSpace -FilePaths $items) {
                Copy-Item $LogPath\* $CopyToThisLocation -Recurse -ErrorAction SilentlyContinue
                Invoke-ZipFolder $CopyToThisLocation
            } else {
                Write-ScriptDebug("Not going to copy over this set of data due to size restrictions.")
                New-Item -Path ("{0}\NotEnoughFreeSpace.txt" -f $CopyToThisLocation) -ItemType File -Value (Get-StringDataForNotEnoughFreeSpaceFile -hasher $Script:ItemSizesHashed) | Out-Null
            }
        } else {
            Write-ScriptHost("No data at path '{0}'. Unable to copy this data." -f $LogPath)
            New-Item -Path ("{0}\NoDataDetected.txt" -f $CopyToThisLocation) -ItemType File -Value $LogPath | Out-Null
        }
    } else {
        Write-ScriptHost("No Folder at {0}. Unable to copy this data." -f $LogPath)
        New-Item -Path ("{0}\NoFolderDetected.txt" -f $CopyToThisLocation) -ItemType File -Value $LogPath | Out-Null
    }
    Write-ScriptDebug("Function Exit: Copy-FullLogFullPathRecurse")
}

Function Copy-LogmanData {
    param(
        [Parameter(Mandatory = $true)]$ObjLogman
    )

    if ($PassedInfo.ExperfwizLogmanName -contains $ObjLogman.LogmanName) {
        $folderName = "ExPerfWiz_Data"
    } elseif ($PassedInfo.ExmonLogmanName -contains $ObjLogman.LogmanName) {
        $folderName = "ExmonTrace_Data"
    } else {
        $folderName = "Logman_Data"
    }

    $strDirectory = $ObjLogman.RootPath
    $copyTo = $Script:RootCopyToDirectory + "\" + $folderName
    New-Folder -NewFolder $copyTo -IncludeDisplayCreate $true
    if (Test-Path $strDirectory) {
        $wildExt = "*" + $objLogman.Ext
        $filterDate = $objLogman.StartDate

        $copyFromDate = [DateTime]::Now - $PassedInfo.TimeSpan
        Write-ScriptDebug("Copy From Date: {0}" -f $filterDate)

        if ([DateTime]$filterDate -lt [DateTime]$copyFromDate) {
            $filterDate = $copyFromDate
            Write-ScriptDebug("Updating Copy From Date to: '{0}'" -f $filterDate)
        }

        $childItems = Get-ChildItem $strDirectory -Recurse | Where-Object { ($_.Name -like $wildExt) -and ($_.CreationTime -ge $filterDate) }
        $items = @()
        foreach ($childItem in $childItems) {
            $items += $childItem.VersionInfo.FileName
        }
        if ($null -ne $items) {
            Copy-BulkItems -CopyToLocation $copyTo -ItemsToCopyLocation $items
            Invoke-ZipFolder -Folder $copyTo
        } else {
            Write-ScriptHost -WriteString ("Failed to find any files in the directory: '{0}' that was greater than or equal to this time: {1}" -f $strDirectory, $filterDate) -ForegroundColor "Yellow"
            Write-ScriptHost -WriteString  ("Going to try to see if there are any files in this directory for you..." ) -NoNewline $true
            $files = Get-ChildItem $strDirectory -Recurse | Where-Object { $_.Name -like $wildExt }
            if ($null -ne $files) {
                #only want to get latest data
                $newestFilesTime = ($files | Sort-Object CreationTime -Descending)[0].CreationTime.AddDays(-1)
                $newestFiles = $files | Where-Object { $_.CreationTime -ge $newestFilesTime }

                $items = @()
                foreach ($newestFile in $newestFiles) {
                    $items += $newestFile.VersionInfo.FileName
                }

                if ($null -ne $items) {
                    Copy-BulkItems -CopyToLocation $copyTo -ItemsToCopyLocation $items
                    Invoke-ZipFolder -Folder $copyTo
                }
            } else {
                Write-ScriptHost -WriteString ("Failed to find any files in the directory: '{0}'" -f $strDirectory) -ForegroundColor "Yellow"
                $tempFile = $copyTo + "\NoFiles.txt"
                New-Item $tempFile -ItemType File -Value $strDirectory | Out-Null
            }
        }
    } else {
        Write-ScriptHost -WriteString  ("Doesn't look like this Directory is valid. {0}" -f $strDirectory) -ForegroundColor "Yellow"
        $tempFile = $copyTo + "\NotValidDirectory.txt"
        New-Item $tempFile -ItemType File -Value $strDirectory | Out-Null
    }
}

Function Copy-LogsBasedOnTime {
    param(
        [Parameter(Mandatory = $false)][string]$LogPath,
        [Parameter(Mandatory = $true)][string]$CopyToThisLocation
    )
    Write-ScriptDebug("Function Enter: Copy-LogsBasedOnTime")
    Write-ScriptDebug("Passed: [string]LogPath: {0} | [string]CopyToThisLocation: {1}" -f $LogPath, $CopyToThisLocation)

    if ([string]::IsNullOrEmpty($LogPath)) {
        Write-ScriptDebug("Failed to provide a valid log path to copy.")
        return
    }

    New-Folder -NewFolder $CopyToThisLocation -IncludeDisplayCreate $true

    Function NoFilesInLocation {
        param(
            [Parameter(Mandatory = $true)][string]$CopyFromLocation,
            [Parameter(Mandatory = $true)][string]$CopyToLocation
        )
        Write-ScriptHost -WriteString ("It doesn't look like you have any data in this location {0}." -f $CopyFromLocation) -ForegroundColor "Yellow"
        #Going to place a file in this location so we know what happened
        $tempFile = $CopyToLocation + "\NoFilesDetected.txt"
        New-Item $tempFile -ItemType File -Value $LogPath | Out-Null
        Start-Sleep 1
    }

    $copyFromDate = [DateTime]::Now - $PassedInfo.TimeSpan
    Write-ScriptDebug("Copy From Date: {0}" -f $copyFromDate)
    $skipCopy = $false
    if (!(Test-Path $LogPath)) {
        #if the directory isn't there, we need to handle it
        NoFilesInLocation -CopyFromLocation $LogPath -CopyToLocation $CopyToThisLocation
        Write-ScriptDebug("Function Exit: Copy-LogsBasedOnTime")
        return
    }
    #We are not copying files recurse so we need to not include possible directories or we will throw an error
    $files = Get-ChildItem $LogPath | Sort-Object LastWriteTime -Descending | Where-Object { $_.LastWriteTime -ge $copyFromDate -and $_.Mode -notlike "d*" }
    #if we don't have any logs, we want to attempt to copy something

    if ($null -eq $files) {
        <#
                There are a few different reasons to get here
                1. We don't have any files in the timeframe request in the directory that we are looking at
                2. We have sub directories that we need to look into and look at those files (Only if we don't have files in the currently location so we aren't pulling files like the index files from message tracking)
            #>
        Write-ScriptDebug("Copy-LogsBasedOnTime: Failed to find any logs in the directory provided, need to do a deeper look to find some logs that we want.")
        $allFiles = Get-ChildItem $LogPath | Sort-Object LastWriteTime -Descending
        Write-ScriptDebug("Displaying all items in the directory: {0}" -f $LogPath)
        foreach ($file in $allFiles) {
            Write-ScriptDebug("File Name: {0} Last Write Time: {1}" -f $file.Name, $file.LastWriteTime)
        }

        #Let's see if we have any files in this location while having directories
        $directories = $allFiles | Where-Object { $_.Mode -like "d*" }
        $filesInDirectory = $allFiles | Where-Object { $_.Mode -notlike "d*" }

        if (($null -ne $directories) -and
            ($null -ne $filesInDirectory)) {
            #This means we should be looking in the sub directories not the current directory so let's re-do that logic to try to find files in that timeframe.
            foreach ($dir in $directories) {
                $newLogPath = $dir.FullName
                $newCopyToThisLocation = "{0}\{1}" -f $CopyToThisLocation, $dir.Name
                New-Folder -NewFolder $newCopyToThisLocation -IncludeDisplayCreate $true
                $files = Get-ChildItem $newLogPath | Sort-Object LastWriteTime -Descending | Where-Object { $_.LastWriteTime -ge $copyFromDate -and $_.Mode -notlike "d*" }

                if ($null -eq $files) {
                    NoFilesInLocation -CopyFromLocation $newLogPath -CopyToLocation $newCopyToThisLocation
                } else {
                    Write-ScriptDebug("Found {0} number of files at the location {1}" -f $files.Count, $newLogPath)
                    $filesFullPath = @()
                    $files | ForEach-Object { $filesFullPath += $_.VersionInfo.FileName }
                    Copy-BulkItems -CopyToLocation $newCopyToThisLocation -ItemsToCopyLocation $filesFullPath
                    Invoke-ZipFolder -Folder $newCopyToThisLocation
                }
            }
            Write-ScriptDebug("Function Exit: Copy-LogsBasedOnTime")
            return
        }

        #If we get here, we want to find the latest file that isn't a directory.
        $files = $allFiles | Where-Object { $_.Mode -notlike "d*" } | Select-Object -First 1

        #If we are still null, we want to let them know
        if ($null -eq $files) {
            $skipCopy = $true
            NoFilesInLocation -CopyFromLocation $LogPath -CopyToLocation $CopyToThisLocation
        }
    }
    Write-ScriptDebug("Found {0} number of files at the location {1}" -f $Files.Count, $LogPath)
    #ResetFiles to full path
    $filesFullPath = @()
    $files | ForEach-Object { $filesFullPath += $_.VersionInfo.FileName }

    if (-not ($skipCopy)) {
        Copy-BulkItems -CopyToLocation $CopyToThisLocation -ItemsToCopyLocation $filesFullPath
        Invoke-ZipFolder -Folder $CopyToThisLocation
    }
    Write-ScriptDebug("Function Exit: Copy-LogsBasedOnTime")
}

Function Invoke-CatchBlockActions {
    Write-ScriptDebug -WriteString ("Error Exception: $($Error[0].Exception)")
    Write-ScriptDebug -WriteString ("Error Stack: $($Error[0].ScriptStackTrace)")
    [array]$Script:ErrorsHandled += $Error[0]
}

Function Save-DataInfoToFile {
    param(
        [Parameter(Mandatory = $false)][object]$DataIn,
        [Parameter(Mandatory = $true)][string]$SaveToLocation,
        [Parameter(Mandatory = $false)][bool]$FormatList = $true,
        [Parameter(Mandatory = $false)][bool]$SaveTextFile = $true,
        [Parameter(Mandatory = $false)][bool]$SaveXMLFile = $true,
        [Parameter(Mandatory = $false)][bool]$AddServerName = $true
    )
    [System.Diagnostics.Stopwatch]$timer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-ScriptDebug "Function Enter: Save-DataInfoToFile"

    if ($AddServerName) {
        $SaveToLocation = Add-ServerNameToFileName $SaveToLocation
    }

    Save-DataToFile -DataIn $DataIn -SaveToLocation $SaveToLocation -FormatList $FormatList -SaveTextFile $SaveTextFile -SaveXMLFile $SaveXMLFile
    $timer.Stop()
    Write-ScriptDebug("Took {0} seconds to save out the data." -f $timer.Elapsed.TotalSeconds)
}

#Save out the failover cluster information for the local node, besides the event logs.
Function Save-FailoverClusterInformation {
    Write-ScriptDebug("Function Enter: Save-FailoverClusterInformation")
    $copyTo = "$Script:RootCopyToDirectory\Cluster_Information"
    New-Folder -NewFolder $copyTo -IncludeDisplayCreate $true

    try {
        Save-DataInfoToFile -DataIn (Get-Cluster -ErrorAction Stop) -SaveToLocation "$copyTo\GetCluster"
    } catch {
        Write-ScriptDebug "Failed to run Get-Cluster"
        Invoke-CatchBlockActions
    }

    try {
        Save-DataInfoToFile -DataIn (Get-ClusterGroup -ErrorAction Stop) -SaveToLocation "$copyTo\GetClusterGroup"
    } catch {
        Write-ScriptDebug "Failed to run Get-ClusterGroup"
        Invoke-CatchBlockActions
    }

    try {
        Save-DataInfoToFile -DataIn (Get-ClusterNode -ErrorAction Stop) -SaveToLocation "$copyTo\GetClusterNode"
    } catch {
        Write-ScriptDebug "Failed to run Get-ClusterNode"
        Invoke-CatchBlockActions
    }

    try {
        Save-DataInfoToFile -DataIn (Get-ClusterNetwork -ErrorAction Stop) -SaveToLocation "$copyTo\GetClusterNetwork"
    } catch {
        Write-ScriptDebug "Failed to run Get-ClusterNetwork"
        Invoke-CatchBlockActions
    }

    try {
        Save-DataInfoToFile -DataIn (Get-ClusterNetworkInterface -ErrorAction Stop) -SaveToLocation "$copyTo\GetClusterNetworkInterface"
    } catch {
        Write-ScriptDebug "Failed to run Get-ClusterNetworkInterface"
        Invoke-CatchBlockActions
    }

    try {
        Get-ClusterLog -Node $env:ComputerName -Destination $copyTo -ErrorAction Stop | Out-Null
    } catch {
        Write-ScriptDebug "Failed to run Get-ClusterLog"
        Invoke-CatchBlockActions
    }

    try {
        $clusterNodeFileVersions = Get-ClusterNodeFileVersions
        Save-DataInfoToFile -DataIn $clusterNodeFileVersions -SaveToLocation "$copyTo\ClusterNodeFileVersions" -SaveTextFile $false
        Save-DataInfoToFile -DataIn ($clusterNodeFileVersions.Files.Values) -SaveToLocation "$copyTo\ClusterNodeFileVersions" -SaveXMLFile $false -FormatList $false
    } catch {
        Write-ScriptDebug "Failed to run Get-ClusterNodeFileVersions"
        Invoke-CatchBlockActions
    }

    try {
        $saveName = "$copyTo\ClusterHive.hiv"
        reg save "HKEY_LOCAL_MACHINE\Cluster" $saveName | Out-Null
        "To read the cluster hive. Run 'reg load HKLM\TempHive ClusterHive.hiv'. Then Open your regedit then go to HKLM:\TempHive to view the data." |
            Out-File -FilePath "$copyTo\ClusterHive_HowToRead.txt"
    } catch {
        Write-ScriptDebug "Failed to get the Cluster Hive"
        Invoke-CatchBlockActions
    }

    Invoke-ZipFolder -Folder $copyTo
    Write-ScriptDebug "Function Exit: Save-FailoverClusterInformation"
}

Function Save-LogmanExmonData {
    Get-LogmanData -LogmanName $PassedInfo.ExmonLogmanName -ServerName $env:COMPUTERNAME
}

Function  Save-LogmanExperfwizData {

    $PassedInfo.ExperfwizLogmanName |
        ForEach-Object {
            Get-LogmanData -LogmanName $_ -ServerName $env:COMPUTERNAME
        }
}

Function Save-ServerInfoData {
    Write-ScriptDebug("Function Enter: Save-ServerInfoData")
    $copyTo = $Script:RootCopyToDirectory + "\General_Server_Info"
    New-Folder -NewFolder $copyTo -IncludeDisplayCreate $true

    #Get MSInfo from server
    msinfo32.exe /nfo (Add-ServerNameToFileName -FilePath ("{0}\msinfo.nfo" -f $copyTo))
    Write-ScriptHost -WriteString ("Waiting for msinfo32.exe process to end before moving on...") -ForegroundColor "Yellow"
    while ((Get-Process | Where-Object { $_.ProcessName -eq "msinfo32" }).ProcessName -eq "msinfo32") {
        Start-Sleep 5;
    }

    #Include TLS Registry Information #84
    $tlsSettings = @()
    try {
        $tlsSettings += Get-ChildItem "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" -Recurse | Where-Object { $_.Name -like "*TLS*" } -ErrorAction stop
    } catch {
        Write-ScriptDebug("Failed to get child items of 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'")
        Invoke-CatchBlockActions
    }
    try {
        $regBaseV4 = "HKLM:SOFTWARE\{0}\.NETFramework\v4.0.30319"
        $tlsSettings += Get-Item ($currentKey = $regBaseV4 -f "Microsoft") -ErrorAction stop
        $tlsSettings += Get-Item ($currentKey = $regBaseV4 -f "Wow6432Node\Microsoft") -ErrorAction stop
    } catch {
        Write-ScriptDebug("Failed to get child items of '{0}'" -f $currentKey)
        Invoke-CatchBlockActions
    }
    try {
        $regBaseV2 = "HKLM:SOFTWARE\{0}\.NETFramework\v2.0.50727"
        $tlsSettings += Get-Item ($currentKey = $regBaseV2 -f "Microsoft") -ErrorAction stop
        $tlsSettings += Get-Item ($currentKey = $regBaseV2 -f "Wow6432Node\Microsoft") -ErrorAction stop
    } catch {
        Write-ScriptDebug("Failed to get child items of '{0}'" -f $currentKey)
        Invoke-CatchBlockActions
    }
    Save-DataInfoToFile -DataIn $tlsSettings -SaveToLocation ("{0}\TLS_RegistrySettings" -f $copyTo) -FormatList $false

    #Running Processes #35
    Save-DataInfoToFile -dataIn (Get-Process) -SaveToLocation ("{0}\Running_Processes" -f $copyTo) -FormatList $false

    #Services Information #36
    Save-DataInfoToFile -dataIn (Get-Service) -SaveToLocation ("{0}\Services_Information" -f $copyTo) -FormatList $false

    #VSSAdmin Information #39
    Save-DataInfoToFile -DataIn (vssadmin list Writers) -SaveToLocation ("{0}\VSS_Writers" -f $copyTo) -SaveXMLFile $false

    #Driver Information #34
    Save-DataInfoToFile -dataIn (Get-ChildItem ("{0}\System32\drivers" -f $env:SystemRoot) | Where-Object { $_.Name -like "*.sys" }) -SaveToLocation ("{0}\System32_Drivers" -f $copyTo)

    Save-DataInfoToFile -DataIn (Get-HotFix | Select-Object Source, Description, HotFixID, InstalledBy, InstalledOn) -SaveToLocation ("{0}\HotFixInfo" -f $copyTo)

    #TCPIP Networking Information #38
    Save-DataInfoToFile -DataIn (ipconfig /all) -SaveToLocation ("{0}\IPConfiguration" -f $copyTo) -SaveXMLFile $false
    Save-DataInfoToFile -DataIn (netstat -anob) -SaveToLocation ("{0}\NetStat_ANOB" -f $copyTo) -SaveXMLFile $false
    Save-DataInfoToFile -DataIn (route print) -SaveToLocation ("{0}\Network_Routes" -f $copyTo) -SaveXMLFile $false
    Save-DataInfoToFile -DataIn (arp -a) -SaveToLocation ("{0}\Network_ARP" -f $copyTo) -SaveXMLFile $false
    Save-DataInfoToFile -DataIn (netstat -nato) -SaveToLocation ("{0}\Netstat_NATO" -f $copyTo) -SaveXMLFile $false
    Save-DataInfoToFile -DataIn (netstat -es) -SaveToLocation ("{0}\Netstat_ES" -f $copyTo) -SaveXMLFile $false

    #IPsec
    Save-DataInfoToFile -DataIn (netsh ipsec dynamic show all) -SaveToLocation ("{0}\IPsec_netsh_dynamic" -f $copyTo) -SaveXMLFile $false
    Save-DataInfoToFile -DataIn (netsh ipsec static show all) -SaveToLocation ("{0}\IPsec_netsh_static" -f $copyTo) -SaveXMLFile $false

    #FLTMC
    Save-DataInfoToFile -DataIn (fltmc) -SaveToLocation ("{0}\FLTMC_FilterDrivers" -f $copyTo) -SaveXMLFile $false
    Save-DataInfoToFile -DataIn (fltmc volumes) -SaveToLocation ("{0}\FLTMC_Volumes" -f $copyTo) -SaveXMLFile $false
    Save-DataInfoToFile -DataIn (fltmc instances) -SaveToLocation ("{0}\FLTMC_Instances" -f $copyTo) -SaveXMLFile $false

    Save-DataInfoToFile -DataIn (TASKLIST /M) -SaveToLocation ("{0}\TaskList_Modules" -f $copyTo) -SaveXMLFile $false

    if (!$Script:localServerObject.Edge) {
        $hiveKey = @()
        try {
            $hiveKey = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Exchange\ -Recurse -ErrorAction Stop
        } catch {
            Write-ScriptDebug("Failed to get child item on HKLM:\SOFTWARE\Microsoft\Exchange\")
            Invoke-CatchBlockActions
        }
        $hiveKey += Get-ChildItem HKLM:\SOFTWARE\Microsoft\ExchangeServer\ -Recurse
        Save-DataInfoToFile -DataIn $hiveKey -SaveToLocation ("{0}\Exchange_Registry_Hive" -f $copyTo) -SaveTextFile $false
    }

    Save-DataInfoToFile -DataIn (gpresult /R /Z) -SaveToLocation ("{0}\GPResult" -f $copyTo) -SaveXMLFile $false
    gpresult /H (Add-ServerNameToFileName -FilePath ("{0}\GPResult.html" -f $copyTo))

    #Storage Information
    if (Test-CommandExists -command "Get-Volume") {
        Save-DataInfoToFile -DataIn (Get-Volume) -SaveToLocation ("{0}\Volume" -f $copyTo)
    } else {
        Write-ScriptDebug("Get-Volume isn't a valid command")
    }

    if (Test-CommandExists -command "Get-Disk") {
        Save-DataInfoToFile -DataIn (Get-Disk) -SaveToLocation ("{0}\Disk" -f $copyTo)
    } else {
        Write-ScriptDebug("Get-Disk isn't a valid command")
    }

    if (Test-CommandExists -command "Get-Partition") {
        Save-DataInfoToFile -DataIn (Get-Partition) -SaveToLocation ("{0}\Partition" -f $copyTo)
    } else {
        Write-ScriptDebug("Get-Partition isn't a valid command")
    }

    Invoke-ZipFolder -Folder $copyTo
    Write-ScriptDebug("Function Exit: Save-ServerInfoData")
}

Function Save-WindowsEventLogs {

    Write-ScriptDebug("Function Enter: Save-WindowsEventLogs")
    $baseSaveLocation = $Script:RootCopyToDirectory + "\Windows_Event_Logs"
    $SaveLogs = @{}
    $rootLogPath = "$env:SystemRoot\System32\Winevt\Logs"
    $allLogPaths = Get-ChildItem $rootLogPath |
        ForEach-Object {
            $_.VersionInfo.FileName
        }

    if ($PassedInfo.AppSysLogs) {
        Write-ScriptDebug("Adding Application and System Logs")
        $logs = @()
        $logs += "$rootLogPath\Application.evtx"
        $logs += "$rootLogPath\System.evtx"
        $logs += "$rootLogPath\MSExchange Management.evtx"
    }

    if ($PassedInfo.WindowsSecurityLogs) { $logs += "$rootLogPath\Security.evtx" }

    if ($PassedInfo.AppSysLogs -or
        $PassedInfo.WindowsSecurityLogs) {
        $SaveLogs.Add("Windows-Logs", $logs)
    }

    if ($PassedInfo.ManagedAvailabilityLogs) {
        Write-ScriptDebug("Adding Managed Availability Logs")

        $logs = $allLogPaths | Where-Object { $_.Contains("Microsoft-Exchange-ActiveMonitoring") }
        $SaveLogs.Add("Microsoft-Exchange-ActiveMonitoring", $Logs)

        $logs = $allLogPaths | Where-Object { $_.Contains("Microsoft-Exchange-ManagedAvailability") }
        $SaveLogs.Add("Microsoft-Exchange-ManagedAvailability", $Logs)
    }

    if ($PassedInfo.HighAvailabilityLogs) {
        Write-ScriptDebug("Adding High Availability Logs")

        $logs = $allLogPaths | Where-Object { $_.Contains("Microsoft-Exchange-HighAvailability") }
        $SaveLogs.Add("Microsoft-Exchange-HighAvailability", $Logs)

        $logs = $allLogPaths | Where-Object { $_.Contains("Microsoft-Exchange-MailboxDatabaseFailureItems") }
        $SaveLogs.Add("Microsoft-Exchange-MailboxDatabaseFailureItems", $Logs)

        $logs = $allLogPaths | Where-Object { $_.Contains("Microsoft-Windows-FailoverClustering") }
        $SaveLogs.Add("Microsoft-Windows-FailoverClustering", $Logs)
    }

    foreach ($directory in $SaveLogs.Keys) {
        Write-ScriptDebug("Working on directory: {0}" -f $directory)

        $logs = $SaveLogs[$directory]
        $saveLocation = "$baseSaveLocation\$directory"

        Copy-BulkItems -CopyToLocation $saveLocation -ItemsToCopyLocation $logs
        Get-ChildItem $saveLocation | Rename-Item -NewName { $_.Name -replace "%4", "-" }

        if ($directory -eq "Windows-Logs" -and
            $PassedInfo.AppSysLogsToXml) {
            try {
                Write-ScriptDebug("starting to collect event logs and saving out to xml files.")
                Save-DataInfoToFile -DataIn (Get-EventLog Application -After ([DateTime]::Now - $PassedInfo.TimeSpan)) -SaveToLocation ("{0}\Application" -f $saveLocation) -SaveTextFile $false
                Save-DataInfoToFile -DataIn (Get-EventLog System -After ([DateTime]::Now - $PassedInfo.TimeSpan)) -SaveToLocation ("{0}\System" -f $saveLocation) -SaveTextFile $false
                Write-ScriptDebug("end of collecting event logs and saving out to xml files.")
            } catch {
                Write-ScriptDebug("Error occurred while trying to export out the Application and System logs to xml")
                Invoke-CatchBlockActions
            }
        }

        Invoke-ZipFolder -Folder $saveLocation
    }
}

#Calls the $Script:Logger object to write the data to file only.
Function Write-DebugLog($message) {
    if ($null -ne $message -and
        ![string]::IsNullOrEmpty($message) -and
        $null -ne $Script:Logger) {
        $Script:Logger.WriteToFileOnly($message)
    }
}

Function Write-ScriptDebug {
    param(
        [Parameter(Mandatory = $true)]$WriteString
    )
    Write-DebugLog $WriteString

    if ($PassedInfo.ScriptDebug -or $Script:ScriptDebug) {
        Write-Host("[{0} - Script Debug] : {1}" -f $env:COMPUTERNAME, $WriteString) -ForegroundColor Cyan
    }
}

Function Write-ScriptHost {
    param(
        [Parameter(Mandatory = $true)][string]$WriteString,
        [Parameter(Mandatory = $false)][bool]$ShowServer = $true,
        [Parameter(Mandatory = $false)][string]$ForegroundColor = "Gray",
        [Parameter(Mandatory = $false)][bool]$NoNewLine = $false
    )
    Write-DebugLog $WriteString

    if ($ShowServer) {

        if ($WriteString.StartsWith("[")) {
            Write-Host ($WriteString.Insert(1, "$env:COMPUTERNAME - ")) -ForegroundColor $ForegroundColor -NoNewline:$NoNewLine
        } else {
            Write-Host("[{0}] : {1}" -f $env:COMPUTERNAME, $WriteString) -ForegroundColor $ForegroundColor -NoNewline:$NoNewLine
        }
    } else {
        Write-Host("{0}" -f $WriteString) -ForegroundColor $ForegroundColor -NoNewline:$NoNewLine
    }
}

Function Get-LogmanData {
    param(
        [Parameter(Mandatory = $true)][string]$LogmanName,
        [Parameter(Mandatory = $true)][string]$ServerName
    )
    $objLogman = Get-LogmanObject -LogmanName $LogmanName -ServerName $ServerName

    if ($null -ne $objLogman) {
        switch ($objLogman.Status) {
            "Running" {
                Write-ScriptHost -WriteString ("Looks like logman {0} is running...." -f $LogmanName)
                Write-ScriptHost -WriteString ("Going to stop {0} to prevent corruption...." -f $LogmanName)
                Stop-Logman -LogmanName $LogmanName -ServerName $ServerName
                Copy-LogmanData -ObjLogman $objLogman
                Write-ScriptHost -WriteString ("Starting Logman {0} again for you...." -f $LogmanName)
                Start-Logman -LogmanName $LogmanName -ServerName $ServerName
                Write-ScriptHost -WriteString ("Done starting Logman {0} for you" -f $LogmanName)
                break
            }
            "Stopped" {
                Write-ScriptHost -WriteString ("Doesn't look like Logman {0} is running, so not going to stop it..." -f $LogmanName)
                Copy-LogmanData -ObjLogman $objLogman
                break
            }
            Default {
                Write-ScriptHost -WriteString  ("Don't know what the status of Logman '{0}' is in" -f $LogmanName)
                Write-ScriptHost -WriteString  ("This is the status: {0}" -f $objLogman.Status)
                Write-ScriptHost -WriteString ("Going to try stop it just in case...")
                Stop-Logman -LogmanName $LogmanName -ServerName $ServerName
                Copy-LogmanData -ObjLogman $objLogman
                Write-ScriptHost -WriteString ("Not going to start it back up again....")
                Write-ScriptHost -WriteString ("Please start this logman '{0}' if you need to...." -f $LogmanName) -ForegroundColor "Yellow"
                break
            }
        }
    } else {
        Write-ScriptHost -WriteString ("Can't find {0} on {1} ..... Moving on." -f $LogmanName, $ServerName)
    }
}

Function Get-LogmanExt {
    param(
        [Parameter(Mandatory = $true)]$RawLogmanData
    )
    $strLocation = "Output Location:"
    if (-not($RawLogmanData[15].Contains($strLocation))) {
        $i = 0
        while ((-not($RawLogmanData[$i].Contains($strLocation))) -and ($i -lt ($RawLogmanData.Count - 1))) {
            $i++
        }
    } else {
        $i = 15
    }

    $strLine = $RawLogmanData[$i]
    [int]$index = $strLine.LastIndexOf(".")
    if ($index -ne -1) {
        $strExt = $strLine.SubString($index)
    } else {
        $strExt = $null
    }
    return $strExt
}

Function Get-LogmanObject {
    param(
        [Parameter(Mandatory = $true)][string]$LogmanName,
        [Parameter(Mandatory = $true)][string]$ServerName
    )
    $rawDataResults = logman -s $ServerName $LogmanName

    if ($rawDataResults[$rawDataResults.Count - 1].Contains("Set was not found.")) {
        return $null
    } else {
        $objLogman = New-Object -TypeName psobject
        $objLogman | Add-Member -MemberType NoteProperty -Name LogmanName -Value $LogmanName
        $objLogman | Add-Member -MemberType NoteProperty -Name Status -Value (Get-LogmanStatus -RawLogmanData $rawDataResults)
        $objLogman | Add-Member -MemberType NoteProperty -Name RootPath -Value (Get-LogmanRootPath -RawLogmanData $rawDataResults)
        $objLogman | Add-Member -MemberType NoteProperty -Name StartDate -Value (Get-LogmanStartDate -RawLogmanData $rawDataResults)
        $objLogman | Add-Member -MemberType NoteProperty -Name Ext -Value (Get-LogmanExt -RawLogmanData $rawDataResults)
        $objLogman | Add-Member -MemberType NoteProperty -Name RestartLogman -Value $false
        $objLogman | Add-Member -MemberType NoteProperty -Name ServerName -Value $ServerName
        $objLogman | Add-Member -MemberType NoteProperty -Name RawData -Value $rawDataResults
        $objLogman | Add-Member -MemberType NoteProperty -Name SaveRootLocation -Value $FilePath

        return $objLogman
    }
}

Function Get-LogmanRootPath {
    param(
        [Parameter(Mandatory = $true)]$RawLogmanData
    )
    $rootPath = "Root Path:"
    if (-not($RawLogmanData[3].Contains($rootPath))) {
        $i = 0
        while ((-not($RawLogmanData[$i].Contains($rootPath))) -and ($i -lt ($RawLogmanData.count - 1))) {
            $i++
        }
    } else {
        $i = 3
    }

    $strRootPath = $RawLogmanData[$i]
    $replace = $strRootPath.Replace("Root Path:", "")
    [int]$index = $replace.IndexOf(":") - 1
    $strReturn = $replace.SubString($index)
    return $strReturn
}

Function Get-LogmanStartDate {
    param(
        [Parameter(Mandatory = $true)]$RawLogmanData
    )
    $strStart_Date = "Start Date:"
    if (-not($RawLogmanData[11].Contains($strStart_Date))) {
        $i = 0
        while ((-not($RawLogmanData[$i].Contains($strStart_Date))) -and ($i -lt ($RawLogmanData.count - 1))) {
            $i++
        }
        #Circular Log collection doesn't contain Start Date
        if (-not($RawLogmanData[$i].Contains($strStart_Date))) {
            $strReturn = (Get-Date).AddDays(-1).ToString()
            return $strReturn
        }
    } else {
        $i = 11
    }
    $strLine = $RawLogmanData[$i]

    [int]$index = $strLine.LastIndexOf(" ") + 1
    $strReturn = $strLine.SubString($index)
    return $strReturn
}

Function Get-LogmanStatus {
    param(
        [Parameter(Mandatory = $true)]$RawLogmanData
    )
    $status = "Status:"
    $stop = "Stopped"
    $run = "Running"

    if (-not($RawLogmanData[2].Contains($status))) {
        $i = 0
        while ((-not($RawLogmanData[$i].Contains($status))) -and ($i -lt ($RawLogmanData.count - 1))) {
            $i++
        }
    } else {
        $i = 2
    }
    $strLine = $RawLogmanData[$i]

    if ($strLine.Contains($stop)) {
        $currentStatus = $stop
    } elseif ($strLine.Contains($run)) {
        $currentStatus = $run
    } else {
        $currentStatus = "unknown"
    }
    return $currentStatus
}

Function Start-Logman {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'I like Start Logman')]
    param(
        [Parameter(Mandatory = $true)][string]$LogmanName,
        [Parameter(Mandatory = $true)][string]$ServerName
    )
    Write-ScriptHost -WriteString ("Starting Data Collection {0} on server {1}" -f $LogmanName, $ServerName)
    logman start -s $ServerName $LogmanName
}

Function Stop-Logman {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'I like Stop Logman')]
    param(
        [Parameter(Mandatory = $true)][string]$LogmanName,
        [Parameter(Mandatory = $true)][string]$ServerName
    )
    Write-ScriptHost -WriteString ("Stopping Data Collection {0} on server {1}" -f $LogmanName, $ServerName)
    logman stop -s $ServerName $LogmanName
}

Function Invoke-RemoteMain {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Required to be used in the current format')]
    [CmdletBinding()]
    param()
    Write-ScriptDebug("Function Enter: Remote-Main")

    foreach ($server in $PassedInfo.ServerObjects) {

        if ($server.ServerName -eq $env:COMPUTERNAME) {
            $Script:localServerObject = $server
            break
        }
    }

    if ($null -eq $Script:localServerObject -or
        $Script:localServerObject.ServerName -ne $env:COMPUTERNAME) {
        Write-ScriptHost -WriteString ("Something went wrong trying to find the correct Server Object for this server. Stopping this instance of execution.")
        exit
    }

    $Script:TotalBytesSizeCopied = 0
    $Script:TotalBytesSizeCompressed = 0
    $Script:AdditionalFreeSpaceCushionGB = $PassedInfo.StandardFreeSpaceInGBCheckSize
    $Script:CurrentFreeSpaceGB = Get-FreeSpace -FilePath ("{0}\" -f $Script:RootCopyToDirectory)
    $Script:FreeSpaceMinusCopiedAndCompressedGB = $Script:CurrentFreeSpaceGB
    $Script:localExInstall = Get-ExchangeInstallDirectory
    $Script:localExBin = $Script:localExInstall + "Bin\"

    $cmdsToRun = @()
    #############################################
    #                                           #
    #              Exchange 2013 +              #
    #                                           #
    #############################################
    $copyInfo = "-LogPath '{0}' -CopyToThisLocation '{1}'"

    if ($Script:localServerObject.Version -ge 15) {
        Write-ScriptDebug("Server Version greater than 15")

        if ($PassedInfo.EWSLogs) {

            if ($Script:localServerObject.Mailbox) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\EWS"), ($Script:RootCopyToDirectory + "\EWS_BE_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += ("Copy-LogsBasedOnTime {0}" -f $info)
                } else {
                    $cmdsToRun += ("Copy-FullLogFullPathRecurse {0}" -f $info)
                }
            }

            if ($Script:localServerObject.CAS) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\HttpProxy\Ews"), ($Script:RootCopyToDirectory + "\EWS_Proxy_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += ("Copy-LogsBasedOnTime {0}" -f $info)
                } else {
                    $cmdsToRun += ("Copy-FullLogFullPathRecurse {0}" -f $info)
                }
            }
        }

        if ($PassedInfo.RPCLogs) {

            if ($Script:localServerObject.Mailbox) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\RPC Client Access"), ($Script:RootCopyToDirectory + "\RCA_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }
            }

            if ($Script:localServerObject.CAS) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\HttpProxy\RpcHttp"), ($Script:RootCopyToDirectory + "\RCA_Proxy_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }
            }

            if (-not($Script:localServerObject.Edge)) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\RpcHttp"), ($Script:RootCopyToDirectory + "\RPC_Http_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }
            }
        }

        if ($Script:localServerObject.CAS -and $PassedInfo.EASLogs) {
            $info = ($copyInfo -f ($Script:localExinstall + "Logging\HttpProxy\Eas"), ($Script:RootCopyToDirectory + "\EAS_Proxy_Logs"))

            if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            } else {
                $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
            }
        }

        if ($PassedInfo.AutoDLogs) {

            if ($Script:localServerObject.Mailbox) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\Autodiscover"), ($Script:RootCopyToDirectory + "\AutoD_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }
            }

            if ($Script:localServerObject.CAS) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\HttpProxy\Autodiscover"), ($Script:RootCopyToDirectory + "\AutoD_Proxy_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }
            }
        }

        if ($PassedInfo.OWALogs) {

            if ($Script:localServerObject.Mailbox) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\OWA"), ($Script:RootCopyToDirectory + "\OWA_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }
            }

            if ($Script:localServerObject.CAS) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\HttpProxy\OwaCalendar"), ($Script:RootCopyToDirectory + "\OWA_Proxy_Calendar_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }

                $info = ($copyInfo -f ($Script:localExinstall + "Logging\HttpProxy\Owa"), ($Script:RootCopyToDirectory + "\OWA_Proxy_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }
            }
        }

        if ($PassedInfo.ADDriverLogs) {
            $info = ($copyInfo -f ($Script:localExinstall + "Logging\ADDriver"), ($Script:RootCopyToDirectory + "\AD_Driver_Logs"))

            if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            } else {
                $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
            }
        }

        if ($PassedInfo.MapiLogs) {

            if ($Script:localServerObject.Mailbox -and $Script:localServerObject.Version -eq 15) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\MAPI Client Access"), ($Script:RootCopyToDirectory + "\MAPI_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }
            } elseif ($Script:localServerObject.Mailbox) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\MapiHttp\Mailbox"), ($Script:RootCopyToDirectory + "\MAPI_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }
            }

            if ($Script:localServerObject.CAS) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\HttpProxy\Mapi"), ($Script:RootCopyToDirectory + "\MAPI_Proxy_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }
            }
        }

        if ($PassedInfo.ECPLogs) {

            if ($Script:localServerObject.Mailbox) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\ECP"), ($Script:RootCopyToDirectory + "\ECP_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }
            }

            if ($Script:localServerObject.CAS) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\HttpProxy\Ecp"), ($Script:RootCopyToDirectory + "\ECP_Proxy_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }
            }
        }

        if ($Script:localServerObject.Mailbox -and $PassedInfo.SearchLogs) {
            $info = ($copyInfo -f ($Script:localExBin + "Search\Ceres\Diagnostics\Logs"), ($Script:RootCopyToDirectory + "\Search_Diag_Logs"))
            $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            $info = ($copyInfo -f ($Script:localExBin + "Search\Ceres\Diagnostics\ETLTraces"), ($Script:RootCopyToDirectory + "\Search_Diag_ETLs"))
            $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            $info = ($copyInfo -f ($Script:localExInstall + "Logging\Search"), ($Script:RootCopyToDirectory + "\Search"))
            $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
            $info = ($copyInfo -f ($Script:localExInstall + "Logging\Monitoring\Search"), ($Script:RootCopyToDirectory + "\Search_Monitoring"))
            $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info

            if ($Script:localServerObject.Version -ge 19) {
                $info = ($copyInfo -f ($Script:localExInstall + "Logging\BigFunnelMetricsCollectionAssistant"), ($Script:RootCopyToDirectory + "\BigFunnelMetricsCollectionAssistant"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                $info = ($copyInfo -f ($Script:localExInstall + "Logging\BigFunnelQueryParityAssistant"), ($Script:RootCopyToDirectory + "\BigFunnelQueryParityAssistant")) #This might not provide anything
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                $info = ($copyInfo -f ($Script:localExInstall + "Logging\BigFunnelRetryFeederTimeBasedAssistant"), ($Script:RootCopyToDirectory + "\BigFunnelRetryFeederTimeBasedAssistant"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            }
        }

        if ($PassedInfo.DailyPerformanceLogs) {
            #Daily Performance Logs are always by days worth
            $copyFrom = "$Script:localExinstall`Logging\Diagnostics\DailyPerformanceLogs"

            try {
                $logmanOutput = logman ExchangeDiagnosticsDailyPerformanceLog
                $logmanRootPath = $logmanOutput | Select-String "Root Path:"

                if (!$logmanRootPath.ToString().Contains($copyFrom)) {
                    $copyFrom = $logmanRootPath.ToString().Replace("Root Path:", "").Trim()
                    Write-ScriptDebug "Changing the location to get the daily performance logs to '$copyFrom'"
                }
            } catch {
                Write-ScriptDebug "Couldn't get logman info to verify Daily Performance Logs location"
                Invoke-CatchBlockActions
            }

            $info = ($copyInfo -f $copyFrom, ($Script:RootCopyToDirectory + "\Daily_Performance_Logs"))
            $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
        }

        if ($PassedInfo.ManagedAvailabilityLogs) {
            $info = ($copyInfo -f ($Script:localExinstall + "\Logging\Monitoring"), ($Script:RootCopyToDirectory + "\ManagedAvailabilityMonitoringLogs"))
            $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
        }

        if ($PassedInfo.OABLogs) {
            $info = ($copyInfo -f ($Script:localExinstall + "\Logging\HttpProxy\OAB"), ($Script:RootCopyToDirectory + "\OAB_Proxy_Logs"))

            if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            } else {
                $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
            }

            $info = ($copyInfo -f ($Script:localExinstall + "\Logging\OABGeneratorLog"), ($Script:RootCopyToDirectory + "\OAB_Generation_Logs"))

            if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            } else {
                $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
            }

            $info = ($copyInfo -f ($Script:localExinstall + "\Logging\OABGeneratorSimpleLog"), ($Script:RootCopyToDirectory + "\OAB_Generation_Simple_Logs"))

            if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            } else {
                $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
            }

            $info = ($copyInfo -f ($Script:localExinstall + "\Logging\MAPI AddressBook Service"), ($Script:RootCopyToDirectory + "\MAPI_AddressBook_Service_Logs"))

            if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            } else {
                $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
            }
        }

        if ($PassedInfo.PowerShellLogs) {
            $info = ($copyInfo -f ($Script:localExinstall + "\Logging\HttpProxy\PowerShell"), ($Script:RootCopyToDirectory + "\PowerShell_Proxy_Logs"))

            if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            } else {
                $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
            }
        }

        if ($Script:localServerObject.DAGMember -and
            $PassedInfo.DAGInformation) {
            $cmdsToRun += "Save-FailoverClusterInformation"
        }

        if ($PassedInfo.MitigationService) {
            $info = ($copyInfo -f ($Script:localExinstall + "\Logging\MitigationService"), ($Script:RootCopyToDirectory + "\Mitigation_Service_Logs"))

            if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            } else {
                $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
            }
        }
    }

    ############################################
    #                                          #
    #              Exchange 2010               #
    #                                          #
    ############################################
    if ($Script:localServerObject.Version -eq 14) {

        if ($Script:localServerObject.CAS) {

            if ($PassedInfo.RPCLogs) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\RPC Client Access"), ($Script:RootCopyToDirectory + "\RCA_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }
            }

            if ($PassedInfo.EWSLogs) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\EWS"), ($Script:RootCopyToDirectory + "\EWS_BE_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += ("Copy-LogsBasedOnTime {0}" -f $info)
                } else {
                    $cmdsToRun += ("Copy-FullLogFullPathRecurse {0}" -f $info)
                }
            }
        }
    }

    ############################################
    #                                          #
    #          All Exchange Versions           #
    #                                          #
    ############################################
    if ($PassedInfo.AnyTransportSwitchesEnabled -and
        $Script:localServerObject.TransportInfoCollect) {

        if ($PassedInfo.MessageTrackingLogs -and
            (-not ($Script:localServerObject.Version -eq 15 -and
                $Script:localServerObject.CASOnly))) {
            $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.HubLoggingInfo.MessageTrackingLogPath), ($Script:RootCopyToDirectory + "\Message_Tracking_Logs"))
            $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
        }

        if ($PassedInfo.HubProtocolLogs -and
            (-not ($Script:localServerObject.Version -eq 15 -and
                $Script:localServerObject.CASOnly))) {
            $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.HubLoggingInfo.ReceiveProtocolLogPath), ($Script:RootCopyToDirectory + "\Hub_Receive_Protocol_Logs"))
            $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.HubLoggingInfo.SendProtocolLogPath), ($Script:RootCopyToDirectory + "\Hub_Send_Protocol_Logs"))
            $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
        }

        if ($PassedInfo.HubConnectivityLogs -and
            (-not ($Script:localServerObject.Version -eq 15 -and
                $Script:localServerObject.CASOnly))) {
            $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.HubLoggingInfo.ConnectivityLogPath), ($Script:RootCopyToDirectory + "\Hub_Connectivity_Logs"))
            $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
        }

        if ($PassedInfo.QueueInformation -and
            (-not ($Script:localServerObject.Version -eq 15 -and
                $Script:localServerObject.CASOnly))) {

            if ($Script:localServerObject.Version -ge 15 -and
                $null -ne $Script:localServerObject.TransportInfo.HubLoggingInfo.QueueLogPath) {
                $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.HubLoggingInfo.QueueLogPath), ($Script:RootCopyToDirectory + "\Queue_V15_Data"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            }
        }

        if ($PassedInfo.TransportConfig) {

            if ($Script:localServerObject.Version -ge 15 -and (-not($Script:localServerObject.Edge))) {
                $items = @()
                $items += $Script:localExBin + "\EdgeTransport.exe.config"
                $items += $Script:localExBin + "\MSExchangeFrontEndTransport.exe.config"
                $items += $Script:localExBin + "\MSExchangeDelivery.exe.config"
                $items += $Script:localExBin + "\MSExchangeSubmission.exe.config"
            } else {
                $items = @()
                $items += $Script:localExBin + "\EdgeTransport.exe.config"
            }

            Copy-BulkItems -CopyToLocation ($Script:RootCopyToDirectory + "\Transport_Configuration") -ItemsToCopyLocation $items
        }

        #Exchange 2013+ only
        if ($Script:localServerObject.Version -ge 15 -and
            (-not($Script:localServerObject.Edge))) {

            if ($PassedInfo.FrontEndConnectivityLogs -and
                (-not ($Script:localServerObject.Version -eq 15 -and
                    $Script:localServerObject.MailboxOnly))) {
                Write-ScriptDebug("Collecting FrontEndConnectivityLogs")
                $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.FELoggingInfo.ConnectivityLogPath), ($Script:RootCopyToDirectory + "\FE_Connectivity_Logs"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            }

            if ($PassedInfo.FrontEndProtocolLogs -and
                (-not ($Script:localServerObject.Version -eq 15 -and
                    $Script:localServerObject.MailboxOnly))) {
                Write-ScriptDebug("Collecting FrontEndProtocolLogs")
                $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.FELoggingInfo.ReceiveProtocolLogPath), ($Script:RootCopyToDirectory + "\FE_Receive_Protocol_Logs"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.FELoggingInfo.SendProtocolLogPath), ($Script:RootCopyToDirectory + "\FE_Send_Protocol_Logs"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            }

            if ($PassedInfo.MailboxConnectivityLogs -and
                (-not ($Script:localServerObject.Version -eq 15 -and
                    $Script:localServerObject.CASOnly))) {
                Write-ScriptDebug("Collecting MailboxConnectivityLogs")
                $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.MBXLoggingInfo.ConnectivityLogPath + "\Delivery"), ($Script:RootCopyToDirectory + "\MBX_Delivery_Connectivity_Logs"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.MBXLoggingInfo.ConnectivityLogPath + "\Submission"), ($Script:RootCopyToDirectory + "\MBX_Submission_Connectivity_Logs"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            }

            if ($PassedInfo.MailboxProtocolLogs -and
                (-not ($Script:localServerObject.Version -eq 15 -and
                    $Script:localServerObject.CASOnly))) {
                Write-ScriptDebug("Collecting MailboxProtocolLogs")
                $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.MBXLoggingInfo.ReceiveProtocolLogPath), ($Script:RootCopyToDirectory + "\MBX_Receive_Protocol_Logs"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.MBXLoggingInfo.SendProtocolLogPath), ($Script:RootCopyToDirectory + "\MBX_Send_Protocol_Logs"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            }

            if ($PassedInfo.MailboxDeliveryThrottlingLogs -and
                (!($Script:localServerObject.Version -eq 15 -and
                    $Script:localServerObject.CASOnly))) {
                Write-ScriptDebug("Collecting Mailbox Delivery Throttling Logs")
                $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.MBXLoggingInfo.MailboxDeliveryThrottlingLogPath), ($Script:RootCopyToDirectory + "\MBX_Delivery_Throttling_Logs"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            }
        }
    }

    if ($PassedInfo.ImapLogs) {
        Write-ScriptDebug("Collecting IMAP Logs")
        $info = ($copyInfo -f ($Script:localServerObject.ImapLogsLocation), ($Script:RootCopyToDirectory + "\Imap_Logs"))
        $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
    }

    if ($PassedInfo.PopLogs) {
        Write-ScriptDebug("Collecting POP Logs")
        $info = ($copyInfo -f ($Script:localServerObject.PopLogsLocation), ($Script:RootCopyToDirectory + "\Pop_Logs"))
        $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
    }

    if ($PassedInfo.IISLogs) {

        Get-IISLogDirectory |
            ForEach-Object {
                $copyTo = "{0}\IIS_{1}_Logs" -f $Script:RootCopyToDirectory, ($_.Substring($_.LastIndexOf("\") + 1))
                $info = ($copyInfo -f $_, $copyTo)
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            }

        $info = ($copyInfo -f ($env:SystemRoot + "\System32\LogFiles\HTTPERR"), ($Script:RootCopyToDirectory + "\HTTPERR_Logs"))
        $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
    }

    if ($PassedInfo.ServerInformation) {
        $cmdsToRun += "Save-ServerInfoData"
    }

    if ($PassedInfo.Experfwiz) {
        $cmdsToRun += "Save-LogmanExperfwizData"
    }

    if ($PassedInfo.Exmon) {
        $cmdsToRun += "Save-LogmanExmonData"
    }

    $cmdsToRun += "Save-WindowsEventLogs"

    #Execute the cmds
    foreach ($cmd in $cmdsToRun) {
        Write-ScriptDebug("cmd: {0}" -f $cmd)

        try {
            Invoke-Expression $cmd -ErrorAction Stop
        } catch {
            Write-ScriptDebug("Failed to finish running command: $cmd")
            Invoke-CatchBlockActions
        }
    }

    if ($Error.Count -ne 0) {
        Save-DataInfoToFile -DataIn $Error -SaveToLocation ("$Script:RootCopyToDirectory\AllErrors")
        Save-DataInfoToFile -DataIn $Script:ErrorsHandled -SaveToLocation ("$Script:RootCopyToDirectory\HandledErrors")
    } else {
        Write-ScriptDebug ("No errors occurred within the script")
    }
}


    try {
        $Script:VerboseFunctionCaller = ${Function:Write-ScriptDebug}
        $Script:HostFunctionCaller = ${Function:Write-ScriptHost}

        if ($PassedInfo.ByPass -ne $true) {
            $Script:RootCopyToDirectory = "{0}{1}" -f $PassedInfo.RootFilePath, $env:COMPUTERNAME
            $Script:Logger = New-LoggerObject -LogDirectory $Script:RootCopyToDirectory -LogName ("ExchangeLogCollector-Instance-Debug") `
                -HostFunctionCaller $Script:HostFunctionCaller `
                -VerboseFunctionCaller $Script:VerboseFunctionCaller
            Write-ScriptDebug("Root Copy To Directory: $Script:RootCopyToDirectory")
            Invoke-RemoteMain
        } else {
            Write-ScriptDebug("Loading common functions")
        }
    } catch {
        Write-ScriptHost -WriteString ("An error occurred in Invoke-RemoteFunctions") -ForegroundColor "Red"
        Invoke-CatchBlockActions
        #This is a bad place to catch the error that just occurred
        #Being that there is a try catch block around each command that we run now, we should never hit an issue here unless it is is prior to that.
        Write-ScriptDebug "Critical Failure occurred."
    } finally {
        Write-ScriptDebug("Exiting: Invoke-RemoteFunctions")
        Write-ScriptDebug("[double]TotalBytesSizeCopied: {0} | [double]TotalBytesSizeCompressed: {1} | [double]AdditionalFreeSpaceCushionGB: {2} | [double]CurrentFreeSpaceGB: {3} | [double]FreeSpaceMinusCopiedAndCompressedGB: {4}" -f $Script:TotalBytesSizeCopied,
            $Script:TotalBytesSizeCompressed,
            $Script:AdditionalFreeSpaceCushionGB,
            $Script:CurrentFreeSpaceGB,
            $Script:FreeSpaceMinusCopiedAndCompressedGB)
    }
}

Function Main {

    Start-Sleep 1
    Test-PossibleCommonScenarios
    Test-NoSwitchesProvided

    $display = @"

        Exchange Log Collector v{0}

        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
        BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
        NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
        DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
        OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

        -This script will copy over data based off the switches provided.
        -We will check for at least {1} GB of free space at the local target directory BEFORE
            attempting to do the remote execution. It will continue to check to make sure that we have
            at least {2} GB of free space throughout the data collection. If some data is determined
            that if we were to copy it over it would place us over that threshold, we will not copy that
            data set over. The script will continue to run while still constantly check the free space
            available before doing a copy action.
        -Please run this script at your own risk.

"@ -f $BuildVersion, ($Script:StandardFreeSpaceInGBCheckSize = 10), $Script:StandardFreeSpaceInGBCheckSize

    Clear-Host
    Write-ScriptHost -WriteString $display -ShowServer $false

    if (-not($AcceptEULA)) {
        Enter-YesNoLoopAction -Question "Do you wish to continue? " -YesAction {} -NoAction { exit }
    }

    if (-not (Confirm-Administrator)) {
        Write-ScriptHost -WriteString ("Hey! The script needs to be executed in elevated mode. Start the Exchange Management Shell as an Administrator.") -ForegroundColor "Yellow"
        exit
    }

    $Script:LocalExchangeShell = Confirm-ExchangeShell -Identity $env:COMPUTERNAME

    if (!($Script:LocalExchangeShell.ShellLoaded)) {
        Write-ScriptHost -WriteString ("It appears that you are not on an Exchange 2010 or newer server. Sorry I am going to quit.") -ShowServer $false
        exit
    }

    if (!$Script:LocalExchangeShell.RemoteShell) {
        $Script:localExInstall = Get-ExchangeInstallDirectory
    }

    if ($Script:LocalExchangeShell.EdgeServer) {
        #If we are on an Exchange Edge Server, we are going to treat it like a single server on purpose as we recommend that the Edge Server is a non domain joined computer.
        #Because it isn't a domain joined computer, we can't use remote execution
        Write-ScriptHost -WriteString ("Determined that we are on an Edge Server, we can only use locally collection for this role.") -ForegroundColor "Yellow"
        $Script:EdgeRoleDetected = $true
        $Servers = @($env:COMPUTERNAME)
    }

    if ($null -ne $Servers -and
        !($Servers.Count -eq 1 -and
            $Servers[0].ToUpper().Equals($env:COMPUTERNAME.ToUpper()))) {
        [array]$Script:ValidServers = Test-RemoteExecutionOfServers -ServerList $Servers
    } else {
        [array]$Script:ValidServers = $Servers
    }

    #possible to return null or only a single server back (localhost)
    if (!($null -ne $Script:ValidServers -and
            $Script:ValidServers.Count -eq 1 -and
            $Script:ValidServers[0].ToUpper().Equals($env:COMPUTERNAME.ToUpper()))) {

        $Script:ArgumentList = Get-ArgumentList -Servers $Script:ValidServers
        #I can do a try catch here, but i also need to do a try catch in the remote so i don't end up failing here and assume the wrong failure location
        try {
            Invoke-Command -ComputerName $Script:ValidServers -ScriptBlock ${Function:Invoke-RemoteFunctions} -ArgumentList $argumentList -ErrorAction Stop
        } catch {
            Write-Error "An error has occurred attempting to call Invoke-Command to do a remote collect all at once. Please notify ExToolsFeedback@microsoft.com of this issue. Stopping the script."
            Invoke-CatchBlockActions
            exit
        }

        Write-DataOnlyOnceOnMasterServer
        Write-LargeDataObjectsOnMachine
        Invoke-ServerRootZipAndCopy
    } else {

        if ($null -eq (Test-DiskSpace -Servers $env:COMPUTERNAME -Path $FilePath -CheckSize $Script:StandardFreeSpaceInGBCheckSize)) {
            Write-ScriptHost -ShowServer $false -WriteString ("Failed to have enough space available locally. We can't continue with the data collection") -ForegroundColor "Yellow"
            exit
        }
        if (-not($Script:EdgeRoleDetected)) {
            Write-ScriptHost -ShowServer $false -WriteString ("Note: Remote Collection is now possible for Windows Server 2012 and greater on the remote machine. Just use the -Servers paramater with a list of Exchange Server names") -ForegroundColor "Yellow"
            Write-ScriptHost -ShowServer $false -WriteString ("Going to collect the data locally")
        }
        $Script:ArgumentList = (Get-ArgumentList -Servers $env:COMPUTERNAME)
        Invoke-RemoteFunctions -PassedInfo $Script:ArgumentList
        Write-DataOnlyOnceOnMasterServer
        Write-LargeDataObjectsOnMachine
        Invoke-ServerRootZipAndCopy -RemoteExecute $false
    }

    Write-ScriptHost -WriteString "`r`n`r`n`r`nLooks like the script is done. If you ran into any issues or have additional feedback, please feel free to reach out ExToolsFeedback@microsoft.com." -ShowServer $false
}
#Need to do this here otherwise can't find the script path
$configPath = "{0}\{1}.json" -f (Split-Path -Parent $MyInvocation.MyCommand.Path), (Split-Path -Leaf $MyInvocation.MyCommand.Path)

try {
    $Error.Clear()
    <#
    Added the ability to call functions from within a bundled function so i don't have to duplicate work.
    Loading the functions into memory by using the '.' allows me to do this,
    providing that the calling of that function doesn't do anything of value when doing this.
    #>
    . Invoke-RemoteFunctions -PassedInfo ([PSCustomObject]@{
            ByPass = $true
        })

    if ((Test-Path $configPath) -and
        !$DisableConfigImport) {
        try {
            Import-ScriptConfigFile -ScriptConfigFileLocation $configPath
        } catch {
            Write-ScriptHost "Failed to load the config file at $configPath. `r`nPlease update the config file to be able to run 'ConvertFrom-Json' against it" -ForegroundColor "Red"
            Invoke-CatchBlockActions
            Enter-YesNoLoopAction -Question "Do you wish to continue?" -YesAction {} -NoAction { exit }
        }
    }
    $Script:RootFilePath = "{0}\{1}\" -f $FilePath, (Get-Date -Format yyyyMd)
    $Script:Logger = New-LoggerObject -LogDirectory ("{0}{1}" -f $RootFilePath, $env:COMPUTERNAME) -LogName "ExchangeLogCollector-Main-Debug" `
        -HostFunctionCaller $Script:HostFunctionCaller `
        -VerboseFunctionCaller $Script:VerboseFunctionCaller

    Main
} finally {

    if ($Script:VerboseEnabled -or
        ($Error.Count -ne $Script:ErrorsFromStartOfCopy)) {
        $Script:Logger.RemoveLatestLogFile()
    }
}

# SIG # Begin signature block
# MIIjqgYJKoZIhvcNAQcCoIIjmzCCI5cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBRodJ0R/LM3Xms
# cRAoPtAj5bYyv+4CMKCKSpjyLBDJ/6CCDYEwggX/MIID56ADAgECAhMzAAACUosz
# qviV8znbAAAAAAJSMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjEwOTAyMTgzMjU5WhcNMjIwOTAxMTgzMjU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDQ5M+Ps/X7BNuv5B/0I6uoDwj0NJOo1KrVQqO7ggRXccklyTrWL4xMShjIou2I
# sbYnF67wXzVAq5Om4oe+LfzSDOzjcb6ms00gBo0OQaqwQ1BijyJ7NvDf80I1fW9O
# L76Kt0Wpc2zrGhzcHdb7upPrvxvSNNUvxK3sgw7YTt31410vpEp8yfBEl/hd8ZzA
# v47DCgJ5j1zm295s1RVZHNp6MoiQFVOECm4AwK2l28i+YER1JO4IplTH44uvzX9o
# RnJHaMvWzZEpozPy4jNO2DDqbcNs4zh7AWMhE1PWFVA+CHI/En5nASvCvLmuR/t8
# q4bc8XR8QIZJQSp+2U6m2ldNAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUNZJaEUGL2Guwt7ZOAu4efEYXedEw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDY3NTk3MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAFkk3
# uSxkTEBh1NtAl7BivIEsAWdgX1qZ+EdZMYbQKasY6IhSLXRMxF1B3OKdR9K/kccp
# kvNcGl8D7YyYS4mhCUMBR+VLrg3f8PUj38A9V5aiY2/Jok7WZFOAmjPRNNGnyeg7
# l0lTiThFqE+2aOs6+heegqAdelGgNJKRHLWRuhGKuLIw5lkgx9Ky+QvZrn/Ddi8u
# TIgWKp+MGG8xY6PBvvjgt9jQShlnPrZ3UY8Bvwy6rynhXBaV0V0TTL0gEx7eh/K1
# o8Miaru6s/7FyqOLeUS4vTHh9TgBL5DtxCYurXbSBVtL1Fj44+Od/6cmC9mmvrti
# yG709Y3Rd3YdJj2f3GJq7Y7KdWq0QYhatKhBeg4fxjhg0yut2g6aM1mxjNPrE48z
# 6HWCNGu9gMK5ZudldRw4a45Z06Aoktof0CqOyTErvq0YjoE4Xpa0+87T/PVUXNqf
# 7Y+qSU7+9LtLQuMYR4w3cSPjuNusvLf9gBnch5RqM7kaDtYWDgLyB42EfsxeMqwK
# WwA+TVi0HrWRqfSx2olbE56hJcEkMjOSKz3sRuupFCX3UroyYf52L+2iVTrda8XW
# esPG62Mnn3T8AuLfzeJFuAbfOSERx7IFZO92UPoXE1uEjL5skl1yTZB3MubgOA4F
# 8KoRNhviFAEST+nG8c8uIsbZeb08SeYQMqjVEmkwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVfzCCFXsCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAlKLM6r4lfM52wAAAAACUjAN
# BglghkgBZQMEAgEFAKCBxjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgzW+UVvfC
# PKzAcXQlJ1/bGUv9rzZ61dXAiNOYZozjRHYwWgYKKwYBBAGCNwIBDDFMMEqgGoAY
# AEMAUwBTACAARQB4AGMAaABhAG4AZwBloSyAKmh0dHBzOi8vZ2l0aHViLmNvbS9t
# aWNyb3NvZnQvQ1NTLUV4Y2hhbmdlIDANBgkqhkiG9w0BAQEFAASCAQCh6fiz6PK/
# iuzgccVmneSiXJm9hLymd+Ef7aOlQLmyZMS9dOI3ZXxefFZUTzQD7bdVODl7RxaR
# djtuBrhfcvF1WQPMZlXcAaiZoFsXcic+9SsTOkgdSzUMiz6iLgQIwz+66zuf1qh4
# 7NPZrzPnkxIHE3zgKN5/HjgOj09SmF+P7YVe5Pcvon8i2FVxBOFjzQQZvLz+Q1sK
# limDqaR04WeyawimvgxQwYWbrwg2YOpmoskI9jTJFmAtIkDrE4JgGMOhGvuyOCty
# pGjRqwRS1/Xjy7RHb37ZzOX/3vu9O+Lm5KV/Lbv2Ad5Q9BABSM9+kEqnRaIDL8WM
# k2X9m6Uc7BgqoYIS8TCCEu0GCisGAQQBgjcDAwExghLdMIIS2QYJKoZIhvcNAQcC
# oIISyjCCEsYCAQMxDzANBglghkgBZQMEAgEFADCCAVUGCyqGSIb3DQEJEAEEoIIB
# RASCAUAwggE8AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIAZo27qD
# qChp8nH6qGLvU3bDqNrOo9XFUhaaZJ5KFFfdAgZh/DWibcoYEzIwMjIwMjA1MTY0
# NjU4LjY2NVowBIACAfSggdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0
# byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjowQTU2LUUzMjktNEQ0RDEl
# MCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCDkQwggT1MIID
# 3aADAgECAhMzAAABW3ywujRnN8GnAAAAAAFbMA0GCSqGSIb3DQEBCwUAMHwxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIxMDExNDE5MDIxNloXDTIyMDQx
# MTE5MDIxNlowgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# KTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYD
# VQQLEx1UaGFsZXMgVFNTIEVTTjowQTU2LUUzMjktNEQ0RDElMCMGA1UEAxMcTWlj
# cm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCASIwDQYJKoZIhvcNAQEBBQADggEP
# ADCCAQoCggEBAMgkf6Xs9dqhesumLltnl6lwjiD1jh+Ipz/6j5q5CQzSnbaVuo4K
# iCiSpr5WtqqVlD7nT/3WX6V6vcpNQV5cdtVVwafNpLn3yF+fRNoUWh1Q9u8XGiSX
# 8YzVS8q68JPFiRO4HMzMpLCaSjcfQZId6CiukyLQruKnSFwdGhMxE7GCayaQ8ZDy
# EPHs/C2x4AAYMFsVOssSdR8jb8fzAek3SNlZtVKd0Kb8io+3XkQ54MvUXV9cVL1/
# eDdXVVBBqOhHzoJsy+c2y/s3W+gEX8Qb9O/bjBkR6hIaOwEAw7Nu40/TMVfwXJ7g
# 5R/HNXCt7c4IajNN4W+CugeysLnYbqRmW+kCAwEAAaOCARswggEXMB0GA1UdDgQW
# BBRl5y01iG23UyBdTH/15TnJmLqrLjAfBgNVHSMEGDAWgBTVYzpcijGQ80N7fEYb
# xTNoWoVtVTBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5j
# b20vcGtpL2NybC9wcm9kdWN0cy9NaWNUaW1TdGFQQ0FfMjAxMC0wNy0wMS5jcmww
# WgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpL2NlcnRzL01pY1RpbVN0YVBDQV8yMDEwLTA3LTAxLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IB
# AQCnM2s7phMamc4QdVolrO1ZXRiDMUVdgu9/yq8g7kIVl+fklUV2Vlout6+fpOqA
# GnewMtwenFtagVhVJ8Hau8Nwk+IAhB0B04DobNDw7v4KETARf8KN8gTH6B7RjHhr
# eMDWg7icV0Dsoj8MIA8AirWlwf4nr8pKH0n2rETseBJDWc3dbU0ITJEH1RzFhGkW
# 7IzNPQCO165Tp7NLnXp4maZzoVx8PyiONO6fyDZr0yqVuh9OqWH+fPZYQ/YYFyhx
# y+hHWOuqYpc83Phn1vA0Ae1+Wn4bne6ZGjPxRI6sxsMIkdBXD0HJLyN7YfSrbOVA
# YwjYWOHresGZuvoEaEgDRWUrMIIGcTCCBFmgAwIBAgIKYQmBKgAAAAAAAjANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTAwHhcNMTAwNzAxMjEzNjU1WhcNMjUwNzAxMjE0NjU1WjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
# ggEBAKkdDbx3EYo6IOz8E5f1+n9plGt0VBDVpQoAgoX77XxoSyxfxcPlYcJ2tz5m
# K1vwFVMnBDEfQRsalR3OCROOfGEwWbEwRA/xYIiEVEMM1024OAizQt2TrNZzMFcm
# gqNFDdDq9UeBzb8kYDJYYEbyWEeGMoQedGFnkV+BVLHPk0ySwcSmXdFhE24oxhr5
# hoC732H8RsEnHSRnEnIaIYqvS2SJUGKxXf13Hz3wV3WsvYpCTUBR0Q+cBj5nf/Vm
# wAOWRH7v0Ev9buWayrGo8noqCjHw2k4GkbaICDXoeByw6ZnNPOcvRLqn9NxkvaQB
# wSAJk3jN/LzAyURdXhacAQVPIk0CAwEAAaOCAeYwggHiMBAGCSsGAQQBgjcVAQQD
# AgEAMB0GA1UdDgQWBBTVYzpcijGQ80N7fEYbxTNoWoVtVTAZBgkrBgEEAYI3FAIE
# DB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNV
# HSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVo
# dHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29D
# ZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAC
# hj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1
# dF8yMDEwLTA2LTIzLmNydDCBoAYDVR0gAQH/BIGVMIGSMIGPBgkrBgEEAYI3LgMw
# gYEwPQYIKwYBBQUHAgEWMWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9QS0kvZG9j
# cy9DUFMvZGVmYXVsdC5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8A
# UABvAGwAaQBjAHkAXwBTAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQEL
# BQADggIBAAfmiFEN4sbgmD+BcQM9naOhIW+z66bM9TG+zwXiqf76V20ZMLPCxWbJ
# at/15/B4vceoniXj+bzta1RXCCtRgkQS+7lTjMz0YBKKdsxAQEGb3FwX/1z5Xhc1
# mCRWS3TvQhDIr79/xn/yN31aPxzymXlKkVIArzgPF/UveYFl2am1a+THzvbKegBv
# SzBEJCI8z+0DpZaPWSm8tv0E4XCfMkon/VWvL/625Y4zu2JfmttXQOnxzplmkIz/
# amJ/3cVKC5Em4jnsGUpxY517IW3DnKOiPPp/fZZqkHimbdLhnPkd/DjYlPTGpQqW
# hqS9nhquBEKDuLWAmyI4ILUl5WTs9/S/fmNZJQ96LjlXdqJxqgaKD4kWumGnEcua
# 2A5HmoDF0M2n0O99g/DhO3EJ3110mCIIYdqwUB5vvfHhAN/nMQekkzr3ZUd46Pio
# SKv33nJ+YWtvd6mBy6cJrDm77MbL2IK0cs0d9LiFAR6A+xuJKlQ5slvayA1VmXqH
# czsI5pgt6o3gMy4SKfXAL1QnIffIrE7aKLixqduWsqdCosnPGUFN4Ib5KpqjEWYw
# 07t0MkvfY3v1mYovG8chr1m1rtxEPJdQcdeh0sVV42neV8HR3jDA/czmTfsNv11P
# 6Z0eGTgvvM9YBS7vDaBQNdrvCScc1bN+NR4Iuto229Nfj950iEkSoYIC0jCCAjsC
# AQEwgfyhgdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYw
# JAYDVQQLEx1UaGFsZXMgVFNTIEVTTjowQTU2LUUzMjktNEQ0RDElMCMGA1UEAxMc
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUACrtB
# bqYy0r+YGLtUaFVRW/Yh7qaggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOWorkwwIhgPMjAyMjAyMDUxMjA1MzJa
# GA8yMDIyMDIwNjEyMDUzMlowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5aiuTAIB
# ADAKAgEAAgIjrQIB/zAHAgEAAgIRbTAKAgUA5an/zAIBADA2BgorBgEEAYRZCgQC
# MSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqG
# SIb3DQEBBQUAA4GBAKubBkvhOWHhm0RvMRFqNpfbIY5w2CbQ+0pYTEIMh49iMt+K
# gi59bB6tjPDoMy7ErXCDUGOGulWDc658fu1mjLuZTXTqknbz3hfIvnSw0Ax9D3xh
# UDImdWLCUqCT58ml83nO+DaS6s9RCNOtc5zt/dh/KSdvcxAetV6Nn18i8rzyMYID
# DTCCAwkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAFb
# fLC6NGc3wacAAAAAAVswDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzEN
# BgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgUh68UGpqfLjnBBANS/O+FG/q
# VSys0B5sV3c3JRtWldMwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCDJIuCp
# KGMRh4lCGucGPHCNJ7jq9MTbe3mQ2FtSZLCFGTCBmDCBgKR+MHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABW3ywujRnN8GnAAAAAAFbMCIEINplOy/y
# omFfh8hxBaZyZpLyLxShbzRnWLUTNQYHbZgtMA0GCSqGSIb3DQEBCwUABIIBAMLl
# 7LJrXvwPIWZf0gLbBj7PbqM5gm9zkg2f0fdo4AHfI4fjn4kA1MIPwqRbcoDAnIwU
# DbTkKfoLLD3LE81mqfACoGSCZWirSOPc0zVHZlReXMf6J/h41bxsfe/UiHFtFeQb
# +5ZYyRMkyc8hbkNNhXbk4RIxDrMP7Jp1KhaE54XDTUQICi1DIlER2noBpZf+8PZR
# 4XR/WuCg8qGai1tWQMNfxCV3kvUfDCvkGizohrOG22TKD6q+dH/w/i7Z/nYQpZof
# IBy/IIEkniXytClPeypPKY3jXJmD1Sv63f/4W5Ga2lcSO4Ia18CbCL5qTxM8JeoZ
# W3X/+5GEtZRzgpxOxkg=
# SIG # End signature block
