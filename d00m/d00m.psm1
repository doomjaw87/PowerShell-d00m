<#
.SYNOPSIS
    Creates new BOFH-style excuses

.DESCRIPTION
    Randomly generates BOFH-style excuses from 3 different word lists

.EXAMPLE
    Get-d00mExcuse

    This example outputs a single randomly generated BOFH-style excuse

.EXAMPLE
    Get-d00mExcuse -Count 10

    This example outputs 10 randly generated BOFH-style excuses

.EXAMPLE
    Get-d00mExcuse -Speak

    This example uses the speech synthesizer to speak the output of 
    the randomly generated BOFH-style excuse
#>
function Get-d00mExcuse
{
    [CmdletBinding()]
    param
    (
        #Number of excuses to generate
        [parameter()]
        [int]$Count = 1,

        #Specify if the computer should speak the excuse
        [parameter()]
        [switch]$Speak
    )

    begin
    {
        $cmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
        $timer = New-Object -TypeName System.Diagnostics.Stopwatch
        Write-Verbose -Message ('{0} : Begin execution : {1}' -f $cmdletName, (Get-Date))
        $counter = 1
        $timer.Start()
    }

    process
    {
        $list1 = @("Temporary", "Intermittant", "Partial",
            "Redundant", "Total", "Multiplexed",
            "Inherent", "Duplicated", "Dual-Homed",
            "Synchronous", "Bidirectional", "Serial",
            "Asynchronous", "Multiple", "Replicated",
            "Non-Replicated", "Unregistered", "Non-Specific",
            "Generic", "Migrated", "Localized",
            "Resignalled", "Dereferenced", "Nullified",
            "Aborted", "Serious", "Minor",
            "Major", "Extraneous", "Illegal",
            "Insufficient", "Viral", "Unsupported",
            "Outmoded", "Legacy", "Permanent",
            "Invalid", "Depreciated", "Virtual",
            "Unreportable", "Undetermined", "Undiagnosable",
            "Unfiltered", "Static", "Dynamic",
            "Delayed", "Immediate", "Nonfatal",
            "Fatal", "Non-valid", "Unvalidated",
            "Non-static", "Unreplicatable", "Non-serious")
        Write-Verbose -Message ('{0} : list1 count : {1}' -f $cmdletName, $list1.Count)

        $list2 = @("Array", "Systems", "Hardware",
            "Software", "Firmware", "Backplane",
            "Logic-Subsystem", "Integrity", "Subsystem",
            "Memory", "Comms", "Integrity",
            "Checksum", "Protocol", "Parity",
            "Bus", "Timing", "Synchronization",
            "Topology", "Transmission", "Reception"
            "Stack", "Framing", "Code",
            "Programming", "Peripheral", "Environmental",
            "Loading", "Operation", "Parameter",
            "Syntax", "Initialization", "Execution",
            "Resource", "Encryption", "Decryption",
            "File", "Precondition", "Authentication",
            "Paging", "Swapfile", "Service",
            "Gateway", "Request", "Proxy",
            "Media", "Registry", "Configuration",
            "Metadata", "Streaming", "Retrieval",
            "Installation", "Library", "Handler")
        Write-Verbose -Message ('{0} : list2 count : {1}' -f $cmdletName, $list2.Count)

        $list3 = @("Interruption", "Destabilization", "Destruction",
            "Desynchronization", "Failure", "Dereferencing",
            "Overflow", "Underflow", "Packet",
            "Interrupt", "Corruption", "Anomoly",
            "Seizure", "Override", "Reclock",
            "Rejection", "Invalidation", "Halt",
            "Exhaustion", "Infection", "Incompatibility",
            "Timeout", "Expiry", "Unavailability",
            "Bug", "Condition", "Crash",
            "Dump", "Crashdump", "Stackdump",
            "Problem", "Lockout")
        Write-Verbose -Message ('{0} : list3 count : {1}' -f $cmdletName, $list3.Count)

        if ($Speak)
        {
            Add-Type -AssemblyName System.Speech
            $voice = New-Object -TypeName System.Speech.Synthesis.SpeechSynthesizer
            $voice.SelectVoiceByHints('Female')
        }

        while ($counter -le $Count)
        {
            $message = '{0} {1} {2}' -f (Get-Random -InputObject $list1),
                                        (Get-Random -InputObject $list2),
                                        (Get-Random -InputObject $list3)
            $message | Write-Output
            if ($Speak)
            {
                $voice.Speak($message)
            }
            $counter++
        }
    }

    end
    {
        $timer.Stop()
        Write-Verbose -Message ('{0} : End execution' -f $cmdletName)
        Write-Verbose -Message ('Total execution time: {0} ms' -f $timer.Elapsed.TotalMilliseconds)
    }
}


function Get-d00mRandomColor
{
    $(switch(Get-Random -Minimum 1 -Maximum 15)
    {
        1  {'Gray'}
        2  {'Blue'}
        3  {'Green'}
        4  {'Cyan'}
        5  {'Red'}
        6  {'Magenta'}
        7  {'Yellow'}
        8  {'White'}
        9  {'Black'}
        10 {'DarkBlue'}
        11 {'DarkGreen'}
        12 {'DarkCyan'}
        13 {'DarkRed'}
        14 {'DarkMagenta'}
        15 {'DarkYellow'}
    }) | Write-Output
}


function Get-d00mRandomSpace
{
    $(switch(Get-Random -Minimum 1 -Maximum 15)
    {
        1  {' '}
        2  {'  '}
        3  {'   '}
        4  {'    '}
        6  {'     '}
        7  {'      '}
        8  {'       '}
        9  {'        '}
        10 {'         '}
        11 {'          '}
        12 {'           '}
        13 {'            '}
        14 {'             '}
        15 {'              '}
    }) | Write-Output
}


function New-d00mColorFlood
{
    while ($true)
    {
        $params = @{BackgroundColor = $(Get-d00mRandomColor)
                    NoNewLine       = $true}
        Write-Host $(Get-d00mRandomSpace) @params
    }
}


<#
.SYNOPSIS
    Say some things!

.DESCRIPTION
    Use the SpeechSynthesizer object to speak specified text    

.EXAMPLE
    Get-d00mSayThings 'Hello world!'

    This example gets the first female installed voice and uses
    it to synthesize 'Hello world'

.EXAMPLE
    'Sup world' | Get-d00mSayThings -Gender Male

    This example passes the piped-in string to the first male
    installed voice and synthesizes 'Sup world'
#>
function Get-d00mSayThings
{
    [cmdletbinding()]
    param
    (
        #Things you want me to say
        [parameter(mandatory = $true, 
                   ValueFromPipeline = $true, 
                   Position=0)]
        [string[]]$Things,

        #Gender of speaker voice
        [ValidateSet('Male','Female')]
        [parameter()]
        [string]$Gender = 'Female'
    )

    begin
    {
        Add-Type -AssemblyName System.Speech
        $voice = New-Object -TypeName System.Speech.Synthesis.SpeechSynthesizer
        $voice.SelectVoiceByHints($Gender)
        $cmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
        $timer = New-Object -TypeName System.Diagnostics.Stopwatch
        Write-Verbose -Message ('{0} : Begin execution : {1}' -f $cmdletName, (Get-Date))
        $timer.Start()
    }

    process
    {
        foreach ($thing in $Things)
        {
            Write-Verbose -Message ('{0} : Speaking {1}' -f $cmdletName, $thing)
            $props = @{Spoken = $thing
                       Gender = $Gender}
            try
            {
                $voice.Speak($thing)
                $props.Add('Success', $true)
            }
            catch
            {
                $props.Add('Success', $false)
            }
            New-Object -TypeName psobject -Property $props |
                Write-Output
        }
    }

    end
    {
        $timer.Stop()
        Write-Verbose -Message ('{0} : Killing $voice object' -f $cmdletName)
        $voice.Dispose()
        Write-Verbose -Message ('{0} : End execution' -f $cmdletName)
        Write-Verbose -Message ('Total execution time: {0} ms' -f $timer.Elapsed.TotalMilliseconds)
    }
}


<#
.SYNOPSIS
    Add Chocolatey as a package source

.DESCRIPTION
    Adds Chocolatey as a package source on computers and
    sets if its a trusted repository or not

.EXAMPLE
    Add-d00mChocolateyPackageSource -Trusted

    This example adds Chocolatey as a trusted package source
    on the local computer

.EXAMPLE
    Add-d00mChocolateyPackageSource -ComputerName Computer1, Computer2

    This example adds Chocolatey as an untrusted package source
    on the remote computers, Computer1 and Computer2

.EXAMPLE
    'Computer1' | Add-d00mChocolateyPackageSource -Trusted -Credential (Get-Credential)

    This example adds Chocolatey as a trusted package source on
    the piped in computer, Computer1, using the specified credentials

#>
function Add-d00mChocolateyPackageSource
{
    [CmdletBinding()]
    param
    (
        [parameter(ValueFromPipeline = $true,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [parameter()]
        [switch]$Trusted,

        [parameter()]
        [pscredential]$Credential
    )

    begin
    {
        $timer = New-Object -TypeName System.Diagnostics.Stopwatch
        $cmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-Verbose -Message ('{0} : Begin execution : {1}' -f $cmdletName, (Get-Date))
        $timer.Start()
    }

    process
    {
        foreach ($computer in $ComputerName)
        {
            try
            {
                Write-Verbose -Message ('{0} : {1} : Begin execution' -f $cmdletName, $computer)
            
                $sessionParams = @{ComputerName = $computer
                                   ErrorAction  = 'Stop'}
                if ($Credential -ne $null)
                {
                    $sessionParams.Add('Credential', $Credential)
                    Write-Verbose -Message ('{0} : {1} : Using supplied credentials' -f $cmdletName, $computer)
                }
                else
                {
                    Write-Verbose -Message ('{0} : {1} : Using default credentials' -f $cmdletName, $computer)
                }
                $session = New-PSSession @sessionParams

                $result = Invoke-Command -Session $session -ScriptBlock {
                    If (!(Get-PackageProvider -Name chocolatey))
                    {
                        try
                        {
                            $params = @{Name         = 'Chocolatey'
                                        ProviderName = 'Chocolatey'
                                        Location     = 'https://chocolatey.org/api/v2'
                                        Trusted      = $args[0]
                                        Force        = $true}
                            Register-PackageSource @params
                            Write-Output $true
                        }
                        catch
                        {
                            Write-Output $false
                        }
                    }
                    else
                    {
                        Write-Output $true
                    }
                } -ArgumentList $(if($Trusted){$true}else{$false})
                Remove-PSSession -Session $session
                New-Object -TypeName psobject -Property @{ComputerName     = $computer
                                                          ChocolateyResult = $result
                                                          Trusted          = $Trusted} |
                    Write-Output

                Write-Verbose -Message ('{0} : {1} : End execution' -f $cmdletName, $computer)
            }

            catch
            {
                throw
            }
        }
    }

    end
    {
        $timer.Stop()
        Write-Verbose -Message ('{0} : End execution' -f $cmdletName)
        Write-Verbose -Message ('Total execution time: {0} ms' -f $timer.Elapsed.TotalMilliseconds)
    }
}


<#
.SYNOPSIS
    Creates a new secure password

.DESCRIPTION
    Creates a randomly generated password using ASCII characters

.EXAMPLE
    New-d00mPassword

    This example will generate a random password that is 10
    characters long (default length)

.EXAMPLE
    New-d00mPassword -Lenth 50

    This example will generate a random password that is 50
    characters long
#>
function New-d00mPassword
{
    [CmdletBinding()]
    param
    (
        #Password length
        [parameter()]
        [ValidateScript({$_ -gt 0})]
        [int]$Length = 10
    )

    begin
    {
        $timer = New-Object -TypeName System.Diagnostics.Stopwatch
        $cmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-Verbose -Message ('{0} : Begin execution : {1}' -f $cmdletName, (Get-Date))
        $timer.Start()
    }

    process
    {
        Write-Verbose -Message ('{0} : Generating {1} length password' -f $cmdletName, $Length)
        $ascii = New-Object -TypeName System.Collections.ArrayList
        $a = 33
        while ($a -le 126)
        {
            $ascii.Add([char][byte]$a) | Out-Null
            $a++
        }
        
        $password = New-Object -TypeName System.Text.StringBuilder
        $counter = 1
        while ($counter -le $Length)
        {
            $password.Append(($ascii | Get-Random)) | Out-Null
            $counter++
        }
        $password.ToString() | Write-Output
    }

    end
    {
        $timer.Stop()
        Write-Verbose -Message ('{0} : End execution' -f $cmdletName)
        Write-Verbose -Message ('Total execution time: {0} ms' -f $timer.Elapsed.TotalMilliseconds)
    }
}


function New-d00mShortcutCheatSheet
{
    [CmdletBinding()]
    param
    (
        [parameter()]
        [string]$FilePath = (Get-Location)
    )

    begin
    {
        $timer = New-Object -TypeName System.Diagnostics.Stopwatch
        $cmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-Verbose -Message ('{0} : Begin execution : {1}' -f $cmdletName, (Get-Date))
        $timer.Start()
    }

    process
    {
        $html = New-Object -TypeName System.Text.StringBuilder
        $html.AppendLine('<html>
                            <head>
                                <title>Shortcuts Cheat Sheet</title>
                                <style>
                                    table, tr, td {
                                        border: 1px solid green;
                                        border-collapse: collapse;
                                    }

                                    tr.alt td {
                                        background-color: #171717;
                                    }

                                    tr.heading td {
                                        font-weight: bold;
                                        text-align: center;
                                        font-size: larger;
                                        color: white;
                                        background-color: #333333;
                                    }

                                    body {
                                        background-color: black;
                                        color: #bdbdbd;
                                        font-family: lucida consolas, monospace;
                                    }
                                </style>
                            </head>
                            <body>
                                <table>
                                    <tr class="heading">
                                        <td>Utility</td>
                                        <td>Shortcut</td>
                                    </tr>
                                    <tr class="alt">
                                        <td>Add Hardware Wizard</td>
                                        <td>hdwwiz.cpl</td>
                                    </tr>
                                    <tr>
                                        <td>Administrative Tools</td>
                                        <td>control admintools</td>
                                    </tr>
                                    <tr clas="alt">
                                        <td>Calculator</td>
                                        <td>calc</td>
                                    </tr>
                                    <tr>
                                        <td>Command Prompt</td>
                                        <td>cmd</td>
                                    </tr>
                                    <tr class="alt">
                                        <td>Computer Management</td>
                                        <td>compmgmt.msc</td>
                                    </tr>
                                    <tr>
                                        <td>Control Panel</td>
                                        <td>control.exe</td>
                                    </tr>
                                    <tr class="alt">
                                        <td>Date and Time</td>
                                        <td>timedate.cpl</td>
                                    </tr>
                                    <tr>
                                        <td>Device Manager</td>
                                        <td>devmgmt.msc</td>
                                    </td>
                                    <tr class="alt">
                                        <td>Devices and Printers</td>
                                        <td>control printers</td>
                                    </tr>
                                    <tr>
                                        <td>Dial-In</td>
                                        <td>rasphone</td>
                                    </tr>
                                    <tr class="alt">
                                        <td>Disk Cleanup Utility</td>
                                        <td>cleanmgr</td>
                                    </tr>
                                    <tr>
                                        <td>Disk Defragment</td>
                                        <td>dfrg.msc</td>
                                    </tr>
                                    <tr class="alt">
                                        <td>Disk Management</td>
                                        <td>diskmgmt.msc</td>
                                    </tr>
                                    <tr>
                                        <td>Disk Partition Manager</td>
                                        <td>diskmgmt.msc</td>
                                    </tr>
                                    <tr class="alt">
                                        <td>Event Viewer</td>
                                        <td>eventvwr</td>
                                    </tr>
                                    <tr>
                                        <td>Folders Properties</td>
                                        <td>control folders</td>
                                    </tr>
                                    <tr class="alt">
                                        <td>Explorer</td>
                                        <td>Win+e</td>
                                    </tr>
                                    <tr>
                                        <td>Google Chrome</td>
                                        <td>chrome</td>
                                    </tr>
                                    <tr class="alt">
                                        <td>Group Policy Editor</td>
                                        <td>gpedit.msc</td>
                                    </tr>
                                    <tr>
                                        <td>Internet Explorer</td>
                                        <td>iexplorer</td>
                                    </tr>
                                    <tr class="alt">
                                        <td>Internet Properties</td>
                                        <td>inetcpl.cpl</td>
                                    </tr>
                                    <tr>
                                        <td>Local Security Settings</td>
                                        <td>secpol.cpl</td>
                                    </tr>
                                    <tr class="alt">
                                        <td>Local Users and Groups</td>
                                        <td>lusrmgr.msc</td>
                                    </tr>
                                    <tr>
                                        <td>Network Connections</td>
                                        <td>ncpa.cpl</td>
                                    </tr>
                                    <tr class="alt">
                                        <td>Notepad</td>
                                        <td>notepad</td>
                                    </tr>
                                    <tr>
                                        <td>Office Excel</td>
                                        <td>excel</td>
                                    </tr>
                                    <tr class="alt">
                                        <td>Office Outlook</td>
                                        <td>outlook</td>
                                    </tr>
                                    <tr>
                                        <td>Office Word</td>
                                        <td>winword</td>
                                    </tr>
                                    <tr class="alt">
                                        <td>Performance Monitor</td>
                                        <td>perfmon</td>
                                    </tr>
                                    <tr>
                                        <td>PowerShell</td>
                                        <td>powershell</td>
                                    </tr>
                                    <tr class="alt">
                                        <td>Power Options</td>
                                        <td>powercfg.cpl</td>
                                    </tr>
                                    <tr>
                                        <td>Registry Editor</td>
                                        <td>regedit</td>
                                    </tr>
                                    <tr class="alt">
                                        <td>Remote Desktop Connections</td>
                                        <td>mstsc</td>
                                    </tr>
                                    <tr>
                                        <td>Resource Monitor</td>
                                        <td>resmon</td>
                                    </tr>
                                    <tr class="alt">
                                        <td>Restart computer</td>
                                        <td> shutdown /r</td>
                                    </tr>
                                    <tr>
                                        <td>Resultant Set of Policy</td>
                                        <td>rsop.msc</td>
                                    </tr>
                                    <tr class="alt">
                                        <td>Security Center</td>
                                        <td>wscui.cpl</td>
                                    </tr>
                                    <tr>
                                        <td>Screen Resolution</td>
                                        <td>desk.cpl</td>
                                    </tr>
                                    <tr class="alt">
                                        <td>Shutdown computer</td>
                                        <td>shutdown</td>
                                    </tr>
                                    <tr>
                                        <td>System Configuration Editor</td>
                                        <td>sysedit</td>
                                    </tr>
                                    <tr class="alt">
                                        <td>System Configuration Utility</td>
                                        <td>msconfig</td>
                                    </tr>
                                    <tr>
                                        <td>Task Scheduler</td>
                                        <td>taskschd.msc</td>
                                    </tr>
                                    <tr class="alt">
                                        <td>User Account Management</td>
                                        <td>nusrmgr.cpl</td>
                                    </tr>
                                    <tr>
                                        <td>Windows Firewall</td>
                                        <td>wf.msc</td>
                                    </tr>
                                    <tr class="alt">
                                        <td>Windows Update</td>
                                        <td>wuapp.exe</td>
                                    </tr>
                                </table>
                            </body>
                        </html>') | Out-Null
        $filename = 'Shortcut-CheatSheet.html'
        $html.ToString() | Out-File -FilePath ('{0}\{1}' -f $FilePath, $filename)
    }

    end
    {
        $timer.Stop()
        Write-Verbose -Message ('{0} : End execution' -f $cmdletName)
        Write-Verbose -Message ('Total execution time: {0} ms' -f $timer.Elapsed.TotalMilliseconds)
    }
}


<#
.SYNOPSIS
    Checks for and install PowerShell module updates

.DESCRIPTION
    Checks for PowerShell module updates through PowerShellGet

.EXAMPLE
    Get-d00mModuleUpdate

    This example iterates through all the locally installed PowerShell
    modules, checks for the latest version, and compares the returned 
    version information to the locally installed module version. If the
    returned version is greater than the locally installed module version,
    the function will return True for that module, otherwise false.

.EXAMPLE
    Get-d00mModuleUpdate -Update

    This example iterates through all the locally installed PowerShell
    modules, checks for the latest version, and compares the returned
    version information to the locally installed module version. If the
    returned version is greater than the locally installed module version,
    the function will try to install the latest version.

    NOTE: If the module being updated is installed from a non-trusted source,
          the function will ask for each module update to confirm.

.EXAMPLE
    Get-d00mModuleUpdate -Update -Force

    This example iterates through all the locally installed Powershell
    modules, checks for the latest version, and compares the returned
    version information to the locally installed module version. If the
    returned version is greater than the locally installed module version,
    the function will try to install the latest version. With with Force switch,
    the function will not ask to confirm for any modules installed from a non-
    trusted source.
#>
function Get-d00mModuleUpdate
{
    [CmdletBinding()]
    param
    (
        [parameter()]
        [switch]$Update,

        [parameter()]
        [switch]$Force
    )

    begin
    {
        $timer = New-Object -TypeName System.Diagnostics.StopWatch
        $cmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-Verbose -Message ('{0} : Begin execution : {1}' -f $cmdletName, (Get-Date))
        $timer.Start()
    }

    process
    {
        if ($Update)
        {
            Get-InstalledModule | ForEach-Object {
                try
                {
                    Write-Verbose -Message ('{0} : {1} : Checking for updates' -f $cmdletName, $_.Name)
                    $module      = Find-Module -Name $_.Name -ErrorAction Stop
                    $newVersion  = $module.Version
                    $needsupdate = $_.Version -lt $newVersion
                }
                catch
                {
                    $newVersion  = 'no longer available'
                    $needsupdate = $true
                }
                Write-Verbose -Message ('{0} : {1} : Local version : {2}' -f $cmdletName, $_.Name, $_.Version)
                Write-Verbose -Message ('{0} : {1} : Latest version : {2}' -f $cmdletName, $_.Name, $newVersion)
                Write-Verbose -Message ('{0} : {1} : Needs update : {2}' -f $cmdletName, $_.Name, $needsupdate)
                if ($needsUpdate)
                {
                    try
                    {
                        Write-Verbose -Message ('{0} : {1} : Updating...' -f $cmdletName, $_.Name)
                        $params = @{Name = $_.Name}
                        if ($force)
                        {
                            $params.Add('Force', $true)
                        }
                        Update-Module @params
                    }
                    catch
                    {
                        throw
                    }   
                }
            }
        }

        else
        {
            Get-InstalledModule | ForEach-Object {
                Try
                {
                    $module      = Find-Module -Name $_.Name -ErrorAction Stop
                    $newVersion  = $module.Version
                    $needsUpdate = $_.Version -lt $newVersion
                }
                catch
                {
                    $newVersion  = 'no longer available'
                    $needsupdate = $true
                }

                $_ | Add-Member -MemberType NoteProperty -Name VersionAvailable -Value $newVersion
                $_ | Add-Member -MemberType NoteProperty -Name NeedsUpdate -Value $needsUpdate

                Write-Output $_
            } | Select-Object -Property Name, NeedsUpdate, Version, VersionAvailable |
            Out-GridView
        }
    }

    end
    {
        $timer.Stop()
        Write-Verbose -Message ('{0} : End execution' -f $cmdletName)
        Write-Verbose -Message ('Total execution time: {0} ms' -f $timer.Elapsed.TotalMilliseconds)
    }
}


<#
.SYNOPSIS
    Sets the default shell to PowerShell

.DESCRIPTION
    Sets registry key to specify PowerShell as default shell.
    (HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon\Shell)
    
.EXAMPLE
    Set-d00mPowerShellDefaultShell -Credential (Get-Credential)

    This example sets PowerShell as the default shell on the local machine using
    the supplied credentials.

.EXAMPLE
    Set-d00mPowerShellDefaultShell -ComputerName Computer1, Computer2 -Credential (Get-Credential)

    This example sets PowerShell as the default shell on the remote computers using
    the supplied credentials.

.EXAMPLE
    Read-Content c:\computers.txt | Set-d00mPowerShellDefaultShell

    This example sets PowerShell as the default shell on the list of computers read from
    the file using the user's current credentials.

.EXAMPLE
    (Get-AdComputer -Filter {(Enabled -eq 'true')}).Name | Set-d00mPowerShellDefaultShell -Credential (Get-Credential)

    This example sets PowerShell as the default shell on the computers returned from the
    Get-AdComputer cmdlet using the supplied credentials.

.EXAMPLE
    Set-d00mPowerShellDefaultShell -VMName vm01, vm02 -VMCredential (Get-Credential)

    This example sets PowerShell as the default shell on the virtual machines vm01 and vm02
    using the supplied VM administrator credentials

.EXAMPLE
    Set-d00mPowerShellDefaultShell -ComputerName Computer1 -Restart

    This example sets PowerShell as the default shell on Computer1 and restarts Computer1
    after execution
#>
function Set-d00mPowerShellDefaultShell
{
    [CmdletBinding(DefaultParameterSetName = "Computer")]
    param
    (
        #Computer names
        [parameter(ValueFromPipelineByPropertyName = $true,
                   ValueFromPipeline = $true,
                   ParameterSetName  = "Computer")]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        #Computer name admin credential
        [parameter(ParameterSetName = "Computer")]
        [pscredential]$Credential,

        #VM names
        [parameter(ValueFromPipelineByPropertyName = $true,
                   ValueFromPipeline = $true,
                   ParameterSetName  = "VM")]
        [string[]]$VMName,

        #VM admin credential
        [parameter(ParameterSetNAme = "VM")]
        [pscredential]$VMCredential,

        #Restart computer after completion
        [parameter()]
        [switch]$Restart
    )

    begin
    {
        $cmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
        $start      = Get-Date
        Write-Verbose -Message ('{0} : Begin execution : {1}' -f $cmdletName, $start)

        $keyPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        Write-Verbose -Message ('{0} : Key Path : {1}' -f $cmdletName, $keyPath)
    }

    process
    {
        Write-Verbose -Message ('{0} : ParameterSetName : {1}' -f $cmdletName, $PSCmdlet.ParameterSetName)

        switch ($PSCmdlet.ParameterSetName)
        {
            "Computer"
            {
                foreach ($computer in $ComputerName)
                {
                    Write-Verbose -Message ('{0} : {1} : Begin execution' -f $cmdletName, $computer)
                    try
                    {
                        $params = @{ComputerName = $computer
                                    ErrorAction  = 'Stop'}

                        # Add credentials if specified
                        if ($Credential -ne $null)
                        {
                            $params.Add('Credential', $Credential)
                            Write-Verbose -Message ('{0} : {1} : Using supplied credentials' -f $cmdletName, $computer)
                        }
                        else
                        {
                            Write-Verbose -Message ('{0} : {1} : Using current user credentials' -f $cmdletName, $computer)
                        }

                        # Set restart flag
                        if ($Restart)
                        {
                            $params.Add('ArgumentList', @($keyPath, $true))
                            Write-Verbose -Message ('{0} : {1} : Restarting computer after execution' -f $cmdletName, $computer)
                        }
                        else
                        {
                            $params.Add('ArgumentList', $keyPath)
                            Write-Verbose -Message ('{0} : {1} : Not restarting computer after execution' -f $cmdletName, $computer)
                        }


                        $result = Invoke-Command @params -ScriptBlock {
                            $shellParams = @{Path  = $args[0]
                                             Name  = 'shell'
                                             Value = 'PowerShell.exe -NoExit'}
                            Set-ItemProperty @shellParams
                    
                            if ($(Get-ItemProperty -Path $args[0] -Name 'shell').Shell -eq 'PowerShell.exe -NoExit')
                            {
                                Write-Output $true
                            }
                            else
                            {
                                Write-Output $false
                            }

                            # Check for restart flag
                            if ($args[1] -ne $null)
                            {
                                Restart-Computer -Force
                            }
                        }

                        New-Object -TypeName psobject -Property @{ComputerName      = $computer
                                                                  PowerShellDefault = $result} | 
                            Write-Output
                    }
                    catch
                    {
                        throw
                    }
                }
            }

            "VM"
            {
                foreach ($vm in $VMName)
                {
                    Write-Verbose -Message ('{0} : {1} : Begin execution' -f $cmdletName, $vm)
                    try
                    {
                        $params = @{VMName       = $vm
                                    ErrorAction  = 'Stop'}
                        if ($VMCredential -ne $null)
                        {
                            $params.Add('Credential', $VMCredential)
                            Write-Verbose -Message ('{0} : {1} : Using supplied credentials' -f $cmdletName, $vm)
                        }
                        else
                        {
                            Write-Verbose -Message ('{0} : {1} : Using current user credentials' -f $cmdletName, $vm)
                        }

                        if ($Restart)
                        {
                            $params.Add('ArgumentList', @($keyPath, $true))
                            Write-Verbose ('{0} : {1} : Restarting VM after execution' -f $cmdletName, $vm)
                        }
                        else
                        {
                            $params.Add('ArgumentList', $keyPath)
                            Write-Verbose ('{0} : {1} : Not restarting VM after execution' -f $cmdletName, $vm)
                        }

                        $result = Invoke-Command @params -ScriptBlock {
                            $shellParams = @{Path  = $args[0]
                                             Name  = 'shell'
                                             Value = 'PowerShell.exe -NoExit'}
                            Set-ItemProperty @shellParams
                    
                            if ($(Get-ItemProperty -Path $args[0] -Name 'shell').Shell -eq 'PowerShell.exe -NoExit')
                            {
                                Write-Output $true
                            }
                            else
                            {
                                Write-Output $false
                            }

                            If ($args[1] -ne $null)
                            {
                                Restart-Computer -Force
                            }
                        }

                        New-Object -TypeName psobject -Property @{ComputerName      = $vm
                                                                  PowerShellDefault = $result} | 
                            Write-Output
                    }
                    catch
                    {
                        throw
                    }
                }
            }
        }
    }

    end
    {
        $end = ($(Get-Date) - $start).TotalMilliseconds
        Write-Verbose -Message ('{0} : End execution' -f $cmdletName)
        Write-Verbose -Message ('Total execution time: {0} ms' -f $end)
    }
}


<#
.SYNOPSIS
    Encrypt a string

.DESCRIPTION
    Convert a string to a Base64 encoded encrypted string

.EXAMPLE
    ConvertTo-d00mEncryptedString -StringToEncrypt 'Hello World'

    This example will convert 'Hello World' to a Base64 encoded
    encrypted string

.EXAMPLE
    'Things and stuff' | ConvertTo-d00mEncryptedString

    This example will convert the piped in string, 'Things and stuff' to
    a Base64 encoded encrypted string

.EXAMPLE
    Read-Content c:\file.txt | ConvertTo-d00mEncryptedString

    This example will read the contents of the file and convert the contents
    into a Base64 encoded encrypted string
#>
function ConvertTo-d00mEncryptedString
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory,
                   ValueFromPipeline)]
        [string]$StringToEncrypt
    )

    begin
    {
        $cmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
        $timer = New-Object -TypeName System.Diagnostics.StopWatch
        Write-Verbose -Message ('{0} : Begin execution : {1}' -f $cmdletName, (Get-Date))
        $timer.Start()
    }

    process
    {
        $eBytes = New-Object System.Collections.ArrayList
        $pBytes = [System.Text.Encoding]::UTF32.GetBytes($StringToEncrypt)
        foreach ($byte in $pBytes)
        {
            $eBytes.Add($byte*2) | Out-Null
        }
        [System.Convert]::ToBase64String($eBytes) | Write-Output
    }

    end
    {
        $timer.Stop()
        Write-Verbose -Message ('{0} : End execution' -f $cmdletName)
        Write-Verbose -Message ('Total execution time: {0} ms' -f $timer.ElapsedMilliseconds)
    }
}


<#
.SYNOPSIS
    Decrypt a string

.DESCRIPTION
    Convert a Base64 encoded encrypted string to plain text

.EXAMPLE
    ConvertFrom-d00mEncryptedString -StringToDecrypt '6AAAAMoAAADmAAAA6AAAAA==

    This example will decrypt the specified string value from a Base64
    encoded encrypted string to plain text

.EXAMPLE
    Read-Content c:\encrypted.txt | ConvertFrom-d00mEncryptedString

    This example will decrypt the contents of the file from a Base64
    encoded encrypted string to plain text

.EXAMPLE
    ConvertTo-d00mEncryptedString 'Hello' | ConvertFrom-d00mEncryptedString

    This example will encrypt the string 'Hello' into a Base64 encrypted
    string and then decrypt the value by piping in the Base64 encrypted
    string to the ConvertFrom-d00mEncryptedString function
#>
function ConvertFrom-d00mEncryptedString
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory,
                   ValueFromPipeline)]
        [string]$StringToDecrypt
    )

    begin
    {
        $cmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
        $timer = New-Object -TypeName System.Diagnostics.StopWatch
        Write-Verbose -Message ('{0} : Begin execution : {1}' -f $cmdletName, (Get-Date))
        $timer.Start()
    }

    process
    {
        $b64 = [System.Convert]::FromBase64String($StringToDecrypt)
        $eBytes = New-Object -TypeName System.Collections.ArrayList
        foreach ($byte in $b64)
        {
            $eBytes.Add($byte / 2) | Out-Null
        }
        [System.Text.Encoding]::UTF32.GetString($eBytes) | Write-Output
    }

    end
    {
        $timer.Stop()
        Write-Verbose -Message ('{0} : End execution' -f $cmdletName)
        Write-Verbose -Message ('Total execution time: {0} ms' -f $timer.ElapsedMilliseconds)
    }
}


<#
.SYNOPSIS
    Connect to a VM

.DESCRIPTION
    Connect to a VM on a remote/local Hyper-V host using default credentials

    THE SERVER MUST BE RUNNING SERVER 2016+

.EXAMPLE
    Connect-d00mVm -VmName vm1

    This example will connect to the local Hyper-V host to a virtual machine
    named vm1 using the default credentials

.EXAMPLE
    Connect-d00mVm -ServerName server1 -VmName vm1

    This example will connect to the remote Hyper-V host named server1 to a
    virtual machine named vm1 using the default credentials
#>
function Connect-d00mVm
{
    [CmdletBinding()]
    param
    (
        [parameter()]
        [string]$ServerName = $env:COMPUTERNAME,

        [parameter(Mandatory = $true)]
        [string]$VmName
    )

    begin
    {
        $cmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
        $timer = New-Object -TypeName System.Diagnostics.Stopwatch
        Write-Verbose -Message ('{0} : Begin execution : {1}' -f $cmdletName, (Get-Date))
        $timer.Start()
    }

    process
    {
        try
        {
            $params = @{FilePath     = 'VmConnect'
                        ArgumentList = $ServerName, $VmName
                        ErrorAction  = 'Stop'}
            Start-Process @params
        }

        catch
        {
            throw
        }
    }

    end
    {
        $timer.Stop()
        Write-Verbose -Message ('{0} : End execution' -f $cmdletName)
        Write-Verbose -Message ('Total execution time: {0} ms' -f $timer.ElapsedMilliseconds)
    }
}


<#
.SYNOPSIS
    Enable RDP connections

.DESCRIPTION
    Configures the registry to allow secure RDP connections and enables the Remote Administration
    and Remote Desktop firewall rule group

.EXAMPLE
    Enable-d00mRdp

    This example will configure the registry to allow secure RDP connections and enables the 
    Remote Administration and Remote Desktop firewall rule group on the local computer

.EXAMPLE
    Enable-d00mRdp -ComputerName Computer1, Computer2 -Credential (Get-Credential)

    This example will configure the registry to allow secure RDP connections and enables the
    Remote Administration and Remote Desktop firewall rule group on the remote computers,
    Computer1 and Computer2, using the supplied credentials

.EXAMPLE
    Read-Content C:\file.txt | Enable-d00mRdp -Credential (Get-Credential)

    This example will configure the registry to allow secure RDP connections and enables the
    Remote Administration and Remote Desktop firewall rule group on the computer names found
    in the file c:\file.txt, using the supplied credentials

#>
function Enable-d00mRdp
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory,
                   ValueFromPipeline,
                   ValueFromPipelineByPropertyName)]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [parameter()]
        [pscredential]$Credential
    )

    begin
    {
        $timer = New-Object -TypeName System.Diagnostics.StopWatch
        $cmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
        $start      = Get-Date
        Write-Verbose -Message ('{0} : Begin execution : {1}' -f $cmdletName, (Get-Date))
        $timer.Start()
    }

    process
    {
        try
        {
            foreach ($computer in $ComputerName)
            {
                Write-Verbose -Message ('{0} : {1} : Begin execution' -f $cmdletName, $computer)
                $sessionParams = @{ComputerName = $computer
                                   ErrorAction  = 'Stop'}
                if ($Credential -ne $null)
                {
                    $sessionParams.Add('Credential', $Credential)
                    Write-Verbose -Message ('{0} : {1} : Using specified credentials' -f $cmdletName, $computer)
                }
                else
                {
                    Write-Verbose -Message ('{0} : {1} : Using default credentials' -f $cmdletName, $computer)
                }
                $session = New-PSSession @sessionParams

                Invoke-Command -Session $session -ScriptBlock {
                    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0 -Force
                    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 0 -Force
                    netsh advfirewall firewall set rule group="Remote Administration" new enable=yes
                    netsh advfirewall firewall set rule group="Remote Desktop" new enable=yes
                }

                Remove-PSSession -Session $session
            }
        }
        catch
        {
            throw
        }
    }

    end
    {
        $timer.Stop()
        Write-Verbose -Message ('{0} : End execution' -f $cmdletName)
        Write-Verbose -Message ('Total execution time: {0} ms' -f $timer.Elapsed.TotalMilliseconds)
    }
}


<#
.SYNOPSIS
    Disable RDP connections

.DESCRIPTION
    Configures the registry to disallow any RDP connections and disables the Remote Desktop firewall
    rule group

.EXAMPLE
    Disable-d00mRdp

    This example will configure the registry to disallow RDP connections and disables the
    Remote Desktop firewall rule group on the local computer

.EXAMPLE
    Disable-d00mRdp -ComputerName Computer1, Computer2 -Credential (Get-Credential)

    This example will configure the registry to disallow RDP connections and disables the 
    Remote Desktop firewall rule group on the remote computers, Computer1 and Computer2, using
    the supplied credentials

.EXAMPLE
    Read-Content C:\file.txt | Disable-d00mRdp -Credential (Get-Credential)

    This example will configure the registry to disallow RDP connections and disables the
    Remote Desktop firewall rule group on the computer names found in the file c:\file.txt,
    using the supplied credentials
#>
function Disable-d00mRdp
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory,
                   ValueFromPipeline,
                   ValueFromPipelineByPropertyName)]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [parameter()]
        [pscredential]$Credential
    )

    begin
    {
        $timer = New-Object -TypeName System.Diagnostics.StopWatch
        $cmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
        $start      = Get-Date
        Write-Verbose -Message ('{0} : Begin execution : {1}' -f $cmdletName, (Get-Date))
        $timer.Start()
    }

    process
    {
         try
        {
            foreach ($computer in $ComputerName)
            {
                Write-Verbose -Message ('{0} : {1} : Begin execution' -f $cmdletName, $computer)
                $sessionParams = @{ComputerName = $computer
                                   ErrorAction  = 'Stop'}
                if ($Credential -ne $null)
                {
                    $sessionParams.Add('Credential', $Credential)
                    Write-Verbose -Message ('{0} : {1} : Using specified credentials' -f $cmdletName, $computer)
                }
                else
                {
                    Write-Verbose -Message ('{0} : {1} : Using default credentials' -f $cmdletName, $computer)
                }
                $session = New-PSSession @sessionParams

                Invoke-Command -Session $session -ScriptBlock {
                    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1 -Force
                    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1 -Force
                    netsh advfirewall firewall set rule group="Remote Desktop" new enable=no
                }

                Remove-PSSession -Session $session
            }
        }
        catch
        {
            throw
        }
    }

    end
    {
        $timer.Stop()
        Write-Verbose -Message ('{0} : End execution' -f $cmdletName)
        Write-Verbose -Message ('Total execution time: {0} ms' -f $timer.Elapsed.TotalMilliseconds)
    }
}


<#
.SYNOPSIS
    Switch mouse buttons

.DESCRIPTION
    Switch mouse buttons between left- and right-handed operations
    
.PARAMETER Hand
    Left or right, for left or right operations respectively

.EXAMPLE
    Switch-d00mMouseButton -Hand Left

    This example will set the mouse operation to left-handed mode

.EXAMPLE
    Switch-d00mMouseButton -Hand Right

    This example will set the mouse operationg to right-handed mode
#>
function Switch-d00mMouseButton
{
    [CmdletBinding()]
    param
    (
        [ValidateSet('Left', 'Right')]
        [string]$Hand
    )

    begin
    {
        $cmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
        $timer = New-Object -TypeName System.Diagnostics.StopWatch
        Write-Verbose -Message ('{0} : Begin execution : {1}' -f $cmdletName, (Get-Date))
        $timer.Start()
    }

    process
    {
        try
        {
            [Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null
            $swapButtons = Add-Type -MemberDefinition '
            [DllImport("user32.dll")]
            public static extern bool SwapMouseButton(bool swap);' -Name "NativeMethods" -Namespace "PInvoke" -PassThru

            switch ($Hand)
            {
                'Left'
                {
                    if ([bool][System.Windows.Forms.SystemInformation]::MouseButtonsSwapped -eq $false)
                    {
                        $swapButtons::SwapMouseButton($true) | Out-Null
                    }
                    else
                    {
                        throw ('{0} : Mouse buttons already left-handed' -f $cmdletName)
                    }
                }

                'Right'
                {
                    if ([bool][System.Windows.Forms.SystemInformation]::MouseButtonsSwapped -eq $true)
                    { 
                        $swapButtons::SwapMouseButton($false) | Out-Null
                    }
                    else
                    {
                        throw ('{0} : Mouse buttons already right-handed' -f $cmdletName)
                    }
                }
            }
        }
        catch
        {
            throw
        }
    }

    end
    {
        $timer.Stop()
        Write-Verbose -Message ('{0} : End execution' -f $cmdletName)
        Write-Verbose -Message ('Total execution time: {0} ms' -f $timer.ElapsedMilliseconds)
    }
}


<#
.SYNOPSIS
    Enable firewall rule groups

.DESCRIPTION
    Use netsh to enable remote administration firewall rule groups:
    - Remote Desktop
    - File and Printer Sharing
    - Performance Logs and Alerts
    - Remote Event Log Management
    - Remote Scheduled Task Management
    - Remote Volume Management
    - Windows Firewall Remote Managment
    - Windows Management Instrumentation (WMI)

.PARAMETER ComputerName
    The computer to enable remote administration firewall rule groups

.PARAMETER RuleGroup
    The rule group display name to enable

.PARAMETER Credential
    The credential to use when establishing a remote PSSession. Leave blank to use default credentials

.EXAMPLE
    Enable-d00mFirewallRuleGroup -ComputerName computer1, computer2 -RuleGroup 'File and Printer Sharing'

    This example establishes a remote PSSession to the computers computer1 and computer2 and runs netsh
    to enable the specified rule group, File and Printer Sharing, using default credentials

.EXAMPLE
    (Get-AdComputer -Filter {(Enabled -eq 'true') -and (OperatingSystem -like '*windows*')}).Name | Enable-d00mFirewallRuleGroup -RuleGroup 'Windows Management Instrumentation (WMI)'

    This example establishes a remote PSSession to the computers returned from the Get-AdComputer cmdlet 
    and runs netsh to enable the specified rule group, Windows Management Instrumentation (WMI), using default 
    credentials

.EXAMPLE
    $creds = (Get-Credential)
    Enable-d00mFirewallRuleGroup -ComputerName 'Server1', 'Server2', 'Server3' -RuleGroup 'Remote Scheduled Task Management' -Credential $creds

    This example establishes a remote PSSession to the computers specified- Server1, Server2, and Server3-
    and runs netsh to enable the specified rule group, Remote Scheduled Task Management, using the specified
    credentials
#>
function Enable-d00mFirewallRuleGroup
{
    [CmdletBinding()]
    param
    (
        [alias('name')]
        [parameter(ValueFromPipeline,
                   ValueFromPipelineByPropertyName,
                   Mandatory)]
        [string[]]$ComputerName,

        [ValidateSet('Remote Desktop',
                     'File and Printer Sharing',
                     'Remote Service Management',
                     'Performance Logs and Alerts',
                     'Remote Event Log Management',
                     'Remote Scheduled Task Management',
                     'Remote Volume Management',
                     'Windows Firewall Remote Management',
                     'Windows Management Instrumentation (WMI)')]
        [parameter(Mandatory)]
        [string[]]$RuleGroup,

        [parameter()]
        [pscredential]$Credential
    )

    begin
    {
        $timer = New-Object -TypeName System.Diagnostics.StopWatch
        $cmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-Verbose -Message ('{0} : Begin execution : {1}' -f $cmdletName, (Get-Date))
        $timer.Start()
    }

    process
    {
        $computerTimer = New-Object -TypeName System.Diagnostics.Stopwatch
        foreach ($computer in $ComputerName)
        {
            $computerTimer.Start()
            Write-Verbose -Message ('{0} : {1} : Begin execution' -f $cmdletName, $computer)
            try
            {
                Write-Verbose -Message ('{0} : {1} : Creating PSSession' -f $cmdletName, $computer)
                $sessionParams = @{ComputerName = $computer
                                   ErrorAction  = 'Continue'}
                if ($Credential -ne $null)
                {
                    $sessionParams.Add('Credential', $Credential)
                    Write-Verbose -Message ('{0} : {1} : Using specified credential' -f $cmdletName, $computer)
                }
                else
                {
                    Write-Verbose -Message ('{0} : {1} : Using default credential' -f $cmdletName, $computer)
                }
                $session = New-PSSession @sessionParams

                if ($session)
                {
                    foreach ($rule in $RuleGroup)
                    {
                        Write-Verbose -Message ('{0} : {1} : Enabling {2} Firewall rule group' -f $cmdletName, $computer, $rule)
                        $result = Invoke-Command -Session $session -ArgumentList $rule -ScriptBlock {
                            try
                            {
                                Start-Process -FilePath netsh.exe -ArgumentList ('advfirewall firewall set rule group="{0}" new enable=yes' -f $args[0])
                                Write-Output $true
                            }
                            catch
                            {
                                Write-Output $false
                            }
                        }

                        New-Object -TypeName psobject -Property @{ComputerName = $computer
                                                                  RuleGroup    = $rule
                                                                  Success      = $result} |
                            Write-Output
                    }
                    Write-Verbose -Message ('{0} : {1} : Removing PSSession' -f $cmdletName, $computer)
                    Remove-PSSession -Session $session
                }
                else
                {
                    $error[0] | Write-Error
                }
            }
            catch
            {
                throw
            }

            $computerTimer.Stop()
            Write-Verbose -Message ('{0} : {1} : End execution. {2} ms' -f $cmdletName, $computer, $computerTimer.ElapsedMilliseconds)
            $computerTimer.Reset()
        }
    }

    end
    {
        $timer.Stop()
        Write-Verbose -Message ('{0} : End execution' -f $cmdletName)
        Write-Verbose -Message ('Total execution time: {0} ms' -f $timer.Elapsed.TotalMilliseconds)
    }
}


<#
.SYNOPSIS
    Rename the Recycle Bin!

.DESCRIPTION
    Change a registry key to rename the Recycle Bin and then
    restart the explorer process so that the change is reflected

.PARAMETER ComputerName
    The names of computers to change the name of the Recycle Bin

.PARAMETER NewName
    The new name of the Recycle Bin

.PARAMETER Credential
    Administrative credentials for the computers

.EXAMPLE
    Rename-d00mRecycleBin -ComputerName localhost -NewName 'Recycle Bin'

    This example will change a registry key to rename the Recycle Bin to
    the new name specified, Recycle Bin (maybe to change the name back from
    changing it earlier), for the specified computer name, the local host, and
    then restart the explorer process so that the change is reflected using
    the default credentials

.EXAMPLE
    'Computer1', 'Computer2' | Rename-d00mRecycleBin -NewName 'Garbage'

    This example will change a registry key to rename the Recycle Bin to
    the new name specified, Garbage, for the piped in computer names, Computer1 
    and Computer2, and then restart the explorer process so that the change
    is reflected using the default credentials

.EXAMPLE
    $cred = Get-Credential
    (Get-AdComputer -Filter {(enabled -eq 'true') -and (operatingsystem -like '*Windows*')}).Name | Rename-d00mRecycleBin -NewName 'Your hopes and dreams' -Credential $cred

    This example will change a registry key to rename the Recycle Bin to
    the new name specified, Your Hopes and Dreams, for all the computer names
    piped in from the Get-AdComputer cmdlet, and then restart the explorer process
    so that the changes are reflected using the specified credentials. Kind of a 
    rude thing to do...
#>
function Rename-d00mRecycleBin
{
    [CmdletBinding()]
    param
    (
        #Computer's recycle bin to rename
        [Alias('name')]
        [parameter(Mandatory,
                   ValueFromPipeline,
                   ValueFromPipelineByPropertyName)]
        [string[]]$ComputerName,

        #New Recycle Bin name
        [parameter(Mandatory)]
        [string]$NewName,

        [parameter()]
        [pscredential]$Credential
    )

    begin
    {
        $timer = New-Object -TypeName System.Diagnostics.StopWatch
        $cmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-Verbose -Message ('{0} : Begin execution : {1}' -f $cmdletName, (Get-Date))
        $timer.Start()
    }

    process
    {
        $computerTimer = New-Object -TypeName System.Diagnostics.Stopwatch
        foreach ($computer in $ComputerName)
        {
            $computerTimer.Start()
            Write-Verbose -Message ('{0} : {1} : Begin execution' -f $cmdletName, $computer)
            try
            {
                $sessionParams = @{ComputerName = $computer
                                   ErrorAction  = 'Stop'}
                if ($Credential -ne $null)
                {
                    Write-Verbose -Message ('{0} : {1} : Using specified credential' -f $cmdletName, $computer)
                    $sessionParams.Add('Credential', $Credential)
                }
                else
                {
                    Write-Verbose -Message ('{0} : {1} : Using default credential' -f $cmdletName, $computer)
                }

                Write-Verbose -Message ('{0} : {1} : Creating PSSession' -f $cmdletName, $computer)
                $session = New-PSSession @sessionParams
                if ($session)
                {
                    Write-Verbose -Message ('{0} : {1} : Changing Recycle Bin name to {2}' -f $cmdletName, $computer, $NewName)
                    $result = Invoke-Command -Session $session -ArgumentList $NewName -ScriptBlock {
                        try
                        {
                            $regParams = @{Path        = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}'
                                           Name        = '(default)'
                                           Value       = $args[0]
                                           Force       = $true
                                           ErrorAction = 'Stop'}
                            Set-ItemProperty @regParams
                            Get-Process -Name explorer | Stop-Process -Force
                            Write-Output $true
                        }
                        catch
                        {
                            Write-Output $false
                        }
                    }

                    New-Object -TypeName psobject -Property @{ComputerName      = $computer
                                                              NewRecycleBinName = $NewName
                                                              Success           = $result} |
                        Write-Output

                    Write-Verbose -Message ('{0} : {1} : Removing PSSession' -f $cmdletName, $computer)
                    Remove-PSSession -Session $session
                }
                else
                {
                    $Global:error[0] | Write-Error
                }
            }
            catch
            {
                throw
            }
            $computerTimer.Stop()
            Write-Verbose -Message ('{0} : {1} : End execution. {2} ms' -f $cmdletName, $computer, $computerTimer.ElapsedMilliseconds)
            $computerTimer.Reset()
        }

        try
        {
            $param = @{Path        = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}'
                       Name        = '(default)'
                       Value       = $NewName
                       ErrorAction = 'Stop'}
        }
        catch
        {

        }
    }

    end
    {
        $timer.Stop()
        Write-Verbose -Message ('{0} : End execution' -f $cmdletName)
        Write-Verbose -Message ('Total execution time: {0} ms' -f $timer.Elapsed.TotalMilliseconds)
    }
}



<#
.SYNOPSIS
    Get League of Legends champions

.DESCRIPTION
    Get free-to-play League of Legends champions from
    http://freechampionrotation.com

.EXAMPLE
    Get-d00mLoLFreeChampions

    This example will invoke a web request to http://freechampionrotation.com
    and pull the current rotation's free to play champions
#>
function Get-d00mLoLFreeChampions
{
    [CmdletBinding()]
    param
    (

    )

    begin
    {
        $timer = New-Object -TypeName System.Diagnostics.StopWatch
        $cmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-Verbose -Message ('{0} : Begin execution : {1}' -f $cmdletName, (Get-Date))
        $timer.Start()
    }

    process
    {
        Write-Verbose -Message ('{0} : Getting URI content' -f $cmdletName)
        $championRotation = New-Object -TypeName System.Collections.ArrayList
        (Invoke-WebRequest -Uri http://freechampionrotation.com/ -UseBasicParsing).Images.OuterHtml | ForEach-Object {
            $championRotation.Add($_.Split('"')[3]) | Out-Null
        }

        Write-Verbose -Message ('{0} : Generating unique champion array' -f $cmdletName)
        $championRotation | Select-Object -Unique | ForEach-Object {
            $_ | Write-Output
        }
    }

    end
    {
        $timer.Stop()
        Write-Verbose -Message ('{0} : End execution' -f $cmdletName)
        Write-Verbose -Message ('Total execution time: {0} ms' -f $timer.Elapsed.TotalMilliseconds)
    }
}


function Get-d00mLocalTime
{
    param
    (
        [parameter(mandatory, position=0)]
        [string]$UTCTime
    )

    $tz = [System.TimeZoneInfo]::FindSystemTimeZoneById($((Get-CimInstance -ClassName Win32_TimeZone).StandardName))
    $localTime = [System.TimeZoneInfo]::ConvertTimeFromUtc($UTCTime, $tz)
    $localTime.ToString('HH:mm:ss dd-MMM-yyyy')
}