#Powershell Toolkit

#Get Hotfixes
Function HotFixes
    {
    $computer = Read-Host 'Enter computer name'
    Write-Host
    Get-HotFix -ComputerName $computer
    Write-Host
    MainMenu
    }

#Get system last boot time
Function LastBoot
    {
        $computer = Read-Host 'Enter computer name'
        if(Test-Connection $computer -Count 1 -Quiet)
            {
                $query = Get-WmiObject win32_operatingsystem -Computer $computer | select csname, @{LABEL='LastBootUpTime';EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}
                Write-Host
                Write-Host $query
                Write-Host
                MainMenu
            }
         Else
            {
                Write-Host
                Write-Host -ForegroundColor Red $computer" is not online."
                Write-Host
                MainMenu
            }
    }

#Check to see if a user is logged on and what user
Function UsrQuery
    {
        $computer = Read-Host 'Enter computer name'
        Write-Host
        query user /server:$computer
        Write-Host
        MainMenu
    }
#Process Menu
Function EnumProcessMenu
    {
        Write-Host
        Write-Host '1.    Enumerate Single Process'
        Write-Host '2.    Enumerate All Processes'
        Write-Host '0.    Cancel'
        $Selection = Read-Host 'Make a Selection'
        Switch($Selection)
            {
                "1" {EnumProcessGrep}
                "2" {$computer = Read-Host 'Enter computer name';tasklist /s $computer}
                "0" {Write-Host;MainMenu}
                default {Write-Host "Invalid Selection";Write-Host;EnumService}
            }
        Write-Host
        MainMenu
    }


#Search for a specific process
Function EnumProcessGrep
    {
        $computer = Read-Host 'Enter computer name'
        $process = Read-Host 'Enter process to look for (full or partial name)'
        $ProcRunning = tasklist /s $computer | findstr /I "$process"
        if($ProcRunning -eq $null)
            {
                Write-Host
                Write-Host "$process not found" -ForegroundColor Red
            }
        else
            {
                Write-Host $ProcRunning -ForegroundColor Green
            }
        Write-Host
        MainMenu
    }

#List Services
Function EnumService
    {
        $computer = Read-Host 'Enter computer name'
        Write-Host
        Write-Host '1.    Query Single Service'
        Write-Host '2.    Enumerate All Services'
        Write-Host '0.    Cancel'
        $Selection = Read-Host 'Make a Selection'
        Switch($Selection)
            {
                "1" {$service = Read-Host "Enter Service Name";Get-Service -Computer $computer $service}
                "2" {Get-Service -Computer $computer}
                "0" {Write-Host;MainMenu}
                default {Write-Host "Invalid Selection";Write-Host;EnumService}
            }
        Write-Host
        MainMenu
    }

#Ping Menu
Function PingMenu
    {
        
        Write-Host "1. Ping single host"
        Write-Host "2. Ping sweep address range"
        Write-Host "0. Cancel"
        $Selection = Read-Host 'Make a selection'
        Switch($Selection)
            {
                "1" {PingHost}
                "2" {PingSweep}
                "0" {Write-Host;MainMenu}
                default {Write-Host "Invalid Selection";Write-Host;PingMenu}
            }
    }
#Ping Host
Function PingHost
    {
        $computer = Read-Host 'Enter computer name'
        Write-Host
        ping -a $computer
        Write-Host
        MainMenu
    }
#Ping a range of IP Addresses
Function PingSweep
    {
        #Get IP Range
        $Range1 = Read-Host "Enter full starting IP"
        $Range2 = Read-Host "Enter full ending IP"
        #Break the IP into octets
        $StartRange = @($Range1.Split(".",4))
        $EndRange = @($Range2.Split(".",4))
        #Convert last octet to an integer
        $cnt = [INT]$StartRange[3]
        #Loop until hitting the end IP
        While ($cnt -le $EndRange[3])
            {
            #Build the IP
                        $IP = $StartRange[0]
                        $IP = $IP + "."
                        $IP = $IP + $StartRange[1]
                        $IP = $IP + "."
                        $IP = $IP + $StartRange[2]
                        $IP = $IP + "."
                        $IP = $IP + $cnt
                        #Attempt to resolve the hostname                 
                      try
                           {
                            #If a host name can be resolved ping to make sure the host is up
                            if(Test-Connection $IP -Count 1 -Quiet)
                                {
                                     
                                    $hostname = Resolve-DnsName $IP | Select -Property NameHost
                                    Write-Host $IP $hostname
                                }
                            $cnt++
                           }
                       catch
                             {
                                $cnt++
                             }                              
             } 
                            
        Write-Host    
        MainMenu

    }
#Get OS Name, Build Number, and Version
Function OSandBuild
    {
        $computer = Read-Host 'Enter computer name'   
        Write-Host
        $query = Get-WMIObject Win32_OperatingSystem -ComputerName $computer | select-object CSName, Caption, BuildNumber, Version
        Write-Host $query
        Write-Host
        MainMenu
    }

#Get File and Folder Permissions
Function AuditPermissions
    {
        $Filepath = Read-Host 'Enter path'
        Write-Host
        Get-Acl -Path $Filepath | Format-List
        Write-Host
        MainMenu
    }

#Get File and Folder Permissions Recursively
Function AuditPermissionsRecursive
    {
        $Filepath = Read-Host 'Enter path'
        Write-Host
        Get-Childitem $Filepath -R | Get-Acl | Format-List
        Write-Host
        MainMenu
    }

#Check status of Firewall profiles
Function FirewallStatus
    {
        $computer = Read-Host 'Enter computer name'   
        Write-Host
        netsh -r $computer advfirewall show allprofiles
        Write-Host
        MainMenu
    }

#Get computer IP from specified DNS server
Function DCIP
    {
        $HostToGet = Read-Host 'Enter computer name IP needed for'
        $ClosestDC = Read-Host 'Enter server name of closest DC'
        Write-Host
        nslookup $HostToGet $ClosestDC
        Write-Host
        MainMenu
    }



#Open event viewer for a remote host
Function RemoteEvents
    {
        $computer = Read-Host 'Enter computer name'
        & eventvwr $computer
        Write-Host
        MainMenu
    }

#Open msinfo32 for a remote host
Function SysInfo
    {
        $computer = Read-Host 'Enter computer name'
        & msinfo32 -Computer $computer
        Write-Host
        MainMenu
    }

#Run a single Powershell command
Function PSCommand
    {
        $RunCommand = Read-Host 'Enter Powershell command to run'
        Write-Host
        & $RunCommand
        Write-Host
        MainMenu
    }

#Run a single Command Prompt command
Function CMDCommand
    {
        $RunCommand = Read-Host 'Enter Command Prompt command to run'
        Write-Host
        & cmd /c $RunCommand
        Write-Host
        MainMenu
    }

#Query if user is logged on and notify when logged off. Configurable recheck duration.
Function UsrQueryNotify
    {
        $computer = Read-Host 'Enter computer name'
        $timetowait = Read-Host 'How long to wait until next check(seconds)'
        
        Write-Host "Last Check"

        $usr = query user /server:$computer

        While ($usr -ne $null )
            {
                Get-Date | Select-Object TimeOfDay
                Sleep $timetowait
                $usr = query user /server:$computer
                Write-Host
   
            }

#Make Toast
        
        $app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]

        $Template = [Windows.UI.Notifications.ToastTemplateType]::ToastImageAndText01

        #Gets the Template XML so we can manipulate the values
        [xml]$ToastTemplate = ([Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($Template).GetXml())

        [xml]$ToastTemplate = @"
        <toast launch="app-defined-string">
            <visual>
                <binding template="ToastGeneric">
                <text>Toasty!</text>
                <text>User logged off.</text>
                </binding>
            </visual>
            <actions>
                <action activationType="background" content="Remind me later" arguments="later"/>
            </actions>
        </toast>
"@

$ToastXml = New-Object -TypeName Windows.Data.Xml.Dom.XmlDocument
$ToastXml.LoadXml($ToastTemplate.OuterXml)

$notify = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app)

$notify.Show($ToastXml)

#Create notification pop up box
        $wshell = New-Object -ComObject Wscript.Shell

        $wshell.Popup("User is Logged off",0,"User Logged Off Notification",0x0)
        Write-Host

        MainMenu

    }

#Open user C share in Powershell
Function ConnectRemoteFSShell
    {
        $computer = Read-Host 'Enter computer name'
        $computer = "\\" + $computer + "\C$"
        powershell -NoExit Set-Location $computer
        Write-Host 
        MainMenu
    }

#Open user C share in File Explorer
Function ConnectRemoteFSExplorer
    {
        $computer = Read-Host 'Enter computer name'
        $computer = "\\" + $computer + "\C$"
        & explorer $computer
        Write-Host
        MainMenu
    }


#View logs without invoking event viewer
Function EventLogShell
    {
        
        Write-Host '1.   View Full Log'
        Write-Host '2.   Filter to specific Event ID'
        $ViewType = Read-Host 'Make Selection'
        switch($ViewType)
            {
                "1" {FullLog}
                "2" {FilteredLog}
            }
        MainMenu
    }

#View unfiltered log
Function FullLog
    {
        $computer = Read-Host 'Enter computer name'
        $LogName = Read-Host 'Enter Log Name'
        Write-Host '1. Format-List'
        Write-Host '2. GridView (Will not display large amounts of information)'
        Write-Host '3. Export CSV'
        $ViewFormat = Read-Host 'Select view format'
        Write-Host 'Prompting for credential to ensure all logs are pulled'
        switch($ViewFormat)
            {
                "1" {Get-WinEvent -LogName $LogName -ComputerName $computer | Format-List}
                "2" {Get-WinEvent -LogName $LogName -ComputerName $computer | Out-GridView}
                "3" {Get-WinEvent -LogName $LogName -ComputerName $computer | Export-Csv -Path $LogName}
            }
        MainMenu
    }

#View logs filtered by event ID
Function FilteredLog
    {
        $computer = Read-Host 'Enter computer name'
        $LogName = Read-Host 'Enter Log Name'
        $EventID = Read-Host 'Enter Event ID'
        Write-Host '1. Format-List'
        Write-Host '2. GridView (Will not display large amounts of information)'
        Write-Host '3. Export CSV'
        $ViewFormat = Read-Host 'Select view format'
        Write-Host 'Prompting for credential to ensure all logs are pulled'
        switch($ViewFormat)
            {
                "1" {Get-WinEvent -ComputerName $computer -FilterHashtable @{ LogName = $LogName; ID = $EventID } | Format-List}
                "2" {Get-WinEvent -ComputerName $computer -FilterHashtable @{ LogName = $LogName; ID = $EventID } | Out-GridView}
                "3" {Get-WinEvent -ComputerName $computer -FilterHashtable @{ LogName = $LogName; ID = $EventID } | Export-Csv $LogName}
            }
        MainMenu

    }
 Function WOL
{
Write-Host
$MacAddress = Read-Host "Enter MAC Address of Host (no separators)"
Write-Host
    <#
    .SYNOPSIS
    Sends a number of magic packets using UDP broadcast.
 
    .DESCRIPTION
    Send-Packet sends a specified number of magic packets to a MAC address in order to wake up the machine.  
 
    .PARAMETER MacAddress
    The MAC address of the machine to wake up.
    #>
 
    try
    {
        $Broadcast = ([System.Net.IPAddress]::Broadcast)
 
        ## Create UDP client instance
        $UdpClient = New-Object Net.Sockets.UdpClient
 
        ## Create IP endpoints for each port
        $IPEndPoint = New-Object Net.IPEndPoint $Broadcast, 9
 
        ## Construct physical address instance for the MAC address of the machine (string to byte array)
        $MAC = [Net.NetworkInformation.PhysicalAddress]::Parse($MacAddress.ToUpper())
 
        ## Construct the Magic Packet frame
        $Packet =  [Byte[]](,0xFF*6)+($MAC.GetAddressBytes()*16)
 
        ## Broadcast UDP packets to the IP endpoint of the machine
        $UdpClient.Send($Packet, $Packet.Length, $IPEndPoint) | Out-Null
        $UdpClient.Close()
    }
    catch
    {
        $UdpClient.Dispose()
        $Error | Write-Error;
    }

MainMenu
}
# Open a remote desktop connection
Function RemoteCon
    {
        $computer = Read-Host 'Enter computer name'
        & mstsc /v $computer
        Write-Host
        MainMenu
    }
# Get MAC address of Remote Computer
Function GetMACAddress
    {
        $computer = Read-Host 'Enter computer name'
        & getmac /S $computer
        Write-Host
        MainMenu
    }
#Get User SID
Function GetUserSID
    {
        #Get user name
        $usrname = Read-Host "Enter user name of account"
        #Getting user SID
        Write-Host "Getting user SID."
        $usrsid = Get-WMIObject Win32_UserAccount | Where Name -eq $usrname | Select -ExpandProperty SID
        Write-Host $usrsid
        Write-Host
        MainMenu
    }
#Get Username from SID
Function GetUserName
    {
        #Get user SID
        $usrsid = Read-Host "Enter user SID"
        #Getting user
        Write-Host "Getting username."
        $usrname = Get-WMIObject Win32_UserAccount | Where SID -eq $usrsid | Select -ExpandProperty Name0
        Write-Host
        Write-Host $usrname
        Write-Host
        MainMenu
    }
#Shutdown/Reboot Remote Computer
Function ShutBootRemote
    {
        #Get computer name
        $computer = Read-Host 'Enter computer name'
        Write-Host '1. Shutdown'
        Write-Host '2. Restart'
        $option = Read-Host 'Select Option'
        switch($option)
            {
            "1" {shutdown /s /m \\$computer /t 00}
            "2" {shutdown /r /m \\$computer /t 00}
            default {Write-Host 'Invalid Selection';Write-Host;MainMenu}
            }
        Write-Host
        MainMenu
    }
#Get Installed Software
Function EnumSoftware
    {
        #Get computer name
        $computer = Read-Host "Enter computer name"
        if(!(Test-Connection -ComputerName $Computer -Count 1 -quiet)) 
            { 
                Write-Host
                Write-Host -Foregroundcolor Red "$Computer is not online"
                Write-Host 
                MainMenu
            }
        Write-Host
        Write-Host "Pulling software this may take a moment" 
        Write-Host
        try
            {
                #Set Registry Hive as HKLM
                $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$computer) 
                #Set registry path
                $RootPath1 = "Software\Microsoft\WINDOWS\CurrentVersion\Uninstall"
                #Open path
                $RegSubKey = $Reg.OpenSubKey($RootPath1)
                #Get subkeys
                $Values = $RegSubKey.GetSubKeyNames()
                #Loop through all the subkeys
                foreach($value in $Values) 
                    {
                        #Set subkey as path
                        $RegPath = $RootPath1 + '\' + $value
                        $listname = @()
                        $listpublisher = @()
                        #Get key value for display name
                        $listname = $listname + $Reg.OpenSubKey($RegPath).GetValue('DisplayName')
                        #Get key value for publisher
                        $listpublisher = $listpublisher + $Reg.OpenSubKey($RegPath).GetValue('Publisher')
                    }
        $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$computer) 
        $RootPath2 = "Software\Wow6432Node\Microsoft\WINDOWS\CurrentVersion\Uninstall"
        $RegSubKey = $Reg.OpenSubKey($RootPath2)
        $Values = $RegSubKey.GetSubKeyNames()

                foreach($value in $Values) 
                    {

                        $RegPath = $RootPath2 + '\' + $value

                        $listname = $listname + $Reg.OpenSubKey($RegPath).GetValue('DisplayName')
                        $listpublisher = $listpublisher + $Reg.OpenSubKey($RegPath).GetValue('Publisher')
                    }
        $tabName = "Software List"

        #Create Table object
        $table = New-Object system.Data.DataTable “$tabName”

        #Define Columns
        $col1 = New-Object system.Data.DataColumn Name,([string])
        $col2 = New-Object system.Data.DataColumn Publisher,([string])

        #Add the Columns
        $table.columns.add($col1)
        $table.columns.add($col2)

        #Create a row
        $row = $table.NewRow()
        $cnt = 0
        While ($cnt -le $listname.Count)
            {
                #Create a row
                $row = $table.NewRow()
                #Enter data in the row
                $row.Name = $listname[$cnt] 
                $row.Publisher = $listpublisher[$cnt] 

                #Add the row to the table
                $table.Rows.Add($row)
                $cnt = $cnt + 1
            }

        #Display the table
        $table | format-table -AutoSize 
        #Export to csv
        $E2CSV = Read-Host "Export to CSV?"
        if ($E2CSV.ToUpper() -eq "Y" -or $E2CSV.ToUpper() -eq "YES")
            {
                $csvname = Read-Host "Enter path and file name"                
                $tabCsv = $table | export-csv $csvname".csv" -noType
                Write-Host
            }
        }
    catch
        {
            Write-Host -Foregroundcolor Red "RemoteRegistry service Stopped AND/OR Disabled"
            Get-WMIObject Win32_Service -computer $computer -filter "name='RemoteRegistry'"
            $start = Read-Host "Start RemoteRegistry service?"
            if($start.ToUpper() -eq "Y")
                {
                    (Get-WmiObject -Class Win32_Service -Filter "name='RemoteRegistry'" -ComputerName $computer).ChangeStartMode("Manual")        
                    (Get-WmiObject -Class Win32_Service -Filter "name='RemoteRegistry'" -ComputerName $computer).StartService()
                    Write-Host "Please run command 28 again for the software list"
                    Write-Host
                }
        }
    MainMenu
}
Function CompareSoftware
    {
            #Get computer name
        $computer = Read-Host "Enter reference computer name"
        if(!(Test-Connection -ComputerName $Computer -Count 1 -quiet)) 
            { 
                Write-Host
                Write-Host -Foregroundcolor Red "$Computer is not online"
                Write-Host 
                MainMenu
            }
        Write-Host
        Write-Host "Pulling software this may take a moment" 
        Write-Host
        try
            {
                #Set Registry Hive as HKLM
                $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$computer) 
                #Set registry path
                $RootPath1 = "Software\Microsoft\WINDOWS\CurrentVersion\Uninstall"
                #Open path
                $RegSubKey = $Reg.OpenSubKey($RootPath1)
                #Get subkeys
                $Values = $RegSubKey.GetSubKeyNames()
                #Loop through all the subkeys
                foreach($value in $Values) 
                    {
                        #Set subkey as path
                        $RegPath = $RootPath1 + '\' + $value
                        $listname = @()
                        $listpublisher = @()
                        #Get key value for display name
                        $listname = $listname + $Reg.OpenSubKey($RegPath).GetValue('DisplayName')
                        #Get key value for publisher
                        $listpublisher = $listpublisher + $Reg.OpenSubKey($RegPath).GetValue('Publisher')
                    }
        $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$computer) 
        $RootPath2 = "Software\Wow6432Node\Microsoft\WINDOWS\CurrentVersion\Uninstall"
        $RegSubKey = $Reg.OpenSubKey($RootPath2)
        $Values = $RegSubKey.GetSubKeyNames()

                foreach($value in $Values) 
                    {

                        $RegPath = $RootPath2 + '\' + $value

                        $listname = $listname + $Reg.OpenSubKey($RegPath).GetValue('DisplayName')
                        $listpublisher = $listpublisher + $Reg.OpenSubKey($RegPath).GetValue('Publisher')
                    }
                    }
        catch
        {
            Write-Host -Foregroundcolor Red "RemoteRegistry service Stopped AND/OR Disabled"
            Get-WMIObject Win32_Service -computer $computer -filter "name='RemoteRegistry'"
            $start = Read-Host "Start RemoteRegistry service?"
            if($start.ToUpper() -eq "Y")
                {
                    (Get-WmiObject -Class Win32_Service -Filter "name='RemoteRegistry'" -ComputerName $computer).ChangeStartMode("Manual")        
                    (Get-WmiObject -Class Win32_Service -Filter "name='RemoteRegistry'" -ComputerName $computer).StartService()
                    Write-Host
                }
        }
       $computer2 = Read-Host "Enter computer name to compare to"
        if(!(Test-Connection -ComputerName $computer2 -Count 1 -quiet)) 
            { 
                Write-Host
                Write-Host -Foregroundcolor Red "$computer2 is not online"
                Write-Host 
                MainMenu
            }
        Write-Host
        Write-Host "Pulling software this may take a moment" 
        Write-Host
        try
            {
                #Set Registry Hive as HKLM
                $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$computer) 
                #Set registry path
                $RootPath1 = "Software\Microsoft\WINDOWS\CurrentVersion\Uninstall"
                #Open path
                $RegSubKey = $Reg.OpenSubKey($RootPath1)
                #Get subkeys
                $Values = $RegSubKey.GetSubKeyNames()
                #Loop through all the subkeys
                foreach($value in $Values) 
                    {
                        #Set subkey as path
                        $RegPath = $RootPath1 + '\' + $value
                        $listname2 = @()
                        $listpublisher2 = @()
                        #Get key value for display name
                        $listname2 = $listname2 + $Reg.OpenSubKey($RegPath).GetValue('DisplayName')
                        #Get key value for publisher
                        $listpublisher2 = $listpublisher2 + $Reg.OpenSubKey($RegPath).GetValue('Publisher')
                    }
        $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$computer2) 
        $RootPath2 = "Software\Wow6432Node\Microsoft\WINDOWS\CurrentVersion\Uninstall"
        $RegSubKey = $Reg.OpenSubKey($RootPath2)
        $Values = $RegSubKey.GetSubKeyNames()

                foreach($value in $Values) 
                    {

                        $RegPath = $RootPath2 + '\' + $value

                        $listname2 = $listname2 + $Reg.OpenSubKey($RegPath).GetValue('DisplayName')
                        $listpublisher2 = $listpublisher2 + $Reg.OpenSubKey($RegPath).GetValue('Publisher')
                    }
        $Difference = $listname | Where {$listname2 -notcontains $_}
        $Difference
        #Export to csv
        $E2CSV = Read-Host "Export to CSV?"
        if ($E2CSV.ToUpper() -eq "Y" -or $E2CSV.ToUpper() -eq "YES")
            {
                #Convert variable to an object so Export-Csv can be used
                $Difference = $Difference | Select-Object @{Name='Name';Expression={$_}}
                $csvname = Read-Host "Enter path and file name"                
                $Difference | export-csv $csvname".csv" -noType
                Write-Host
            }
        }
    catch
        {
            Write-Host -Foregroundcolor Red "RemoteRegistry service Stopped AND/OR Disabled"
            Get-WMIObject Win32_Service -computer $computer -filter "name='RemoteRegistry'"
            $start = Read-Host "Start RemoteRegistry service?"
            if($start.ToUpper() -eq "Y")
                {
                    (Get-WmiObject -Class Win32_Service -Filter "name='RemoteRegistry'" -ComputerName $computer).ChangeStartMode("Manual")        
                    (Get-WmiObject -Class Win32_Service -Filter "name='RemoteRegistry'" -ComputerName $computer).StartService()
                    Write-Host
                }
        }
        MainMenu
    }
#Modify the status of services
# TODO: Add an alernate method the modifies the start status via registry as some services need modified that way. See Windows update script for method
Function ManageServices
    {
        $computer = Read-Host "Enter Computer Name"
        $service = Read-Host "Enter Service Name"
        Write-Host '1. WMI (All functions work for most services)'
        Write-Host '2. Registry (Change start mode only, but works for all services) (Requires script to be run as Administrator)'
        Write-Host '0. Return to Main Menu'
        $changemode = Read-Host "Choose the modification method"
        switch($changemode)
            {
                "1" {$ServiceModMode ="WMI"}
                "2" {$ServiceModMode ="Registry"}
                "0" {Write-Host;MainMenu}
                default {Write-Host "Invalid Selection";MainMenu}
            }
        Write-Host '1. Change Start Mode'
        Write-Host '2. Start Service (Unsupported in registry mode)'
        Write-Host '3. Stop Service (Unsupported in registry mode)'
        Write-Host '0. Cancel'
        $Selection = Read-Host "Make Selection"
        Switch($Selection)
            {
                "1" {
                        Write-Host '1.Automatic'
                        Write-Host '2.Manual'
                        Write-Host '3.Disabled'
                        Write-Host '0.Cancel'
                        $startmode = Read-Host "Select Start Mode"

                        Switch($startmode)
                            {
                                "1" 
                                    {
                                       if($ServiceModMode -eq "WMI")
                                            {
                                                 (Get-WmiObject -Class Win32_Service -Filter "name='$service'" -ComputerName $computer).ChangeStartMode("Automatic")
                                            }
                                        if($ServiceModMode -eq "Registry")
                                            {
                                                $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$computer)
                                                #Set the service path
                                                $ServicePath = "SYSTEM\CurrentControlSet\Services\$service"
                                                #Open the key and set it to be writeable thus the true parameter.
                                                $RegSubKey = $Reg.OpenSubKey($ServicePath,$true)
                                                #Set the value for that key
                                                $RegSubKey.SetValue("Start",2)
                                            }
                                    }
                                "2"  
                                    {
                                       if($ServiceModMode -eq "WMI")
                                            {
                                                 (Get-WmiObject -Class Win32_Service -Filter "name='$service'" -ComputerName $computer).ChangeStartMode("Manual")
                                            }
                                        if($ServiceModMode -eq "Registry")
                                            {
                                                $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$computer)
                                                #Set the service path
                                                $ServicePath = "SYSTEM\CurrentControlSet\Services\$service"
                                                #Open the key and set it to be writeable thus the true parameter.
                                                $RegSubKey = $Reg.OpenSubKey($ServicePath,$true)
                                                #Set the value for that key
                                                $RegSubKey.SetValue("Start",3)
                                            }
                                    }
                                "3"  
                                    {
                                       if($ServiceModMode -eq "WMI")
                                            {
                                                 (Get-WmiObject -Class Win32_Service -Filter "name='$service'" -ComputerName $computer).ChangeStartMode("Disabled")
                                            }
                                        if($ServiceModMode -eq "Registry")
                                            {
                                                $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$computer)
                                                #Set the service path
                                                $ServicePath = "SYSTEM\CurrentControlSet\Services\$service"
                                                #Open the key and set it to be writeable thus the true parameter.
                                                $RegSubKey = $Reg.OpenSubKey($ServicePath,$true)
                                                #Set the value for that key
                                                $RegSubKey.SetValue("Start",4)
                                            }
                                    }
                                "0" {Write-Host;MainMenu}
                                default {Write-Host 'Invalid Selection';ManageServices}
                            }
                    }
                "2" {Write-Host "How many times do I have to tell you it's not supported?";Write-Host "Defaulting to WMI mode";Get-Service -ComputerName $computer -Name $service | Start-Service -Verbose}
                "3" {Write-Host "How many times do I have to tell you it's not supported?";Write-Host "Defaulting to WMI mode";Get-Service -ComputerName $computer -Name $service | Stop-Service -Verbose}
                "0" {Write-Host;MainMenu}
                default {Write-Host 'Invalid Selection';MainMenu}
            }
        Write-Host
        MainMenu
    }
#Query the current encryption of a computer
Function BitlockerStatus
    {
        #Get computer name
        $computer = Read-Host "Enter computer name"
        #Open a elevated command prompt that does not instantly close to run the command
        Start-Process -FilePath "cmd" -ArgumentList "/K, manage-bde -status -ComputerName $computer" -Verb runAs
        Write-Host
        MainMenu
    }

#Run a command on remote computer with PSEXEC
Function RunPSexec
    {
        #Get computer name
        $computer = Read-Host "Enter computer name"
        $psexecmd = Read-Host "Enter command to run with PSexec"
        C:\Users\yostb\Downloads\PSTools\PsExec.exe \\$computer $psexecmd
        Write-Host
        MainMenu
    }
Function Compmgmt
    {
        $computer = Read-Host "Enter computer name"
        & compmgmt.msc /computer:$computer
        Write-Host
        MainMenu
    }

#Perform various forensics tasks
Function ForensicsMenu
    {
        Write-Host
        Write-Host "0. Return to Main Menu"
        Write-Host "1. Logon and Logoff History"
        Write-Host "2. Get Firefox Browsing History"
        Write-Host "3. Get Chrome Browsing History"
        Write-Host "4. Get Internet Explorer Browsing History"
        Write-Host "5. Get Edge Browsing History"
        Write-Host "6. Create File Hash"
        Write-Host "7. Get Outlook NST and OST files"
        Write-Host
        $Choice = Read-Host 'Select Tool to Use'
        switch($Choice)
            {
                "0" {Write-Host;MainMenu}
                "1" {LogonoffHistory}
                "2" {FirefoxHistory}
                "3" {ChromeHistory}
                "4" {IEHistory}
                "5" {EdgeHistory}
                "6" {FileHash}
                "7" {ForensicOutlookMailbox}
                Default {Write-Host "Invalid Selection";ForensicsMenu}
            }
    }
 #Get the logon and off History
Function LogonoffHistory
        {
            $computer = Read-Host "Enter computer name"
            $usrname = Read-Host "Enter user name (Leave blank for all)"
            $days = Read-Host "Enter number of days to display (Leave blank for all)"
            if ($usrname -ne $null)
                {
                    Write-Host "Getting SID"
                    $usrsid = Get-WMIObject Win32_UserAccount | Where Name -eq $usrname | Select -ExpandProperty SID
                }
            if ($days -ne $null)
                {
                    $StartTime = (Get-Date).AddDays(-$days)
                }
            $LogName = 'Microsoft-Windows-User Profile Service/Operational'
            $EventID = 2,4
            Write-Host '1. Format-List'
            Write-Host '2. GridView (Will not display large amounts of information)'
            Write-Host '3. Export CSV'
            $ViewFormat = Read-Host 'Select view format'
            Write-Host 'Prompting for credential to ensure all logs are pulled'
            Write-Host 'Getting logs. This may take several minutes.'
            switch($ViewFormat)
                {
                    "1" {Get-WinEvent -ComputerName $computer -FilterHashtable @{ LogName = $LogName; ID = $EventID; Userid = $usrsid; StartTime = $StartTime } | Format-List -Property * }
                    "2" {Get-WinEvent -ComputerName $computer -FilterHashtable @{ LogName = $LogName; ID = $EventID; Userid = $usrsid } | Select-Object -Property * | Out-GridView}
                    "3" {$dest = Read-Host "Enter path to save log"; Get-WinEvent -ComputerName $computer -FilterHashtable @{ LogName = $LogName; ID = $EventID; Userid = $usrsid } | Select-Object -Property * | Export-Csv -Path $dest".csv" }
                    default {Write-Host "Invalid Selection";LogonoffHistory}
                }
            MainMenu
        }

#Get Browsing History of Mozilla Firefox
Function FirefoxHistory
    {
      $computer = Read-Host "Enter computer name"
      $usr = Read-Host "Enter username of target user"
      $dest = Read-Host "Enter path to save History File"
      $mozprofile = Get-ChildItem -Path "\\$computer\C$\Users\$usr\AppData\Roaming\Mozilla\Firefox\Profiles\" | foreach {$_.Name}
      Copy-Item -Path "\\$computer\C$\Users\$usr\AppData\Roaming\Mozilla\Firefox\Profiles\$mozprofile\places.sqlite" -Destination $dest".sqlite"
      MainMenu
        
    }

#Get Browsing History of Google Chrome
Function ChromeHistory
    {
      $computer = Read-Host "Enter computer name"
      $usr = Read-Host "Enter username of target user"
      $dest = Read-Host "Enter path to save History File"
      Copy-Item -Path "\\$computer\C$\Users\$usr\AppData\Local\Google\Chrome\User Data\Default\History" -Destination $dest
      MainMenu      
    }
#Get Browsing History of Microsoft Edge
Function EdgeHistory
    {
      $computer = Read-Host "Enter computer name"
      $usr = Read-Host "Enter username of target user"
      $dest = Read-Host "Enter path to save History File"
      Copy-Item -Path "\\$computer\C$\Users\$usr\AppData\Local\Microsoft\Edge\User Data\Default\History" -Destination $dest
      MainMenu      
    }

#Get Browsing History Internet Explorer 11
Function IEHistory
    {
      $computer = Read-Host "Enter computer name"
      $usr = Read-Host "Enter username of target user"
      $dest = Read-Host "Enter path to save History File"
      try
        {
            Copy-Item -Path "\\$computer\C$\Users\$usr\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat" -Destination $dest
        }
      catch
           {
                Write-Host
                Write-Host "The user might be logged in unable to copy file while user is logged in" -ForegroundColor Red
                Write-Host
                query user /server:$computer
                Write-Host
           }
      Write-Host "Note this file also contains Cache, Cookies, and Downloads"
      Write-Host
      MainMenu      
    }
#Display the calculate a file hash
Function FileHash
    {
        $PathtoFile = Read-Host "Enter the path to the file"
        #Select the hash type
        Write-Host
        Write-Host "1. MD5"
        Write-Host "2. SHA1"
        Write-Host "3. SHA256"
        Write-Host "4. SHA384"
        Write-Host "5. SHA512"
        $Alg = Read-Host "Select which algorithim to use"
        switch($Alg)
            {
                "1" {$SelectedAlg = "MD5"}
                "2" {$SelectedAlg = "SHA1"}
                "3" {$SelectedAlg = "SHA256"}
                "4" {$SelectedAlg = "SHA384"}
                "5" {$SelectedAlg = "SHA512"}
                "6" {$SelectedAlg = "MACTripleDES"}
                "7" {$SelectedAlg = "RIPEMD160"}
                default {$SelectedAlg = "SHA256"}
            }
        Get-FileHash -Path $PathtoFile -Algorithm $SelectedAlg
        Write-Host
        MainMenu
    }
#Grab User Outlook PST and NST files
Function ForensicOutlookMailbox
    {
      $computer = Read-Host "Enter computer name"
      $usr = Read-Host "Enter username of target user"
      $dest = Read-Host "Enter path to save Outlook files"
      $emailaddress = "$usr@erdmananthony.com"
      try
        {
            #Check to see if there are any NST files
            $nstfiles= Get-ChildItem "\\$computer\C$\Users\$usr\AppData\Local\Microsoft\Outlook" | Where-Object -Property name -Like "*.nst" | Select -ExpandProperty Name
            If($nstfiles -ne $null)
                {
                    #Go through all NST files found and copy where was specified
                    foreach($nstfile in $nstfiles)
                        {
                            Copy-Item -Path "\\$computer\C$\Users\$usr\AppData\Local\Microsoft\Outlook\$nstfile" -Destination $dest
                        }
                    Write-Host -ForegroundColor Green "NST Files Copied"
                }
            else
                {
                    Write-Host "No NST files present"
                }
            #Check to see if there are any PST files
            $ostfiles = Get-ChildItem "\\$computer\C$\Users\$usr\AppData\Local\Microsoft\Outlook" | Where-Object -Property name -Like "*.ost" | Select -ExpandProperty Name
            If($ostfiles -ne $null)
                {
                    #Go through all OST files found and copy where was specified
                    foreach($ostfile in $ostfiles)
                        {
                            Copy-Item -Path "\\$computer\C$\Users\$usr\AppData\Local\Microsoft\Outlook\$ostfile" -Destination $dest
                        }
                    Write-Host -ForegroundColor Green "OST Files Copied"
                }
            else
                {
                    Write-Host "No OST files present"
                }
        }

      catch
           {
                Write-Host
                Write-Host "Unable to copy files while user has Outlook open" -ForegroundColor Red
                Write-Host
                query user /server:$computer
                Write-Host
           }
     Write-Host
     MainMenu
    }
#Get the version of a file
Function GetFileVersion
    {
      $computer = Read-Host "Enter computer name"
      $filepath = Read-Host "Enter path to file (Ex: Program Files\Barracuda\Network Access Client\nacvpn.exe)"
      Write-Host
      (Get-Item "\\$computer\C$\$filepath").VersionInfo.FileVersion
      Write-Host
      MainMenu
        
    }
#Get the Model and RAM of remote system
Function GetModelRam
    {
        $computer = Read-Host "Enter computer name"
        Write-Host
        $query = Get-WmiObject -ComputerName $computer win32_computersystem | select Model, TotalPhysicalMemory
        Write-Host $query
        Write-Host
        MainMenu
    }
#Active Directorty Tools
#To use these tools you must have RSAT installed or Run it from a Domain Controller
Function ADToolsMenu
    {
        #Check to see if Active Directory PowerShell Module is installed.
        $RSATCheck = Get-Module -ListAvailable |  Where-Object {$_.Name -eq "ActiveDirectory"}
        if ($RSATCheck -eq $null)
            {
                Write-host
                Write-Host -ForegroundColor Red "ATTENTION:" 
                Write-Host "You do not have RSAT installed. To run these tools install RSAT or run them from a domain controller"
                Write-Host
            }
        Write-Host "0. Return to Main Menu"
        Write-Host "1. Get Members of a Group"
        Write-Host "2. Get Groups of a User"
        Write-Host "3. Get BitLocker Recovery Key"
        Write-Host "4. Get Last AD replication of server"
        Write-Host
        $Selection = Read-Host "Make a selection"
        switch($Selection)
            {
                "0" {Write-Host;MainMenu}
                "1" {Write-Host;ADToolsGroupMembers}
                "2" {Write-Host;ADToolsMemberGroups}
                "3" {Write-Host;ADToolsGetBitLockerKey}
                "4" {Write-Host;ADToolsLastADReplication}
                default {Write-Host "Invalid Selection";Write-Host;ADToolsMenu}
            }
    }
#Get all the members of a specific group
Function ADToolsGroupMembers
    {
        $ADToolGroup = Read-Host "Enter name of Group"
        $EXCSV = Read-Host "Export to CSV? (Y/N)"
        switch($EXCSV.ToUpper())
            {
                "Y" {$CSVname = Read-Host "Enter path for file";Get-ADGroupMember -identity $ADToolGroup | Export-CSV $CSVname".csv"}
                "N" {Get-ADGroupMember -identity $ADToolGroup}
                default {Write-Host "Invalid Selection";ADToolsGroupMembers}
            }
        Write-Host
        MainMenu
    }
#Get groups of a user
Function ADToolsMemberGroup
    {
        $ADToolUser = Read-Host "Enter user name"
        $EXCSV = Read-Host "Export to CSV? (Y/N)"
        switch($EXCSV.ToUpper())
            {
                "Y" {$CSVname = Read-Host "Enter path for file";Get-ADPrincipalGroupMembership -Identity $ADToolUser | Export-CSV $CSVname".csv"}
                "N" {Get-ADPrincipalGroupMembership -Identity $ADToolUser}
                default {Write-Host "Invalid Selection";ADToolsMemberGroup}
            }
        Write-Host
        MainMenu
    }
Function ADToolsGetBitLockerKey
    {
        $computer = Read-Host "Enter computer name"
        $objComputer = Get-ADComputer $computer
        Write-Host "Check the name for the proper date.";Write-Host
        $Bitlocker_Object = Get-ADObject -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -SearchBase $objComputer.DistinguishedName -Properties 'msFVE-RecoveryPassword'
        $Bitlocker_Object
        If($Bitlocker_Object -eq $null)
            {
                Write-Host "No keys found"
            }
        Write-Host 
        MainMenu
    }
#Find out the last time a DC Replicated
Function ADToolsLastADReplication
    {
        $computer = Read-Host "Enter server name (MUST ENTER FQDN)"
        (Get-ADReplicationPartnerMetadata -Target $computer).LastReplicationSuccess
        Write-Host
        Write-Host "Replication takes place every 3 hours"
        Write-Host
        MainMenu
    }
#Compare two files
#TODO: Make it so a dynamic number of files can be compared
Function FileCompare
    {
        $FiletoCompare1 = Read-Host "Enter path of first file to compare"
        #Remove double quotes from string incase path was dragged and dropped
        $FiletoCompare1 = $FiletoCompare1 -replace '"', ""
        $FiletoCompare2 = Read-Host "Enter path of second file to compare"
        #Remove double quotes from string incase path was dragged and dropped
        $FiletoCompare2 = $FiletoCompare2 -replace '"', ""
        #Compare the hash of each file
        If((Get-FileHash $FiletoCompare1).hash -eq (Get-FileHash $FiletoCompare2).hash)
            {
                Write-Host -foregroundcolor Green "The files are the same"
                Write-Host 
                MainMenu

            }   
          Else 
                    {
                        Write-Host -foregroundcolor Red "The files are different"
                        Write-Host 
                        MainMenu
                    }
            
    }

#Change color of interface
Function InterfaceColor
    {
        Write-Host '
        0 = Black       8 = Gray
        1 = Blue        9 = Light Blue
        2 = Green       A = Light Green
        3 = Aqua        B = Light Aqua
        4 = Red         C = Light Red
        5 = Purple      D = Light Purple
        6 = Yellow      E = Light Yellow
        7 = White       F = Bright White
        '
        $BGColor = Read-Host 'Choose background color'
        $FGColor = Read-Host 'Choose text color'
        & cmd /c color $BGColor$FGColor
        MainMenu
    }

Function MainMenu
    {
        Write-Host ' 1.  List Hotfixes'
        Write-Host ' 2.  Last Boot Time'
        Write-Host ' 3.  Query Logged in User'
        Write-Host ' 4.  Enumerate Processes'
        Write-Host ' 5.  Enumerate Services'
        Write-Host ' 6.  Ping Tools'
        Write-Host ' 7.  OS and Build Version'
        Write-Host ' 8.  Audit Folder/File Permissions'
        Write-Host ' 9.  Audit Folder/File Permissions Recursive'
        Write-Host '10.  Show Firewall Status'
        Write-Host '11.  Get Client IP from DC'
        Write-Host '12.  Open Event Viewer for Remote Computer'
        Write-Host '13.  Open Msinfo32 for Remote Computer'
        Write-Host '14.  Execute Powershell Command (Mainly Only Cmdlets)'
        Write-Host '15.  Execute a Command Prompt Command'
        Write-Host '16.  Spawn a Powershell Shell'
        Write-Host '17.  Spawn Command Prompt Shell'
        Write-Host '18.  Query Logged in User and Notify when Logged Off'
        Write-Host '19.  Connect to File System in Shell'
        Write-Host '20.  Connect to File System in Explorer'
        Write-Host '21.  View Event Log Shell'
        Write-Host '22.  Wake on LAN'
        Write-Host '23.  Remote Connection'
        Write-Host '24.  Get Remote MAC Address'
        Write-Host '25.  Get User SID'
        Write-Host '26.  Get User Name from SID'
        Write-Host '27.  Shutdown/Reboot Remote Computer'
        Write-Host '28.  Enumerate Software'
        Write-Host '29.  Get BitLocker Status'
        Write-Host '30.  Compare Software'
        Write-Host '31.  Run command with PSexec'
        Write-Host '32.  Open Computer Management for Remote Computer'
        Write-Host '33.  Manage Services(Run Elevated for Local Management)'
        Write-Host '34.  Forensics Tools'
        Write-Host '35.  Get File Version'
        Write-Host '36.  Get Model of Computer and RAM size'
        Write-Host '37.  Active Directory Tools'
        Write-Host '38.  Compare Files'
        Write-Host ' C.  Clear Screen'
        Write-Host 'IC.  Change Interface Color'
        Write-Host ' 0.  Exit'
        $selection = Read-Host 'Make a selection'

        switch($selection.ToUpper())
            {
                "1"{HotFixes}
                "2"{LastBoot}
                "3"{UsrQuery}
                "4"{EnumProcessMenu}
                "5"{EnumService}
                "6"{PingMenu}
                "7"{OSandBuild}
                "8"{AuditPermissions}
                "9"{AuditPermissionsRecursive}
                "10"{FirewallStatus}
                "11"{DCIP}
                "12"{RemoteEvents}
                "13"{SysInfo}
                "14"{PSCommand}
                "15"{CMDCommand}
                "16"{powershell;Write-Host;MainMenu}
                "17"{cmd;Write-Host;MainMenu}
                "18"{UsrQueryNotify}
                "19"{ConnectRemoteFSShell}
                "20"{ConnectRemoteFSExplorer}
                "21"{EventLogShell}
                "22"{WOL}
                "23"{RemoteCon}
                "24"{GetMACAddress}
                "25"{GetUserSID}
                "26"{GetUserName}
                "27"{ShutBootRemote}
                "28"{EnumSoftware}
                "29"{BitlockerStatus}
                "30"{CompareSoftware}
                "31"{RunPSexec}
                "32"{Compmgmt}
                "33"{ManageServices}
                "34"{ForensicsMenu}
                "35"{GetFileVersion}
                "36"{GetModelRAM}
                "37"{ADToolsMenu}
                "38"{FileCompare}
                "C"{clear;MainMenu}
                "IC"{InterfaceColor}
                "0"{exit}
                "EXIT"{exit}
                default {Write-Host 'Invalid Selection';Write-Host;MainMenu}
            }
    }
MainMenu