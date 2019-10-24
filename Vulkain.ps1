<#
    .SYNOPSIS
        This script permits to check some security compliance, generate a report.
    
    .DESCRIPTION
        Compile this to exe file and execute it or paste it in a Powershell console 
  
    .NOTES
        This script works in Windows Server and Windows 10 environment. 
		/!\ Need admin rights
 
    
    .LINK
        Useful Link to ressources or others.
 
    .Parameter ParameterName
        No Parameter.
#>

$Pathtmp = "$env:HOMEPATH/Desktop"
cd $Pathtmp

$FileName = "Rapport.txt"
if (Test-Path $FileName) 
{
  Remove-Item $FileName
}

$FileName2 = "Rapport.doc"
if (Test-Path $FileName2) 
{
  Remove-Item $FileName2
}
New-Item -Name Rapport.txt -ItemType File | Out-Null

# Check for admins right needed to execute the script
Function Check_Admin{
Write-Host "[?] Checking for administrative privileges ..`n" -ForegroundColor Yellow

$isAdmin = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    
if(!$isAdmin){
            
            Write-Warning  "[-] Some of the operations need administrative privileges.`n"
            
            Write-Warning  "[*] Please run the script using an administrative account.`n"
            
            Read-Host "Type any key to continue .."

            exit 1
}
cls
}
Check_admin


# Function for coloring text easier
function write-chost($message = ""){
    [string]$pipedMessage = @($Input)
    if (!$message)
    {  
        if ( $pipedMessage ) {
            $message = $pipedMessage
        }
    }
	if ( $message ){
		# predefined Color Array
		$colors = @("black","blue","cyan","darkblue","darkcyan","darkgray","darkgreen","darkmagenta","darkred","darkyellow","gray","green","magenta","red","white","yellow");

		# Get the default Foreground Color
		$defaultFGColor = $host.UI.RawUI.ForegroundColor

		# Set CurrentColor to default Foreground Color
		$CurrentColor = $defaultFGColor

		# Split Messages
		$message = $message.split("#")

		# Iterate through splitted array
		foreach( $string in $message ){
			# If a string between #-Tags is equal to any predefined color, and is equal to the defaultcolor: set current color
			if ( $colors -contains $string.tolower() -and $CurrentColor -eq $defaultFGColor ){
				$CurrentColor = $string          
			}else{
				# If string is a output message, than write string with current color (with no line break)
				write-host -nonewline -f $CurrentColor $string
				# Reset current color
				$CurrentColor = $defaultFGColor
			}
			# Write Empty String at the End
		}
		# Single write-host for the final line break
		write-host
	}
}

# This function write a line
Function Write_line{
Write-Host "---------------------------------------------------------------------------------------------------"
}

# This function return a vulcain in ascii 
Function Vulkain_ascii {

Write-chost "
              #darkgray#(   (( . : (    .)   ) :  )                              
                (   ( :  .  :    :  )  ))                              
                 ( ( ( (  .  :  . . ) )			                                
                  ( ( : :  :  )   )  )				                                 
                   ( :(   .   .  ) .'                                  
                    '. :(   :    )                                     
                      (   :  . )  )                                    
                       ')   :    )#                                 
                      #darkred#@#',#darkred#@##darkred#@##darkred#@#   #darkred#@##darkred#@#      
                     #darkred#@#/ #darkred#@#'#darkred#@#~#darkred#@##darkred#@#~/\        
                   #darkred#@##darkred#@#  #darkred#@##darkred#@##darkred#@# #darkred#@##darkred#@##darkred#@##darkred#@#  `..#darkred#@#,                                 
                 #darkred#@##darkred#@#/  #darkred#@##darkred#@##darkred#@#   _#darkred#@##darkred#@#     `\                                 
               #darkred#@##darkred#@##darkred#@#;  `#darkred#@#~._.' #darkred#@##darkred#@##darkred#@#      \_                               
             .-#darkred#@#/           #darkred#@##darkred#@##darkred#@##darkred#@##darkred#@#--,_,--\                              
            / `#darkred#@##darkred#@##darkred#@#..,     .~#darkred#@##darkred#@##darkred#@#'         `~.                           
          _/         `-.-' #darkred#@##darkred#@##darkred#@##darkred#@##darkred#@##darkred#@##darkred#@#          \                          
       __/     ^^^       ^#darkred#@#^#darkred#@##darkred#@#~#darkred#@##darkred#@#__.   ^     \_                        
      /       ^^ ^^      #darkred#@##darkred#@#^#darkred#@##darkred#@##darkred#@##darkred#@#^^#darkred#@##darkred#@#____  ^    \                       
    ~/         ^^^    ^^^   ^^   ^^^^  __. ^^^   `~._                   
 .-'   ^^    ^^^. _^   ___^     ^^   ^^ ^^   ^^     \                  
/   ^^^ ___^^^ - ^ ^^       ^ ___ ^____^^ . ^^^^^   `~.  "    



}


# This function return the menu and a vulcain eruption 
Function Menu{
Vulkain_ascii
Write-Host "`n`nVulkain v1.0 (25/01/2019)" -ForeGroundColor darkred
Write-Host "Author: LEGUY Olivier | IDIRI Sami | RAKOTOMALALA Manase | SOYEZ Pol"
Write-Host "Powered by Obsidian Security"
Write-Host "contact : contact@obsidiansecurity.eu`n"

do {
    try {
        $OK = $true
		Write-Host "Press" -NoNewline
		Write-Host " [1] " -ForeGroundColor Yellow -NoNewline
		Write-Host "to launch the programm or Press" -NoNewline
		Write-Host " [0] " -ForegroundColor Yellow -NoNewline
		Write-Host "to exit: " -NoNewline
		$Rep = Read-Host
        } # end try
    catch {$OK = $false}
    } # end do 
until (($Rep -eq "1" -or $Rep -eq "0") -and $OK)

if ($Rep -eq "0"){
exit 0
}elseif ($Rep -eq "1"){
cls


Write-Host "Vulkain is about to erupt WATCH OUT ..." -ForeGroundColor Red
Start-sleep -s 4
cls
1..6000 | foreach {Write-Host " " -BackgroundColor (Get-Random 'DarkRed','Red') -NoNewline}
}
}

Menu
   
cls

$ComputerSystem = Get-CimInstance CIM_ComputerSystem
$ComputerSystemInfo = Get-WmiObject -Class Win32_ComputerSystem 
$Model = $ComputerSystemInfo.Manufacturer + " " + $ComputerSystemInfo.Model
$ComputerName = hostname
$Username = whoami
$Domain = $ComputerSystem.Domain
$W = (gwmi win32_operatingsystem).caption
$Winversion_release = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ReleaseId).ReleaseId | Out-Null
$Winversion = $W + " version " + $Winversion_release

# Those line permits to generate the report introduction which show an ascii title and some information of the system in the Rapport.txt file

$date = Get-date -Format "dd/MM/yyyy"

echo "
`t`t`t _____                      _  _
`t`t`t|   __| ___  ___  _ _  ___ |_|| |_  _ _
`t`t`t|__   || -_||  _|| | ||  _|| ||  _|| | |
`t`t`t|_____||___||___||___||_|  |_||_|  |_  |
`t`t`t                                   |___|
`t`t`t
`t`t`t     _____                      _
`t`t`t    | __  | ___  ___  ___  ___ | |_
`t`t`t    |    -|| -_|| . || . ||  _||  _|
`t`t`t    |__|__||___||  _||___||_|  |_|
`t`t`t                |_|                       " | Out-File Rapport.txt -Append 
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append
echo "Date : $date" | Out-File Rapport.txt -Append
echo "OS Version : $Winversion `r`nModel : $Model`r`nName: $ComputerName`r`nUser logged in : $Username`r`nDomain : $Domain`r`n" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r" | Out-File Rapport.txt -Append


										################################
										##        Check Functions	####
										################################

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

# Function which check SMBv1 Protocol status on the system
function Check_SMB {

echo "`r" | Out-File Rapport.txt -Append
echo "______________________________________________________________`r`n" | Out-File Rapport.txt -Append
echo "------------------------SMBv1 check--------------------------" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append

Try {
$check_smb1 = $(Get-SmbServerConfiguration | Select EnableSMB1Protocol).EnableSMB1Protocol

switch ( $check_smb1 ) 
{"True" 
{$Return_smb1 = "$([char]0x26A0) | SMB1 protocol is enable on the system"
Write-Host "[/!\] SMB1 protocol is enable on the system" -ForegroundColor Red
}

"False"
{$Return_smb1 = "$([char]0x2713) | SMB1 protocol is disable on the system"
Write-Host "[OK] SMB1 protocol is disable on the system" -ForegroundColor Green
}
}}Catch {
Write-Host "/!\ Error when checking SMBv1 protocol status /!\" -Foreground Red
$Return_smb1 = "/!\ Error when checking SMBv1 protocol status /!\" 
}

echo $Return_smb1 | Out-File Rapport.txt -Append
}

## Reco ###########################################################################################################
# Disable SMB1 : 
# In a powershall admin prompt execute this command :
# Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol												
###################################################################################################################

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

# Function which check the bitlocker disk encryption status of the different drives of the system

function Check_Bitlocker{

echo "`r" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append
echo "-----------------Bitlocker encryption check------------------" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append


Try {
$list_of_drive = wmic logicaldisk get name | Select-String -Pattern "Name" -NotMatch 
$clear_list = $list_of_drive.Where({ -not [string]::IsNullOrWhiteSpace($_) })
foreach ($drive in $clear_list)
		{
			
			$drive = $drive -replace '\s',''
			$Output = Get-BitlockerVolume -MountPoint $drive
			if ($Output.volumeType -eq "OperatingSystem" -And $Output.volumestatus -ne "FullyEncrypted"){
			Write-Host "[/!\] The disk $drive which contain the Operating system is not encrypted" -ForegroundColor Red
			echo "$([char]0x26A0) | The disk $drive which contain the Operating system is not encrypted" | Out-File Rapport.txt -Append
			} elseif ($Output.volumeType -ne "OperatingSystem" -And $Output.volumestatus -ne "FullyEncrypted"){
			Write-Host "[/!\] The disk $drive is not encrypted" -ForegroundColor Red
			echo "$([char]0x26A0) | The disk $drive is not encrypted" | Out-File Rapport.txt -Append
			} else {
			Write-Host "[OK] The disk $drive is encrypted" -ForegroundColor Green
			echo "$([char]0x2713) | The disk $drive is encrypted" | Out-File Rapport.txt -Append}			
		}
		
}Catch {
Write-Host "/!\ Error when checking bitlocker disk encryption /!\" -Foreground Red
echo "/!\ Error when checking bitlocker disk encryption /!\" | Out-File Rapport.txt -Append
} 
}

## Reco ####################################################################################################################
#Encrypt all of your drive with Bitlocker
############################################################################################################################

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

# Function which check Netbios Protocol status on the system
# Netbios protocol

function Check_Netbios{
echo "`r" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append
echo "------------------------Netbios check------------------------" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append

Try {
$check_netbios = "0"

$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey | foreach { $Currentkey = get-ItemProperty -Path "$regkey\$($_.pschildname)"

$Netbios_current_status = $Currentkey.NetbiosOptions
if ($Netbios_current_status -ne "2"){
$check_netbios = "1"
}
}
if ($check_netbios -eq "0"){
write-host "[OK] The Netbios protocol is disable" -ForeGroundColor Green
$Return_netbios = "$([char]0x2713) | Netbios protocol is disable on the system"
}else{
write-host "[/!\] The Netbios protocol is enable" -ForeGroundColor Red
$Return_netbios = "$([char]0x26A0) | Netbios protocol is enable on the system"
}

}Catch {
Write-Host "/!\ Error when checking Netbios /!\" -Foreground Red
$Return_netbios = "/!\ Error when checking Netbios /!\"
}

echo $Return_netbios | Out-File Rapport.txt -Append
}

## Reco #######################################################################################################################
# If you don't need it disable Netbios :
# execute this two line in a powershell admin prompt
# $regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
# Get-ChildItem $regkey |foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose
###############################################################################################################################

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

# Function which check the user access control status on the system

function Check_UAC {

echo "`r" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append
echo "-------------------------UAC check---------------------------" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append

Try {
   #Checking for UAC configuration
   $UACRegValues = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
   if([int]$UACRegValues.EnableLUA -eq 1){
   $Check_UAC = "1"
   $UAC_Status_On = "UAC is enabled"
   }else{
   $Check_UAC = "0"
   $UAC_Status_Off = "UAC is disabled"
   }                    
   
   #Checking for UAC level
   $consentPrompt=$UACregValues.ConsentPromptBehaviorAdmin
   $secureDesktop=$UACregValues.PromptOnSecureDesktop
		if( $consentPrompt -eq 0 -and $secureDesktop -eq 0){
			$UAC_Ok = "0"
			$UAC_level = "UAC Level is set at Never Notify"
        }elseif($consentPrompt -eq 5 -and $secureDesktop -eq 0){	
			$UAC_Ok = "0"
            $UAC_level = "UAC Level is set at Notify only when apps try to make changes (No secure desktop)."
        }elseif($consentPrompt -eq 5 -and $secureDesktop -eq 1){
			$UAC_Ok = "1"
            $UAC_level = "UAC Level is set at Notify only when apps try to make changes (secure desktop on)."
        }elseif($consentPrompt -eq 2 -and $secureDesktop -eq 1){
			$UAC_Ok = "1"
            $UAC_level = "UAC Level is set at Always Notify with secure desktop."
		}
	
	#Define Secure UAC status
		if ($Check_UAC -eq "0"){
			Write-Host "[/!\] $UAC_Status_Off" -ForeGroundColor Red
			$Return_UAC = "$([char]0x26A0) | $UAC_Status_Off"
		}elseif($Check_UAC -eq "1" -And $UAC_Ok -eq "0"){
			Write-Host "[/!\] $UAC_Status_On `n`r     $UAC_level" -ForeGroundColor Red
			$Return_UAC = "$([char]0x26A0) | $UAC_Status_On `n`r    $UAC_level"
		}elseif($Check_UAC -eq "1" -And $UAC_Ok -eq "1"){
			Write-Host "[OK] $UAC_Status_On `n`r     $UAC_level" -ForeGroundColor Green
			$Return_UAC = "$([char]0x2713) | $UAC_Status_On `n`r    $UAC_level"
		}
}Catch {
Write-Host "/!\ Error when trying to check the UAC status /!\ " -Foreground Red
$Return_UAC = "/!\ Error when trying to check the UAC status /!\"
}
#Write UAC status to report
echo $Return_UAC | Out-File Rapport.txt -Append
}

#### Reco ##################################################################################################################
# Enable UAC if its not and set it up to Always Notify with secure desktop or 
# at least to Notify only when apps try to make changes (secure desktop on).
############################################################################################################################

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

# Function which check the Autorun feature status on the system.

function Check_Autorun { 

echo "`r" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append
echo "------------------------Autorun check------------------------" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append


$regkey = "HKCU:Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\"

$check_Autorunkey = Test-Path -Path $regkey
if ($check_Autorunkey  -eq $False){


write-host "[/!\] The Autorun features is enable on the system" -ForeGroundColor Red
$Return_Autorun = "$([char]0x26A0) | Autorun features is enable on the system"


}else{


Try {
$check_Autorun = "0"

Get-ChildItem $regkey | foreach { $Currentkey = get-ItemProperty -Path "$regkey"

$Autorun_current_status = $Currentkey.NoDriveTypeAutoRun
if ($Autorun_current_status -ne "FF"){
$check_Autorun = "1"
}
}
if ($check_Autorun -eq "0"){
write-host "[OK] The Autorun features is disable" -ForeGroundColor Green
$Return_Autorun = "$([char]0x2713) | Autorun features is disable on the system"
}else{
write-host "[/!\] The Autorun features is enable" -ForeGroundColor Red
$Return_Autorun = "$([char]0x26A0) | Autorun features is enable on the system"
}
echo $Return_Autorun | Out-File Rapport.txt -Append

}Catch {Write-Host "/!\ Error when checking Autorun /!\" -Foreground Red}
}
}
### Reco ###################################################################################################################
# Turn off AutoRun
# HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun
# Change the value to 'FF' 
############################################################################################################################

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

# Function which check the Antivirus status on the system

function Check_AV {

echo "`r" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append
echo "-----------------------Antivirus check-----------------------" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append

    function Get-AVStatus {
    [CmdletBinding()]
    param (
    [parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [Alias('name')]
    $computername=$env:computername


    )

    #$AntivirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Query $wmiQuery  @psboundparameters # -ErrorVariable myError -ErrorAction 'SilentlyContinue' # did not work            
     $AntiVirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct  -ComputerName $computername

    $ret = @()
    foreach($AntiVirusProduct in $AntiVirusProducts){
        switch ($AntiVirusProduct.productState) {
		"262144" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
		"262160" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
		"266240" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
		"266256" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
		"393216" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
		"393232" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
		"393488" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
		"397312" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
		"397328" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
		"397584" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
		"397568" {$defstatus = "Up to date"; $rtstatus = "Enabled"}
		"393472" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
		"401664" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
        default {$defstatus = "Unknown" ;$rtstatus = "Unknown"}
            }

        #Create hash-table for each computer
        $ht = @{}
        $ht.Computername = $computername
        $ht.Name = $AntiVirusProduct.displayName
        $ht.'Product GUID' = $AntiVirusProduct.instanceGuid
        $ht.'Product Executable' = $AntiVirusProduct.pathToSignedProductExe
        $ht.'Reporting Exe' = $AntiVirusProduct.pathToSignedReportingExe
        $ht.'Definition Status' = $defstatus
        $ht.'Real-time Protection Status' = $rtstatus


        #Create a new object for each computer
        $ret += New-Object -TypeName PSObject -Property $ht 
    }
    Return $ret
}


$Av_status = Get-AVStatus
$AVName = $Av_status.Name
# $AVState = $Av_status.Enabled
$AVstate = ($Av_status).'Real-time Protection Status'
if ($Avstate -ne "Disabled" -And -Not($AvName -eq $Null -Or [string]::IsNullOrEmpty($AVName) -Or $AVName -eq " ")){
Write-Host "[OK] The antivirus $AVName is running" -ForeGroundColor Green
echo "$([char]0x2713) | The antivirus $AVName is running" | Out-File Rapport.txt -Append
}else{
Write-Host "[/!\] There is no antivirus on the system" -ForeGroundColor Red
echo "$([char]0x26A0) | There is no active antivirus on the system" | Out-File Rapport.txt -Append
}
}

## Reco ####################################################################################################################
# Install an Antivirus 
############################################################################################################################

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

# Function which check the presence of unattend file on the system

function Check_Unattend_Files {
 
echo "`r" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append
echo "--------------------Unattend files check---------------------" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append

$found = $false
$targetFiles = @(
                            "C:\unattended.xml",
                            "C:\Windows\Panther\unattend.xml",
                            "C:\Windows\Panther\Unattend\Unattend.xml",
                            "C:\Windows\System32\sysprep.inf",
                            "C:\Windows\System32\sysprep\sysprep.xml"

        )

#Checking for unattended install leftovers

try{
	$targetFiles | ? {$(Test-Path $_) -eq $true} | %{
		$found=$true; 
		Write-Host "[/!\] Unattended install file were found : $_" -ForeGroundColor Red
		$Return_Ufile = "$([char]0x26A0) | Unattended install file were found : $_"
	}
		if(!$found){
			Write-Host "[OK] No unattended install files were found" -ForeGroundColor Green
			$Return_Ufile = "$([char]0x2703) | No unattended install files were found"
                 }
        }catch{
Write-Host "/!\ Error when trying to check the Unattended files /!\ " -Foreground Red
$Return_UFile = "/!\ Error when trying to check the Unattented files /!\"
}
#Write to report
echo $Return_UFile | Out-File Rapport.txt -Append
}


## Reco ############################################################################################
# 
# Just delete the file(s)
####################################################################################################

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

# Function which list listening port

function Check_Listening_Port{
echo "`r" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append
echo "---------------------Listening port check--------------------" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append

function Get-Listening_Port {
[OutputType('System.Management.Automation.PSObject')]
$properties = 'Protocol','State','ProcessName','LocalPort'
$processes = Get-Process | select name, id
$results = netstat -ano | Select-String -Pattern '\s+(LISTENING)'
foreach($result in $results) {
	$item = $result.line.split(' ',[System.StringSplitOptions]::RemoveEmptyEntries)
    if($item[1] -notmatch '^\[::'){
	$localPort = $item[1].split(':')[-1]
	$procId = $item[-1]
	$proto = $item[0]
	$status = if($item[0] -eq 'tcp') {$item[3]} else {$null}	
		if($procName = $processes | Where {$_.id -eq $procId} | select -ExpandProperty name ){ }
		else {$procName = "Unknown"}
New-Object -TypeName PSObject -Property @{
ProcessName = $procName
Protocol = $proto
LocalPort = $localPort
State = $status
} | Select-Object -Property $properties								
}
}
}
	
$Listening_Port = (Get-Listening_Port)
$count = $Listening_Port.count - 1

try {
for ($i=0;$i -lt $count ; $i++) {
if ($Listening_port[$i].LocalPort -notmatch "443" -And $Listening_port[$i].ProcessName -notmatch "svchost|System|lsass|ManagementAgentNT|swi_fc|SCNotification|spoolsv|wininit|services|RouterNT" -And $Listening_port[$i].LocalPort -ne $Listening_port[$i+1].LocalPort){
Write-Host "[?] The port n°" -ForeGroundColor Yellow $Listening_port[$i].LocalPort"is listening it's used by"$Listening_port[$i].ProcessName"process "  
echo "$([char]0x2754) |The port n°"$Listening_port[$i].LocalPort | Out-File Rapport.txt -Append -NoNewline
echo " is listening it's used by "$Listening_port[$i].ProcessName | Out-File Rapport.txt -Append -NoNewline
echo " process." | Out-File Rapport.txt -Append -NoNewline
echo "`r`n" | Out-File Rapport.txt -Append
}
}
}catch {
Write-Host "/!\ Error when trying to check the listening port /!\ " -Foreground Red
echo "/!\ Error when trying to check to check the listening port /!\" | Out-File Rapport.txt -Append
}
}

## Reco ####################################################################################################################
# 
# Look at listening port and watch if everything is ok.
############################################################################################################################

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

# Function which check the IPv6 status on each network interfaces 

function Check_IPV6{

echo "`r" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append
echo "-------------------------IPv6 check--------------------------" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append

Try {
$Network_card_IPv6 = Get-NetAdapterBinding | where {$_.ComponentID -match 'ip6'}

$count = $Network_card_IPv6.count - 1

for ($i=0;$i -lt $count; $i++) {
	if ($Network_card_IPv6[$i].Enabled -eq "True"){
	Write-Host "[/!\] Ipv6 is active on the Network card :" -ForegroundColor Red $Network_card_IPv6[$i].Name
	echo "$([char]0x26A0) | Ipv6 is active on the Network card : " $Network_card_IPv6[$i].Name | Out-File Rapport.txt -Append -NoNewline
	echo "`r`n" | Out-File Rapport.txt -Append}
	else{
	Write-Host "[OK] Ipv6 is not active on the Network card :" -ForegroundColor Green $Network_card_IPv6[$i].Name
	echo "$([char]0x2713) | Ipv6 is not active on the Network card : " $Network_card_IPv6[$i].Name | Out-File Rapport.txt -Append -NoNewline
	echo "`r`n" | Out-File Rapport.txt -Append}
	
	}	

}Catch {
Write-Host "[/!\] Error when checking IPv6 status [/!\]" -Foreground Red
echo "/!\ Error when checking IPv6 status /!\" | Out-File Rapport.txt -Append
} 

}

### Reco #################################################################################################################################################
#Disable IPv6 on all the interfaces
#New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\' -Name  'DisabledComponents' -Value '0xffffffff' -PropertyType 'DWord'
##########################################################################################################################################################

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

# Function which check autoruns programm stored in registry keys. 

function Check_Autoruns_regkeys{
 
echo "`r" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append
echo "--------------------Autoruns regkey check--------------------" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append

$RegistryKeys = @( 
	"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
	"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
    "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell",
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices\",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows\load",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler",
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs"# DLLs specified in this entry can hijack any process that uses user32.dll        
    )

	$exits=$false
	
	#Checking registry keys for autoruns
	try{
		$RegistryKeys | %{
			$key = $_
			if(Test-Path -Path $key){
				$executables = @{}
				[array]$properties = get-item $key | Select-Object -ExpandProperty Property
				if($properties.Count -gt 0){
					
					$Return_Autoruninreg = "$([char]0x2754) | Autoruns regkey found : $key"
					Write-Host "[?] Autoruns regkey found : `n$key" -ForeGroundColor Yellow
					echo $Return_Autoruninreg | Out-File Rapport.txt -Append
					foreach($exe in $properties) {
						$executables[$exe]=$($($(Get-ItemProperty $key).$exe)).replace('"','')
					}
					$R = $executables | ft  @{Expression={$_.Value};Label="Path :"}
					$R | Out-File Rapport.txt -Append
                       $exits=$true
                    }
                }
        }
        
		if($exits -eq $false){
		Write-Host "No autoruns are found in regkeys" -ForeGroundColor Green
		$Return_Autoruninreg = "$([char]0x2713) | No autoruns are found in regkeys" 
        }
	}Catch {	
Write-Host "/!\ Error when trying to check the Autoruns regkeys  /!\ " -Foreground Red
$Return_Autoruninreg = "/!\ Error when trying to check the Autoruns regkeys /!\"
}
}

### Reco ###############################################################################################################
#Make sure that the programm which are launched automatically thanks to this method are legit.
#If it's not the case, delete the key
########################################################################################################################

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

# Function which check the LLMNR protocol status on the system.

function Check_LLMNR {

echo "`r" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append
echo "------------------------LLMNR check--------------------------" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append

$key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"

$check_DNSkey = Test-Path -Path $key
if ($check_DNSkey -eq $False){

$Return_LLMNR = "$([char]0x26A0) | LLMNR protocol is enable on the system"
Write-Host "[/!\] LLMNR protocol is enable on the system" -ForegroundColor Red

}else{

Try {
$LLMNR_status = (Get-ItemProperty $key).EnableMulticast

if ($LLMNR_status -eq "0"){
	$Return_LLMNR = "$([char]0x2713) | LLMNR protocol is disable on the system"
	Write-Host "[OK] LLMNR protocol is disable on the system" -ForegroundColor Green

}else{
	$Return_LLMNR = "$([char]0x26A0) | LLMNR protocol is enable on the system"
	Write-Host "[/!\] LLMNR protocol is enable on the system" -ForegroundColor Red

}
}Catch {
Write-Host "/!\ Error when checking LLMNR status /!\" -Foreground Red
$Return_LLMNR = "/!\ Error when checking LLMNR status /!\" 
}

}
echo $Return_LLMNR | Out-File Rapport.txt -Append
}

### Reco ###############################################################################################################
#Disable the LLMNR protocol.
#
########################################################################################################################

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
 
# Function which check the firewall status on the system.

function Check_FW {

echo "`r" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append
echo "-----------------------Firewall check------------------------" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append

Try {
$FW_Status = @(netsh advfirewall show currentprofile)[3] 
$RGX_FW_Status = $FW_Status -replace 'État' -replace '\s' 

if ($RGX_FW_Status -eq "Actif"){
	$Return_FW = "$([char]0x2713) | The Windows firewall is enable on the system"
	Write-Host "[OK] The Windows firewall is enable on the system" -ForegroundColor Green

}else{
	$Return_FW = "$([char]0x26A0) | The Windows firewall is disable on the system"
	Write-Host "[/!\] The Windows firewall is disable on the system" -ForegroundColor Red
}
}Catch {
Write-Host "/!\ Error when checking the Windows firewall status /!\" -Foreground Red
$Return_FW = "/!\ Error when checking the Windows firewall status /!\" 
}

echo $Return_FW | Out-File Rapport.txt -Append
}

### Reco ###############################################################################################################
# Turn on the Windows firewall
########################################################################################################################

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

# SOFTWARE versions check

Function Get-Software  {
  [OutputType('System.Software.Inventory')]
  $Paths  = @("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall","SOFTWARE\\Wow6432node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")         
  ForEach($Path in $Paths) { 
  Write-Verbose  "Checking Path: $Path"
  $reg = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
  Try  {
	$regkey=$reg.OpenSubKey($Path)  
	$subkeys=$regkey.GetSubKeyNames()      
	ForEach ($key in $subkeys){   
		Write-Verbose "Key: $Key"
		$thisKey=$Path+"\\"+$key 
			Try {  
			$thisSubKey=$reg.OpenSubKey($thisKey)   
			$DisplayName =  $thisSubKey.getValue("DisplayName")
			If ($DisplayName -AND $DisplayName -notmatch '^Update  for|rollup|^Security Update|^Service Pack|^HotFix') {
				$Version = Try {
				$thisSubKey.GetValue('DisplayVersion').TrimEnd(([char[]](32,0)))
				} 
				Catch {
				$thisSubKey.GetValue('DisplayVersion')
				}
				  $Object = [pscustomobject]@{
				  DisplayName = $DisplayName
				  Version  = $Version
				  }
				  $Object.pstypenames.insert(0,'System.Software.Inventory')
				  Write-Output $Object
			}
  } Catch {
  Write-Warning "$Key : $_"
  }   
  }
  } Catch  {}    
  }  
  } 

Function Get-Software-Version{
$Software_name = $args[0]
$Check_CVE_link = $args[1]
$prefixe = $args[2]
$check_software = Get-Software | Where-Object {$_.DisplayName -Match "$Software_name"}
if ($check_software -eq $Null -Or [string]::IsNullOrEmpty($check_software)){
Write-Host "$Software_name is not installed `r`n" -ForeGroundColor Yellow
}else{
		$Software_version = $check_software[0].version
		$Software_Full_name = $check_software[0].DisplayName
		Write-Host "$Software_Full_name version $Software_version is installed on the system.`r`nStarting of the version check ..." -ForegroundColor Black -BackgroundColor Yellow
		$check_cve = (iwr $Check_CVE_link -UseBasicParsing).rawcontent -match "$prefixe$Software_version"
		if ($check_cve -eq "True"){
			Write-Host "[/!\] $Software_name has to be updated the version $Software_version has known security breaches`r`n" -ForeGroundColor Red
			echo " $([char]0x26A0) | $Software_name has to be updated the version $Software_version has known security breaches " | Out-File Rapport.txt -Append
		}else{
			Write-Host "[OK] $Software_name version $Software_version is secure `r`n" -ForeGroundColor Green
			echo " $([char]0x2713) | $Software_Full_name version $Software_version is secure`r`n" | Out-File Rapport.txt -Append
			}
}
}


### Reco ###############################################################################################################
# Get all the software up to date for security patches.
########################################################################################################################

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

						#######################################
						## Specific check for Windows server ##
						#######################################

# Function which check the null session status on shared folder on the system.

function Check_NullSessionAccess {

echo "`r" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append
echo "--------------Null session shared folder check---------------" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append

$key = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"

if (Get-ItemProperty -Path $key -Name restrictnullsessaccess -ErrorAction SilentlyContinue){
	Try {
	$Nullsession_status = (Get-ItemProperty $key).restrictnullsessaccess

	if ($Nullsession_status -eq "0"){
		$Return_NullSession = "$([char]0x2713) | Null session shared folder is disable on the system"
		Write-Host "[OK] Null session shared folder is disable on the system" -ForegroundColor Green

	}else{
		$Return_NullSession = "$([char]0x26A0) | Null session shared folder is enable on the system"
		Write-Host "[/!\] Null session shared folder is enable on the system" -ForegroundColor Red

	}
	}Catch {
	Write-Host "/!\ Error when checking null session shared folder status /!\" -Foreground Red
	$Return_NullSession = "/!\ Error when checking null session shared folder status /!\" 
	}

}else{
$Return_NullSession = "$([char]0x26A0) | DNS service socket cache is enable on the system"
Write-Host "[/!\] DNS service socket cache is enable on the system" -ForegroundColor Red
}
echo $Return_NullSession | Out-File Rapport.txt -Append
}

### Reco ###############################################################################################################
# Get all the software up to date for security patches.
########################################################################################################################

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#


# Windows Server check

if ($Winversion -like '*Server*'){
	cls
	Write-Host "Windows server detected" -ForegroundColor Yellow
	Write-Host "OS Version : `r$Winversion`n`rModèle : $Model`r`nComputer Name: $ComputerName`n`rUser logged in : $Username`n`rDomain : $Domain"
	
	clear
	Write-Host "`n[x] Starting of Windows server checks ...`n" -ForegroundColor Black -BackgroundColor Yellow 
	
		
#####################
#    SMBv1 Check    #
#####################

Check_SMB

Write_line

#####################
##### NETBIOS #######
#####################

Check_Netbios

Write_line

##############################
##			LLMNR			##
##############################

Check_LLMNR

Write_line

##################################
## Bitlocker encryption check   ##
##################################

Check_Bitlocker

Write_line		

############################
##     Firewall check 	  ##
############################

Check_FW

Write_line

############################
## Active Antivirus check ##
############################

Check_AV

Write_line

#################
##  UAC check  ##
#################

Check_UAC

Write_line

##############
## Autorun ###
############## 

Check_Autorun

Write_line

##########################
## Null Session access ###
##########################

Check_NullSessionAccess

Write_line

##############################
##		Listening port		##
##############################

Check_Listening_Port

Write_line

##############################
##			IPv6			##
##############################

Check_IPV6

Write_line		

##############################
##   Check autoruns regkey  ##
##############################

Check_Autoruns_regkeys

Write_line
	
########################
##  Software Version  ##
########################

Write-Host "`n Software version checks" -ForegroundColor Black -BackgroundColor Blue 
Write_line
#Check Internet Connection
$Check_Internet = (test-connection 8.8.8.8 -Count 2 -Quiet)
$Check_CVE_Website = (test-connection cve.circl.lu -Count 2 -Quiet)
if ($Check_Internet -eq $True){
# Write-Host "Check of the Internet connection is successful" -ForeGroundColor Green
	if($Check_CVE_Website -eq $True){
		# Write-Host "Connection to CVE source established start of the different software check ..." -ForeGroundColor Yellow

echo "`r" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append
echo "-------------------Software version check--------------------" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append
	
		
# Wireshark version check
# old version : https://www.wireshark.org/download/win64/all-versions/
Get-Software-Version "Wireshark" "https://cve.circl.lu/api/search/wireshark" "wireshark:"

#Oracle Java version check
# old version : https://www.oracle.com/technetwork/java/archive-139210.html
Get-Software-Version "Java" "https://cve.circl.lu/api/search/oracle/jre" "jre:"

# Adobe Acrobat Reader check
#old version : ftp://ftp.adobe.com/pub/adobe/reader/win/
Get-Software-Version "Adobe Acrobat Reader" "https://cve.circl.lu/api/search/adobe/acrobat_reader" "acrobat_reader_dc:"

# Adobe Flash Player check
#old version : https://helpx.adobe.com/fr/flash-player/kb/archived-flash-player-versions.html
Get-Software-Version "Adobe Flash Player" "https://cve.circl.lu/api/search/adobe/flash_player" "adobe:flash_player:"

#old version https://ftp.mozilla.org/pub/firefox/releases/
# Mozilla Firefox version checks
Get-Software-Version "Mozilla Firefox" "https://cve.circl.lu/api/search/mozilla/firefox" "firefox:"

# Thunderbird version checks
Get-Software-Version  "Thunderbird" "https://cve.circl.lu/api/search/mozilla/firefox" "thunderbird:"	

# VLC
Get-Software-Version  "VLC" "https://cve.circl.lu/api/search/videolan/vlc" "vlc_media_player:"	

# Microsoft Silverlight
Get-Software-Version  "Silverlight" "https://cve.circl.lu/api/search/microsoft/silverlight" "silverlight:"	

	}else{
		Write-Host "CVE source is unreacheable ..." -ForeGroundColor Red
	}
}else{
Write-Host "No Internet connection unable to proceed to softwares check" -ForeGroundColor Red
}

##########

Write_line
Start-sleep -s 2

#######################################
## Conversion to Word 				  #
#######################################

Write-Host "`n[x] Report Generation ...`n" -ForegroundColor Black -BackgroundColor Yellow 
Start-sleep -s 4

Function Convert_to_doc{
Try {
ren Rapport.txt Rapport.doc
Write-Host "Report has succesfully been converted and can be consulted to this location :`n`r $Pathtmp" -ForeGroundColor Yellow
Start-sleep -s 4
#ii $Pathtmp
#ii "$Pathtmp\Rapport.doc"
write "$Pathtmp\Rapport.doc"
} 
Catch{
Write-Host "/!\ Error when trying to convert the report to Doc /!\"
}
}

Convert_to_doc

# Windows client check

}else{
	cls
	Write-Host "Windows Client detected`n" -ForegroundColor Yellow
	Write-Host "OS Version : `r$Winversion`n`rModèle : $Model`r`nComputer Name: $ComputerName`n`rUser logged in : $Username`n`rDomain : $Domain"
	Start-sleep -s 2
    Write-Host "`n[x] Starting of Windows client checks ...`n" -ForegroundColor Black -BackgroundColor Yellow 
	Start-sleep -s 2

	
#####################
#    SMBv1 Check    #
#####################

Check_SMB

Write_line


#####################
##### NETBIOS #######
#####################

Check_Netbios

Write_line


##############################
##			LLMNR			##
##############################

Check_LLMNR

Write_line



##################################
## Bitlocker encryption check   ##
##################################

Check_Bitlocker

Write_line		


############################
##     Firewall check 	  ##
############################

Check_FW

Write_line


############################
## Active Antivirus check ##
############################

Check_AV

Write_line


#################
##  UAC check  ##
#################

Check_UAC

Write_line


##############
## Autorun ###
############## 

Check_Autorun

Write_line


#########################
## Unattend files check #
#########################

Check_Unattend_Files

Write_line


##############################
##		Listening port		##
##############################

Check_Listening_Port

Write_line


##############################
##			IPv6			##
##############################

Check_IPV6

Write_line		


##############################
##   Check autoruns regkey  ##
##############################

Check_Autoruns_regkeys

Write_line


########################
##  Software Version  ##
########################


Write-Host "`n Software version checks" -ForegroundColor Black -BackgroundColor Blue 
Write_line
#Check Internet Connection
$Check_Internet = (test-connection 8.8.8.8 -Count 2 -Quiet)
$Check_CVE_Website = (test-connection cve.circl.lu -Count 2 -Quiet)
if ($Check_Internet -eq $True){
# Write-Host "Check of the Internet connection is successful" -ForeGroundColor Green
	if($Check_CVE_Website -eq $True){
		# Write-Host "Connection to CVE source established start of the different software check ..." -ForeGroundColor Yellow

echo "`r" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append
echo "-------------------Software version check--------------------" | Out-File Rapport.txt -Append
echo "_____________________________________________________________`r`n" | Out-File Rapport.txt -Append
	
		
# Wireshark version check
# old version : https://www.wireshark.org/download/win64/all-versions/
Get-Software-Version "Wireshark" "https://cve.circl.lu/api/search/wireshark" "wireshark:"

#Oracle Java version check
# old version : https://www.oracle.com/technetwork/java/archive-139210.html
Get-Software-Version "Java" "https://cve.circl.lu/api/search/oracle/jre" "jre:"

# Adobe Acrobat Reader check
#old version : ftp://ftp.adobe.com/pub/adobe/reader/win/
Get-Software-Version "Adobe Acrobat Reader" "https://cve.circl.lu/api/search/adobe/acrobat_reader" "acrobat_reader_dc:"

# Adobe Flash Player check
#old version : https://helpx.adobe.com/fr/flash-player/kb/archived-flash-player-versions.html
Get-Software-Version "Adobe Flash Player" "https://cve.circl.lu/api/search/adobe/flash_player" "adobe:flash_player:"

#old version https://ftp.mozilla.org/pub/firefox/releases/
# Mozilla Firefox version checks
Get-Software-Version "Mozilla Firefox" "https://cve.circl.lu/api/search/mozilla/firefox" "firefox:"

# Thunderbird version checks
Get-Software-Version  "Thunderbird" "https://cve.circl.lu/api/search/mozilla/firefox" "thunderbird:"	

# VLC
Get-Software-Version  "VLC" "https://cve.circl.lu/api/search/videolan/vlc" "vlc_media_player:"	

# Microsoft Silverlight
Get-Software-Version  "Silverlight" "https://cve.circl.lu/api/search/microsoft/silverlight" "silverlight:"	

	}else{
		Write-Host "CVE source is unreacheable ..." -ForeGroundColor Red
	}
}else{
Write-Host "No Internet connection unable to proceed to softwares check" -ForeGroundColor Red
}

##########
##########

Write_line
Start-sleep -s 2

#######################################
#######################################
## Conversion to Word #
#######################################

Write-Host "`n[x] Report Generation ...`n" -ForegroundColor Black -BackgroundColor Yellow 
Start-sleep -s 4

Function Convert_to_doc{
Try {
ren Rapport.txt Rapport.doc
Write-Host "Report has succesfully been converted and can be consulted to this location :`n`r $Pathtmp" -ForeGroundColor Yellow
Start-sleep -s 4
#ii $Pathtmp
write.exe "$Pathtmp\Rapport.doc"
} 
Catch{
Write-Host "/!\ Error when trying to convert the report to Doc /!\"
}
}

Convert_to_doc

}


do {
    try {
        $OK = $true
		Write-Host "Press" -NoNewline
		Write-Host " [Q] " -ForeGroundColor Yellow -NoNewline
		Write-Host "to exit the programm."
		$Rep = Read-Host
        } # end try
    catch {$OK = $false}
    } # end do 
until (($Rep -eq "Q") -and $OK)
