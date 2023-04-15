param (
    [string] $username,
    [string] $pass,
    [string] $smb,
    [string] $triage,
    [string] $path,
    [string] $analyzer
)


## Get your own VT API key here: https://www.virustotal.com/gui/join-us
$VTApiKey = "*"
$AbuseApiKey = "*"

## Set TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$pw= convertto-securestring  $pass -AsPlainText -Force
$cred=new-object -typename System.Management.Automation.PSCredential -argumentlist $username,$pw
$local_hostname= hostname #Local Computer Hostname
$smb_share=$smb
$computerlist=Get-Content computerlist.txt

Write-Host `n
Write-Host "
_______  _______         _______  ______    ___   _______  _______  _______
|       ||       |       |       ||    _ |  |   | |   _   ||       ||       |
|    _  ||  _____| ____  |_     _||   | ||  |   | |  |_|  ||    ___||    ___|
|   |_| || |_____ |____|   |   |  |   |_||_ |   | |       ||   | __ |   |___
|    ___||_____  |         |   |  |    __  ||   | |       ||   ||  ||    ___|
|   |     _____| |         |   |  |   |  | ||   | |   _   ||   |_| ||   |___
|___|    |_______|         |___|  |___|  |_||___| |__| |__||_______||_______| For Incident Response - Kaan Yeniyol
"  -ForegroundColor White -BackgroundColor Black
Write-Host `n
try{
    $s1= New-PSSession -computername $computerlist[1] -Credential $cred -EA Stop
    Write-Host "Credential Access Verify... Connecting" -ForegroundColor White -BackgroundColor DarkGreen
    Remove-PSSession $computerlist[1]
    write-host $(Get-Date -format "HH:mm:ss")"- PS-Triage Analyzer Run on $local_hostname" -ForegroundColor White -BackgroundColor DarkGreen


}Catch{
    Write-Host "Username or password failed... Exiting" -ForegroundColor White -BackgroundColor Red
    return

}

Function Get_Amcache(){

    $run_rawcopy=Invoke-Command -Session $session -ScriptBlock {param($hostname) C:\Triage\Rawcopy.exe /FileNamePath:"C:\Windows\appcompat\Programs\Amcache.hve" /OutputPath:$env\Triage} -ArgumentList ($hostname) #Created Amcache.hive on the Destination Computer
    #write-host $(Get-Date -format "HH:mm:ss")-, ($computerlist.IndexOf($hostname_list)+1)-,$hostname_list " - Get-Amcache module is started. -" $hostname -ForegroundColor Black -BackgroundColor DarkGray
    if(!$smb_share -eq ""){
    Copy-Item -Path C:\Triage\Amcache.hve -FromSession $session -Destination Collection:\$hostname #Copy Amcache.hive Destination Computer to SMB SHARE

    }
    #$run_rawcopy=Invoke-Command -Session $session -ScriptBlock {C:\Rawcopy.exe /FileNamePath:"C:\Windows\system32\config\SYSTEM" /OutputPath:C:\}  #Created Amcache.hive on the Destination Computer
    #Copy-Item -Path C:\SYSTEM -FromSession $session -Destination Collection:\$hostname #Copy Amcache.hive Destination Computer to SMB SHARE
    #Invoke-Command -Session $session -ScriptBlock {rm C:$env\PS-Triage\Rawcopy.exe, C:\Amcache.hve}
    write-host $(Get-Date -format "HH:mm:ss")-, ($computerlist.IndexOf($hostname_list)+1)-,$hostname_list " - Get-Amcache Artifact saved to C:\Triage\Amcache.hve" -ForegroundColor White -BackgroundColor DarkGreen
    #write-host $(Get-Date -format "HH:mm:ss")-, ($computerlist.IndexOf($hostname_list)+1)-,$hostname_list " - Get-Netstat module is started. -" $hostname -ForegroundColor Black -BackgroundColor DarkGray

}

Function Get_Netstat(){

    Invoke-Command -Session $session -ScriptBlock {netstat | Out-File C:\Triage\Tempnetstat_$hostname.txt}

    if(!$smb_share -eq ""){
        Copy-Item -Path C:\Triage\Tempnetstat_$hostname.txt -FromSession $session -Destination Collection:\$hostname #Copy Amcache.hive Destination Computer to SMB SHARE

        }
    write-host $(Get-Date -format "HH:mm:ss")-, ($computerlist.IndexOf($hostname_list)+1)-,$hostname_list " - Get-Netstat Artifact saved to C:\Triage\Tempnetstat_$hostname.txt" -ForegroundColor White -BackgroundColor DarkGreen

}

Function Get_Winevt(){
    #write-host $(Get-Date -format "HH:mm:ss")-, ($computerlist.IndexOf($hostname_list)+1)-,$hostname_list " - Get-Winevt module is started. -" $hostname -ForegroundColor Black -BackgroundColor DarkGray
    $get_evt =Invoke-Command -Session $session -ScriptBlock {param($hostname,$smb_share) Robocopy.exe $env:windir\System32\winevt\Logs\ $env\Triage\Windows\System32\winevt\Logs\  /S /E} -ArgumentList ($hostname,$smb_share)
    #Copy-Item -Path C:\Triage\Windows\ -FromSession $session -Destination Collection:\$hostname\ -Recurse -Force #Copy Amcache.hive Destination Computer to SMB SHARE
    write-host $(Get-Date -format "HH:mm:ss")-, ($computerlist.IndexOf($hostname_list)+1)-,$hostname_list " - Get-Winevt Artifact saved to C:\Triage\Windows\System32\winevt\Logs\" -ForegroundColor White -BackgroundColor DarkGreen
}

Function Get_Process(){
    $Get_Process =Invoke-Command -Session $session -ScriptBlock {wmic path win32_process get Caption,Processid,CommandLine | Out-File C:\Triage\process_$hostname.txt}
    write-host $(Get-Date -format "HH:mm:ss")-, ($computerlist.IndexOf($hostname_list)+1)-,$hostname_list " - Get-Process Artifact saved to C:\Triage\process_$hostname.txt" -ForegroundColor White -BackgroundColor DarkGreen
}

Function Get_Prefetch(){
    #write-host $(Get-Date -format "HH:mm:ss")-, ($computerlist.IndexOf($hostname_list)+1)-,$hostname_list " - Get-Prefetch module is started. -" $hostname -ForegroundColor Black -BackgroundColor DarkGray
    $get_prefetch=Invoke-Command -Session $session -ScriptBlock {param($hostname,$smb_share) C:\Triage\HoboCopy.exe $env:windir\Prefetch\ $env\Triage\Windows\Prefetch\ *.pf} -ArgumentList ($hostname,$smb_share)
    #Copy-Item -Path C:\Triage\Windows\Prefetch\ -FromSession $session -Destination Collection:\$hostname\Windows\Prefetch\ -Recurse -Force #Copy Get_Prefetch Destination Computer to SMB SHARE
    write-host $(Get-Date -format "HH:mm:ss")-, ($computerlist.IndexOf($hostname_list)+1)-,$hostname_list " - Get-Prefetch Artifact saved to C:\Triage\Windows\Prefetch\" -ForegroundColor White -BackgroundColor DarkGreen
}

Function Get_Srum(){
    #write-host $(Get-Date -format "HH:mm:ss")-, ($computerlist.IndexOf($hostname_list)+1)-,$hostname_list " - Get-SruDB module is started. -" $hostname -ForegroundColor Black -BackgroundColor DarkGray
    $get_srum=Invoke-Command -Session $session -ScriptBlock {param($hostname,$smb_share) Robocopy.exe  $env:windir\System32\sru\ $env\Triage\Windows\System32\sru\ SRUDB.dat} -ArgumentList ($hostname,$smb_share)
    #Copy-Item -Path C:\Triage\Windows\System32\sru\ -FromSession $session -Destination Collection:\$hostname\Windows\System32\sru -Recurse -Force
    write-host $(Get-Date -format "HH:mm:ss")-, ($computerlist.IndexOf($hostname_list)+1)-,$hostname_list " - Get-SruDB Artifact saved to C:\Triage\Windows\System32\sru\" -ForegroundColor White -BackgroundColor DarkGreen
}


Function Get_Filesystem(){
    #write-host $(Get-Date -format "HH:mm:ss")-, ($computerlist.IndexOf($hostname_list)+1)-,$hostname_list " - Get-Filesystem[MFT] module is started. -" $hostname -ForegroundColor Black -BackgroundColor DarkGray
    $get_mft=Invoke-Command -Session $session -ScriptBlock {param($hostname,$smb_share) C:\Triage\Rawcopy.exe /FileNamePath:c:0 /OutputPath:$env\Triage /OutputName:$env\Triage\$MFT} -ArgumentList ($hostname,$smb_share)
    write-host $(Get-Date -format "HH:mm:ss")-, ($computerlist.IndexOf($hostname_list)+1)-,$hostname_list " - Get-Filesystem[MFT] Artifact saved to C:\Triage\`$MFT" -ForegroundColor White -BackgroundColor DarkGreen
    #write-host $(Get-Date -format "HH:mm:ss")-, ($computerlist.IndexOf($hostname_list)+1)-,$hostname_list " - Get-Filesystem[LOGFILE] module is started. -" $hostname -ForegroundColor Black -BackgroundColor DarkGray
    $get_logfile=Invoke-Command -Session $session -ScriptBlock {param($hostname,$smb_share) C:\Triage\Rawcopy.exe /FileNamePath:c:2 /OutputPath:$env\Triage /OutputName:$env\Triage\$Logfile} -ArgumentList ($hostname,$smb_share)
    write-host $(Get-Date -format "HH:mm:ss")-, ($computerlist.IndexOf($hostname_list)+1)-,$hostname_list " - Get-Filesystem[LOGFILE] Artifact saved to C:\Triage\`$Logfile" -ForegroundColor White -BackgroundColor DarkGreen
    #Copy-Item -Path C:\Triage\`$MFT -FromSession $session -Destination Collection:\$hostname\
    #Copy-Item -Path C:\Triage\`$Logfile -FromSession $session -Destination Collection:\$hostname\
    #write-host $(Get-Date -format "HH:mm:ss")-, ($computerlist.IndexOf($hostname_list)+1)-,$hostname_list " - Get-Filesystem Artifact saved to $smb_share\PS-Triage\$hostname\" -ForegroundColor White -BackgroundColor DarkGreen
}

Function Get_Hive(){
    #write-host $(Get-Date -format "HH:mm:ss")-, ($computerlist.IndexOf($hostname_list)+1)-,$hostname_list " - Get-Hive module is started. -" $hostname -ForegroundColor Black -BackgroundColor DarkGray
    $get_hive=Invoke-Command -Session $session -ScriptBlock {param($hostname,$smb_share) C:\Triage\HoboCopy.exe $env:windir\System32\config\ $env\Triage\Windows\System32\config\ SYSTEM* SOFTWARE* SAM*} -ArgumentList ($hostname,$smb_share)
    $allusers= $(Invoke-Command -Session $session -ScriptBlock { Get-ChildItem $env\users|where{$_.name -notmatch 'Public|default'} })
    foreach ($user in $allusers)
    {

     $username = $user.name
     $get_ntuserdat=Invoke-Command -Session $session -ScriptBlock {param($username,$user) C:\Triage\HoboCopy.exe $user.fullname $env\Triage\Users\$username NTUSER*} -ArgumentList ($username,$user)
     $get_usrclass=Invoke-Command -Session $session -ScriptBlock {param($username,$user) C:\Triage\HoboCopy.exe $env\Users\$username\Appdata\Local\Microsoft\Windows\ $env\Triage\Users\$username\Appdata\Local\Microsoft\Windows\ UsrClass*} -ArgumentList ($username,$user)

    }

    $attrib =Invoke-Command -Session $session -ScriptBlock {param($hostname,$smb_share)attrib -h -s C:\Triage\* /S /D} -ArgumentList ($hostname,$smb_share)
    #Copy-Item -Path C:\Triage\Users\ -FromSession $session -Destination Collection:\$hostname\ -Recurse -Force  -PassThru
    write-host $(Get-Date -format "HH:mm:ss")-, ($computerlist.IndexOf($hostname_list)+1)-,$hostname_list " - Get-Hive Artifact saved to C:\Triage\Users\" -ForegroundColor White -BackgroundColor DarkGreen

    #Copy-Item -Path C:\Triage\Windows\ -FromSession $session -Destination Collection:\$hostname\ -Recurse -Force  -PassThru

    #Invoke-Command -Session $session -ScriptBlock {Remove-Item -LiteralPath $env\PS-Triage -Force -Recurse}
    write-host $(Get-Date -format "HH:mm:ss")-, ($computerlist.IndexOf($hostname_list)+1)-,$hostname_list " - Get-Hive Artifact saved to C:\Triage\$hostname\Windows\System32\config\" -ForegroundColor White -BackgroundColor DarkGreen
}

Function submit-VTHash($VThash)
{
    $VTbody = @{resource = $VThash; apikey = $VTApiKey}
    $VTresult = Invoke-RestMethod -Method GET -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $VTbody

    return $vtResult

}



function search-VTHash {
    $sha1_pathname= Get-ChildItem -LiteralPath "$smb_share\PS-Triage\" -Filter sha*.txt -File -Recurse  | % { $_.FullName }
    foreach ($sha1_path in $sha1_pathname) {
        $sha1_content= Get-Content $sha1_path
        $sha1_path = Split-Path $sha1_path -leaf
        $sha1_gethostname = $($sha1_path -replace '.*?_(.*).txt','$1')
        Write-Host "Virustotal Search Starting  $sha1_gethostname" -ForegroundColor White -BackgroundColor DarkGreen

## Loop through hashes
    foreach ($hash in $sha1_content)
        {
            ## Set sleep value to respect API limits (4/min)
                if ($sha1_content.count -ge 4) {$sleepTime = 15}
                else {$sleepTime = 1 }

            ## Submit the hash!
                $VTresult = submit-VTHash($hash)

            ## Color positive results
                if ($VTresult.positives -ge 1) {
                    $fore = "Magenta"
                    $VTpct = (($VTresult.positives) / ($VTresult.total)) * 100
                    $VTpct = [math]::Round($VTpct,2)
                }
                else {
                    $fore = (get-host).ui.rawui.ForegroundColor
                    $VTpct = 0
                }

            ## Display results
                Write-Host "==================="
                Write-Host -f Cyan "Hostname    : " -NoNewline; Write-Host $sha1_gethostname
                Write-Host -f Cyan "Resource    : " -NoNewline; Write-Host $VTresult.resource
                Write-Host -f Cyan "Scan date   : " -NoNewline; Write-Host $VTresult.scan_date
                Write-Host -f Cyan "Positives   : " -NoNewline; Write-Host $VTresult.positives -f $fore
                Write-Host -f Cyan "Total Scans : " -NoNewline; Write-Host $VTresult.total
                Write-Host -f Cyan "Permalink   : " -NoNewline; Write-Host $VTresult.permalink
                Write-Host -f Cyan "Percent     : " -NoNewline; Write-Host $VTpct "%" -f $fore



                Start-Sleep -seconds $sleepTime

                $details = @{
                    ComputerHostame = $sha1_gethostname
                    SHA1             = $VTresult.resource
                    ScanDate     = $VTresult.scan_date
                    Positives      = $VTresult.positives
                    TotalScans      = $VTresult.total
                    Permalink       = $VTresult.permalink
                    Percent      = "$VTpct"
            }
            [array]$results += New-Object PSObject -Property $details
            $results | export-csv -Path "$smb_share\PS-Triage\VTSearch-Total.csv" -NoTypeInformation

        }


    }}

function submit-Abuse($ip){
    $IPabuseresult = Invoke-RestMethod -Uri "https://api.abuseipdb.com/api/v2/check" -Body @{"ipAddress" = $ip} -ContentType "application/json" -Headers @{"Key" = $AbuseApiKey; "Accept" = "application/json"} -Method Get -UseBasicParsing
    return $IPabuseresult

}
function search-AbuseIP {

    $netstat_pathname= Get-ChildItem -LiteralPath "$smb_share\PS-Triage\" -Filter netstat*.txt -File -Recurse  | % { $_.FullName }
    foreach ($netstat_path in $netstat_pathname) {
        $netstat_content= Get-Content $netstat_path
        $netstat_path = Split-Path $netstat_path -leaf
        $netstat_gethostname = $($netstat_path -replace '.*?_(.*).txt','$1')
        Write-Host "AbuseIPDB Search Starting  $netstat_gethostname" -ForegroundColor White -BackgroundColor Black

        foreach ($ip2 in $netstat_content)
            {

            $IPabuseresult = submit-Abuse($ip2)


            if ($IPabuseresult.data.isPublic -like "True"){
                if ($IPabuseresult.data.abuseConfidenceScore -ne 0){
                Write-Host "IP Adress    :" $ip2 - "Score    :" $IPabuseresult.data.abuseConfidenceScore -ForegroundColor White -BackgroundColor Red

            }else{
                Write-Host "IP Adress    :" $ip2 - "Score    :" $IPabuseresult.data.abuseConfidenceScore -ForegroundColor White -BackgroundColor DarkGreen

            }

            $details = @{
                ComputerHostame = $netstat_gethostname
                IPAdress = $ip2
                Score     = $IPabuseresult.data.abuseConfidenceScore

        }
        [array]$results += New-Object PSObject -Property $details
        $results | export-csv -Path "$smb_share\PS-Triage\AbuseSearch-Total.csv" -NoTypeInformation

        }}
        Write-Host "`n"
    }}




if(!$smb_share -eq ""){


    $control_path2 = "$smb_share\PS-Triage"

    if(-not (test-path -Path $control_path2)){
        #clear-host
        try{
            $mkdir1= mkdir $control_path2
        }
        catch{
            #clear-host
            write-host "not making the directory"}}


    Try{
        $drive=New-PSDrive -Name Collection -PSProvider FileSystem -root $smb_share\PS-Triage\
        Write-Host $(Get-Date -format "HH:mm:ss")"- Created PSDrive $smb_share\PS-Triage\ on $local_hostname" -ForegroundColor White -BackgroundColor DarkGreen
        Write-Host "`n"}
    catch{
        Write-host "Could not map a PsDrive to $local_hostname`n Error message : `n" $error[0]
        Write-Host "please fix this issue...`nExiting....."
            break}
        }

function Get-Triage {

    foreach($hostname_list in ($computerlist)){

        $session= New-PSSession -computername $hostname_list -Credential $cred

        $hostname= $(Invoke-Command -Session $session -ScriptBlock {Hostname}) #Destination Computer Hostname

        write-host $(Get-Date -format "HH:mm:ss")-, ($computerlist.IndexOf($hostname_list)+1)-,$hostname_list "- Destination Computer: $hostname" -ForegroundColor White -BackgroundColor Black

        $control_path = "$smb_share\PS-Triage\$hostname"
        $rawcopy_file= "Rawcopy.exe"
        $hobocopy_file= "HoboCopy.exe"
        $7za_file= "7za.exe"

        if(!$smb_share -eq ""){

        if(-not (test-path -Path $control_path)){
            #clear-host
            write-host $(Get-Date -format "HH:mm:ss")-, ($computerlist.IndexOf($hostname_list)+1)-,$hostname_list " - $control_path directory does not exist on the target system." -ForegroundColor White -BackgroundColor Red
            try{
                $mkdir1= mkdir $control_path
                write-host $(Get-Date -format "HH:mm:ss")-, ($computerlist.IndexOf($hostname_list)+1)-,$hostname_list " - $control_path directory Created" -ForegroundColor White -BackgroundColor DarkGreen
            }
            catch{
                #clear-host
                write-host "not making the directory"}}}

        $createdDIR= $(Invoke-Command -Session $session -ScriptBlock { param($hostname,$smb_share) mkdir C:\Triage } -ArgumentList ($hostname,$smb_share)) #Destination Computer Hostname
        Copy-Item -Path $rawcopy_file -ToSession $session -Destination C:\Triage\Rawcopy.exe #Destination Computer to copy rawcopy
        Copy-Item -Path $hobocopy_file -ToSession $session -Destination C:\Triage\Hobocopy.exe #Destination Computer to copy Hobocopy
        Copy-Item -Path $7za_file -ToSession $session -Destination C:\7za.exe #Destination Computer to copy Hobocopy
        write-host $(Get-Date -format "HH:mm:ss")-, ($computerlist.IndexOf($hostname_list)+1)-,$hostname_list " - Get-Triage From $hostname" -ForegroundColor White -BackgroundColor DarkGreen


        foreach ($p in $triage.Split(",")) {
            if ($p -eq "Amcache"){Get_Amcache}
            elseif($p -eq "Srum"){Get_Srum}
            elseif($p -eq "Filesystem"){Get_Filesystem}
            elseif($p -eq "ProcessInfo"){Get_Process}
            elseif($p -eq "Winevt"){Get_Winevt}
            elseif($p -eq "Prefetch"){Get_Prefetch}
            elseif($p -eq "Hives"){Get_Hive}
            elseif($p -eq "Netstat"){Get_Netstat}
            elseif($p -eq "All"){
                Get_Amcache
                Get_Winevt
                Get_Hive
                Get_Netstat
                Get_Srum
                Get_Filesystem
                Get_Prefetch
                Get_Process
            }

        }


        #Get_Amcache
        #Get_Winevt
        #Write-Host "`n"
        #Get_Hive
        #Write-Host "`n"
        #Get_Filesystem
        #Get_Prefetch
        #Get_Srum

        #Invoke-Command -Session $session -ScriptBlock {Remove-Item -LiteralPath $env\Triage -Force -Recurse}



        Invoke-Command -Session $session -ScriptBlock {rm $env\Triage\Rawcopy.exe,$env\Triage\Hobocopy.exe}
        $7zaexec=$(Invoke-Command -Session $session -ScriptBlock { param($hostname,$smb_share) C:\7za.exe a $env\triage-$hostname.zip $env\Triage\ } -ArgumentList ($hostname,$smb_share)) #Destination Computer Hostname
        write-host $(Get-Date -format "HH:mm:ss")-, ($computerlist.IndexOf($hostname_list)+1)-,$hostname_list " - 7za-Exec From $hostname" -ForegroundColor White -BackgroundColor DarkGreen


        if($smb_share -eq ""){
            write-host $(Get-Date -format "HH:mm:ss")-, ($computerlist.IndexOf($hostname_list)+1)-,$hostname_list " - Created Triage to C:\triage-$hostname.zip" -ForegroundColor White -BackgroundColor DarkGreen
            Invoke-Command -Session $session -ScriptBlock {Remove-Item -LiteralPath $env\Triage -Force -Recurse}
            Invoke-Command -Session $session -ScriptBlock { param($hostname,$smb_share) rm $env\7za.exe} -ArgumentList ($hostname,$smb_share)
        } else
        {
            Copy-Item -Path C:\triage-$hostname.zip -FromSession $session -Destination Collection:\$hostname\ -Recurse -Force
            write-host $(Get-Date -format "HH:mm:ss")-, ($computerlist.IndexOf($hostname_list)+1)-,$hostname_list " - Copy C:\triage-$hostname.zip to $smb_share\PS-Triage" -ForegroundColor White -BackgroundColor DarkGreen
            Invoke-Command -Session $session -ScriptBlock { param($hostname,$smb_share) rm $env\7za.exe, C:\triage-$hostname.zip} -ArgumentList ($hostname,$smb_share)
            Invoke-Command -Session $session -ScriptBlock {Remove-Item -LiteralPath $env\Triage -Force -Recurse}
    }

        Write-Host "`n"

        Remove-PSSession $hostname_list

    # write-host "                                                                                                                                " -ForegroundColor White -BackgroundColor White
    }}


function Amcache-Parser {


    $folder_hostname=Get-ChildItem -Path $smb_share\PS-Triage\ -Directory
    $len_folder = $folder_hostname.length
    write-host $(Get-Date -format "HH:mm:ss") "- Amcache Parser Module Started on $len_folder Hostname" -ForegroundColor White -BackgroundColor Black

    foreach ($hostname in $folder_hostname) {
        $run_rawcopy=Invoke-Command -ScriptBlock {param($smb_share,$hostname) cmd /c "AmcacheParser -f  $smb_share\PS-Triage\$hostname\Amcache.hve --csv  $smb_share\PS-Triage\$hostname --nl --csvf PS-Triage-Amcache"}  -ArgumentList ($smb_share,$hostname)
        Invoke-Command -ScriptBlock {param($smb_share,$hostname)  Import-Csv $smb_share\PS-Triage\$hostname\PS-Triage-Amcache_UnassociatedFileEntries | Select-Object -Property FileKeyLastWriteTimestamp,SHA1,FullPath,IsOsComponent,ProductName  | Export-CSV  -NoTypeInformation -Path $smb_share\PS-Triage\$hostname\AmcacheResult_$hostname.txt}  -ArgumentList ($smb_share,$hostname)
        Invoke-Command -ScriptBlock {param($smb_share,$hostname)  rm $smb_share\PS-Triage\$hostname\PS-Triage-Amcache*, $smb_share\PS-Triage\$hostname\Amcache.hve}  -ArgumentList ($smb_share,$hostname)
        write-host $(Get-Date -format "HH:mm:ss")" [OK] Get-SHA1 $hostname from Amcache file" -ForegroundColor White -BackgroundColor DarkGreen
    }
}

function Netstat-Parser {


    $folder_hostname=Get-ChildItem -Path $smb_share\PS-Triage\ -Directory
    $len_folder = $folder_hostname.length
    write-host $(Get-Date -format "HH:mm:ss") "- Netstat Parser Module Started on $len_folder Hostname" -ForegroundColor White -BackgroundColor Black

    foreach ($hostname in $folder_hostname) {


        $input_path= "$smb_share\PS-Triage\$hostname\Tempnetstat_$hostname.txt"
        $output_file= "$smb_share\PS-Triage\$hostname\netstat_$hostname.txt"
        $regex = "\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
        select-string -Path $input_path -Pattern $regex -AllMatches | % { $_.Matches } | % { $_.Value } | Get-Unique | where{$_ -ne ""} > $output_file
        Invoke-Command -ScriptBlock {param($input_path,$hostname) rm $input_path}  -ArgumentList ($input_path,$hostname)

        write-host $(Get-Date -format "HH:mm:ss")" [OK] Get-Netstat from $hostname " -ForegroundColor White -BackgroundColor DarkGreen


}}

function Get-EOE {


    $Amcache_pathname= Get-ChildItem -LiteralPath "$smb_share\PS-Triage\" -Filter Amcache*.txt -File -Recurse  | % { $_.FullName }
    foreach ($Amcache_path in $Amcache_pathname) {

        $Amcache_path = Split-Path $Amcache_path -leaf
        $Amcache_gethostname = $($Amcache_path -replace '.*?_(.*).txt','$1')

        $b=  Import-CSV -Path "$smb_share\PS-Triage\$Amcache_gethostname\$Amcache_path" -Delimiter "," | Where-Object {$_.IsOsComponent -eq "False"}

        write-host ":::::Suspicious files run on" $Amcache_gethostname ":::::" -ForegroundColor White -BackgroundColor Red
        foreach ($result in $b) {

         if (!$result.SHA1 -eq "") {
            if (!$result.FullPath -eq "" ) {
                if (!$result.ProductName -eq "microsoft" -OR !$result.ProductName -eq "Google") {

            #write-host "Hostname           :"   $Amcache_gethostname -ForegroundColor White -BackgroundColor Black
            write-host "SHA1 Hash          :"  $result.SHA1 -ForegroundColor White -BackgroundColor Black
            write-host "Path               :"  $result.FullPath -ForegroundColor White -BackgroundColor Black
            write-host "Execution Time     :"  $result.FileKeyLastWriteTimestamp -ForegroundColor White -BackgroundColor Black
            Write-Host "`n"

         }}
         $output = @{
            Hostname = $Amcache_gethostname
            SHA1Hash =  $result.SHA1
            SuspiciousPath     = $result.FullPath
            ExecutionTime     = $result.FileKeyLastWriteTimestamp


    }
    [array]$results += New-Object PSObject -Property $output
    $results | export-csv -Path "$smb_share\PS-Triage\SuspiciousEOE.csv" -NoTypeInformation

        }

    }      }}
Get-Triage
#if(!$smb_share -eq ""){Remove-PSDrive Collection}

#Write-Host "`n"
#search-AbuseIP
if ($analyzer -eq "Yes") {
    Amcache-Parser
    Netstat-Parser
    search-AbuseIP
    Get-EOE
}


#Write-Host "`n"
#search-VTHash

#Comment


    #Invoke-Command -Session $session -ScriptBlock {C:\Rawcopy.exe /FileNamePath:"C:\Windows\appcompat\Programs\Amcache.hve" /OutputPath:\\$local_hostname\c$\$hostname}
    #.\RawCopy.exe /FileNamePath:"C:\Windows\appcompat\Programs\Amcache.hve" /OutputPath:\\EDR-DC\c$
    #Invoke-Command -Session $session -ScriptBlock {C:\Rawcopy.exe /FileNamePath:"C:\Windows\appcompat\Programs\Amcache.hve" /OutputPath:\\172.22.79.13\c$\}
    #Invoke-Command -Session $session -ScriptBlock {C:\Rawcopy.exe /FileNamePath:"C:\Windows\appcompat\Programs\Amcache.hve" /OutputPath:C:\}
    #Copy-Item -Path C:\beacon.ps1 -Destination test:\$hostname
    #Set-Item Wsman:\localhost\Client\TrustedHosts -Value "*" -Force


    #Invoke-Command -Session $session -ScriptBlock {param($hostname,test) Copy-Item -Path C:\Amcache.hve -Destination test:\$hostname } -ArgumentList ($hostname,test)
    #Copy-Item -Path C:\Amcache.hve -FromSession $session -Destination test:\$hostname
    #write-host "Connect -computername"

    #$file= "abc.exe"
    #Copy-Item -Path $file -ToSession $session -Destination 'C:\abc.exe'
    #Invoke-Command -Session $session -ScriptBlock {Get-Process }

    #Remove-PSSession $session


    #SMB-SHARE

    #winrm quickconfig
    #COLLECTION -- HOSTNAME
