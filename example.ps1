#Kaden waz here!!!!

Get-LocalUser | Out-File $env:TMP\userlist.txt
Get-LocalGroupMember -Group Administrators | Out-File $env:TMP\adminlist.txt

$exempted = "Administrator","DefaultAccount","Guest","WDAGUtilityAccount",(whoami).Split("\")[1]

function DisableInsecureUsers {
    Write-Host "DisablingInsecureUsers Started" -ForegroundColor Yellow
    # Check if the Guest account exists
    $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue

    if ($guestAccount -ne $null) {
        # Disable the Guest account
        Disable-LocalUser -Name "Guest"
        Write-Host "Guest account has been disabled" -ForegroundColor Green
    } else {
        Write-Host "Guest account not found" -ForegroundColor Red
    }

    Write-Host "Disabling Built-In Administrator" -ForegroundColor Yellow
    # Check if the Built-In Administrator account exists
    $adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue

    if ($adminAccount -ne $null) {
        # Disable the Guest account
        Disable-LocalUser -Name "Administrator"
        Write-Host "Built-in Administrator account has been disabled" -ForegroundColor Green
    } else {
        Write-Host "Built-in Administrator account not found" -ForegroundColor Red
    }

 }

function createFiles($name){
    New-Item "$name.txt"
    Write-Host "Put list of authorized users in each script" -ForegroundColor Yellow
    Start-Process 'C:\WINDOWS\system32\notepad.exe' ".\$name.txt" -Wait
} 

function UserManagement {
    if (!(Test-Path -Path .\usersd.txt)){
        createFiles("usersd")
    }
    $password = ConvertTo-SecureString -AsPlainText "S3miF!nals!1024" -Force
    foreach($user in Get-LocalUser){
        if(!(Select-String -Path .\usersd.txt -Pattern $user.name) -and (!($exempted.Contains($user.name)))){
            write-host $user" is unauthorized! Removing user..." -ForegroundColor Red
            Remove-LocalUser $user | Out-Null
        }
    }
    if(Get-Content -Path .\usersd.txt){
        foreach($user in (Get-Content .\usersd.txt)){
    
            if(!(Select-String -Path $env:TMP\userlist.txt -Pattern $user)){
                Write-Host $user" not in list. Adding user..." -ForegroundColor Yellow
                New-LocalUser -Name $user -Password $password | Out-Null
            }
        }
    }else{Write-Host "FILE EMPTY"}
}

function AdminManagement{
    if (!(Test-Path -Path .\adminsd.txt)){
        createFiles("adminsd")
    }
    foreach($user in Get-LocalGroupMember -Group Administrators){
        $user = ("$user").Split("\")[1]
        if(!(Select-String -Path .\adminsd.txt -Pattern $user) -and (!($exempted.Contains($user)))){
            write-host $user" is unauthorized! Removing user..." -ForegroundColor Red
            Remove-LocalGroupMember -Group Administrators -Member $user | Out-Null
        }
    }

    if(Get-Content -Path .\adminsd.txt){
        Get-Content $env:TMP\adminlist.txt
        
        foreach($user in (Get-Content -Path .\adminsd.txt)){
            if(!(Select-String -Path $env:TMP\adminlist.txt -Pattern $user)){
                Write-Host $user" not in list. Adding user..." -ForegroundColor Yellow
                Add-LocalGroupMember -Group Administrators -Member $user | Out-Null
            }
        }
        
    }else{Write-Host "FILE EMPTY"}
}

function ChangePasswords {
    Write-Host "ChangePasswords Started" -ForegroundColor Yellow
    # Get the username of the current user
    $currentUsername = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split("\")[1]

    # Get a list of all user accounts on the system
    $userList = Get-LocalUser

    # Loop through the list of user accounts and change their passwords
    foreach ($user in $userList) {
        $username = $user.Name

        if ($username -ne $currentUsername -and $username -ne "DefaultAccount" -and $username -ne "WDAGUtilityAccount") {
            try {
                $staticPassword = "S3miF!nals!1024"  # Set the new password here
                # Convert the new password to a SecureString
                $securePassword = ConvertTo-SecureString -String $staticPassword -AsPlainText -Force

                # Change the user's password
                Set-LocalUser -Name $username -Password $securePassword
                Write-Host "Password for user $username has been changed." -ForegroundColor Green
            } catch {
                Write-Host "Error changing password for user $username" -ForegroundColor Red
            }
        }
    }
}

function SecurityPolicies {
    Write-Host "SecurityPolicies Started" -ForegroundColor Yellow
    $polpath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $lsapath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $remotepath = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
    $updatepath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'

    # Define the recommended minimum password age (in days)
    $minimumPasswordAge = 1 
    # Set the minimum password age for all user accounts
    Set-ItemProperty -Path $polpath -Name "MinimumPasswordAge" -Value $minimumPasswordAge -Type DWord
    # Verify the minimum password age
    $actualMinPassAge = (Get-ItemProperty -Path $polpath).MinimumPasswordAge
    if ($actualMinPassAge -eq $minimumPasswordAge) {
        Write-Host "Minimum password age has been set to $minimumPasswordAge." -ForegroundColor Green
    } else {
        Write-Host "Failed to set the minimum password age to the desired value." -ForegroundColor Red
        Write-Host "Current lockout duration is $actualMinPassAge seconds, but the desired value was $minimumPasswordAge." -ForegroundColor Red
    }


    # Define the account lockout duration in minutes
    $lockoutDurationMinutes = 30
    # Convert the lockout duration to seconds (Windows uses seconds)
    $lockoutDurationSeconds = $lockoutDurationMinutes * 60
    # Set the account lockout duration
    Set-ItemProperty -Path $polpath -Name "LockoutDuration" -Value $lockoutDurationSeconds -Type DWord
    # Verify the set lockout duration
    $actualLockoutDurationSeconds = (Get-ItemProperty -Path $polpath).LockoutDuration
    if ($actualLockoutDurationSeconds -eq $lockoutDurationSeconds) {
        Write-Host "Account lockout duration has been set to $lockoutDurationMinutes minutes." -ForegroundColor Green
    } else {
        Write-Host "Failed to set the account lockout duration to the desired value." -ForegroundColor Red
        Write-Host "Current lockout duration is $actualLockoutDurationSeconds seconds, but the desired value was $lockoutDurationSeconds seconds." -ForegroundColor Red
    }



    ##Sets consent prompt and UAC level. These do not have error checking like the two secpolicies above. You can re-use the above code with the below policies
    Set-ItemProperty -Path $polpath -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord#5
    Set-ItemProperty -Path $polpath -Name "PromptOnSecureDesktop" -Value 1 -Type DWord

    Set-ItemProperty -Path $polpath -Name "legalnoticetext" -Value "Unauthorized access is prohibited!"
    Set-ItemProperty -Path $polpath -Name "legalnoticecaption" -Value "WARNING!"

    Set-ItemProperty -Path "$lsapath\FIPSAlgorithmPolicy" -Name "Enabled" -Value 1 -Type DWord

    Set-ItemProperty -Path $polpath -Name "DontDisplayLastUserName" -Value 1 -Type DWord
    Set-ItemProperty -Path $polpath -Name "DontDisplayUserName" -Value 1 -Type DWord
    
    Set-ItemProperty -Path $polpath -Name "EnableInstallerDetection" -Value 1 -Type DWord
    Set-ItemProperty -Path $polpath -Name "EnableSecureUIAPaths" -Value 1 -Type DWord
    Set-ItemProperty -Path $polpath -Name "EnableUIADesktopToggle" -Value 1 -Type DWord
    Set-ItemProperty -Path $polpath -Name "InactivityTimeoutSecs" -Value 600 -Type DWord
    Set-ItemProperty -Path $polpath -Name "NoConnectedUser" -Value 1 -Type DWord




    Write-Host "SecurityPolicies function has completed" -ForegroundColor Green
    Write-Host "SecurityPolicies function has completed" -ForegroundColor Green


    # Set the "LimitBlankPasswordUse" value to 1 (console only)
    Set-ItemProperty -Path $lsapath -Name "LimitBlankPasswordUse" -Value 1 -Type DWord

    #Set-GPRegistryValue -Name "Local Computer" -Key $updatepath -ValueName 'BranchReadinessLevel' -Value 20 -Type 'DWORD'

    # Verify the setting
    $actualValue = (Get-ItemProperty -Path $lsapath).LimitBlankPasswordUse

    if ($actualValue -eq 1) {
        Write-Host "Local use of blank passwords has been limited to console only." -ForegroundColor Green
    } else {
        Write-Host "Failed to set the limit for local use of blank passwords." -ForegroundColor Red
        Write-Host "Current value is $actualValue, but it should be 1 (console only)." -ForegroundColor Red
    }
}

function FirewallConfig {
    # Attempt to enable the Windows Firewall
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        Write-Host "Windows Firewall has been enabled." -ForegroundColor Green
    } catch {
        Write-Host "Error enabling Windows Firewall" -ForegroundColor Red
    }

}

function ServicesConfig {
    # Enable the Windows Update service
    Set-Service -Name "wuauserv" -Status Running -StartupType Automatic
    # Verify the service status
    $serviceStatus = Get-Service -Name "wuauserv"
    if ($serviceStatus.Status -eq "Running") {
        Write-Host "Windows Update service has been enabled and is running." -ForegroundColor Green
    } else {
        Write-Host "Failed to enable the Windows Update service." -ForegroundColor Red
    }
    
    <#
    # Stop the Microsoft FTP service (MSFTPSvc)
    #Stop-Service -Name "MSFTPSvc"
    # Set the Microsoft FTP service to Disabled
    #Set-Service -Name "MSFTPSvc" -StartupType Disabled
    # Verify the service status and startup type
    $serviceStatus = Get-Service -Name "MSFTPSvc"
    if ($serviceStatus.Status -eq "Stopped" -and $serviceStatus.StartType -eq "Disabled") {
        Write-Host "Microsoft FTP service has been stopped and disabled." -ForegroundColor Green
    } else {
        Write-Host "Failed to stop and disable the Microsoft FTP service." -ForegroundColor Red
    }#>
}

function BadFilesAndMedia {
    # Directories to scan (you can customize this list)
    $directoriesToScan = @("C:\")
    #$maliciousExtensions = @(".exe", ".bat", ".vbs", ".ps1", ".js", ".scr", ".com", ".cmd", ".sh", ".shosts", ".perl", ".docx", ".log", ".rtf", ".txt", ".csv", ".dat", ".pptx", ".xml", ".m4a", ".mp3", ".mp4", ".wav", ".avi", ".m4v", ".mov", ".svg", ".xlsx", ".db", ".sql", ".apk", ".wsf", ".zip", ".rar", ".torrent", ".jpeg", ".jpg", ".tiff", ".pdf", ".raw", ".png", ".gif", ".eps", ".ai", ".psd", ".indd", ".bmp", ".wmf", ".exif", ".jfif", ".webp", ".heif", ".inf")
    $maliciousExtensions = @(".exe", ".bat", ".vbs", ".ps1", ".js", ".scr", ".com", ".cmd", ".sh", ".shosts", ".perl", ".docx", ".log", ".rtf", ".txt", ".csv", ".pptx", ".m4a", ".mp3", ".mp4", ".wav", ".avi", ".m4v", ".mov", ".svg", ".xlsx", ".db", ".sql", ".apk", ".wsf", ".zip", ".rar", ".torrent", ".jpeg", ".jpg", ".tiff", ".pdf", ".raw", ".png", ".gif", ".eps", ".ai", ".psd", ".indd", ".bmp", ".wmf", ".exif", ".jfif", ".webp", ".heif")
    # Initialize a counter for progress
    $progressCounter = 0

    # Loop through the directories and their subdirectories
    foreach ($directory in $directoriesToScan) {
        Write-Host "Directory: $directory" -ForegroundColor Yellow
        $directoryInfo = Get-Item -Path $directory
        # Get files within the directory and its subdirectories
        Write-Host "Getting list of all files in $directory" -ForegroundColor Yellow
        $files = Get-ChildItem -Path $directory -Recurse -File -ErrorAction SilentlyContinue
        
        #set a variable for the total count of files, and then 0 for the current files its already processed. 
        $totalFiles = $files.Count
        $currentFiles = 0
        #this is set to 1 because the percentage variable rounding will start at 0, and this variable needs to be different from 0
        $previousPercentage = 1
        Write-Host "Processing File List" -ForegroundColor Yellow
        # Process files in the current directory
        foreach ($file in $files) {
            # Search for files with malicious extensions and the specified string in their name
            if ($maliciousExtensions -contains $file.Extension -or $file.Name -like "*backdoor*" -or $file.Name -like "*bind*") {
                $outputFilePath = Join-Path -Path $PSScriptRoot -ChildPath "malicious_files.txt"
                $file.FullName | Out-File -FilePath $outputFilePath -Append

                #Write-Host "Potentially malicious files found: $file" -ForegroundColor Red
                $currentFiles += 1
                $percentage = [math]::Round(($currentFiles / $totalFiles) * 100, 0)
                if ($percentage -ne $previousPercentage) {
                    Write-Host "$percentage% Complete" -ForegroundColor Yellow
                    $previousPercentage = $percentage
                }
                
            } else {
                $currentFiles += 1
                $percentage = [math]::Round(($currentFiles / $totalFiles) * 100, 0)
                if ($percentage -ne $previousPercentage) {
                    Write-Host "$percentage% Complete" -ForegroundColor Yellow
                    $previousPercentage = $percentage
                }
            }
        }
    }
}

function Show-Menu {
    param (
        [string]$Title = 'Windows 10 Script'
    )
    Clear-Host
    Write-Host "`n================ $Title ================`n"
    
    Write-Host "1: Run All"
    Write-Host "2: DisableInsecureUsers"
    Write-Host "3: UserManagement"
    Write-Host "4: AdminManagement"
    Write-Host "5: ChangePasswords"
    Write-Host "6: SecurityPolicies"
    Write-Host "7: FirewallConfig"
    Write-Host "8: ServicesConfig"
    Write-Host "9: BadFilesAndMedia"
    Write-Host "Q: Press 'Q' to quit."
}

do
 {
    Show-Menu
    $selection = Read-Host "`nSelect Option: "
    switch ($selection)
    {
    '1' {
        DisableInsecureUsers
        UserManagement
        AdminManagement
        ChangePasswords
        SecurityPolicies
        FirewallConfig
        ServicesConfig
    } 
    '2' {DisableInsecureUsers} 
    '3' {UserManagement}
    '4' {AdminManagement}
    '5' {ChangePasswords}
    '6' {SecurityPolicies}
    '7' {FirewallConfig}
    '8' {ServicesConfig}
    '9' {BadFilesAndMedia}
    }
    pause
 }
 until ($selection -eq 'q') 
