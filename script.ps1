$evilApps = @("Wireshark","npcap","Metasploit")
Set-Location C:\

$choices = '&Yes','&No'
$title = "Do you want to remove this application?"

foreach($app in $evilApps){
    try{
        $inputs = "Application: $app"

        $confirm = $Host.UI.PromptForChoice($title, $inputs, $choices, 1)
        if($confirm -eq 0){
            $package = Get-Package -Name "*$app*"
            $pn = $package.ProviderName
            switch ($pn) {
                "msi" { Uninstall-Package $package }
                "Programs" { 
                    if(Test-Path -Path "C:\Program Files (x86)\*$app*"){
                        & ".\Program Files (x86)\*$app*\*uninstall*.exe"
                    }elseif(Test-Path -Path "C:\Program Files\*$app*"){
                        & ".\Program Files\*$app*\*uninstall*.exe"
                    }
                }
                Default {Write-Host "Unable to remove package!" -ForegroundColor Red}
            }
        }else{Write-Host "$app was skipped" -ForegroundColor Yellow}
    }catch{
        Write-Host "$app was not found" -ForegroundColor Yellow
    }
}