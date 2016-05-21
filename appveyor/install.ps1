function InstallPackage ($python_home, $pkg) {
    $pip_path = $python_home + "/Scripts/pip.exe"
    & $pip_path install $pkg
}

function DownloadWinpcapDev () {
    $webclient = New-Object System.Net.WebClient

    $download_url = "https://www.winpcap.org/install/bin/WpdPack_4_1_2.zip"
    $filename = "WpdPack_4_1_2.zip"
    
    $basedir = $pwd.Path + "\"
    $filepath = $basedir + $filename
    if (Test-Path $filepath) {
        Write-Host "Reusing" $filepath
        return $filepath
    }

    # Download and retry up to 5 times in case of network transient errors.
    Write-Host "Downloading" $filename "from" $download_url
    $retry_attempts = 3
    for($i=0; $i -lt $retry_attempts; $i++){
        try {
            $webclient.DownloadFile($download_url, $filepath)
            break
        }
        Catch [Exception]{
            Start-Sleep 1
        }
   }
   Write-Host "File saved at" $filepath

   & 7z x $filename
}


function main () {
    InstallPackage $env:PYTHON wheel
    & DownloadWinpcapDev
}

main
