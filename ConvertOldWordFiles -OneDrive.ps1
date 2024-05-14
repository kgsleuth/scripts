<#
.SYNOPSIS
    Convert old Word documents (.doc) to the new format (.docx) in OneDrive directories and move old files to a local "converted_old" folder.

.DESCRIPTION
    This script searches recursively for all .doc files in the user's OneDrive directory, converts them to .docx format using Word COM object,
    and moves the original .doc files to a local "converted_old" folder within each directory where the .doc files were found.

.PARAMETER
    $OneDrivePath - The path to the OneDrive directory.
    $ConvertedFolderName - The name of the folder where old files will be moved.
    $WordFormat - The format code for saving the document as .docx (16 for wdFormatXMLDocument).

.NOTES
    Ensure that you have the necessary permissions to access and modify files in the specified OneDrive directory.
    This script requires Word to be installed on the system.

.EXAMPLE
    .\ConvertWordFiles.ps1 -OneDrivePath "C:\Users\User\OneDrive" -ConvertedFolderName "converted_old" -WordFormat 16
#>

param (
    [string]$OneDrivePath = $env:OneDrive,
    [string]$ConvertedFolderName = "converted_old",
    [int]$WordFormat = 16
)

# Function to move the old file to a local "converted_old" folder
function Move-OldFile {
    param (
        [string]$filePath,
        [string]$convertedFolderName
    )
    
    $directory = [System.IO.Path]::GetDirectoryName($filePath)
    $convertedOldFolder = Join-Path -Path $directory -ChildPath $convertedFolderName
    
    # Ensure the local "converted_old" folder exists
    if (-not (Test-Path -Path $convertedOldFolder)) {
        New-Item -ItemType Directory -Path $convertedOldFolder | Out-Null
    }
    
    # Define the new file path
    $newFilePath = Join-Path -Path $convertedOldFolder -ChildPath (Get-Item $filePath).Name
    
    # Move the file
    Move-Item -Path $filePath -Destination $newFilePath -Force
}

# Function to get a unique file name
function Get-UniqueFileName {
    param (
        [string]$filePath
    )
    
    $directory = [System.IO.Path]::GetDirectoryName($filePath)
    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($filePath)
    $extension = [System.IO.Path]::GetExtension($filePath)
    
    $newFilePath = Join-Path -Path $directory -ChildPath "$fileName$extension"
    $counter = 1

    while (Test-Path -Path $newFilePath) {
        $newFilePath = Join-Path -Path $directory -ChildPath "$fileName ($counter)$extension"
        $counter++
    }

    return $newFilePath
}

# Logging function
function Log-Message {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "$timestamp - $message"
}

# Get all .doc files in OneDrive, excluding those in the converted_old folder
Log-Message "Starting conversion process..."
$wordFiles = Get-ChildItem -Path $OneDrivePath -Recurse -Include *.doc | Where-Object { $_.FullName -notmatch "\\$ConvertedFolderName\\" }
$totalFiles = $wordFiles.Count
$currentFile = 0

foreach ($file in $wordFiles) {
    $currentFile++
    try {
        # Initialize Word COM object
        $word = New-Object -ComObject Word.Application
        $word.Visible = $false
        $word.DisplayAlerts = [Microsoft.Office.Interop.Word.WdAlertLevel]::wdAlertsNone
        
        # Open the document
        $document = $word.Documents.Open($file.FullName)

        # Define the new file name with .docx extension
        $newFileName = [System.IO.Path]::ChangeExtension($file.FullName, ".docx")
        
        # Get a unique file name if the file already exists
        if (Test-Path -Path $newFileName) {
            $newFileName = Get-UniqueFileName -filePath $newFileName
        }

        # Save the document as .docx format
        $document.SaveAs([ref] $newFileName, [ref] $WordFormat)
        Log-Message "Converted: $($file.FullName) to $newFileName"

        # Close the document
        $document.Close()
        
        # Move the old file to the local "converted_old" folder
        Move-OldFile -filePath $file.FullName -convertedFolderName $ConvertedFolderName
        Log-Message "Moved: $($file.FullName) to $ConvertedFolderName"
    }
    catch {
        Log-Message "Failed to convert $($file.FullName): $_"
    }
    finally {
        # Quit Word application
        $word.Quit()
        # Release COM objects
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($document) | Out-Null
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) | Out-Null
    }

    # Report progress
    Write-Progress -Activity "Converting Word Documents" -Status "Processing file $currentFile of $totalFiles" -PercentComplete (($currentFile / $totalFiles) * 100)
}

# Cleanup orphaned COM objects
[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()

Log-Message "Conversion completed."
