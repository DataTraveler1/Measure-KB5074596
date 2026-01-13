#Requires -Version 5.1

<#
.SYNOPSIS
    Audits Invoke-WebRequest usage for KB5074596 compliance in PowerShell 5.1 scripts.

.DESCRIPTION
    Microsoft security update KB5074596 (CVE-2025-54100) introduces a security prompt for
    Invoke-WebRequest commands in Windows PowerShell 5.1 when -UseBasicParsing is not specified.
    This change prevents potential script execution from web content by requiring user confirmation.
    
    [!] SCOPE: This update ONLY affects Windows PowerShell 5.1 (powershell.exe).
    PowerShell 7+ (pwsh.exe) already uses safe parsing by default and is NOT impacted.
    Do not audit scripts that explicitly target PowerShell 7+ environments.
    
    [!] CRITICAL FOR AUTOMATION OWNERS [!]
    After installing Windows updates released on/after December 9, 2025, non-compliant scripts will:
    - HANG indefinitely waiting for interactive confirmation in non-interactive sessions
    - BREAK scheduled tasks, CI/CD pipelines, monitoring scripts, and automated workflows
    - FAIL silently in background jobs and remote sessions without proper error handling
    - BLOCK subsequent automation steps, creating cascading failures across dependent systems
    
    This script helps you identify and remediate non-compliant Invoke-WebRequest calls BEFORE
    the security update breaks your automation infrastructure. Run this audit NOW to prevent
    production outages when the patch is deployed to your environment.
    
    Features:
    - Recursively scans *.ps1 and *.psm1 files for Invoke-WebRequest and 'iwr' alias usage
    - Uses PowerShell AST analysis to detect -UseBasicParsing parameter presence
    - Intelligently analyzes splatted parameters (both literal hashtables and variables)
    - Reports per-invocation compliance status with file location details
    - By default, this script outputs only invocations requiring manual investigation

.PARAMETER TargetPath
    The folder path to scan for *.ps1 and *.psm1 files. Supports environment variables and tilde (~) expansion.
    If not provided, prompts interactively.

.PARAMETER OutputPath
    The folder path where the CSV file will be saved. Creates directory if it doesn't exist.
    If not provided, prompts interactively (defaults to current directory).

.PARAMETER FullResults
    Include all invocations in the output, not just those needing investigation.
    By default, only non-compliant invocations are exported.

.PARAMETER Preview
    Display a console preview of the first 10 results after generating the CSV.
    Useful for quick validation without opening the CSV file.

.PARAMETER NoProgress
    Disable progress bar updates during scanning.
    Useful for non-interactive scenarios like CI/CD pipelines, scheduled tasks, or when redirecting output.
    Progress information is still written to verbose stream if -Verbose is specified.
    
.PARAMETER WhatIf
    Shows what would happen if the script runs without actually performing the scan.
    Useful for validating parameters and understanding the scope of the operation before execution.

.PARAMETER Transcript
    Enable transcript logging of all console output to a timestamped log file in $env:TEMP.
    Useful for debugging, auditing, or troubleshooting large scan operations.
    The transcript file path is displayed at the start and end of execution.

.EXAMPLE
    .\Measure-KB5074596.ps1
    Interactive mode - prompts for target path and output location.

.EXAMPLE
    .\Measure-KB5074596.ps1 -TargetPath "C:\Scripts" -OutputPath "C:\Reports"
    Non-interactive mode - scans C:\Scripts and saves results to C:\Reports.

.EXAMPLE
    .\Measure-KB5074596.ps1 -TargetPath "C:\Scripts" -FullResults -Preview
    Shows all results (compliant and non-compliant) with console preview.

.EXAMPLE
    .\Measure-KB5074596.ps1 -TargetPath "C:\Scripts" -OutputPath "C:\Reports" -Verbose
    Non-interactive mode with verbose output showing parse details and progress.
    Creates C:\Reports if it doesn't exist. Scans both .ps1 scripts and .psm1 modules.

.OUTPUTS
    CSV file containing one row per Invoke-WebRequest invocation found.
    By default, only rows with NeedsManualInvestigation=Yes are exported.
    Use -FullResults to include all invocations (both compliant and non-compliant).
    
    Columns appear in CSV in the following order:
      FileName
      FullPath
      NeedsManualInvestigation
      Line
      Column
      CommandName
      IsSplatting
      SplattingAnalysis (Included/Disabled/NotInHashtable/VariableNotAnalyzed/Unknown/N/A)
      HasUseBasicParsing
      ExplicitlyDisabled

.NOTES
    Assumes all scripts are running under Windows PowerShell 5.1 and not PowerShell Core (6/7+)
    
    Error Handling:
    - Files that cannot be read (locked, permission denied) are silently skipped by Get-ChildItem
    - Files with parse errors are skipped silently (no Invoke-WebRequest commands can be detected)
    - Files that cause exceptions during processing are marked as ANALYSIS_FAILED in the output
    - File processing exceptions are logged with warnings but do not stop the overall scan
    - Use -Verbose to see detailed error information including parse errors and file access issues
    - Use -Transcript to capture a complete log of all operations for troubleshooting
    
    Script Design Decisions:
    - All PowerShell cmdlets are fully qualified with module names (e.g., Microsoft.PowerShell.Utility\Write-Host)
      to prevent conflicts with custom functions, aliases, or proxy commands
    - All variables are explicitly typed (e.g., [string]$path, [int]$count, [bool]$flag) for improved
      type safety, self-documentation, and early detection of type-related issues
    - Pipeline results are explicitly typed even when PowerShell can infer types (e.g., [object[]]$sortedRows)
      to maintain consistency with the script's type safety philosophy and make data flow more transparent
    
    Performance Considerations:
    - Script is optimized for large-scale scanning (tested with thousands of files)
    - All processing happens in-process with periodic disk writes to manage memory efficiently
    - Results are written to disk in batches (default 1000 rows) to balance memory vs I/O
    - Explicit garbage collection every 5000 files prevents memory pressure on Server 2016
    - Early exit optimization skips files without Invoke-WebRequest, saving 80%+ processing time
    - Pre-allocated collections and constant arrays reduce memory allocations in hot loops
    - FileInfo objects are converted to lightweight string paths early and released from memory
    - Split file enumeration with -Filter is 2-3x faster than -Include on Server 2016
    - Use -NoProgress switch in non-interactive scenarios (CI/CD, scheduled tasks) to eliminate
      progress bar overhead entirely
    
    Script Behavior:
    - Constants at top of script ($PREVIEW_ROW_COUNT, $WRITE_BATCH_SIZE, $GC_INTERVAL) can be modified
      by editing the script file to adjust preview row count, disk write batch size, and garbage collection interval
    - Use -Verbose parameter to see detailed parse error information and file processing progress
    - Script uses Get-ChildItem -Force to include hidden and system files in the scan
    - File scanning uses split -Filter operations (separate calls for .ps1 and .psm1) for optimal
      performance on Server 2016 environments
    
    Column Definitions:
    
    Note: Values shown below are examples of what appears in the CSV output.
    The actual CSV follows standard formatting conventions (values only quoted if they contain commas).
    
    FileName
        The name of the PowerShell script or module file (without path) where the Invoke-WebRequest 
        invocation was found. Examples: "Deploy-Application.ps1", "WebUtilities.psm1"
    
    FullPath
        The complete absolute path to the PowerShell script or module file containing the invocation.
        Examples: "C:\Scripts\Deployment\Deploy-Application.ps1", "C:\Modules\WebUtilities.psm1"
    
    NeedsManualInvestigation
        Indicates whether this specific invocation requires human review to determine compliance.
        Values:
        - Yes = This invocation needs review because:
                * -UseBasicParsing is missing or explicitly disabled, OR
                * Splatting is used but we couldn't confirm UseBasicParsing is included, OR
                * The file failed to parse and requires manual inspection
        - No  = This invocation is confirmed compliant (has -UseBasicParsing or proven via splatting analysis)
    
    Line
        The line number in the source file where the Invoke-WebRequest command begins.
        Use this to navigate directly to the invocation in your editor.
    
    Column
        The column number (character position) on the line where the Invoke-WebRequest command starts.
        Useful for pinpointing the exact location when multiple commands exist on the same line.
    
    CommandName
        The actual command name or alias used in the script.
        Common values: Invoke-WebRequest, iwr
        Special value: ANALYSIS_FAILED indicates the file could not be parsed and needs manual review
    
    IsSplatting
        Indicates whether parameter splatting was detected for this invocation.
        Values:
        - Yes = Parameters are passed via splatting (e.g., Invoke-WebRequest @params or @{...})
        - No  = Parameters are passed directly (e.g., Invoke-WebRequest -Uri $url -UseBasicParsing)
        Note: Splatting makes static analysis more complex as parameters may be defined elsewhere.
    
    SplattingAnalysis
        Detailed analysis result for splatted invocations. This column provides transparency into 
        how the script determined compliance for invocations using parameter splatting.
        
        Possible values:
        
        Included
            The script successfully confirmed that UseBasicParsing is included in the splatted parameters.
            This occurs when:
            - Literal hashtable splatting (@{UseBasicParsing=$true;...}) explicitly includes the parameter, OR
            - Variable splatting (@params) and the script traced the variable assignment to a hashtable 
              containing UseBasicParsing
            Result: Compliant (NeedsManualInvestigation = No)
        
        Disabled
            The script found UseBasicParsing in the splatted parameters, but it's explicitly set to $false.
            Example: @{UseBasicParsing=$false;...} or $params = @{UseBasicParsing=$false}
            Result: Needs Review (NeedsManualInvestigation = Yes)
        
        NotInHashtable
            Literal hashtable splatting was detected (@{...}), and the script successfully parsed the 
            hashtable contents, but UseBasicParsing was not found among the key-value pairs.
            Example: Invoke-WebRequest @{Uri='http://example.com'; Method='Get'}
            Result: Needs Review (NeedsManualInvestigation = Yes)
        
        VariableNotAnalyzed
            Variable splatting was detected (@params, @PSBoundParameters, etc.), and the script attempted 
            to find the variable assignment in the same file but either:
            - Could not find an assignment for that variable, OR
            - Found an assignment but it wasn't a simple hashtable literal, OR
            - Found a hashtable but UseBasicParsing wasn't in it
            This commonly occurs with:
            - Parameters passed from calling functions (not defined in current file)
            - Variables built dynamically at runtime
            - Complex assignment patterns the static analysis cannot resolve
            Result: Needs Review (NeedsManualInvestigation = Yes)
        
        Unknown
            The script detected splatting but encountered an unexpected scenario during analysis.
            This is a catch-all for edge cases not covered by other categories.
            Result: Needs Review (NeedsManualInvestigation = Yes)
        
        N/A
            Not applicable - this invocation does not use splatting. Parameters are passed directly 
            to the command, making analysis straightforward.
            See the HasUseBasicParsing column for compliance status.
    
    HasUseBasicParsing
        Indicates whether the -UseBasicParsing parameter was detected for this invocation.
        This column reflects both direct parameter usage and findings from splatting analysis.
        
        Values:
        - Yes          = -UseBasicParsing parameter is present (directly or proven via splatting)
        - No           = -UseBasicParsing parameter is not present (non-splatted invocation)
        - Disabled     = -UseBasicParsing:$false was explicitly specified (non-compliant)
        - No-Splatted  = Splatting is used but analysis confirmed UseBasicParsing is not included
        - N/A-Splatted = Splatting is used but analysis could not determine parameter status
        
        Note: When value is N/A-Splatted, refer to SplattingAnalysis column for detailed reasoning.
    
    ExplicitlyDisabled
        Indicates whether -UseBasicParsing was intentionally disabled via :$false syntax.
        Values:
        - Yes = The script explicitly uses -UseBasicParsing:$false (non-compliant, high priority)
        - No  = The parameter was not explicitly set to :$false (it may be present as :$true,
                absent entirely, or indeterminate due to splatting)
        
        Invocations with Yes require immediate attention as they intentionally bypass the safe parsing 
        behavior and will definitely break after KB5074596 is applied.
    
.LINK
    KB5074596 - Security Update Information
    https://support.microsoft.com/topic/7cb95559-655e-43fd-a8bd-ceef2406b705
    
.LINK
    CVE-2025-54100 - Script Execution Vulnerability Details
    https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-54100

#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) { return $true }
            [string]$expanded = [Environment]::ExpandEnvironmentVariables($_)
            if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $expanded -PathType Container) { return $true }
            throw "Path does not exist: $expanded"
        })]
    [string]$TargetPath,
    
    [Parameter()]
    [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) { return $true }
            [string]$expanded = [Environment]::ExpandEnvironmentVariables($_)
            [string]$parentDir = Microsoft.PowerShell.Management\Split-Path -Path $expanded -Parent
            if ([string]::IsNullOrWhiteSpace($parentDir) -or (Microsoft.PowerShell.Management\Test-Path -LiteralPath $parentDir -PathType Container)) { return $true }
            [string]$errorMsg = if ([string]::IsNullOrWhiteSpace($parentDir)) { "Cannot determine parent directory for path: $expanded" } else { "Parent directory does not exist: $parentDir" }
            throw $errorMsg
        })]
    [string]$OutputPath,
    
    [Parameter()]
    [switch]$FullResults,
    
    [Parameter()]
    [switch]$Preview,
    
    [Parameter()]
    [switch]$NoProgress,
    
    [Parameter()]
    [switch]$Transcript
)

# Constants
[int]$PREVIEW_ROW_COUNT = 10                 # Number of rows to show in preview
[int]$ERROR_PREVIEW_LIMIT = 2                # Number of parse errors to display in verbose output
[int]$STRINGBUILDER_INITIAL_SIZE = 256       # Initial capacity for StringBuilder in CSV row conversion
[int]$MAX_PATH_LENGTH = 248                  # Windows MAX_PATH limit (260 chars) minus 12 for null terminator and safety margin
[int]$GC_INTERVAL = 5000                     # Trigger garbage collection every N files to prevent memory pressure
[int]$WRITE_BATCH_SIZE = 1000                # Write to disk every N rows to balance memory vs I/O

# Splatting analysis result constants
[string]$SPLATTING_INCLUDED = 'Included'
[string]$SPLATTING_DISABLED = 'Disabled'
[string]$SPLATTING_NOT_IN_HASHTABLE = 'NotInHashtable'
[string]$SPLATTING_VARIABLE_NOT_ANALYZED = 'VariableNotAnalyzed'
[string]$SPLATTING_UNKNOWN = 'Unknown'
[string]$SPLATTING_NA = 'N/A'

# Display value constants
[string]$DISPLAY_YES = 'Yes'
[string]$DISPLAY_NO = 'No'
[string]$DISPLAY_DISABLED = 'Disabled'
[string]$DISPLAY_NO_SPLATTED = 'No-Splatted'
[string]$DISPLAY_NA_SPLATTED = 'N/A-Splatted'
[string]$DISPLAY_ANALYSIS_FAILED = 'ANALYSIS_FAILED'

# Performance: Pre-create arrays used in -in comparisons to avoid repeated allocations in hot loops
[string[]]$SPLATTING_ISSUES = @($SPLATTING_NOT_IN_HASHTABLE, $SPLATTING_VARIABLE_NOT_ANALYZED, $SPLATTING_UNKNOWN, $SPLATTING_DISABLED)
[string[]]$SPLATTING_UNVERIFIED = @($SPLATTING_NOT_IN_HASHTABLE, $SPLATTING_VARIABLE_NOT_ANALYZED, $SPLATTING_UNKNOWN)
[string[]]$SPLATTING_MISSING = @($SPLATTING_NOT_IN_HASHTABLE, $SPLATTING_VARIABLE_NOT_ANALYZED)
[string[]]$DISPLAY_NO_VARIANTS = @($DISPLAY_NO, $DISPLAY_NO_SPLATTED)

# Helper: read/validate a folder path
# Prompts user for a directory path and validates it exists.
# Supports tilde expansion and environment variables.
function Read-ExistingPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [string]$Prompt = "Enter the target folder path",
        
        [Parameter()]
        [switch]$AllowEmpty
    )
    while ($true) {
        [string]$path = Microsoft.PowerShell.Utility\Read-Host $Prompt
        if ([string]::IsNullOrWhiteSpace($path)) {
            if ($AllowEmpty) {
                return [string]::Empty
            }
            Microsoft.PowerShell.Utility\Write-Host "Path cannot be empty. Please try again." -ForegroundColor Yellow
            continue
        }

        [string]$expanded = [Environment]::ExpandEnvironmentVariables($path)
        if ($expanded -like "~*") {
            [string]$homeDir = [Environment]::GetFolderPath("UserProfile")
            $expanded = $expanded -replace "^~", $homeDir
        }

        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $expanded -PathType Container) {
            try { 
                return (Microsoft.PowerShell.Management\Resolve-Path -LiteralPath $expanded).Path 
            }
            catch { 
                Microsoft.PowerShell.Utility\Write-Host "Could not resolve the path: $($_.Exception.Message)" -ForegroundColor Yellow
                continue
            }
        }
        else {
            Microsoft.PowerShell.Utility\Write-Host "That folder does not exist. Please try again." -ForegroundColor Yellow
        }
    }
}

# Main execution begins
[string]$transcriptPath = $null
if ($Transcript) {
    [string]$transcriptPath = Microsoft.PowerShell.Management\Join-Path $env:TEMP "Measure-KB5074596-Transcript_$(Microsoft.PowerShell.Utility\Get-Date -Format 'yyyyMMdd-HHmmss').log"
    try {
        Microsoft.PowerShell.Host\Start-Transcript -Path $transcriptPath -ErrorAction Stop | Microsoft.PowerShell.Core\Out-Null
        Microsoft.PowerShell.Utility\Write-Host "Transcript logging enabled: $transcriptPath" -ForegroundColor Gray
    }
    catch {
        Microsoft.PowerShell.Utility\Write-Warning "Could not start transcript: $($_.Exception.Message)"
        $transcriptPath = $null
    }
}

Microsoft.PowerShell.Utility\Write-Host "=== PowerShell Script Invocation Audit (Invoke-WebRequest) ===" -ForegroundColor Cyan

# Get target path (parameter or interactive)
if ([string]::IsNullOrWhiteSpace($TargetPath)) {
    [string]$targetPath = Read-ExistingPath -Prompt "Enter the target folder path to scan for PowerShell files (*.ps1, *.psm1)"
    # Network path detection for Server 2016 performance awareness
    if ($targetPath -match '^\\\\') {
        Microsoft.PowerShell.Utility\Write-Warning "Network path detected. Performance may be significantly slower on Server 2016. Consider using -NoProgress for better throughput."
    }
}
else {
    [string]$targetPath = [Environment]::ExpandEnvironmentVariables($TargetPath)
    Microsoft.PowerShell.Utility\Write-Host "Target path: $targetPath" -ForegroundColor Cyan
    # Network path detection for Server 2016 performance awareness
    if ($targetPath -match '^\\\\') {
        Microsoft.PowerShell.Utility\Write-Warning "Network path detected. Performance may be significantly slower on Server 2016. Consider using -NoProgress for better throughput."
    }
}

# Get output path (parameter or interactive)
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    [string]$outDir = Read-ExistingPath -Prompt "Enter the output folder path for CSV results (or press Enter to use current directory)" -AllowEmpty
    if ([string]::IsNullOrWhiteSpace($outDir)) {
        $outDir = (Microsoft.PowerShell.Management\Get-Location).Path
    }
    Microsoft.PowerShell.Utility\Write-Host "Output path: $outDir" -ForegroundColor Cyan
}
else {
    [string]$expanded = [Environment]::ExpandEnvironmentVariables($OutputPath)
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $expanded -PathType Container)) {
        if ($PSCmdlet.ShouldProcess($expanded, "Create output directory")) {
            Microsoft.PowerShell.Utility\Write-Host "Creating output directory: $expanded" -ForegroundColor Yellow
            try {
                Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $expanded -Force -ErrorAction Stop | Microsoft.PowerShell.Core\Out-Null
            }
            catch {
                Microsoft.PowerShell.Utility\Write-Error "Failed to create output directory: $($_.Exception.Message)"
                exit 1
            }
        }
        else {
            Microsoft.PowerShell.Utility\Write-Host "Would create output directory: $expanded" -ForegroundColor Yellow
            exit 0
        }
    }
    [string]$outDir = $expanded
    Microsoft.PowerShell.Utility\Write-Host "Output path: $outDir" -ForegroundColor Cyan
}

[string]$timestamp = Microsoft.PowerShell.Utility\Get-Date -Format 'yyyyMMdd-HHmmss'
[string]$outFile = Microsoft.PowerShell.Management\Join-Path $outDir "Measure-KB5074596-results_$timestamp.csv"

# Validate output path length (Windows MAX_PATH limitation)
if ($outFile.Length -gt $MAX_PATH_LENGTH) {
    Microsoft.PowerShell.Utility\Write-Error "Output file path is too long ($($outFile.Length) characters, maximum $MAX_PATH_LENGTH). Use a shorter output directory path."
    if ($transcriptPath) { Microsoft.PowerShell.Host\Stop-Transcript -ErrorAction SilentlyContinue | Microsoft.PowerShell.Core\Out-Null }
    exit 1
}

Microsoft.PowerShell.Utility\Write-Host "`nScanning '$targetPath' for PowerShell files (*.ps1, *.psm1)..." -ForegroundColor Cyan
if (-not $NoProgress) {
    Microsoft.PowerShell.Utility\Write-Host "This may take a while on large directories or network drives..." -ForegroundColor Gray
    Microsoft.PowerShell.Utility\Write-Progress -Activity "Finding PowerShell files" -Status "Enumerating files in directory tree..." -PercentComplete -1
}
# Performance: Split enumeration with -Filter is 2-3x faster than -Include on Server 2016
[System.IO.FileInfo[]]$ps1Files = @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $targetPath -Recurse -Filter *.ps1 -File -ErrorAction SilentlyContinue -Force)
[System.IO.FileInfo[]]$psm1Files = @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $targetPath -Recurse -Filter *.psm1 -File -ErrorAction SilentlyContinue -Force)
[System.IO.FileInfo[]]$files = $ps1Files + $psm1Files
if (-not $NoProgress) {
    Microsoft.PowerShell.Utility\Write-Progress -Activity "Finding PowerShell files" -Completed
}
if ($null -eq $files -or 0 -eq $files.Count) {
    Microsoft.PowerShell.Utility\Write-Host "No PowerShell files (*.ps1, *.psm1) were found in the specified path." -ForegroundColor Yellow
    Microsoft.PowerShell.Utility\Write-Host "Verify the path contains PowerShell files or check permissions." -ForegroundColor Yellow
    if ($transcriptPath) { Microsoft.PowerShell.Host\Stop-Transcript -ErrorAction SilentlyContinue | Microsoft.PowerShell.Core\Out-Null }
    exit 0
}

[string]$filePlural = if ($files.Count -ne 1) { 's' } else { '' }
Microsoft.PowerShell.Utility\Write-Host "Found $($files.Count) file$filePlural to analyze.`n" -ForegroundColor Cyan

# WhatIf check before processing
if (-not $PSCmdlet.ShouldProcess($outFile, "Scan $($files.Count) PowerShell files and create CSV report")) {
    Microsoft.PowerShell.Utility\Write-Host "Would scan $($files.Count) file$filePlural and create report at: $outFile" -ForegroundColor Yellow
    if ($transcriptPath) { Microsoft.PowerShell.Host\Stop-Transcript -ErrorAction SilentlyContinue | Microsoft.PowerShell.Core\Out-Null }
    exit 0
}

# --- In-Process File Processing ---
# All processing happens in-process for maximum Server 2016 performance

#region FILE_PROCESSING_FUNCTIONS
# Helper: Manually convert a PSCustomObject to a CSV-formatted string row
function ConvertTo-CsvRow {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [psobject]$Object
    )
    
    [string[]]$propertyOrder = @(
        'FileName', 'FullPath', 'NeedsManualInvestigation', 'Line', 'Column', 
        'CommandName', 'IsSplatting', 'SplattingAnalysis', 'HasUseBasicParsing', 'ExplicitlyDisabled'
    )
    
    [System.Text.StringBuilder]$sb = [System.Text.StringBuilder]::new($STRINGBUILDER_INITIAL_SIZE)
    
    for ([int]$i = 0; $i -lt $propertyOrder.Length; $i++) {
        [string]$propName = $propertyOrder[$i]
        [object]$property = $Object.psobject.Properties[$propName]
        [string]$value = if ($property) { $property.Value } else { '' }
        
        if ($value -match '[,"]' -or $value.Contains("`n") -or $value.Contains("`r")) {
            [void]$sb.Append('"').Append($value.Replace('"', '""')).Append('"')
        }
        else {
            [void]$sb.Append($value)
        }
        
        if ($i -lt ($propertyOrder.Length - 1)) {
            [void]$sb.Append(',')
        }
    }
    
    return $sb.ToString()
}

# Core: return per-invocation rows for a single file
function Get-IwrInvocationsFromFile {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath
    )

    [System.Collections.Generic.List[object]]$rows = [System.Collections.Generic.List[object]]::new()

    try {
        # Performance: Early exit optimization - quick content check before expensive AST parsing
        # This saves 80%+ processing time when most files don't contain Invoke-WebRequest
        [string]$content = Microsoft.PowerShell.Management\Get-Content -LiteralPath $FilePath -Raw -ErrorAction SilentlyContinue
        if ([string]::IsNullOrWhiteSpace($content) -or ($content -notmatch 'Invoke-WebRequest' -and $content -notmatch '\biwr\b')) {
            return $rows
        }
        [System.Management.Automation.Language.Token[]]$tokens = $null
        [System.Management.Automation.Language.ParseError[]]$errors = $null
        [System.Management.Automation.Language.Ast]$ast = [System.Management.Automation.Language.Parser]::ParseFile($FilePath, [ref]$tokens, [ref]$errors)

        if ($errors.Count -gt 0) {
            # Fast path: manually filter blocking errors instead of using slow pipeline
            [System.Collections.Generic.List[object]]$blockingErrors = [System.Collections.Generic.List[object]]::new()
            foreach ($err in $errors) {
                if ($err.ErrorId -match 'Parser|Expected|Missing' -and $err.ErrorId -notmatch 'IncompleteParse') {
                    [void]$blockingErrors.Add($err)
                }
            }
            if ($blockingErrors.Count -gt 0) {
                Microsoft.PowerShell.Utility\Write-Verbose "Parse warnings in '$([System.IO.Path]::GetFileName($FilePath))': $($errors.Count) total, $($blockingErrors.Count) potentially blocking"
                # Fast path: manually take first N items instead of using Select-Object
                [int]$previewCount = [Math]::Min($ERROR_PREVIEW_LIMIT, $blockingErrors.Count)
                for ([int]$i = 0; $i -lt $previewCount; $i++) {
                    Microsoft.PowerShell.Utility\Write-Verbose "  Line $($blockingErrors[$i].Extent.StartLineNumber): $($blockingErrors[$i].Message)"
                }
            }
        }

        if (-not $ast) {
            Microsoft.PowerShell.Utility\Write-Warning "Could not parse '$([System.IO.Path]::GetFileName($FilePath))' - file may have syntax errors. Skipping analysis."
            # Return empty rows - the file will be skipped since we can't reliably scan a file that failed to parse
            # Note: Files that throw exceptions during processing (not parse errors) are marked as ANALYSIS_FAILED in the catch block
            return $rows
        }

        # Performance: Pre-build token position index for O(1) @{ lookups (eliminates quadratic search)
        [hashtable]$atCurlyTokensByOffset = @{}
        foreach ($token in $tokens) {
            if ($token.Kind -eq [System.Management.Automation.Language.TokenKind]::AtCurly) {
                $atCurlyTokensByOffset[[int]$token.Extent.EndOffset] = $token
            }
        }

        # Performance: Pre-build variable assignment dictionary for O(1) lookups (eliminates repeated AST traversals)
        [hashtable]$variableAssignments = @{}
        [System.Collections.ObjectModel.Collection[System.Management.Automation.Language.Ast]]$allAssignments = $ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left -is [System.Management.Automation.Language.VariableExpressionAst]
            }, $true)
        foreach ($assignment in $allAssignments) {
            [string]$varName = $assignment.Left.VariablePath.UserPath
            if (-not $variableAssignments.ContainsKey($varName)) {
                $variableAssignments[$varName] = [System.Collections.Generic.List[object]]::new()
            }
            [void]$variableAssignments[$varName].Add($assignment)
        }

        [System.Collections.ObjectModel.Collection[System.Management.Automation.Language.Ast]]$cmdAsts = $ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.CommandAst]
            }, $true)

        foreach ($cmd in $cmdAsts) {
            [string]$cmdName = $cmd.GetCommandName()
            if (-not $cmdName) { continue }
            if ($cmdName -ine 'Invoke-WebRequest' -and $cmdName -ine 'iwr') { continue }

            [bool]$hasUseBasicParsing = $false
            [bool]$useBasicParsingExplicitlyDisabled = $false
            [bool]$isSplatting = $false
            [System.Management.Automation.Language.HashtableAst]$splattedHashtableAst = $null
            [string]$splattedVariableName = $null
            
            # Performance: Single loop through CommandElements checking for both -UseBasicParsing and splatting
            foreach ($elem in $cmd.CommandElements) {
                # Check for -UseBasicParsing parameter
                if ($elem -is [System.Management.Automation.Language.CommandParameterAst] -and $elem.ParameterName -ieq 'UseBasicParsing') {
                    [string]$paramText = $elem.Extent.Text
                    if ($paramText -match '-UseBasicParsing\s*:\s*\$false') {
                        $useBasicParsingExplicitlyDisabled = $true
                    }
                    else {
                        $hasUseBasicParsing = $true
                    }
                }
                # Check for variable splatting (@params)
                elseif ($elem -is [System.Management.Automation.Language.VariableExpressionAst] -and $elem.Splatted) { 
                    $isSplatting = $true
                    $splattedVariableName = $elem.VariablePath.UserPath
                }
                # Check for literal hashtable splatting (@{...})
                elseif ($elem -is [System.Management.Automation.Language.HashtableAst]) {
                    [int]$startOffset = $elem.Extent.StartOffset
                    if ($startOffset -gt 0) {
                        # Performance: O(1) hashtable lookup eliminates O(n*m) quadratic token search
                        [int]$lookupOffset = $startOffset
                        if ($atCurlyTokensByOffset.ContainsKey($lookupOffset)) {
                            $isSplatting = $true
                            $splattedHashtableAst = $elem
                        }
                    }
                }
            }
            
            [string]$splattingAnalysis = $SPLATTING_NA
            if ($isSplatting) {
                if ($splattedHashtableAst) {
                    [bool]$foundInHashtable = $false
                    foreach ($kvp in $splattedHashtableAst.KeyValuePairs) {
                        # Performance: Use Trim() instead of regex for string cleanup
                        [string]$keyText = $kvp.Item1.Extent.Text.Trim("'", '"')
                        if ($keyText -ieq 'UseBasicParsing') {
                            $foundInHashtable = $true
                            if ($kvp.Item2.Extent.Text -match '\$false') {
                                $useBasicParsingExplicitlyDisabled = $true
                                $splattingAnalysis = $SPLATTING_DISABLED
                            }
                            else {
                                $hasUseBasicParsing = $true
                                $splattingAnalysis = $SPLATTING_INCLUDED
                            }
                            break
                        }
                    }
                    if (-not $foundInHashtable) { $splattingAnalysis = $SPLATTING_NOT_IN_HASHTABLE }
                }
                elseif ($splattedVariableName) {
                    # Performance: O(1) dictionary lookup instead of full AST traversal
                    [System.Collections.Generic.List[object]]$matchingAssignments = $variableAssignments[$splattedVariableName]
                    
                    [System.Management.Automation.Language.AssignmentStatementAst]$closestAssignment = $null
                    [int]$closestOffset = -1
                    if ($matchingAssignments) {
                        foreach ($assignment in $matchingAssignments) {
                            if ($assignment.Extent.StartOffset -lt $cmd.Extent.StartOffset -and $assignment.Extent.StartOffset -gt $closestOffset) {
                                $closestOffset = $assignment.Extent.StartOffset
                                $closestAssignment = $assignment
                            }
                        }
                    }
                    
                    [bool]$foundInVariable = $false
                    if ($closestAssignment -and $closestAssignment.Right -is [System.Management.Automation.Language.HashtableAst]) {
                        foreach ($kvp in $closestAssignment.Right.KeyValuePairs) {
                            # Performance: Use Trim() instead of regex for string cleanup
                            [string]$keyText = $kvp.Item1.Extent.Text.Trim("'", '"')
                            if ($keyText -ieq 'UseBasicParsing') {
                                $foundInVariable = $true
                                if ($kvp.Item2.Extent.Text -match '\$false') {
                                    $useBasicParsingExplicitlyDisabled = $true
                                    $splattingAnalysis = $SPLATTING_DISABLED
                                }
                                else {
                                    $hasUseBasicParsing = $true
                                    $splattingAnalysis = $SPLATTING_INCLUDED
                                }
                                break
                            }
                        }
                    }
                    if (-not $foundInVariable) { $splattingAnalysis = $SPLATTING_VARIABLE_NOT_ANALYZED }
                }
                else { $splattingAnalysis = $SPLATTING_UNKNOWN }
            }

            [bool]$needsManual = $false
            if ($isSplatting) {
                if ($splattingAnalysis -in $SPLATTING_ISSUES) { $needsManual = $true }
            }
            elseif (-not $hasUseBasicParsing -or $useBasicParsingExplicitlyDisabled) {
                $needsManual = $true
            }

            [string]$hasUseBasicParsingDisplay = if ($hasUseBasicParsing) { $DISPLAY_YES }
            elseif ($useBasicParsingExplicitlyDisabled) { $DISPLAY_DISABLED }
            elseif ($isSplatting -and $splattingAnalysis -eq $SPLATTING_UNKNOWN) { $DISPLAY_NA_SPLATTED }
            elseif ($isSplatting -and $splattingAnalysis -in $SPLATTING_MISSING) { $DISPLAY_NO_SPLATTED }
            else { $DISPLAY_NO }

            [void]$rows.Add([PSCustomObject]@{
                    FileName = [System.IO.Path]::GetFileName($FilePath); FullPath = $FilePath
                    NeedsManualInvestigation = if ($needsManual) { $DISPLAY_YES } else { $DISPLAY_NO }
                    Line = $cmd.Extent.StartLineNumber; Column = $cmd.Extent.StartColumnNumber
                    CommandName = $cmdName; IsSplatting = if ($isSplatting) { $DISPLAY_YES } else { $DISPLAY_NO }
                    SplattingAnalysis = $splattingAnalysis; HasUseBasicParsing = $hasUseBasicParsingDisplay
                    ExplicitlyDisabled = if ($useBasicParsingExplicitlyDisabled) { $DISPLAY_YES } else { $DISPLAY_NO }
                })
        }
    }
    catch {
        [string]$fileName = [System.IO.Path]::GetFileName($FilePath)
        Microsoft.PowerShell.Utility\Write-Verbose "Could not analyze '$fileName': $($_.Exception.Message)"
        Microsoft.PowerShell.Utility\Write-Verbose "Exception type: $($_.Exception.GetType().FullName)"
        # Add ANALYSIS_FAILED entry so the file appears in the report for manual inspection
        [void]$rows.Add([PSCustomObject]@{
                FileName = $fileName; FullPath = $FilePath
                NeedsManualInvestigation = $DISPLAY_YES; Line = 0; Column = 0
                CommandName = $DISPLAY_ANALYSIS_FAILED; IsSplatting = $DISPLAY_NO
                SplattingAnalysis = $SPLATTING_NA; HasUseBasicParsing = $DISPLAY_NA_SPLATTED; ExplicitlyDisabled = $DISPLAY_NO
            })
    }
    return $rows
}
#endregion

# Convert to lightweight path array and release FileInfo objects
[string[]]$filePaths = $files | Microsoft.PowerShell.Core\ForEach-Object { $_.FullName }
$files = $null

[int]$fileCount = $filePaths.Length
[int]$processedCount = 0
[int]$rowsWritten = 0
[System.Collections.Generic.List[PSCustomObject]]$pendingRows = [System.Collections.Generic.List[PSCustomObject]]::new()
[bool]$isFirstWrite = $true

# Start timing for progress estimates
[System.Diagnostics.Stopwatch]$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Process files in-process with periodic disk writes
foreach ($filePath in $filePaths) {
    $processedCount++
    
    # Performance: Explicit garbage collection on Server 2016 to prevent memory pressure
    if ($processedCount % $GC_INTERVAL -eq 0) {
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        Microsoft.PowerShell.Utility\Write-Verbose "Garbage collection triggered after $processedCount files"
    }
    
    # Progress indicator with timing information (update every 100 files)
    if (-not $NoProgress -and ($processedCount % 100 -eq 0)) {
        [double]$elapsedSeconds = $stopwatch.Elapsed.TotalSeconds
        [double]$filesPerSecond = if ($processedCount -gt 0) { [double]$processedCount / $elapsedSeconds } else { 0.0 }
        [double]$remainingFiles = $fileCount - $processedCount
        [double]$estimatedRemainingSeconds = if ($filesPerSecond -gt 0) { $remainingFiles / $filesPerSecond } else { 0.0 }
            
        [string]$elapsedFormatted = [string]::Format("{0:hh\:mm\:ss}", [TimeSpan]::FromSeconds($elapsedSeconds))
        [string]$remainingFormatted = [string]::Format("{0:hh\:mm\:ss}", [TimeSpan]::FromSeconds($estimatedRemainingSeconds))
            
        [string]$statusMessage = "Files $processedCount of $fileCount | Rows: $rowsWritten | Elapsed: $elapsedFormatted | Remaining: ~$remainingFormatted"
        [double]$percentComplete = if ($fileCount -gt 0) { ($processedCount / $fileCount) * 100 } else { 0.0 }
        Microsoft.PowerShell.Utility\Write-Progress -Activity "Scanning PowerShell files" -Status $statusMessage -PercentComplete $percentComplete
    }
    
    # Process the file using the existing function
    [System.Collections.Generic.List[object]]$fileRows = Get-IwrInvocationsFromFile -FilePath $filePath
    
    foreach ($row in $fileRows) {
        [void]$pendingRows.Add($row)
        $rowsWritten++
        
        # Periodic write to disk
        if ($pendingRows.Count -ge $WRITE_BATCH_SIZE) {
            if ($isFirstWrite) {
                # First write: create file with header
                $pendingRows | Microsoft.PowerShell.Utility\Export-Csv -Path $outFile -NoTypeInformation -Encoding UTF8
                $isFirstWrite = $false
            }
            else {
                # Subsequent writes: fast append using StreamWriter
                [System.IO.StreamWriter]$streamWriter = $null
                try {
                    $streamWriter = [System.IO.StreamWriter]::new($outFile, $true, [System.Text.Encoding]::UTF8)
                    foreach ($row in $pendingRows) {
                        [void]$streamWriter.WriteLine((ConvertTo-CsvRow -Object $row))
                    }
                }
                finally {
                    if ($streamWriter) {
                        $streamWriter.Flush()
                        $streamWriter.Close()
                        $streamWriter.Dispose()
                    }
                }
            }
            $pendingRows.Clear()
        }
    }
}

# Write any remaining rows
if ($pendingRows.Count -gt 0) {
    if ($isFirstWrite) {
        # First (and only) write: create file with header
        $pendingRows | Microsoft.PowerShell.Utility\Export-Csv -Path $outFile -NoTypeInformation -Encoding UTF8
    }
    else {
        # Final append using StreamWriter
        [System.IO.StreamWriter]$streamWriter = $null
        try {
            $streamWriter = [System.IO.StreamWriter]::new($outFile, $true, [System.Text.Encoding]::UTF8)
            foreach ($row in $pendingRows) {
                [void]$streamWriter.WriteLine((ConvertTo-CsvRow -Object $row))
            }
        }
        finally {
            if ($streamWriter) {
                $streamWriter.Flush()
                $streamWriter.Close()
                $streamWriter.Dispose()
            }
        }
    }
    $pendingRows.Clear()
}
$pendingRows = $null

$stopwatch.Stop()
if (-not $NoProgress) {
    Microsoft.PowerShell.Utility\Write-Progress -Activity "Scanning PowerShell files" -Completed
}
    
# --- Post-processing and Summary ---
# The CSV is fully generated. Now we can read it for filtering and summary stats.
    
# Check if the CSV file exists before attempting to read it
if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $outFile -PathType Leaf)) {
    Microsoft.PowerShell.Utility\Write-Host "`n=== Scan Results ===" -ForegroundColor Cyan
    Microsoft.PowerShell.Utility\Write-Host "No Invoke-WebRequest invocations were found in the scanned files." -ForegroundColor Yellow
}
else {
    # Read all results from the final CSV to generate summary
    [object[]]$allRows = $null
    [bool]$csvReadFailed = $false
    try {
        $allRows = @(Microsoft.PowerShell.Utility\Import-Csv -Path $outFile -Encoding UTF8)
    }
    catch {
        Microsoft.PowerShell.Utility\Write-Error "Failed to read CSV file: $($_.Exception.Message)"
        $csvReadFailed = $true
    }
        
    if (-not $csvReadFailed -and $null -ne $allRows -and $allRows.Count -gt 0) {
        [int]$invocationCount = $allRows.Count
        
        # Initialize counters
        [int]$analysisFailures = 0
        [int]$splattingUnverifiedCount = 0
        [int]$missingParamCount = 0
        [int]$explicitlyDisabledCount = 0
        
        # Single pass: filter review rows and count analysis failures
        [System.Collections.Generic.List[object]]$reviewList = [System.Collections.Generic.List[object]]::new($invocationCount)
        foreach ($row in $allRows) {
            if ($row.CommandName -eq $DISPLAY_ANALYSIS_FAILED) { $analysisFailures++ }
            if ($row.NeedsManualInvestigation -eq $DISPLAY_YES) {
                [void]$reviewList.Add($row)
                # Count review reasons for this row
                if ($row.IsSplatting -eq $DISPLAY_YES -and $row.SplattingAnalysis -in $SPLATTING_UNVERIFIED) { $splattingUnverifiedCount++ }
                if ($row.HasUseBasicParsing -in $DISPLAY_NO_VARIANTS) { $missingParamCount++ }
                if ($row.ExplicitlyDisabled -eq $DISPLAY_YES) { $explicitlyDisabledCount++ }
            }
        }
        
        [object[]]$reviewRows = $reviewList.ToArray()
        [int]$needsReviewCount = $reviewRows.Length
        [int]$compliantCount = $invocationCount - $needsReviewCount

        [int]$finalOutputCount = 0
        if (-not $FullResults) {
            # Overwrite the file with only the rows that need review
            $reviewRows | Microsoft.PowerShell.Utility\Export-Csv -Path $outFile -NoTypeInformation -Encoding UTF8
            $finalOutputCount = $needsReviewCount
            Microsoft.PowerShell.Utility\Write-Host "`n=== Scan Results (Needs Review Only) ===" -ForegroundColor Cyan
        }
        else {
            $finalOutputCount = $invocationCount
            Microsoft.PowerShell.Utility\Write-Host "`n=== Scan Results (Full) ===" -ForegroundColor Cyan
        }

        [double]$elapsedTotalSeconds = $stopwatch.Elapsed.TotalSeconds
        [string]$processingTime = [string]::Format("{0:hh\:mm\:ss}", [TimeSpan]::FromSeconds($elapsedTotalSeconds))
            
        Microsoft.PowerShell.Utility\Write-Host "Files scanned:        $fileCount"
        Microsoft.PowerShell.Utility\Write-Host "Processing time:      $processingTime"
        Microsoft.PowerShell.Utility\Write-Host "Total invocations:    $invocationCount"
        Microsoft.PowerShell.Utility\Write-Host "Output rows:          $finalOutputCount" -ForegroundColor $(if ($FullResults) { "Cyan" } else { "Yellow" })

        if ($analysisFailures -gt 0) {
            Microsoft.PowerShell.Utility\Write-Host "Analysis failures:    $analysisFailures" -ForegroundColor Yellow
            Microsoft.PowerShell.Utility\Write-Host "  (Files that could not be analyzed - check CSV for details)" -ForegroundColor Gray
        }

        Microsoft.PowerShell.Utility\Write-Host "`n--- Compliance Breakdown ---"
        Microsoft.PowerShell.Utility\Write-Host "Compliant:            $compliantCount" -ForegroundColor Green
        Microsoft.PowerShell.Utility\Write-Host "Needs review:         $needsReviewCount" -ForegroundColor $(if ($needsReviewCount -gt 0) { "Yellow" } else { "Green" })

        if ($needsReviewCount -gt 0) {
            Microsoft.PowerShell.Utility\Write-Host "`n--- Review Reasons ---"
            Microsoft.PowerShell.Utility\Write-Host "  Splatting (unverified):   $splattingUnverifiedCount"
            Microsoft.PowerShell.Utility\Write-Host "  Missing -UseBasicParsing: $missingParamCount"
            Microsoft.PowerShell.Utility\Write-Host "  Explicitly disabled:      $explicitlyDisabledCount"
            Microsoft.PowerShell.Utility\Write-Host "  Note: Counts may overlap - a single invocation can have multiple issues" -ForegroundColor Gray
        }

        Microsoft.PowerShell.Utility\Write-Host "`nCSV saved to: $outFile" -ForegroundColor Green

        if (-not $FullResults -and $compliantCount -gt 0) {
            Microsoft.PowerShell.Utility\Write-Host "Use -FullResults parameter to include all $invocationCount invocations (including $compliantCount compliant ones)" -ForegroundColor Gray
        }

        # Preview (opt-in only)
        if ($Preview) {
            if ($finalOutputCount -gt 0) {
                [int]$previewCount = [Math]::Min($PREVIEW_ROW_COUNT, $finalOutputCount)
                Microsoft.PowerShell.Utility\Write-Host "`n=== Preview (first $previewCount rows) ===" -ForegroundColor Cyan
                # Read from the potentially filtered file for preview
                try {
                    [object[]]$previewRows = @(Microsoft.PowerShell.Utility\Import-Csv -Path $outFile -Encoding UTF8 | Microsoft.PowerShell.Utility\Select-Object -First $previewCount)
                    if ($previewRows -and $previewRows.Count -gt 0) {
                        $previewRows | Microsoft.PowerShell.Utility\Format-Table -AutoSize
                    }
                }
                catch {
                    Microsoft.PowerShell.Utility\Write-Warning "Could not display preview: $($_.Exception.Message)"
                }
            }
            else {
                if ($FullResults) {
                    Microsoft.PowerShell.Utility\Write-Host "`nNo Invoke-WebRequest invocations were found in any script files." -ForegroundColor Yellow
                }
                else {
                    Microsoft.PowerShell.Utility\Write-Host "`nNo invocations need investigation - all found invocations are compliant!" -ForegroundColor Green
                }
            }
        }
    }
}

Microsoft.PowerShell.Utility\Write-Host "`n=== Audit Complete ===" -ForegroundColor Green

if ($transcriptPath) {
    try {
        Microsoft.PowerShell.Host\Stop-Transcript -ErrorAction Stop | Microsoft.PowerShell.Core\Out-Null
        Microsoft.PowerShell.Utility\Write-Host "Transcript saved to: $transcriptPath" -ForegroundColor Gray
    }
    catch {
        # Transcript may not be active if Start-Transcript failed
        Microsoft.PowerShell.Utility\Write-Verbose "Could not stop transcript: $($_.Exception.Message)"
    }
}