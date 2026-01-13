# Measure-KB5074596 🔍

Detect and report PowerShell scripts that will break when Microsoft's KB5074596 security update is applied.

## What's Going On? 🤔

Microsoft's releasing a security update ([KB5074596](https://support.microsoft.com/topic/7cb95559-655e-43fd-a8bd-ceef2406b705)) that makes PowerShell 5.1 ask for confirmation before downloading web content. Great for security! But if your scripts use `Invoke-WebRequest` without the right parameter, they'll just... stop working. 😬

**The Problem**: After Windows updates roll out (started December 9, 2025), scripts that aren't ready will:
- ⏸️ Hang forever waiting for someone to click "Yes"
- 💥 Break your scheduled tasks and automation
- 🤫 Fail silently in the background
- 🎯 Take down other stuff that depends on them

**The Solution**: This script scans your PowerShell files and tells you exactly which ones need fixing. Think of it as a pre-flight check before the update lands. ✈️

## What This Script Does ✨

- 🔎 Scans all your PowerShell scripts (`*.ps1` and `*.psm1` files)
- 🧠 Uses smart analysis to find `Invoke-WebRequest` calls that need fixing
- 📊 Exports a CSV report showing exactly where the problems are
- 🎯 By default, only shows you what needs attention (no noise!)

## Who Needs to Worry About This?

- ✅ **Yes, you!** - If you're using Windows PowerShell 5.1 (`powershell.exe`)
- ✅ **Probably you!** - If you have scheduled tasks, automation, or scripts that download things from the web
- ❌ **Not you** - If you're already using PowerShell 7+ (`pwsh.exe`) - you're already safe!

## Quick Start 🚀

### Just Run It (Easiest Way)
```powershell
.\Measure-KB5074596.ps1
```
The script will ask where to scan and where to save results. Simple as that! 👍

### If You Like Options 🎛️
```powershell
# Scan a specific folder
.\Measure-KB5074596.ps1 -TargetPath "C:\Scripts" -OutputPath "C:\Reports"

# See EVERYTHING (compliant scripts too)
.\Measure-KB5074596.ps1 -TargetPath "C:\Scripts" -FullResults -Preview

# Want all the details?
.\Measure-KB5074596.ps1 -TargetPath "C:\Scripts" -Verbose

# Scan from pipeline (scan multiple directories)
Get-ChildItem C:\Scripts -Directory | .\Measure-KB5074596.ps1 -OutputPath "C:\Reports"

# Preview before running (WhatIf mode)
.\Measure-KB5074596.ps1 -TargetPath "C:\Scripts" -WhatIf

# Enable transcript logging for debugging
.\Measure-KB5074596.ps1 -TargetPath "C:\Scripts" -Transcript

# For automation (no progress bar)
.\Measure-KB5074596.ps1 -TargetPath "C:\Scripts" -OutputPath "C:\Reports" -NoProgress
```

## Understanding Your Results 📋

The script creates a CSV file showing each script that needs attention. The important columns are:

| Column | What It Means |
|--------|---------------|
| **FileName** | Which script has the issue |
| **Line** | Exact line number (jump right to it!) |
| **NeedsManualInvestigation** | `Yes` = needs your attention, `No` = you're good ✅ |
| **CommandName** | What it found (`Invoke-WebRequest` or `iwr`) |
| **HasUseBasicParsing** | Does it have the magic `-UseBasicParsing` parameter? |

There are more columns with technical details, but those are the main ones to look at first.

## How to Fix It 🔧

Super easy fix - just add `-UseBasicParsing` to your `Invoke-WebRequest` calls:

### Before ❌
```powershell
$response = Invoke-WebRequest -Uri "https://api.example.com/data"
```

### After ✅
```powershell
$response = Invoke-WebRequest -Uri "https://api.example.com/data" -UseBasicParsing
```

That's it! One parameter saves your automation. 🎉

## Smart Detection 🧐

The script is pretty clever - it can even understand when you're using "splatting" (that fancy PowerShell hashtable thing):

```powershell
# It knows this is safe ✅
$params = @{
    Uri = 'https://api.example.com'
    UseBasicParsing = $true
}
Invoke-WebRequest @params

# It knows this needs fixing ⚠️
Invoke-WebRequest @{Uri='https://api.example.com'; Method='Get'}
```

## Need Help? 🤝

- Check the CSV output - it tells you the file name and line number
- Open the script file and search for the line number
- Add `-UseBasicParsing` to the `Invoke-WebRequest` command
- Run this scan again to confirm the fix worked!

## Advanced Features 🎯

**Requirements Check:**
- Script requires PowerShell 5.1 or higher
- Will display error if run on older versions

**Safety Features:**
- `-WhatIf` support - see what would happen without making changes
- `-Confirm` prompts before creating output directories
- Path length validation prevents Windows MAX_PATH issues (260 character limit)
- Validates all paths exist before starting scan

**Pipeline Support:**
- Accepts paths from pipeline for batch scanning
- Example: `Get-ChildItem C:\Projects -Directory | .\Measure-KB5074596.ps1`

**Transcript Logging:**
- Use `-Transcript` to capture complete execution log
- Log saved to `$env:TEMP\Measure-KB5074596-Transcript_[timestamp].log`
- Perfect for debugging or audit trails

**Performance:**
- All processing happens in-process with periodic disk writes to manage memory efficiently
- Early exit optimization skips files without Invoke-WebRequest, saving 80%+ processing time
- Explicit garbage collection every 5000 files prevents memory pressure on Server 2016
- Split file enumeration with -Filter is 2-3x faster than -Include on Server 2016
- Tested on thousands of files without memory problems
- Use `-NoProgress` in CI/CD or scheduled tasks to avoid progress bar overhead

## Technical Details 🤓

(For folks who care about how the sausage is made.)

This script leverages advanced PowerShell Abstract Syntax Tree (AST) analysis to perform static code inspection without execution. Here's what makes it sophisticated:

**AST Deep Inspection:**
- Uses `[System.Management.Automation.Language.Parser]::ParseFile()` to build complete syntax trees
- Recursively walks AST nodes with `FindAll()` to locate all command invocations
- Analyzes `CommandAst` nodes to detect parameter presence and splatting patterns
- Token-level inspection to identify `@{` patterns that distinguish literal hashtable splatting

**Intelligent Splatting Analysis:**
The real challenge is parameter splatting - static analysis must handle multiple patterns:
1. **Literal Hashtable Splatting** (`@{UseBasicParsing=$true}`): Directly inspects `HashtableAst` key-value pairs
2. **Variable Splatting** (`@params`): Traces variable assignments via `AssignmentStatementAst` nodes, finding the most recent assignment before each invocation
3. **Cross-Scope Tracking**: Searches the entire file's AST to locate variable definitions that may be declared in outer scopes

**Performance Optimizations for Scale:**
- Pre-allocated `List<T>` collections with capacity hints (tested on thousands of files)
- Constant arrays for membership tests avoid repeated allocations in hot loops
- Direct type checking replaces pipeline operations to eliminate intermediate arrays
- Pre-built token and variable assignment dictionaries eliminate O(n*m) quadratic searches
- **In-Process Architecture**: All processing happens in-process with periodic disk writes (every 1000 rows by default) to manage memory efficiently
- Early exit optimization performs quick content check before expensive AST parsing, saving 80%+ processing time when files don't contain Invoke-WebRequest
- Explicit garbage collection every 5000 files prevents memory pressure on Server 2016 systems
- FileInfo objects converted to lightweight string paths early and released from memory
- Split file enumeration with -Filter for .ps1 and .psm1 is 2-3x faster than -Include on Server 2016

**Server 2016 Optimizations:**
This script includes specific optimizations for Windows Server 2016 environments:
- Split `Get-ChildItem` operations with `-Filter` parameter (faster than `-Include`)
- Network path detection with warnings (interactive mode prompts for confirmation)
- Aggressive garbage collection to prevent memory pressure
- Early exit pattern matching to skip files without target commands
- Use `-NoProgress` to eliminate progress bar overhead in non-interactive scenarios

**Robustness:**
- Graceful parse error handling (many "errors" from dynamic PowerShell patterns are non-blocking)
- Parse errors are skipped silently (no Invoke-WebRequest commands can be detected in unparseable files)
- Processing exceptions create ANALYSIS_FAILED entries in the output for manual review
- Distinguishes between `-UseBasicParsing:$false` (explicit disable) and omission
- Falls back to manual review flags when static analysis reaches its limits (dynamic parameter construction, runtime splatting, etc.)
- In-process design maintains predictable memory usage with periodic disk writes
- Results stream to CSV in batches - no large intermediate accumulation

The code follows strict PowerShell best practices: full module qualification to prevent function hijacking, explicit typing throughout for clarity and type safety, comprehensive error handling with verbose diagnostics, and `#Requires` statement to enforce minimum PowerShell version.

## References 📚

- [KB5074596 - Microsoft's Official Info](https://support.microsoft.com/topic/7cb95559-655e-43fd-a8bd-ceef2406b705)
- [CVE-2025-54100 - The Security Details](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-54100)

## Acknowledgements

This script was written with the assistance of GitBub Copilot 🤖