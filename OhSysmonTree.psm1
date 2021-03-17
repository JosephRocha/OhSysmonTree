# Oh-SysmonTree.ps1
# Author: Joseph Rocha <@ParticleAccelerator>
# Date: 3/16/2021
#
# TODO: Probably best to write a graph structure, then use Depth First Search
# TODO: Add better event filtering
# TODO: Add Blacklist Feature
# TODO: Add Computer-Name Option
#
# Get-SysmonTree -ProcessGUID "{cde47280-7c3b-6051-220a-000000001400}"
#
# Version: v1.0

function Get-Children {

    param (
        $ProcessGUID,
        [int] $level = 0,
        $logs = $Null
    )
    if(!$logs){
        $logs = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where{$_.Id -eq 1}
    }
    
    ForEach($log in $logs){
        $message = $log.Message -split "`n"
        if($message[19] -Match $ProcessGUID){
            Write-Output "$('    '*$level) $($message[11])"
            $newLevel = $level + 1
            Get-Children -ProcessGUID $message[3] -level $newLevel -logs $logs
        }
    }
}

function Get-Parent {
    param (
        $ProcessGUID,
        $logs = $Null
    )
    if(!$logs){
        $logs = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where{$_.Id -eq 1}
    }
    
    ForEach($log in $logs){
     $message = $log.Message -split "`n"
     if($message[3] -Match $ProcessGUID){ 
        $ParentGUID = [regex]::match($message[19],'.*({.*}).*').Groups[1].Value
        return $ParentGUID
     }
    }
    return "None"
}

function Get-SysmonTree {
    param (
        $ProcessGUID,
        $logs = $Null
    )

    if(!$logs){
        $logs = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where{$_.Id -eq 1}
    }

    while($ProcessGUID -ne "None"){
        $Root = $ProcessGUID
        $ProcessGUID= Get-Parent -ProcessGUID $ProcessGUID -logs $logs
    }

    Get-Children -ProcessGUID $Root -logs $logs
}

$logs = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where{$_.Id -eq 1}
$ProcessGUID = "{cde47280-7c3b-6051-220a-000000001400}"
Get-SysmonTree -ProcessGUID $ProcessGUID -logs $logs
