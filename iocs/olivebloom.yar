/*
    OliveBloom / Auralyx git-hook dropper
    Author : Ali Mehdi Jafeeri
    Date   : 2026-11-04
    Scope  : rule 1 = this kit's hook (text); rule 2 = any zip that ships a live (non-.sample) git hook
*/

rule OliveBloom_PostCheckout_Dropper
{
    meta:
        author      = "Ali Mehdi Jafeeri"
        description = "post-checkout git hook that fetches stage-2 over HTTPS and runs it via PowerShell -File or python3, then deletes itself"
        reference   = "olivebloom.zip -> .git/hooks/post-checkout (1928 bytes)"
        date        = "2026-11-04"

    strings:
        // kit-specific
        $k1 = "wtech_boot_" ascii
        $k2 = "/wtech/auralyx" ascii
        $k3 = "/dtech/auralyx" ascii
        $k4 = "Commando.A!ml" ascii
        $ip = "66.116.241.148" ascii

        // generic hook-dropper behaviour
        $sh   = "#!/bin/sh" ascii
        $bp   = "-ExecutionPolicy Bypass -File" ascii nocase
        $py   = "| python3" ascii
        $self = "git rev-parse --git-path hooks/" ascii
        $rm   = "rm -f \"$hook_path\"" ascii

    condition:
        filesize < 16KB and $sh at 0 and
        ( 2 of ($k*, $ip) or ($self and $rm and ($bp or $py)) )
}

rule Zip_Ships_Live_Git_Hook
{
    meta:
        author      = "Ali Mehdi Jafeeri"
        description = "Zip archive containing a .git/hooks entry that is not a stock *.sample file. git clone never transfers hooks, so a shipped hook is a strong lure signal"
        date        = "2026-11-04"

    strings:
        // entry name followed by a non-name byte, i.e. NOT "<hook>.sample"
        $hook = /\.git\/hooks\/(applypatch-msg|commit-msg|fsmonitor-watchman|post-applypatch|post-checkout|post-commit|post-merge|post-receive|post-rewrite|post-update|pre-applypatch|pre-auto-gc|pre-commit|pre-merge-commit|pre-push|pre-rebase|pre-receive|prepare-commit-msg|push-to-checkout|reference-transaction|sendemail-validate|update)[^a-z.\-_]/

    condition:
        uint32(0) == 0x04034B50 and $hook
}
