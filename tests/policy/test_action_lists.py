"""The forbidden actions and the commands that change an endpoint, kept as data the maintainers
own, read strictly, and measured on commands they must and must not match."""

import time
from pathlib import Path

import pytest

from scenario_tools.adapters.data_files import YamlDataLoader
from scenario_tools.domain.policy.actions import (
    as_command,
    forbidden_from_document,
    side_effects_from_document,
)

DATA = YamlDataLoader(Path(__file__).parents[2] / "policy" / "data")
FORBIDDEN = forbidden_from_document(DATA.load("forbidden-actions"))
SIDE_EFFECTS = side_effects_from_document(DATA.load("side-effects"))


def _forbidden(command: str) -> list[str]:
    read = as_command(command)
    return [action.why for action in FORBIDDEN if action.pattern.search(read)]


def _changes(command: str) -> bool:
    read = as_command(command)
    return any(pattern.search(read) for pattern in SIDE_EFFECTS)


@pytest.mark.parametrize(
    "command",
    [
        "vssadmin.exe Delete Shadows /All /Quiet",
        "wmic shadowcopy delete",
        "wbadmin delete catalog -quiet",
        "bcdedit /set {default} recoveryenabled No",
        "format C: /q",
        "mkfs.ext4 /dev/sdb1",
        "diskpart /s wipe.txt",
        "cipher /w:C:\\",
        "sdelete64 -p 3 x",
        "dd if=/dev/zero of=/dev/sda",
        "rm -rf /",
        "Remove-Item -Recurse -Force C:\\",
        "wevtutil cl Security",
        "Clear-EventLog -LogName Security",
        "cipher /e C:\\data",
        "openssl enc -aes-256-cbc -in a -out b",
        "gpg --symmetric secret.txt",
        "Set-MpPreference -DisableRealtimeMonitoring $true",
        "Add-MpPreference -ExclusionPath C:\\x",
        "netsh advfirewall set allprofiles state off",
        "sc stop WinDefend",
        "systemctl stop auditd",
        "setenforce 0",
        "format /q c:",
        "format.exe /fs:ntfs d:",
        "ri C:\\ -r",
        "rm -rf /*",
        "rm -rf ~",
        "vssadmin resize shadowstorage /for=c: /maxsize=1mb",
        "Set-MpPreference -ExclusionPath C:\\x",
        "Set-MpPreference -MAPSReporting 0",
        "net stop windefend",
        "Stop-Service -Name WinDefend",
        "taskkill /f /im MsMpEng.exe",
        "sc \\\\host stop WinDefend",
        "Set-NetFirewallProfile -Enabled False",
        "service auditd stop",
        "systemctl disable --now firewalld",
        "systemctl mask auditd",
        "auditctl -e 0",
        "setenforce permissive",
        "ufw --force disable",
        "Remove-EventLog -LogName x",
        "wevtutil clear-log Security",
        "Format-Volume -DriveLetter D",
        "Clear-Disk -Number 1",
        "wipefs -a /dev/sdb",
        "fsutil usn deletejournal /d c:",
        "Get-CimInstance Win32_ShadowCopy | Remove-CimInstance",
        "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
        "[Convert]::FromBase64String($x)",
        "echo eA== | base64 -d | sh",
        '&("vssa"+"dmin") delete shadows',
    ],
)
def test_each_forbidden_action_is_matched(command: str) -> None:
    assert _forbidden(command)


@pytest.mark.parametrize(
    "command",
    [
        "Get-Process | Format-Table",
        "vssadmin list shadows",
        "Remove-Item -Path C:\\windows\\temp\\x -Recurse -Force",
        "rm -rf /tmp/x",
        "gpg --verify file.sig",
        "sc query WinDefend",
        "whoami; net.exe group /DOMAIN",
        "dd if=/dev/sda of=/dev/null bs=1M count=1",
        "vssadmin list shadows\nsc.exe delete Crowdoor",  # two statements
        "wbadmin get versions; reg delete HKCU\\x /f",
        "netsh advfirewall show allprofiles | findstr off",
        "gpg --list-keys; echo -e x",
        "Get-MpPreference",
        "grep -e abcdefghijklmnopqrstuvwxyz file",
    ],
)
def test_harmless_commands_are_not_forbidden(command: str) -> None:
    assert _forbidden(command) == []


@pytest.mark.parametrize(
    "command",
    [
        "copy C:\\users\\public\\music\\go4.cab \\\\host\\c$",
        'expand -f:* "C:\\x.cab" "\\\\host\\c$\\drm"',
        "sc.exe create Crowdoor binPath= x",
        'reg.exe add "HKCU\\Software\\x" /v y /d z',
        "schtasks /create /tn x /tr y",
        'wmic process call create "cmd.exe /c x"',
        "PsExec64.exe -accepteula \\\\host -d x",
        "net user x y /add",
        "New-Item -Type Directory x",
        "Set-Content -Path x -Value y",
        "echo test > c:\\windows\\ime\\out3.tmp",
        "Invoke-WebRequest https://x -OutFile y",
        "curl -o x https://y",
        "mkdir x",
        "[IO.File]::WriteAllText('x', 'y')",
        "whoami | tee out.txt",
        "Get-Process | Tee-Object -FilePath x",
        "certutil -urlcache -f https://x y",
        "certutil -decode a b",
        "bitsadmin /transfer j https://x c:\\y",
        "Start-BitsTransfer -Source x -Destination y",
        "msiexec /i x.msi /qn",
        "regsvr32 /s x.dll",
        "rundll32 x.dll,Entry",
        "Start-Process notepad",
        "sc \\\\host create x binPath= y",
        "schtasks /change /tn x /disable",
        "reg save HKLM\\SAM sam.hive",
        "ren a b",
        "ln -s a b",
        "sed -i s/a/b/ f",
        "tar xf a.tar",
        "Compress-Archive -Path a -DestinationPath b",
        "mklink a b",
        "icacls x /grant y:F",
        "takeown /f x",
        "net start x",
        "Start-Service x",
        "systemctl start x",
        "iwr https://x -OutFile y",
        "iwr https://x -o y",
    ],
)
def test_each_command_that_changes_the_endpoint_is_matched(command: str) -> None:
    assert _changes(command)


@pytest.mark.parametrize(
    "command",
    [
        "whoami",
        "net.exe group /DOMAIN",
        'dir "c:\\users\\public\\music\\go4.cab" 2>$null',
        "gci C:\\x -Recurse | select FullName",
        "Get-Process | Out-Null",
        "Remove-Item -Path x -Force",
        "exit 0",
        "curl -k -F file=@x https://y",
        "crontab -l",
        "wget --spider https://x",
        "curl -o /dev/null https://x",
        "Get-Service x",
        "reg query HKCU\\x",
        "sc query x",
    ],
)
def test_read_only_commands_are_not_matched(command: str) -> None:
    assert not _changes(command)


def _seconds(command: str) -> float:
    read = as_command(command)
    start = time.perf_counter()
    for action in FORBIDDEN:
        action.pattern.search(read)
        if action.restore is not None:
            action.restore.search(read)
    for pattern in SIDE_EFFECTS:
        pattern.search(read)
    return time.perf_counter() - start


@pytest.mark.parametrize(
    "unit",
    [
        "wmic shadowcopy ",
        "rm ",
        "vssadmin ",
        "set-mppreference ",
        "schtasks ",
        "netsh firewall ",
        "> ",
        "gpg ",
        "sc stop ",
        "invoke-webrequest ",
    ],
)
def test_every_list_reads_a_long_command_in_linear_time(unit: str) -> None:
    small, large = _seconds(unit * 2_000), _seconds(unit * 8_000)

    assert large < 8 * small + 0.05
    assert large < 1
