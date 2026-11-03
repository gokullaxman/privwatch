"""
PrivWatch 3.0 - GTFOBins Security Knowledge Base
Curated database of Unix binaries with known privilege escalation mechanisms,
risk explanations, and defensive remediation recommendations.
"""

from typing import Dict, List, Optional, Any


class GTFOBins:
    """Knowledge base interface for GTFOBins privilege escalation vectors"""

    DATABASE: Dict[str, Dict[str, Any]] = {
        'nmap': {
            'suid': 'Interactive mode and NSE scripts allow arbitrary shell execution.',
            'sudo': 'NSE scripting or legacy --interactive enables root command execution.',
            'description': 'Network scanner with scripting and interactive shell capabilities.',
            'remediation': 'Remove SUID bit: chmod u-s $(which nmap); remove from sudoers.'
        },
        'vim': {
            'suid': 'Shell escape :!sh or python/lua embedding preserves elevated UID.',
            'sudo': 'Allows shell breakout via :!/bin/sh or :set shell=/bin/sh.',
            'description': 'Text editor with integrated shell escaping and scripting interpreters.',
            'remediation': 'Use sudoedit instead of allowing direct sudo vim; remove SUID bit.'
        },
        'vi': {
            'suid': 'Shell escape :!sh drops into root shell.',
            'sudo': 'Shell breakout via :!/bin/sh.',
            'description': 'Standard editor supporting command execution escapes.',
            'remediation': 'Configure sudoedit for file editing needs; remove SUID bit.'
        },
        'find': {
            'suid': '-exec parameter invokes arbitrary commands with SUID privileges.',
            'sudo': 'Executes arbitrary commands as root using find . -exec /bin/sh \\;.',
            'description': 'File search utility supporting external command execution.',
            'remediation': 'Remove SUID bit: chmod u-s $(which find); restrict sudoers arguments.'
        },
        'bash': {
            'suid': 'Invoking bash -p preserves elevated effective UID without dropping privilege.',
            'sudo': 'Direct interactive root shell execution.',
            'description': 'GNU Bourne-Again Shell.',
            'remediation': 'Never set SUID/SGID bits on shell interpreters: chmod 755 /bin/bash.'
        },
        'sh': {
            'suid': 'Invoking sh -p preserves elevated effective UID.',
            'sudo': 'Spawns direct interactive root shell.',
            'description': 'POSIX system shell interpreter.',
            'remediation': 'Never grant SUID permission to system shells.'
        },
        'python': {
            'suid': 'os.execl() or pty.spawn() drops into root shell.',
            'sudo': 'python -c "import os; os.system(\'/bin/sh\')" yields root shell.',
            'description': 'General-purpose programming language with OS system call access.',
            'remediation': 'Remove SUID bit; restrict sudo access with strict script arguments.'
        },
        'python3': {
            'suid': 'os.execl() executes shell with elevated privileges.',
            'sudo': 'Inline execution executes arbitrary root commands.',
            'description': 'Python 3 interpreter with full OS access.',
            'remediation': 'Remove SUID bit; wrap allowed scripts in dedicated constrained wrappers.'
        },
        'perl': {
            'suid': 'exec "/bin/sh" executes privileged shell.',
            'sudo': 'perl -e \'exec "/bin/sh";\' yields root shell.',
            'description': 'Scripting language with direct exec/system functions.',
            'remediation': 'Remove SUID bit; avoid wildcard sudo permissions for perl.'
        },
        'ruby': {
            'suid': 'exec "/bin/sh" drops into root shell.',
            'sudo': 'Direct shell execution via ruby -e \'exec "/bin/sh"\'.',
            'description': 'Ruby interpreter with system execution capabilities.',
            'remediation': 'Remove SUID bit; audit sudo privileges.'
        },
        'less': {
            'suid': 'Pager escape !/bin/sh launches root shell.',
            'sudo': 'Bypasses paging by invoking !/bin/sh.',
            'description': 'File pager with interactive shell breakout.',
            'remediation': 'Set LESSECURE=1 in environment or remove sudo privileges.'
        },
        'more': {
            'suid': 'Pager escape !/bin/sh launches root shell.',
            'sudo': 'Interactive command escape to root shell.',
            'description': 'File pager supporting command execution.',
            'remediation': 'Remove SUID bit; restrict sudo rules.'
        },
        'nano': {
            'suid': 'Text editor allowing command execution via helper prompts.',
            'sudo': 'Command execution via ^R^X keyboard shortcut.',
            'description': 'Simple text editor with command execution escape.',
            'remediation': 'Configure sudoedit instead of permitting sudo nano.'
        },
        'awk': {
            'suid': 'system("/bin/sh") executes root shell.',
            'sudo': 'awk \'BEGIN {system("/bin/sh")}\' yields root shell.',
            'description': 'Pattern scanning and processing language with system() calls.',
            'remediation': 'Remove SUID bit; restrict sudo privileges.'
        },
        'sed': {
            'suid': 'e command in sed executes arbitrary commands.',
            'sudo': 'sed -n \'1e exec sh 1>&0\' yields root shell.',
            'description': 'Stream editor with command execution extensions.',
            'remediation': 'Remove SUID bit; restrict sudo permissions.'
        },
        'env': {
            'suid': 'env /bin/sh -p executes shell without dropping privileges.',
            'sudo': 'sudo env /bin/sh spawns root shell.',
            'description': 'Program environment runner.',
            'remediation': 'Remove SUID bit: chmod u-s $(which env).'
        },
        'cp': {
            'suid': 'Overwrites sensitive files like /etc/passwd or /etc/shadow.',
            'sudo': 'Arbitrary file read/write by copying protected system files.',
            'description': 'File copy utility capable of overwriting system credentials.',
            'remediation': 'Never set SUID on cp; restrict sudo permissions.'
        },
        'mv': {
            'suid': 'Overwrites or replaces critical system files.',
            'sudo': 'Can replace /etc/shadow or system binaries.',
            'description': 'File move utility capable of altering protected files.',
            'remediation': 'Never set SUID on mv.'
        },
        'docker': {
            'sudo': 'docker run -v /:/mnt --rm -it alpine chroot /mnt mounts host root as root.',
            'description': 'Container engine with full host filesystem mount capabilities.',
            'remediation': 'Restrict docker group membership; do not permit docker via unrestricted sudo.'
        },
        'git': {
            'sudo': 'git -p help config invokes pager escape !/bin/sh.',
            'description': 'Version control system using external pagers for output.',
            'remediation': 'Do not allow sudo git without restricting core.pager.'
        },
        'pkexec': {
            'suid': 'Polkit command execution helper.',
            'description': 'Privilege escalation helper tool; prone to local memory corruption if unpatched (PwnKit).',
            'remediation': 'Keep policykit-1/polkit package updated; remove SUID if unused.'
        },
        'tar': {
            'suid': '--checkpoint-action allows executing external scripts.',
            'sudo': 'tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh.',
            'description': 'Archive utility with execution hooks.',
            'remediation': 'Remove SUID bit; audit cron jobs utilizing tar wildcards.'
        },
        'tee': {
            'suid': 'Writes arbitrary data to privileged files.',
            'sudo': 'Overwrites /etc/passwd or /etc/sudoers.',
            'description': 'Command line pipe splitter that writes to files.',
            'remediation': 'Remove SUID bit: chmod u-s $(which tee).'
        },
        'base64': {
            'suid': 'Can read arbitrary files like /etc/shadow by encoding them.',
            'sudo': 'Reads sensitive system credentials.',
            'description': 'Data encoder allowing arbitrary file reads.',
            'remediation': 'Remove SUID bit: chmod u-s $(which base64).'
        },
        'curl': {
            'suid': 'Uploads or downloads files overwriting system configs.',
            'sudo': 'Can overwrite sensitive files via -o /etc/passwd.',
            'description': 'HTTP transfer utility.',
            'remediation': 'Remove SUID bit.'
        },
        'wget': {
            'suid': 'Downloads malicious configuration overwriting sensitive files.',
            'sudo': 'Can write to /etc/cron.d/ or /etc/sudoers.d/.',
            'description': 'File downloader capable of writing to arbitrary locations.',
            'remediation': 'Remove SUID bit.'
        }
    }

    @classmethod
    def lookup(cls, binary_name: str) -> Optional[Dict[str, Any]]:
        """Look up binary in knowledge base by basename"""
        base = binary_name.lower().split('/')[-1]
        return cls.DATABASE.get(base)

    @classmethod
    def is_dangerous_suid(cls, binary_name: str) -> bool:
        """Check if binary has documented SUID privilege escalation vectors"""
        entry = cls.lookup(binary_name)
        return bool(entry and 'suid' in entry)

    @classmethod
    def is_dangerous_sudo(cls, binary_name: str) -> bool:
        """Check if binary has documented sudo privilege escalation vectors"""
        entry = cls.lookup(binary_name)
        return bool(entry and 'sudo' in entry)

    @classmethod
    def get_exploit_command(cls, binary_name: str, vector: str = 'suid') -> str:
        """Return technical mechanism explanation for vector"""
        entry = cls.lookup(binary_name)
        if entry and vector in entry:
            return entry[vector]
        return ""

    @classmethod
    def get_defense_recommendation(cls, binary_name: str) -> str:
        """Return defensive remediation instructions"""
        entry = cls.lookup(binary_name)
        if entry and 'remediation' in entry:
            return entry['remediation']
        return "Audit binary permissions and remove SUID/sudo elevation if not strictly required."
