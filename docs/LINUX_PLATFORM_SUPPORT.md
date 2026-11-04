# PrivWatch 3.0 — Linux Platform Support Specification

## 1. Operating System Enforcement

PrivWatch 3.0 is an exclusively Linux-native security platform. Non-Linux operating systems (Windows, macOS, FreeBSD, OpenBSD) are explicitly unsupported and rejected during application initialization by `LinuxPlatformValidator`.

### Supported Operating Systems & Distributions

| Distribution | Supported Versions | Package Management | Telemetry Subsystems | Architecture Support |
|---|---|---|---|---|
| **Kali Linux** | 2022.x, 2023.x, 2024.x, Rolling | `apt`, `dpkg` | `auditd`, `journald`, `/proc`, `auth.log` | `x86_64`, `aarch64` |
| **Debian** | 10 (Buster), 11 (Bullseye), 12 (Bookworm) | `apt`, `dpkg` | `auditd`, `journald`, `/proc`, `auth.log` | `x86_64`, `aarch64`, `i686` |
| **Ubuntu** | 20.04 LTS, 22.04 LTS, 24.04 LTS | `apt`, `dpkg` | `auditd`, `journald`, `/proc`, `auth.log` | `x86_64`, `aarch64` |
| **Linux Mint** | 20.x, 21.x, 22.x | `apt`, `dpkg` | `auditd`, `journald`, `/proc`, `auth.log` | `x86_64` |
| **Fedora** | 38, 39, 40, 41 | `dnf`, `rpm` | `auditd`, `journald`, `/proc`, `secure` | `x86_64`, `aarch64` |
| **RHEL / Rocky / Alma** | 8.x, 9.x | `dnf`, `rpm` | `auditd`, `journald`, `/proc`, `secure` | `x86_64`, `aarch64` |
| **Arch Linux** | Rolling Release | `pacman` | `auditd`, `journald`, `/proc`, `auth.log` | `x86_64` |

---

## 2. Linux Kernel & Virtual Filesystem Requirements

PrivWatch 3.0 interacts directly with the Linux kernel via POSIX system calls and standard kernel virtual filesystems:

1. **`/proc` (Procfs)**
   - Must be mounted (`mount -t proc proc /proc`).
   - Required for process ancestry reconstruction (`/proc/[pid]/stat`, `/proc/[pid]/cmdline`, `/proc/[pid]/status`), namespace inspection, and cgroup container boundary validation (`/proc/1/cgroup`).
2. **`/sys` (Sysfs)**
   - Must be mounted (`mount -t sysfs sys /sys`).
   - Required for kernel security parameter inspection, module status, and hardware architecture verification.
3. **Linux Capabilities (POSIX 1003.1e)**
   - Requires kernel support for file capabilities (`CONFIG_SECURITY_FILE_CAPABILITIES=y`).
   - Inspected via `getcap` (`libcap2-bin`).

---

## 3. Platform Validation Process

When `privwatch.py` starts, `LinuxPlatformValidator.validate_platform()` performs sequential checks:

```
[Startup: privwatch.py]
          │
          ▼
   platform.system() == "Linux"? ──► [NO] ──► Raise UnsupportedPlatformError & Exit (Code 1)
          │
         [YES]
          ▼
   Verify /proc & /sys Mounted? ───► [NO] ──► Issue Fatal Telemetry Error
          │
         [YES]
          ▼
   Parse /etc/os-release (ID, Version, Codename)
          │
          ▼
   Inspect Execution EUID (EUID 0 vs Unprivileged)
          │
          ▼
   Check auditd / journalctl / getcap Availability
          │
          ▼
   Generate LinuxSystemReport & Proceed to Execution Mode
```

If executed on Windows or macOS, PrivWatch 3.0 immediately halts with:
```
[FATAL ERROR] PrivWatch 3.0 requires a native Linux environment.
Detected operating system: 'Windows' (win32).
Supported platforms: Kali Linux, Debian, Ubuntu, Fedora, RHEL, CentOS, Arch Linux.
Windows, macOS, and BSD systems are strictly unsupported.
```

