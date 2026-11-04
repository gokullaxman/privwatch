"""
PrivWatch 3.0 - Linux File & Permission Utilities
Safe permission auditing, stat analysis, POSIX ACL inspection, and path traversal prevention.
Strictly adheres to Linux DAC/MAC semantics without cross-platform workarounds.
"""

import os
from pathlib import Path
import stat
from typing import List, Tuple, Optional, Dict, Any

from core.command_exec import LinuxCommandRunner


def is_suid(file_path: str) -> bool:
    """Check if file has SUID (setuid) bit set."""
    try:
        st = os.stat(file_path, follow_symlinks=False)
        return bool(st.st_mode & stat.S_ISUID)
    except Exception:
        return False


def is_sgid(file_path: str) -> bool:
    """Check if file has SGID (setgid) bit set."""
    try:
        st = os.stat(file_path, follow_symlinks=False)
        return bool(st.st_mode & stat.S_ISGID)
    except Exception:
        return False


def is_world_writable(file_path: str) -> bool:
    """Check if file or directory has others-write (S_IWOTH) permission."""
    try:
        st = os.stat(file_path)
        return bool(st.st_mode & stat.S_IWOTH)
    except Exception:
        return False


def is_insecurely_writable(file_path: str, is_root_user: Optional[bool] = None) -> bool:
    """
    Determine if a system file has unauthorized write permissions.
    Avoids false positives where root user can write to normal root files,
    and avoids false positives where non-root user can write to their own temp files.
    """
    try:
        st = os.stat(file_path)
    except Exception:
        return False

    mode = st.st_mode
    uid = st.st_uid
    gid = st.st_gid

    # 1. World-writable bit is universally insecure for system files
    if mode & stat.S_IWOTH:
        return True

    # 2. Group-writable to a non-root group (GID != 0 and GID != shadow/root)
    if (mode & stat.S_IWGRP) and gid not in (0,):
        return True

    # 3. If file is owned by root (UID 0), but current unprivileged user has write access
    curr_euid = os.geteuid() if hasattr(os, 'geteuid') else -1
    is_root = (curr_euid == 0) if is_root_user is None else is_root_user

    if not is_root and uid == 0:
        # Unprivileged user can write to a root-owned file
        if os.access(file_path, os.W_OK):
            return True

    return False


def get_posix_acls(file_path: str) -> Optional[str]:
    """Retrieve POSIX ACLs using getfacl if available."""
    res = LinuxCommandRunner.execute(["getfacl", "-p", "-c", "-E", file_path], timeout=5)
    if res.success and res.stdout_clean():
        return res.stdout_clean()
    return None


def get_file_owner(file_path: str) -> Tuple[int, int]:
    """Get file owner UID and GID."""
    try:
        st = os.stat(file_path)
        return (st.st_uid, st.st_gid)
    except Exception:
        return (-1, -1)


def get_permission_string(file_path: str) -> str:
    """Get standard 10-character human-readable permission string (e.g. -rwsr-xr-x)."""
    try:
        st = os.stat(file_path)
        mode = st.st_mode

        # File type
        if stat.S_ISDIR(mode):
            ft = 'd'
        elif stat.S_ISLNK(mode):
            ft = 'l'
        else:
            ft = '-'

        perms = [ft]
        # Owner
        perms.append('r' if mode & stat.S_IRUSR else '-')
        perms.append('w' if mode & stat.S_IWUSR else '-')
        perms.append('s' if mode & stat.S_ISUID else ('x' if mode & stat.S_IXUSR else '-'))
        # Group
        perms.append('r' if mode & stat.S_IRGRP else '-')
        perms.append('w' if mode & stat.S_IWGRP else '-')
        perms.append('s' if mode & stat.S_ISGID else ('x' if mode & stat.S_IXGRP else '-'))
        # Others
        perms.append('r' if mode & stat.S_IROTH else '-')
        perms.append('w' if mode & stat.S_IWOTH else '-')
        perms.append('x' if mode & stat.S_IXOTH else '-')

        return ''.join(perms)
    except Exception:
        return "??????????"


def find_writable_files_in_path(path_dir: str) -> List[str]:
    """Find files in directory that are world-writable or insecurely writable."""
    writable = []
    if not os.path.exists(path_dir) or not os.path.isdir(path_dir):
        return writable
    try:
        for entry in os.scandir(path_dir):
            try:
                if entry.is_file(follow_symlinks=False):
                    if is_insecurely_writable(entry.path):
                        writable.append(entry.path)
            except Exception:
                continue
    except Exception:
        pass
    return writable


def is_parent_writable(file_path: str) -> bool:
    """Check if the parent directory of a file is insecurely writable."""
    try:
        parent = str(Path(file_path).parent.resolve())
        return is_insecurely_writable(parent)
    except Exception:
        return False


def safe_resolve_path(path_str: str, base_dir: Optional[str] = None) -> Optional[str]:
    """
    Prevent directory traversal attacks. Resolve path and ensure it remains
    within base_dir if base_dir is supplied.
    """
    try:
        resolved = Path(path_str).resolve()
        if base_dir:
            base_resolved = Path(base_dir).resolve()
            if not str(resolved).startswith(str(base_resolved)):
                return None
        return str(resolved)
    except Exception:
        return None


def get_file_stat_metadata(file_path: str) -> Dict[str, Any]:
    """Retrieve detailed stat metadata dictionary for evidence bundles."""
    try:
        st = os.stat(file_path)
        mode_str = get_permission_string(file_path)
        meta = {
            'path': file_path,
            'size_bytes': st.st_size,
            'uid': st.st_uid,
            'gid': st.st_gid,
            'owner': f"{st.st_uid}:{st.st_gid}",
            'mode': mode_str,
            'mode_octal': oct(st.st_mode)[-4:],
            'is_suid': bool(st.st_mode & stat.S_ISUID),
            'is_sgid': bool(st.st_mode & stat.S_ISGID),
            'is_world_writable': bool(st.st_mode & stat.S_IWOTH),
            'parent_writable': is_parent_writable(file_path)
        }
        acls = get_posix_acls(file_path)
        if acls:
            meta['posix_acls'] = acls
        return meta
    except Exception as e:
        return {'path': file_path, 'owner': 'unknown', 'mode': 'unknown', 'error': str(e)}
