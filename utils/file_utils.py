"""
PrivWatch 3.0 - File & Permission Utilities
Safe permission auditing, stat analysis, and path traversal prevention.
"""

import os
from pathlib import Path
import stat
from typing import List, Tuple, Optional, Dict, Any


def is_suid(file_path: str) -> bool:
    """Check if file has SUID (setuid) bit set"""
    try:
        st = os.stat(file_path, follow_symlinks=False)
        return bool(st.st_mode & stat.S_ISUID)
    except Exception:
        return False


def is_sgid(file_path: str) -> bool:
    """Check if file has SGID (setgid) bit set"""
    try:
        st = os.stat(file_path, follow_symlinks=False)
        return bool(st.st_mode & stat.S_ISGID)
    except Exception:
        return False


def is_world_writable(file_path: str) -> bool:
    """Check if file or directory has others-write (S_IWOTH) permission"""
    try:
        st = os.stat(file_path)
        return bool(st.st_mode & stat.S_IWOTH)
    except Exception:
        return False


def get_file_owner(file_path: str) -> Tuple[int, int]:
    """Get file owner UID and GID"""
    try:
        st = os.stat(file_path)
        return (st.st_uid, st.st_gid)
    except Exception:
        return (-1, -1)


def get_permission_string(file_path: str) -> str:
    """Get standard 10-character human-readable permission string (e.g. -rwsr-xr-x)"""
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
    """Find files writable by current execution context within a directory"""
    writable = []
    if not os.path.exists(path_dir) or not os.path.isdir(path_dir):
        return writable
    try:
        for entry in os.scandir(path_dir):
            try:
                if entry.is_file(follow_symlinks=False) and os.access(entry.path, os.W_OK):
                    writable.append(entry.path)
            except Exception:
                continue
    except Exception:
        pass
    return writable


def is_parent_writable(file_path: str) -> bool:
    """Check if the parent directory of a file is writable (enables replacing binary)"""
    try:
        parent = str(Path(file_path).parent.resolve())
        return os.access(parent, os.W_OK)
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
    """Retrieve detailed stat metadata dictionary for evidence bundles"""
    try:
        st = os.stat(file_path)
        return {
            'path': file_path,
            'size_bytes': st.st_size,
            'uid': st.st_uid,
            'gid': st.st_gid,
            'mode_octal': oct(st.st_mode)[-4:],
            'is_suid': bool(st.st_mode & stat.S_ISUID),
            'is_sgid': bool(st.st_mode & stat.S_ISGID),
            'is_world_writable': bool(st.st_mode & stat.S_IWOTH),
            'parent_writable': is_parent_writable(file_path)
        }
    except Exception as e:
        return {'path': file_path, 'error': str(e)}
