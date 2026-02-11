#!/usr/bin/env python3
"""Organise files in a directory by extension into categorised subdirectories."""

import os
import shutil
import sys

CATEGORIES = {
    "images": {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".webp", ".ico"},
    "documents": {".pdf", ".doc", ".docx", ".txt", ".md", ".rtf", ".odt", ".csv", ".xls", ".xlsx"},
    "code": {".py", ".go", ".js", ".ts", ".rs", ".java", ".c", ".cpp", ".h", ".rb", ".sh", ".yaml", ".yml", ".json", ".toml"},
    "audio": {".mp3", ".wav", ".flac", ".ogg", ".aac", ".m4a"},
    "video": {".mp4", ".mkv", ".avi", ".mov", ".webm"},
    "archives": {".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar"},
}


def get_category(ext):
    ext = ext.lower()
    for cat, exts in CATEGORIES.items():
        if ext in exts:
            return cat
    return "other"


def organise(target_dir):
    if not os.path.isdir(target_dir):
        print(f"Error: {target_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    moved = 0
    for entry in os.listdir(target_dir):
        full = os.path.join(target_dir, entry)
        if not os.path.isfile(full):
            continue

        _, ext = os.path.splitext(entry)
        if not ext:
            continue

        cat = get_category(ext)
        dest_dir = os.path.join(target_dir, cat)
        os.makedirs(dest_dir, exist_ok=True)

        dest = os.path.join(dest_dir, entry)
        if os.path.exists(dest):
            print(f"  skip (exists): {entry}")
            continue

        shutil.move(full, dest)
        print(f"  {entry} -> {cat}/")
        moved += 1

    print(f"\nOrganised {moved} file(s)")


if __name__ == "__main__":
    target = os.environ.get("TARGET_DIR", "/workspace")
    print(f"Organising files in: {target}")
    organise(target)
