#!/usr/bin/env python3
"""Generate statistics for a git repository."""

import json
import os
import subprocess
import sys
from collections import Counter


def run_git(args, cwd):
    result = subprocess.run(
        ["git"] + args,
        capture_output=True,
        text=True,
        cwd=cwd,
    )
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def get_stats(repo_dir):
    if not os.path.isdir(os.path.join(repo_dir, ".git")):
        print(f"Error: {repo_dir} is not a git repository", file=sys.stderr)
        sys.exit(1)

    stats = {}

    # Total commits
    log = run_git(["log", "--oneline"], repo_dir)
    commits = log.split("\n") if log else []
    stats["total_commits"] = len(commits)

    # Authors
    author_log = run_git(["log", "--format=%aN"], repo_dir)
    authors = author_log.split("\n") if author_log else []
    author_counts = Counter(authors)
    stats["authors"] = [
        {"name": name, "commits": count}
        for name, count in author_counts.most_common(10)
    ]
    stats["total_authors"] = len(set(authors))

    # File types
    files = run_git(["ls-files"], repo_dir)
    file_list = files.split("\n") if files else []
    ext_counts = Counter()
    for f in file_list:
        _, ext = os.path.splitext(f)
        ext_counts[ext if ext else "(no ext)"] += 1
    stats["file_types"] = [
        {"extension": ext, "count": count}
        for ext, count in ext_counts.most_common(15)
    ]
    stats["total_files"] = len(file_list)

    # Recent activity (last 30 days)
    recent = run_git(["log", "--oneline", "--since=30 days ago"], repo_dir)
    recent_commits = recent.split("\n") if recent else []
    stats["commits_last_30_days"] = len([c for c in recent_commits if c])

    # First and last commit dates
    first_date = run_git(["log", "--reverse", "--format=%aI", "-1"], repo_dir)
    last_date = run_git(["log", "--format=%aI", "-1"], repo_dir)
    stats["first_commit"] = first_date
    stats["last_commit"] = last_date

    return stats


if __name__ == "__main__":
    repo = os.environ.get("REPO_DIR", "/workspace")
    print(f"Analysing git repository: {repo}\n")

    stats = get_stats(repo)

    print(f"Total commits:    {stats['total_commits']}")
    print(f"Total authors:    {stats['total_authors']}")
    print(f"Total files:      {stats['total_files']}")
    print(f"Last 30 days:     {stats['commits_last_30_days']} commits")
    print(f"First commit:     {stats['first_commit']}")
    print(f"Last commit:      {stats['last_commit']}")

    print(f"\nTop authors:")
    for a in stats["authors"][:5]:
        print(f"  {a['name']}: {a['commits']} commits")

    print(f"\nFile types:")
    for ft in stats["file_types"][:10]:
        print(f"  {ft['extension']}: {ft['count']} files")

    # Write JSON output
    print(f"\n{json.dumps(stats, indent=2)}")
