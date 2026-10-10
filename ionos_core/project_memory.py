import os

try:
    from git import Repo
except ImportError:
    Repo = None


def get_project_status():
    status = "Projekt-Status: "
    try:
        if Repo:
            repo = Repo(".")
            # Holt die letzten 3 Commit-Nachrichten
            commits = list(repo.iter_commits(max_count=3))
            commit_history = " | ".join([c.message.strip() for c in commits])
            status += f"Letzte Updates: {commit_history}. "

        # Prüft wichtige Dateien
        files = os.listdir('.')
        status += f"Dateien im Kern: {', '.join(files)}."
    except Exception:
        status += "Kern-Dateien lokal vorhanden."
    return status