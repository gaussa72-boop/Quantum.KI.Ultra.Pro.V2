from pathlib import Path

from tinydb import Query, TinyDB

BASE_DIR = Path(__file__).resolve().parent
DB_DIR = BASE_DIR / "memory"
DB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DB_DIR / "db.json"

db = TinyDB(DB_PATH)
User = Query()


def save_fact(key: str, value: str) -> None:
    """Store or update one persistent fact."""
    db.upsert({"key": key, "value": value}, User.key == key)


def get_memory_string() -> str:
    """Return stored facts as compact context for the AI."""
    facts = db.all()
    if not facts:
        return "Keine vorherigen Daten vorhanden."
    return " ".join(f"{fact['key']} ist {fact['value']}." for fact in facts)


def clear_memory() -> None:
    """Reset the project memory."""
    db.truncate()
