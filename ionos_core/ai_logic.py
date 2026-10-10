import os
def analyze_code():
    report = []
    paths = ['./core', './templates', './static']
    for p in paths:
        if os.path.exists(p):
            files = os.listdir(p)
            report.append(f"Ordner {p}: {len(files)} Dateien gefunden.")
    return "\n".join(report)

def get_ai_response(ai_type, message):
    if ai_type == "mirror":
        return f"MIRROR-SCAN:\n{analyze_code()}\nBereit für Code-Genesis."
    return f"Kern stabil. Nachricht erhalten: {message}"
