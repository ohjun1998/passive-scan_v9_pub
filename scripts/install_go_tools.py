"""Resolve once and lock optional tools, retaining exact module versions."""
import json
import subprocess
from pathlib import Path

PACKAGES = {
    "subfinder": ("github.com/projectdiscovery/subfinder/v2", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"),
    "gau": ("github.com/lc/gau/v2", "github.com/lc/gau/v2/cmd/gau"),
    "waybackurls": ("github.com/tomnomnom/waybackurls", "github.com/tomnomnom/waybackurls"),
    "jsluice": ("github.com/BishopFox/jsluice", "github.com/BishopFox/jsluice/cmd/jsluice"),
}

def main():
    path = Path("state/tools.lock.json")
    lock = json.loads(path.read_text()) if path.exists() else {}
    for name, (module, package) in PACKAGES.items():
        if name not in lock:
            proc = subprocess.run(["go", "list", "-m", "-json", module + "@latest"], check=True, capture_output=True, text=True)
            lock[name] = json.loads(proc.stdout)["Version"]
        subprocess.run(["go", "install", package + "@" + lock[name]], check=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(lock, indent=2))

if __name__ == "__main__":
    main()
