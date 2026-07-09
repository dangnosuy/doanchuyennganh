#!/usr/bin/env python3
"""
Switch between MARL configurations.
Usage:
    python switch_env.py ollama   # Use Ollama models
    python switch_env.py github   # Use GitHub Copilot API
"""
import sys
import shutil
from pathlib import Path

def main():
    if len(sys.argv) < 2:
        print("Usage: python switch_env.py [ollama|github]")
        sys.exit(1)
    
    mode = sys.argv[1].lower()
    env_file = Path(__file__).resolve().parent
    
    if mode == "ollama":
        src = env_file / ".env.ollama"
        dst = env_file / ".env"
        print("Switching to Ollama configuration...")
    elif mode == "github":
        src = env_file / ".env.github"
        dst = env_file / ".env"
        print("Switching to GitHub Copilot configuration...")
    else:
        print(f"Unknown mode: {mode}")
        sys.exit(1)
    
    if not src.exists():
        print(f"Error: {src} not found!")
        sys.exit(1)
    
    # Backup current .env
    if dst.exists():
        backup = env_file / ".env.backup"
        shutil.copy(dst, backup)
        print(f"Backed up current .env to .env.backup")
    
    # Copy new config
    shutil.copy(src, dst)
    print(f"Switched to {mode} configuration!")
    print(f"\nCurrent config:")
    print("-" * 40)
    print(dst.read_text())

if __name__ == "__main__":
    main()
