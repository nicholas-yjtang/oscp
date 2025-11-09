#!/usr/bin/python3
import pty
import os

def run_interactive_bash():
    """
    Spawns an interactive Bash shell.
    """
    print("Spawning interactive Bash shell...")
    pty.spawn("/bin/bash")
    print("Exited interactive Bash shell.")

if __name__ == "__main__":
    run_interactive_bash()