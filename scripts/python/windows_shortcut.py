#!/usr/bin/python3
import sys
import pylnk3
import os

def create_shortcut (target_path, shortcut) :
    lnk = pylnk3.create()
    lnk.path = target_path
    lnk.write(shortcut)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python windows_shortcut.py <target_path> <shortcut>")
        sys.exit(1)

    target_path = sys.argv[1]
    shortcut = sys.argv[2]
    create_shortcut(target_path, shortcut)
    print(f"Shortcut created at '{shortcut}' pointing to '{target_path}'.")