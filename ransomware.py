"""
BENIGN FILE-CONTENT RANDOMIZER (SAFE LAB SIMULATOR)
===================================================
- Creates its own test files in a dedicated subfolder and overwrites ONLY those.
- NOT ransomware: no encryption, no key, no renaming, no recursion.
"""

import os
import time
import random
import string

BASE_FOLDER = r"C:\Users\Student\Desktop\capstone g\watched"
SAFE_FOLDER = os.path.join(BASE_FOLDER, "SAFE_SIM_FILES")

TEST_FILE_COUNT = 5
TEST_FILE_PREFIX = "SAFE_LAB_FILE_"
TEST_FILE_EXTENSION = ".txt"

LOW_PHASE_SECONDS = 12
FILE_SIZE_CHARS = 120_000

def ensure_safe_folder() -> None:
    os.makedirs(SAFE_FOLDER, exist_ok=True)
    print("[*] Safe folder:", SAFE_FOLDER)

def test_file_paths():
    return [
        os.path.join(SAFE_FOLDER, f"{TEST_FILE_PREFIX}{i}{TEST_FILE_EXTENSION}")
        for i in range(1, TEST_FILE_COUNT + 1)
    ]

def _random_text(n: int) -> str:
    alphabet = string.ascii_letters + string.digits + "     \n"
    return "".join(random.choices(alphabet, k=n))

def write_low_entropy_files() -> None:
    print("[*] Phase 1: Writing LOW-entropy content...")
    data = ("A" * 200) + "\n"
    for path in test_file_paths():
        with open(path, "w", encoding="utf-8", errors="ignore") as f:
            reps = max(1, FILE_SIZE_CHARS // len(data))
            f.write(data * reps)
        print("    - wrote low entropy ->", path)
    print("[*] Low-entropy phase done.\n")

def write_random_files() -> None:
    print("[*] Phase 2: Overwriting with RANDOM text...")
    for path in test_file_paths():
        with open(path, "w", encoding="utf-8", errors="ignore") as f:
            f.write(_random_text(FILE_SIZE_CHARS))
        print("    - wrote random content ->", path)
    print("[*] Random phase done.\n")

if __name__ == "_main_":
    ensure_safe_folder()
    write_low_entropy_files()
    print(f"[*] Waiting {LOW_PHASE_SECONDS}s...")
    time.sleep(LOW_PHASE_SECONDS)
    write_random_files()
    print("[*] Done. Only SAFE_LAB_FILE_#.txt inside SAFE_SIM_FILES were modified.")
