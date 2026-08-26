import argparse
import fnmatch
import itertools
import os
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Set, Tuple

DEFAULT_IGNORE: Set[str] = {
    ".git", ".svn", ".hg",
    ".vscode", ".idea", ".vs", ".settings", ".project",
    ".DS_Store", "Thumbs.db",
    "target", ".cargo",
    "build", "builds", "cmake-build-debug", "cmake-build-release",
    "CMakeFiles", "bin", "obj", "_build", ".build", "out", "dist",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".venv", "venv", "env",
    "node_modules", ".next", ".nuxt", ".output", ".cache",
    "vendor",
    ".gradle", ".mvn", ".dart_tool", "Pods", "DerivedData",
    "*.pyc", "*.exe", "*.dll", "*.so", "*.dylib", "*.png", "*.jpg", "*.jpeg", "*.pdf", "*.zip"
}

# Batas maksimum ukuran file yang dibaca kodenya (misal: 5 MB) untuk mencegah OOT
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024 


@dataclass
class TreeState:
    total_folders: int = 0
    total_files: int = 0
    errors: int = 0


class Spinner:
    def __init__(self, message="Memindai folder..."):
        self.message = message
        self.stop_running = False
        self.thread = None

    def _spin(self):
        spinners = itertools.cycle(["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
        while not self.stop_running:
            try:
                sys.stdout.write(f"\r\033[K{next(spinners)} {self.message}")
                sys.stdout.flush()
            except Exception:
                pass
            time.sleep(0.08)
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()

    def start(self):
        self.stop_running = False
        self.thread = threading.Thread(target=self._spin, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_running = True
        if self.thread and self.thread.is_alive():
            self.thread.join()


def load_gitignore_rules(root_dir: Path) -> Set[str]:
    ignore_set = set(DEFAULT_IGNORE)
    gitignore_path = root_dir / ".gitignore"
    if gitignore_path.is_file():
        try:
            with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        clean_line = line.rstrip("/").lstrip("/")
                        if clean_line:
                            ignore_set.add(clean_line)
        except Exception:
            pass
    return ignore_set


def _is_ignored(name: str, rel_path: str, ignore_rules: Set[str]) -> bool:
    if name in ignore_rules:
        return True
    for rule in ignore_rules:
        if fnmatch.fnmatch(name, rule) or fnmatch.fnmatch(rel_path, rule):
            return True
    return False


def _is_binary_file(file_path: Path) -> bool:
    """Deteksi cepat file biner agar tidak dibaca ke memory saat mode --code"""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            return b"\x00" in chunk
    except Exception:
        return True


def scan_and_stream_iterative(
    root_path: Path,
    file_handle,
    ignore_rules: Set[str],
    state: TreeState,
    include_code: bool = False,
    max_depth: int = 15,
):
    # Stack menyimpan Tuple: (current_dir, rel_dir_path, depth, prefix)
    stack: List[Tuple[Path, str, int, str]] = [(root_path, "", 0, "")]
    
    # Menampung file kode hanya jika include_code=True.
    # Menggunakan penulisan sekunder/stream bertahap tanpa menyimpan objek berat.
    code_files_queue: List[Tuple[Path, str]] = []

    file_handle.write(f"# Struktur Proyek: `{root_path.name}`\n\n")

    while stack:
        current_dir, rel_dir_path, depth, prefix = stack.pop()

        if depth > max_depth:
            file_handle.write(f"{prefix}- ⚠️ *[Kedalaman Maksimum Tercapai]*\n")
            continue

        directories = []
        files = []

        try:
            with os.scandir(current_dir) as entries:
                for entry in entries:
                    name = entry.name
                    rel_item_path = os.path.join(rel_dir_path, name) if rel_dir_path else name

                    if _is_ignored(name, rel_item_path, ignore_rules):
                        continue

                    try:
                        if entry.is_symlink():
                            continue

                        if entry.is_dir(follow_symlinks=False):
                            directories.append((name, entry.path, rel_item_path))
                        else:
                            files.append((name, entry.path, rel_item_path))
                    except OSError:
                        continue
        except PermissionError:
            state.errors += 1
            file_handle.write(f"{prefix}- ⚠️ *[Akses Ditolak]*\n")
            continue
        except Exception:
            state.errors += 1
            file_handle.write(f"{prefix}- ⚠️ *[Error Membaca]*\n")
            continue

        directories.sort(key=lambda x: x[0].lower())
        files.sort(key=lambda x: x[0].lower())

        state.total_files += len(files)
        state.total_folders += len(directories)

        # Tulis File dalam folder saat ini
        for file_name, file_path_str, rel_item_path in files:
            file_handle.write(f"{prefix}- 📄 `{file_name}`\n")
            if include_code:
                code_files_queue.append((Path(file_path_str), rel_item_path))

        # Masukkan Folder ke Stack secara terbalik agar diproses sesuai abjad A-Z
        for dir_name, dir_path, rel_item_path in reversed(directories):
            file_handle.write(f"{prefix}- 📁 **{dir_name}/**\n")
            stack.append((Path(dir_path), rel_item_path, depth + 1, prefix + "  "))

        file_handle.flush()

    # Stream isi file jika opsi --code digunakan
    if include_code and code_files_queue:
        file_handle.write("\n---\n\n# Isi Kode Sumber\n\n")
        
        while code_files_queue:
            # Menggunakan pop(0) / iterasi langsung agar daftar dibebaskan dari RAM bertahap
            full_path, rel_path = code_files_queue.pop(0)
            file_handle.write(f"## File: `{rel_path}`\n\n")

            # Protection 1: Cek apakah file biner
            if _is_binary_file(full_path):
                file_handle.write("*[File biner / tidak dapat ditampilkan]*\n\n")
                continue

            # Protection 2: Cek Ukuran File (Anti OOT untuk file jumbo/log/dump)
            try:
                if os.path.getsize(full_path) > MAX_FILE_SIZE_BYTES:
                    file_handle.write("*[File terlalu besar (> 5MB) / dilewati untuk mencegah OOT]*\n\n")
                    continue
            except OSError:
                pass

            lang = full_path.suffix.lstrip(".")
            file_handle.write(f"```{lang}\n")
            try:
                with open(full_path, "r", encoding="utf-8", errors="replace") as f_code:
                    for line in f_code:
                        file_handle.write(line)
            except Exception as e:
                file_handle.write(f"// Error membaca isi file: {e}\n")
            file_handle.write("\n```\n\n")
            file_handle.flush()


def resolve_output_path(output_arg: str, default_name: Path) -> Path:
    out_path = Path(output_arg).resolve() if output_arg else default_name.resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    return out_path


def main():
    parser = argparse.ArgumentParser(
        description="CLI Generator Pohon Direktori & Ekstraktor Kode Proyek ke Markdown."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--tree", type=str, metavar="FOLDER", help="Hanya memetakan struktur hierarki folder.")
    group.add_argument("--code", type=str, metavar="FOLDER", help="Memetakan hierarki folder sekaligus mengekstrak seluruh isi kode.")

    parser.add_argument("-o", "--output", type=str, help="Path file output markdown. Folder otomatis dibuat jika belum ada.")

    args = parser.parse_args()

    include_code = False
    target_dir_str = args.tree if args.tree else args.code
    if args.code:
        include_code = True

    target_dir = Path(target_dir_str).resolve()

    if not target_dir.exists() or not target_dir.is_dir():
        print(f"Error: Path '{target_dir}' tidak ditemukan atau bukan folder.")
        sys.exit(1)

    suffix = "CODE" if include_code else "TREE"
    default_out_path = target_dir.parent / f"{target_dir.name}_{suffix}.md"
    output_file = resolve_output_path(args.output, default_out_path)

    ignore_rules = load_gitignore_rules(target_dir)
    state = TreeState()

    spinner = Spinner(f"Memindai & mengekstrak ({'Kode' if include_code else 'Tree'}): {target_dir.name}...")
    spinner.start()

    start_time = time.perf_counter()

    try:
        with open(output_file, "w", encoding="utf-8", buffering=64 * 1024) as f:
            scan_and_stream_iterative(
                root_path=target_dir,
                file_handle=f,
                ignore_rules=ignore_rules,
                state=state,
                include_code=include_code
            )
    except KeyboardInterrupt:
        spinner.stop()
        print("\n\n⚠️ Proses dibatalkan oleh pengguna (KeyboardInterrupt).")
        sys.exit(1)
    finally:
        spinner.stop()

    elapsed = time.perf_counter() - start_time

    print(f"✅ Selesai dalam {elapsed:.2f} detik!")
    print(f"📁 Total Folder : {state.total_folders}")
    print(f"📄 Total File   : {state.total_files}")
    if state.errors > 0:
        print(f"⚠️ Peringatan   : {state.errors} folder tidak bisa diakses.")
    print(f"📝 Output disimpan di: {output_file}")


if __name__ == "__main__":
    main()
