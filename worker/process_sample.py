import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path


ALGORITHMS = ("markov", "simhash", "bigram_dct", "bin2rgb", "wem")
DATA_DIR = Path("/lab/data")
LIB_DIR = Path("/lab/lib_bin2png")


def log(message: str) -> None:
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}", flush=True)


def selected_image_algorithms() -> tuple[str, ...]:
    configured = os.environ.get("IMAGE_ALGORITHMS", "").strip()
    if not configured:
        return ALGORITHMS
    selected = tuple(
        algorithm.strip()
        for algorithm in configured.split(",")
        if algorithm.strip() in ALGORITHMS
    )
    if not selected:
        raise RuntimeError("No hay algoritmos de imagen seleccionados.")
    return selected


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_file(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_sample(sample_hash: str, destination: Path) -> None:
    api_key = os.environ.get("VIRUSHARE_API_KEY", "").strip()
    template = os.environ.get("VIRUSHARE_URL_TEMPLATE", "").strip()
    if not template:
        template = "https://virusshare.com/apiv2/download?apikey={api_key}&hash={hash}"
    if "{api_key}" in template and not api_key:
        raise RuntimeError("Falta VIRUSHARE_API_KEY para descargar desde VirusShare.")

    url = template.format(api_key=api_key, hash=sample_hash)
    request = urllib.request.Request(url, headers={"User-Agent": "lab-creacion-dataset/0.1"})
    log("Descargando muestra comprimida desde VirusShare.")
    with urllib.request.urlopen(request, timeout=90) as response:
        if response.status >= 400:
            raise RuntimeError(f"VirusShare respondió HTTP {response.status}.")
        with destination.open("wb") as output:
            shutil.copyfileobj(response, output)


def extract_archive(archive_path: Path, work_dir: Path) -> list[Path]:
    log("Descomprimiendo muestra en cuarentena.")
    work_dir.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(archive_path) as archive:
            password = os.environ.get("SAMPLE_ZIP_PASSWORD", "infected").encode()
            archive.extractall(work_dir, pwd=password)
    except RuntimeError:
        with zipfile.ZipFile(archive_path) as archive:
            archive.extractall(work_dir)

    return [path for path in work_dir.rglob("*") if path.is_file()]


def find_matching_binary(paths: list[Path], sample_hash: str) -> Path:
    algorithms = []
    if len(sample_hash) == 32:
        algorithms.append("md5")
    elif len(sample_hash) == 40:
        algorithms.append("sha1")
    elif len(sample_hash) == 64:
        algorithms.append("sha256")

    for path in paths:
        for algorithm in algorithms:
            if hash_file(path, algorithm).lower() == sample_hash:
                log(f"Hash verificado con {algorithm}: {path.name}")
                return path

    if len(paths) == 1:
        log("No se pudo comparar el hash solicitado, pero el ZIP contiene un solo archivo.")
        return paths[0]

    raise RuntimeError("No se encontró un binario que coincida con el hash solicitado.")


def generate_images(binary: Path, image_dir: Path) -> int:
    sys.path.insert(0, str(LIB_DIR))
    from funciones import mapping

    selected = selected_image_algorithms()
    image_dir.mkdir(parents=True, exist_ok=True)
    for algorithm in ALGORITHMS:
        if algorithm not in selected:
            shutil.rmtree(image_dir / algorithm, ignore_errors=True)

    count = 0
    for algorithm in selected:
        output_dir = image_dir / algorithm
        output_dir.mkdir(parents=True, exist_ok=True)
        output = output_dir / f"{binary.name}.png"
        log(f"Generando imagen {algorithm}.")
        mapping[algorithm](str(binary), str(output))
        if output.exists():
            count += 1
    return count


def main() -> int:
    if len(sys.argv) != 2:
        print("Uso: process_sample.py <hash>", file=sys.stderr)
        return 2

    sample_hash = sys.argv[1].lower().strip()
    sample_dir = Path(os.environ.get("SAMPLE_OUTPUT_DIR", str(DATA_DIR / sample_hash)))
    image_dir = sample_dir / "images"

    sample_dir.mkdir(parents=True, exist_ok=True)
    metadata_path = sample_dir / "metadata.json"

    metadata = {
        "hash": sample_hash,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "running",
        "stored_artifacts": ["images", "metadata.json"],
    }

    tmp_root = Path(tempfile.mkdtemp(prefix=f"sample-{sample_hash}-"))
    original_zip = tmp_root / "original.zip"
    work_dir = tmp_root / "work"

    try:
        download_sample(sample_hash, original_zip)
        extracted = extract_archive(original_zip, work_dir)
        binary = find_matching_binary(extracted, sample_hash)
        metadata["binary_sha256"] = sha256_file(binary)
        metadata["image_count"] = generate_images(binary, image_dir)
        metadata["status"] = "completed"
        return 0
    except Exception as exc:
        metadata["status"] = "failed"
        metadata["error"] = str(exc)
        log(f"ERROR: {exc}")
        return 1
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)
        metadata["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
