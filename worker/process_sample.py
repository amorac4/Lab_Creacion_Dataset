import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path


ALGORITHMS = ("markov", "simhash", "bigram_dct", "bin2rgb", "wem")
DATA_DIR = Path("/lab/data")
LIB_DIR = Path("/lab/lib_bin2png")
YARA_RULES_DIR = Path("/lab/worker/yara_rules")
MAX_STORED_STRINGS = 250
MAX_STRING_LENGTH = 300
MAX_TOOL_OUTPUT = 12000
MAX_IOCS_PER_TYPE = 200


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


def all_hashes(path: Path) -> dict:
    digests = {
        "md5": hashlib.md5(usedforsecurity=False),
        "sha1": hashlib.sha1(usedforsecurity=False),
        "sha256": hashlib.sha256(),
    }
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def truncate_text(value: str, limit: int = MAX_TOOL_OUTPUT) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + "\n...[truncated]"


def run_tool(args: list[str], timeout: int = 20) -> dict:
    if not shutil.which(args[0]):
        return {"available": False, "command": args, "error": f"{args[0]} no esta instalado."}
    try:
        result = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"available": True, "command": args, "error": f"Timeout despues de {timeout}s."}
    except Exception as exc:
        return {"available": True, "command": args, "error": str(exc)}
    return {
        "available": True,
        "command": args,
        "returncode": result.returncode,
        "stdout": truncate_text(result.stdout),
        "stderr": truncate_text(result.stderr),
    }


def byte_profile(path: Path) -> dict:
    histogram = [0] * 256
    total = 0
    printable = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            total += len(chunk)
            for byte in chunk:
                histogram[byte] += 1
                if byte in (9, 10, 13) or 32 <= byte <= 126:
                    printable += 1

    entropy = 0.0
    if total:
        for count in histogram:
            if count:
                probability = count / total
                entropy -= probability * math.log2(probability)

    top_bytes = sorted(
        (
            {"byte": index, "hex": f"{index:02x}", "count": count, "ratio": count / total if total else 0}
            for index, count in enumerate(histogram)
        ),
        key=lambda item: item["count"],
        reverse=True,
    )[:16]
    return {
        "size_bytes": total,
        "entropy": round(entropy, 6),
        "printable_ratio": round(printable / total, 6) if total else 0,
        "byte_histogram": histogram,
        "top_bytes": top_bytes,
    }


def extract_ascii_strings(path: Path, min_length: int = 4) -> dict:
    strings = []
    current = bytearray()
    total_found = 0
    longest = 0

    def flush() -> None:
        nonlocal current, total_found, longest
        if len(current) >= min_length:
            total_found += 1
            longest = max(longest, len(current))
            if len(strings) < MAX_STORED_STRINGS:
                text = current[:MAX_STRING_LENGTH].decode("ascii", errors="replace")
                if len(current) > MAX_STRING_LENGTH:
                    text += "...[truncated]"
                strings.append(text)
        current = bytearray()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            for byte in chunk:
                if 32 <= byte <= 126:
                    current.append(byte)
                else:
                    flush()
    flush()
    return {
        "min_length": min_length,
        "stored_limit": MAX_STORED_STRINGS,
        "total_found": total_found,
        "longest_length": longest,
        "values": strings,
    }


def unique_limited(values: list[str], limit: int = MAX_IOCS_PER_TYPE) -> list[str]:
    seen = set()
    result = []
    for value in values:
        cleaned = value.strip().strip(".,;:'\")]}><")
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            result.append(cleaned)
        if len(result) >= limit:
            break
    return result


def extract_iocs(strings: dict) -> dict:
    text = "\n".join(strings.get("values") or [])
    patterns = {
        "urls": r"https?://[^\s\"'<>]+",
        "domains": r"\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:com|net|org|info|biz|ru|cn|ir|br|top|xyz|io|co|mx|es|de|uk|fr|nl|pl|ua|su)\b",
        "ipv4": r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
        "emails": r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+\b",
        "windows_paths": r"(?:[A-Za-z]:\\|\\\\)[^\r\n\t\"'<>|]+",
        "registry_keys": r"\bHKEY_(?:CLASSES_ROOT|CURRENT_USER|LOCAL_MACHINE|USERS|CURRENT_CONFIG)\\[^\r\n\t\"']+",
        "suspicious_commands": r"\b(?:powershell(?:\.exe)?|cmd(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?|mshta(?:\.exe)?|bitsadmin(?:\.exe)?|certutil(?:\.exe)?|curl(?:\.exe)?|wget(?:\.exe)?|Invoke-Expression|FromBase64String)\b",
    }
    findings = {
        name: unique_limited(re.findall(pattern, text, flags=re.IGNORECASE))
        for name, pattern in patterns.items()
    }
    return {
        "counts": {name: len(values) for name, values in findings.items()},
        "values": findings,
    }


def file_identification(path: Path) -> dict:
    with path.open("rb") as handle:
        header = handle.read(32)
    return {
        "first_32_bytes_hex": header.hex(),
        "file": run_tool(["file", "-b", str(path)]),
        "mime": run_tool(["file", "--mime-type", "-b", str(path)]),
    }


def exiftool_metadata(path: Path) -> dict:
    result = run_tool(["exiftool", "-json", "-n", str(path)], timeout=20)
    if result.get("available") and result.get("returncode") == 0 and result.get("stdout"):
        try:
            parsed = json.loads(result["stdout"])
            result["parsed"] = parsed[0] if parsed else {}
            result.pop("stdout", None)
        except Exception as exc:
            result["parse_error"] = str(exc)
    return result


def pe_analysis(path: Path) -> dict:
    try:
        import pefile
    except Exception as exc:
        return {"available": False, "error": f"pefile no esta disponible: {exc}"}

    try:
        pe = pefile.PE(str(path), fast_load=False)
    except Exception as exc:
        return {"available": True, "is_pe": False, "error": str(exc)}

    sections = []
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        sections.append(
            {
                "name": name,
                "virtual_address": section.VirtualAddress,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(section.get_entropy(), 6),
                "characteristics": section.Characteristics,
            }
        )

    imports = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            imports.append(
                {
                    "dll": entry.dll.decode("utf-8", errors="replace"),
                    "symbols": [
                        item.name.decode("utf-8", errors="replace") if item.name else f"ordinal_{item.ordinal}"
                        for item in entry.imports[:200]
                    ],
                    "truncated": len(entry.imports) > 200,
                }
            )

    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        exports = [
            symbol.name.decode("utf-8", errors="replace") if symbol.name else f"ordinal_{symbol.ordinal}"
            for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols[:300]
        ]

    return {
        "available": True,
        "is_pe": True,
        "machine": pe.FILE_HEADER.Machine,
        "number_of_sections": pe.FILE_HEADER.NumberOfSections,
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        "image_base": pe.OPTIONAL_HEADER.ImageBase,
        "subsystem": pe.OPTIONAL_HEADER.Subsystem,
        "sections": sections,
        "imports": imports,
        "exports": exports,
    }


def elf_analysis(path: Path) -> dict:
    with path.open("rb") as handle:
        is_elf = handle.read(4) == b"\x7fELF"
    if not is_elf:
        return {"is_elf": False}
    return {
        "is_elf": True,
        "header": run_tool(["readelf", "-h", str(path)]),
        "sections": run_tool(["readelf", "-S", str(path)]),
        "program_headers": run_tool(["readelf", "-l", str(path)]),
        "dynamic": run_tool(["readelf", "-d", str(path)]),
    }


def pdf_analysis(path: Path, identification: dict) -> dict:
    first_bytes = bytes.fromhex(identification.get("first_32_bytes_hex", ""))
    file_text = ((identification.get("file") or {}).get("stdout") or "").lower()
    mime_text = ((identification.get("mime") or {}).get("stdout") or "").lower()
    is_pdf = first_bytes.startswith(b"%PDF") or "pdf" in file_text or "application/pdf" in mime_text
    if not is_pdf:
        return {"is_pdf": False}

    data = path.read_bytes()
    text = data.decode("latin-1", errors="ignore")
    tokens = [
        "/JavaScript",
        "/JS",
        "/OpenAction",
        "/AA",
        "/Launch",
        "/EmbeddedFile",
        "/AcroForm",
        "/XFA",
        "/RichMedia",
        "/ObjStm",
        "/Encrypt",
        "/URI",
        "/SubmitForm",
        "/GoToE",
        "/GoToR",
        "/Names",
    ]
    token_counts = {token: text.count(token) for token in tokens}
    stream_count = len(re.findall(r"\bstream\b", text))
    object_count = len(re.findall(r"\b\d+\s+\d+\s+obj\b", text))
    suspicious_tokens = {token: count for token, count in token_counts.items() if count}
    risk_flags = []
    for token in ("/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile", "/XFA", "/RichMedia"):
        if token_counts.get(token):
            risk_flags.append(token)
    return {
        "is_pdf": True,
        "version": first_bytes[:8].decode("latin-1", errors="ignore") if first_bytes.startswith(b"%PDF") else None,
        "object_count": object_count,
        "stream_count": stream_count,
        "token_counts": token_counts,
        "suspicious_tokens": suspicious_tokens,
        "risk_flags": risk_flags,
    }


def yara_analysis(path: Path) -> dict:
    if not YARA_RULES_DIR.exists():
        return {"available": False, "error": "No hay reglas YARA locales."}
    rule_files = sorted(YARA_RULES_DIR.rglob("*.yar")) + sorted(YARA_RULES_DIR.rglob("*.yara"))
    if not rule_files:
        return {"available": False, "error": "No hay archivos .yar locales."}

    combined = {
        "available": shutil.which("yara") is not None,
        "commands": [],
        "stdout": "",
        "stderr": "",
        "matches": [],
        "match_count": 0,
    }
    if not combined["available"]:
        return {"available": False, "error": "yara no esta instalado."}

    for rule_file in rule_files:
        result = run_tool(["yara", "-w", str(rule_file), str(path)], timeout=30)
        combined["commands"].append(result.get("command"))
        if result.get("stdout"):
            combined["stdout"] += result["stdout"]
        if result.get("stderr"):
            combined["stderr"] += result["stderr"]
        if result.get("returncode") not in (0, 1, None):
            combined["stderr"] += f"\n{rule_file.name}: codigo {result.get('returncode')}"

    result = combined
    matches = []
    if result.get("available") and result.get("stdout"):
        for line in result["stdout"].splitlines():
            parts = line.strip().split(maxsplit=1)
            if parts:
                matches.append({"rule": parts[0], "target": Path(parts[1]).name if len(parts) > 1 else ""})
    result["matches"] = matches
    result["match_count"] = len(matches)
    return result


def static_analysis(binary: Path, analysis_dir: Path) -> dict:
    log("Ejecutando analisis estatico.")
    analysis_dir.mkdir(parents=True, exist_ok=True)
    identification = file_identification(binary)
    strings = extract_ascii_strings(binary)
    analysis = {
        "schema_version": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_artifact_policy": "El binario y el ZIP se procesan en temporal y no se conservan.",
        "hashes": all_hashes(binary),
        "byte_profile": byte_profile(binary),
        "identification": identification,
        "strings": strings,
        "iocs": extract_iocs(strings),
        "exiftool": exiftool_metadata(binary),
        "pe": pe_analysis(binary),
        "elf": elf_analysis(binary),
        "pdf": pdf_analysis(binary, identification),
        "yara": yara_analysis(binary),
        "objdump_file_header": run_tool(["objdump", "-f", str(binary)]),
    }
    output = analysis_dir / "static_analysis.json"
    output.write_text(json.dumps(analysis, indent=2), encoding="utf-8")
    return analysis


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
    analysis_dir = sample_dir / "analysis"

    sample_dir.mkdir(parents=True, exist_ok=True)
    metadata_path = sample_dir / "metadata.json"

    metadata = {
        "hash": sample_hash,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "running",
        "stored_artifacts": ["images", "analysis/static_analysis.json", "metadata.json"],
    }

    tmp_root = Path(tempfile.mkdtemp(prefix=f"sample-{sample_hash}-"))
    original_zip = tmp_root / "original.zip"
    work_dir = tmp_root / "work"

    try:
        download_sample(sample_hash, original_zip)
        extracted = extract_archive(original_zip, work_dir)
        binary = find_matching_binary(extracted, sample_hash)
        metadata["binary_sha256"] = sha256_file(binary)
        analysis = static_analysis(binary, analysis_dir)
        metadata["static_analysis"] = {
            "path": "analysis/static_analysis.json",
            "size_bytes": analysis["byte_profile"]["size_bytes"],
            "entropy": analysis["byte_profile"]["entropy"],
            "md5": analysis["hashes"]["md5"],
            "sha1": analysis["hashes"]["sha1"],
            "sha256": analysis["hashes"]["sha256"],
        }
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
