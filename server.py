import json
import os
import re
import subprocess
import sys
import threading
import time
import calendar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote


PORT = int(os.environ.get("LAB_PORT", "8000"))
DATA_DIR = Path("/lab/data")
JOBS_FILE = DATA_DIR / "jobs.json"
CONFIG_FILE = DATA_DIR / "config.json"
USAGE_FILE = DATA_DIR / "virushare_usage.json"
VIRUSHARE_INTERVAL_SECONDS = int(os.environ.get("VIRUSHARE_INTERVAL_SECONDS", "16"))
HASH_RE = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$")
HASH_NAME_RE = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$")
BATCH_RE = re.compile(r"[^a-zA-Z0-9_.-]+")
ALGORITHMS = ("markov", "simhash", "bigram_dct", "bin2rgb", "wem")
RESERVED_BATCH_NAMES = {"samples", "archive", "binary", "work", "images", "tmp", "config", "jobs"}

DATA_DIR.mkdir(parents=True, exist_ok=True)
if not JOBS_FILE.exists():
    JOBS_FILE.write_text("[]\n", encoding="utf-8")
if not CONFIG_FILE.exists():
    CONFIG_FILE.write_text("{}\n", encoding="utf-8")
if not USAGE_FILE.exists():
    USAGE_FILE.write_text('{"last_request_at": null}\n', encoding="utf-8")

queue: list[str] = []
running = False
stop_requested = False
current_process = None
lock = threading.Lock()
usage_lock = threading.Lock()


def read_jobs() -> list[dict]:
    try:
        return json.loads(JOBS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def write_jobs(jobs: list[dict]) -> None:
    JOBS_FILE.write_text(json.dumps(jobs, indent=2) + "\n", encoding="utf-8")


def read_config() -> dict:
    try:
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def write_config(config: dict) -> None:
    CONFIG_FILE.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")


def read_usage() -> dict:
    try:
        return json.loads(USAGE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"last_request_at": None}


def write_usage(usage: dict) -> None:
    USAGE_FILE.write_text(json.dumps(usage, indent=2) + "\n", encoding="utf-8")


def sanitize_batch_name(value: str) -> str:
    cleaned = BATCH_RE.sub("_", value.strip()).strip("._-")
    cleaned = cleaned[:80]
    if not cleaned:
        raise ValueError("Ponle nombre al lote o elige uno existente.")
    if cleaned.lower() in RESERVED_BATCH_NAMES or HASH_NAME_RE.match(cleaned.lower()):
        raise ValueError("Ese nombre de lote esta reservado. Usa otro nombre.")
    return cleaned


def batch_path(batch_dir: str) -> Path:
    cleaned = sanitize_batch_name(batch_dir)
    path = (DATA_DIR / cleaned).resolve()
    if not str(path).startswith(str(DATA_DIR.resolve())):
        raise ValueError("Nombre de lote invalido.")
    return path


def list_batches() -> list[dict]:
    batches = []
    if not DATA_DIR.exists():
        return batches
    for path in DATA_DIR.iterdir():
        if not path.is_dir():
            continue
        name = path.name
        lower = name.lower()
        if lower in RESERVED_BATCH_NAMES or HASH_NAME_RE.match(lower) or lower.startswith("."):
            continue
        batches.append({
            "name": name,
            "created_at": path.stat().st_ctime,
            "updated_at": path.stat().st_mtime,
        })
    return sorted(batches, key=lambda batch: batch["updated_at"], reverse=True)


def virushare_api_key() -> str:
    return os.environ.get("VIRUSHARE_API_KEY", "").strip() or read_config().get("virushare_api_key", "").strip()


def processing_options() -> dict:
    config = read_config()
    selected_image_algorithms = config.get("selected_image_algorithms")
    if not isinstance(selected_image_algorithms, list):
        selected_image_algorithms = list(ALGORITHMS)
    selected_image_algorithms = [
        algorithm for algorithm in selected_image_algorithms if algorithm in ALGORITHMS
    ]
    if not selected_image_algorithms:
        selected_image_algorithms = list(ALGORITHMS)
    return {
        "skip_processed_hash": bool(config.get("skip_processed_hash", False)),
        "selected_image_algorithms": selected_image_algorithms,
    }


def public_config() -> dict:
    usage = read_usage()
    options = processing_options()
    return {
        "has_virushare_api_key": bool(virushare_api_key()),
        "virushare_interval_seconds": VIRUSHARE_INTERVAL_SECONDS,
        "last_virushare_request_at": usage.get("last_request_at"),
        **options,
    }


def reserve_virushare_slot(job_id: str) -> bool:
    while True:
        with lock:
            if stop_requested:
                return False

        with usage_lock:
            usage = read_usage()
            last_request_at = usage.get("last_request_at")
            now = time.time()
            elapsed = None if last_request_at is None else now - float(last_request_at)
            if elapsed is None or elapsed >= VIRUSHARE_INTERVAL_SECONDS:
                usage["last_request_at"] = now
                write_usage(usage)
                return True
            wait_seconds = max(1, int(VIRUSHARE_INTERVAL_SECONDS - elapsed))

        update_job(
            job_id,
            {
                "status": "waiting_rate_limit",
                "error": f"Esperando cuota VirusShare: {wait_seconds}s restantes.",
            },
        )
        for _ in range(wait_seconds):
            with lock:
                if stop_requested:
                    return False
            time.sleep(1)


def update_job(job_id: str, patch: dict) -> None:
    with lock:
        jobs = read_jobs()
        for index, job in enumerate(jobs):
            if job["id"] == job_id:
                jobs[index] = {**job, **patch, "updated_at": iso_now()}
                break
        write_jobs(jobs)


def iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def parse_iso(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return calendar.timegm(time.strptime(value, "%Y-%m-%dT%H:%M:%SZ"))
    except Exception:
        return None


def normalize_hashes(value: str) -> list[str]:
    seen = set()
    hashes = []
    for item in re.split(r"[\s,;]+", value.lower()):
        item = item.strip()
        if item and HASH_RE.match(item) and item not in seen:
            seen.add(item)
            hashes.append(item)
    return hashes


def count_pngs(path: Path) -> int:
    if not path.exists():
        return 0
    return len(list(path.rglob("*.png")))


def job_sample_dir(job: dict) -> Path:
    sample_dir = job.get("sample_dir")
    if sample_dir:
        return Path(sample_dir)
    batch_dir = job.get("batch_dir") or "default"
    return DATA_DIR / batch_dir / job["hash"]


def collect_images(job: dict) -> list[str]:
    sample_dir = job_sample_dir(job)
    base = sample_dir / "images"
    if not base.exists():
        return []
    return [
        f"/artifacts/{path.relative_to(DATA_DIR).as_posix()}"
        for path in base.rglob("*.png")
    ]


def collect_analysis(job: dict) -> dict | None:
    sample_dir = job_sample_dir(job)
    path = sample_dir / "analysis" / "static_analysis.json"
    if not path.exists():
        return None
    artifact = f"/artifacts/{path.relative_to(DATA_DIR).as_posix()}"
    try:
        analysis = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"artifact": artifact, "error": str(exc)}

    identification = analysis.get("identification") or {}
    byte_profile = analysis.get("byte_profile") or {}
    strings = analysis.get("strings") or {}
    pe = analysis.get("pe") or {}
    elf = analysis.get("elf") or {}
    exiftool = analysis.get("exiftool") or {}
    exiftool_parsed = exiftool.get("parsed") or {}
    iocs = analysis.get("iocs") or {}
    pdf = analysis.get("pdf") or {}
    yara = analysis.get("yara") or {}
    file_result = identification.get("file") or {}
    mime_result = identification.get("mime") or {}
    create_date = exiftool_parsed.get("CreateDate") or exiftool_parsed.get("CreationDate")
    ioc_counts = iocs.get("counts") or {}
    return {
        "artifact": artifact,
        "summary": {
            "size_bytes": byte_profile.get("size_bytes"),
            "entropy": byte_profile.get("entropy"),
            "printable_ratio": byte_profile.get("printable_ratio"),
            "file_type": file_result.get("stdout", "").strip(),
            "mime_type": mime_result.get("stdout", "").strip(),
            "md5": (analysis.get("hashes") or {}).get("md5"),
            "sha1": (analysis.get("hashes") or {}).get("sha1"),
            "sha256": (analysis.get("hashes") or {}).get("sha256"),
            "strings_total": strings.get("total_found"),
            "strings_stored": len(strings.get("values") or []),
            "is_pe": pe.get("is_pe"),
            "timestamp": pe.get("timestamp"),
            "create_date": create_date,
            "date_source": "ExifTool CreateDate" if create_date else ("PE timestamp" if pe.get("timestamp") else None),
            "pe_sections": len(pe.get("sections") or []),
            "pe_import_dlls": len(pe.get("imports") or []),
            "is_elf": elf.get("is_elf"),
            "exiftool_available": exiftool.get("available"),
            "ioc_total": sum(value for value in ioc_counts.values() if isinstance(value, int)),
            "ioc_counts": ioc_counts,
            "is_pdf": pdf.get("is_pdf"),
            "pdf_risk_flags": pdf.get("risk_flags") or [],
            "yara_match_count": yara.get("match_count", 0),
            "yara_matches": [match.get("rule") for match in (yara.get("matches") or [])],
        },
    }


def has_sample_results(job: dict) -> bool:
    sample_dir = job_sample_dir(job)
    metadata_path = sample_dir / "metadata.json"
    if count_pngs(sample_dir / "images") > 0:
        return True
    if metadata_path.exists():
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            return metadata.get("status") == "completed"
        except Exception:
            return False
    return False


def batch_summary(jobs: list[dict]) -> dict | None:
    if not jobs:
        return None

    latest_batch_id = jobs[0].get("batch_id")
    batch_jobs = [job for job in jobs if job.get("batch_id") == latest_batch_id] if latest_batch_id else jobs
    terminal_statuses = {"completed", "failed", "skipped", "stopped"}
    active_jobs = [job for job in batch_jobs if job.get("status") not in terminal_statuses]
    completed_jobs = [job for job in batch_jobs if job.get("status") == "completed"]

    durations = []
    for job in completed_jobs:
        started_at = parse_iso(job.get("started_at"))
        finished_at = parse_iso(job.get("finished_at"))
        if started_at and finished_at and finished_at > started_at:
            durations.append(finished_at - started_at)

    step_seconds = max(VIRUSHARE_INTERVAL_SECONDS, int(sum(durations) / len(durations)) if durations else VIRUSHARE_INTERVAL_SECONDS)
    now = time.time()
    remaining_seconds = 0

    if active_jobs:
        ordered_active = sorted(active_jobs, key=lambda job: job.get("created_at") or "")
        first_active = ordered_active[0]
        started_at = parse_iso(first_active.get("started_at"))
        if started_at:
            current_remaining = max(0, step_seconds - int(now - started_at))
        else:
            current_remaining = step_seconds
        remaining_seconds = current_remaining + max(0, len(ordered_active) - 1) * step_seconds

    start_candidates = [parse_iso(job.get("started_at")) or parse_iso(job.get("created_at")) for job in batch_jobs]
    finish_candidates = [parse_iso(job.get("finished_at")) for job in batch_jobs]
    started_at = min(value for value in start_candidates if value) if any(start_candidates) else None
    estimated_finish_at = now + remaining_seconds if active_jobs else (max(value for value in finish_candidates if value) if any(finish_candidates) else None)

    return {
        "batch_id": latest_batch_id,
        "total": len(batch_jobs),
        "completed": len(completed_jobs),
        "failed": len([job for job in batch_jobs if job.get("status") == "failed"]),
        "skipped": len([job for job in batch_jobs if job.get("status") == "skipped"]),
        "stopped": len([job for job in batch_jobs if job.get("status") == "stopped"]),
        "active": len(active_jobs),
        "remaining_seconds": int(remaining_seconds),
        "started_at": started_at,
        "estimated_finish_at": estimated_finish_at,
        "step_seconds": step_seconds,
    }


def create_jobs(hashes: list[str], batch_name: str, append_batch: str = "") -> list[dict]:
    global stop_requested
    now = iso_now()
    batch_id = str(int(time.time() * 1000))
    batch_dir = sanitize_batch_name(append_batch or batch_name)
    batch_label = batch_dir
    batch_root = batch_path(batch_dir)
    batch_root.mkdir(parents=True, exist_ok=True)
    created = [
        {
            "id": f"{batch_id}-{index}",
            "batch_id": batch_id,
            "batch_created_at": now,
            "batch_name": batch_label,
            "batch_dir": batch_dir,
            "hash": sample_hash,
            "status": "queued",
            "created_at": now,
            "updated_at": now,
            "started_at": None,
            "finished_at": None,
            "error": None,
            "image_count": 0,
            "sample_dir": str(batch_root / sample_hash),
        }
        for index, sample_hash in enumerate(hashes)
    ]
    with lock:
        stop_requested = False
        jobs = read_jobs()
        write_jobs(created + jobs)
        queue.extend(job["id"] for job in created)
    run_queue()
    return created


def run_queue() -> None:
    global running
    with lock:
        if running or not queue:
            return
        job_id = queue.pop(0)
        jobs = read_jobs()
        job = next((item for item in jobs if item["id"] == job_id), None)
        if not job:
            return
        running = True
    threading.Thread(target=process_job, args=(job,), daemon=True).start()


def stop_processing() -> dict:
    global current_process, running, stop_requested
    stopped_process = False
    with lock:
        stop_requested = True
        queue.clear()
        process = current_process

    if process and process.poll() is None:
        process.terminate()
        stopped_process = True

    with lock:
        jobs = read_jobs()
        now = iso_now()
        for job in jobs:
            if job["status"] in ("queued", "waiting_rate_limit"):
                job["status"] = "stopped"
                job["updated_at"] = now
                job["finished_at"] = now
                job["error"] = "Detenido por usuario."
        write_jobs(jobs)
        if not running:
            stop_requested = False

    return {"ok": True, "stopped_process": stopped_process}


def clear_job_list() -> bool:
    global stop_requested
    with lock:
        if running:
            return False
        queue.clear()
        stop_requested = False
        write_jobs([])
        return True


def shutdown_laboratory() -> dict:
    result = stop_processing()
    threading.Timer(0.35, lambda: os._exit(0)).start()
    return {"ok": True, **result}


def process_job(job: dict) -> None:
    global current_process, running, stop_requested
    sample_hash = job["hash"]
    sample_dir = job_sample_dir(job)
    sample_dir.mkdir(parents=True, exist_ok=True)
    update_job(job["id"], {"status": "running", "started_at": iso_now(), "error": None})
    options = processing_options()
    if options["skip_processed_hash"] and has_sample_results(job):
        update_job(
            job["id"],
            {
                "status": "skipped",
                "finished_at": iso_now(),
                "image_count": count_pngs(sample_dir / "images"),
                "error": "Saltado: el hash ya tiene resultados guardados.",
            },
        )
        with lock:
            running = False
        run_queue()
        return

    if not reserve_virushare_slot(job["id"]):
        update_job(
            job["id"],
            {
                "status": "stopped",
                "finished_at": iso_now(),
                "image_count": count_pngs(sample_dir / "images"),
                "error": "Detenido por usuario.",
            },
        )
        with lock:
            running = False
            stop_requested = False
        return
    update_job(job["id"], {"status": "running", "error": None})
    env = os.environ.copy()
    env["VIRUSHARE_API_KEY"] = virushare_api_key()
    env["IMAGE_ALGORITHMS"] = ",".join(options["selected_image_algorithms"])
    env["SAMPLE_OUTPUT_DIR"] = str(sample_dir)
    process = subprocess.Popen(
        [sys.executable, "/lab/worker/process_sample.py", sample_hash],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    with lock:
        current_process = process
    code = process.wait()
    with lock:
        current_process = None
        stopped = stop_requested
    update_job(
        job["id"],
        {
            "status": "stopped" if stopped else ("completed" if code == 0 else "failed"),
            "finished_at": iso_now(),
            "image_count": count_pngs(sample_dir / "images"),
            "error": "Detenido por usuario." if stopped else (None if code == 0 else f"El worker termino con codigo {code}."),
        },
    )
    with lock:
        running = False
        if stopped:
            stop_requested = False
    if not stopped:
        run_queue()


def page() -> str:
    return """<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Laboratorio de creacion de Dataset</title>
  <style>
    body{margin:0;background:#f6f7f9;color:#20242a;font-family:Segoe UI,system-ui,sans-serif;font-size:14px}
    header{padding:20px 28px 14px;border-bottom:1px solid #d8dde5;background:#fff}
    h1{margin:0;font-size:22px;letter-spacing:0}
    main{max-width:1180px;margin:0 auto;padding:22px;display:grid;grid-template-columns:360px 1fr;gap:18px;align-items:start}
    section,aside{background:#fff;border:1px solid #d8dde5;border-radius:8px;padding:16px}
    h2{font-size:15px;margin:0 0 12px}
    input{width:100%;height:38px;border:1px solid #d8dde5;border-radius:6px;padding:0 10px;margin-bottom:10px}
    input[type=file]{padding:8px 10px;height:auto}
    textarea{width:100%;min-height:190px;resize:vertical;border:1px solid #d8dde5;border-radius:6px;padding:10px;font:13px Consolas,monospace}
    select{width:100%;height:38px;border:1px solid #d8dde5;border-radius:6px;padding:0 10px;margin-bottom:10px;background:#fff}
    button{height:38px;border:0;border-radius:6px;background:#2563eb;color:white;padding:0 14px;font-weight:650;cursor:pointer}
    button:disabled{opacity:.55;cursor:wait}
    .hint,.status{color:#667085;font-size:13px;line-height:1.45}.actions{display:flex;align-items:center;gap:10px;margin-top:12px}
    table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid #d8dde5;padding:10px 8px;text-align:left;vertical-align:top}
    th{color:#667085;font-size:12px;text-transform:uppercase}code{font-family:Consolas,monospace;font-size:12px}
    .pill{display:inline-flex;align-items:center;height:24px;border-radius:999px;padding:0 9px;font-size:12px;font-weight:700}
    .queued{background:#e5e7eb;color:#374151}.waiting_rate_limit{background:#fef3c7;color:#92400e}.running{background:#dbeafe;color:#1d4ed8}.completed{background:#dcfce7;color:#15803d}.skipped{background:#e0f2fe;color:#0369a1}.failed{background:#fee2e2;color:#b42318}.stopped{background:#f3f4f6;color:#4b5563}
    .secondary{background:#4b5563}.danger{background:#b42318}
    .check{display:flex;align-items:center;gap:8px;margin:8px 0;color:#344054}
    input[type=checkbox]{width:auto;height:auto;margin:0}
    .details{margin-top:18px}.images{display:grid;grid-template-columns:repeat(auto-fill,minmax(132px,1fr));gap:10px;margin-top:10px}
    .images img{width:100%;aspect-ratio:1/1;object-fit:contain;border:1px solid #d8dde5;border-radius:6px;background:#fafafa}
    .analysis{margin-top:16px;border-top:1px solid #d8dde5;padding-top:14px}
    .analysis-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:8px;margin:10px 0}
    .analysis-grid div{border:1px solid #d8dde5;border-radius:6px;background:#fafafa;padding:8px;min-width:0}
    .analysis-grid span{display:block;color:#667085;font-size:12px;text-transform:uppercase}
    .analysis-grid strong{display:block;margin-top:3px;overflow-wrap:anywhere}
    .summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:12px 0}
    .metric{border:1px solid #d8dde5;border-radius:6px;padding:10px;background:#fafafa}
    .metric span{display:block;color:#667085;font-size:12px;text-transform:uppercase}
    .metric strong{display:block;margin-top:4px;font-size:14px}
    a{color:#2563eb;text-decoration:none}@media(max-width:860px){main{grid-template-columns:1fr;padding:14px}header{padding-inline:18px}}
  </style>
</head>
<body>
  <header><h1>Laboratorio de creacion de Dataset</h1><div class="status">Transformacion de binarios a png</div></header>
  <main>
    <aside>
      <h2>Configuracion</h2>
      <input id="apiKey" type="password" placeholder="VirusShare API key">
      <div class="actions"><button id="saveApiKey">Guardar key</button><span class="hint" id="configHint"></span></div>
      <p class="hint" id="configStatus">Revisando configuracion...</p>
      <label class="check"><input id="skipProcessedHash" type="checkbox"> Saltar hash si ya tiene resultados</label>
      <p class="hint">Saltar evita consultar VirusShare para hashes ya procesados.</p>
      <h2>Imagenes</h2>
      <p class="hint">En cada lote se generan solo los tipos marcados.</p>
      <label class="check"><input class="imageAlgorithm" data-algorithm="markov" type="checkbox"> Markov</label>
      <label class="check"><input class="imageAlgorithm" data-algorithm="simhash" type="checkbox"> SimHash</label>
      <label class="check"><input class="imageAlgorithm" data-algorithm="bigram_dct" type="checkbox"> Bigram DCT</label>
      <label class="check"><input class="imageAlgorithm" data-algorithm="bin2rgb" type="checkbox"> Bin2RGB</label>
      <label class="check"><input class="imageAlgorithm" data-algorithm="wem" type="checkbox"> WEM</label>
      <div class="actions"><button id="saveOptions">Guardar opciones</button><span class="hint" id="optionsHint"></span></div>
      <h2>Nuevo lote</h2>
      <input id="batchName" type="text" placeholder="Nombre del lote nuevo">
      <select id="existingBatch"><option value="">Crear lote nuevo</option></select>
      <p class="hint">Si eliges un lote existente, los resultados se agregan a esa carpeta.</p>
      <input id="hashFile" type="file" accept=".txt,text/plain">
      <textarea id="hashes" spellcheck="false" placeholder="Pega hashes MD5, SHA1 o SHA256, uno por linea"></textarea>
      <div class="actions"><button id="submit">Procesar</button><span class="hint" id="submitHint"></span></div>
      <p class="hint">Puedes pegar hashes o cargar un .txt. VirusShare se consulta como maximo una vez cada 16 segundos.</p>
    </aside>
    <section>
      <h2>Trabajos</h2>
      <div class="actions"><button class="secondary" id="stopJobs">Detener</button><button class="danger" id="clearJobs">Limpiar lista</button><button class="danger" id="shutdownLab">Terminar laboratorio</button><span class="hint" id="jobsHint"></span></div>
      <div id="batchSummary"></div><div id="jobs"></div><div class="details" id="details"></div>
    </section>
  </main>
  <script>
    const jobsEl=document.querySelector('#jobs'),detailsEl=document.querySelector('#details'),summaryEl=document.querySelector('#batchSummary'),submit=document.querySelector('#submit'),hint=document.querySelector('#submitHint'),jobsHint=document.querySelector('#jobsHint'),optionsHint=document.querySelector('#optionsHint'),existingBatch=document.querySelector('#existingBatch'),batchName=document.querySelector('#batchName');let selectedJobId=null;
    async function api(u,o){const r=await fetch(u,o);if(!r.ok)throw new Error(await r.text());return r.json()}
    function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
    function pill(s){return '<span class="pill '+s+'">'+s+'</span>'}
    async function refreshConfig(){const d=await api('/api/config');document.querySelector('#configStatus').textContent=(d.has_virushare_api_key?'VirusShare API key configurada.':'VirusShare API key no configurada.')+' Intervalo: '+d.virushare_interval_seconds+'s.';document.querySelector('#skipProcessedHash').checked=!!d.skip_processed_hash;const selected=new Set(d.selected_image_algorithms||[]);document.querySelectorAll('.imageAlgorithm').forEach(c=>{c.checked=selected.has(c.dataset.algorithm)})}
    async function refreshBatches(){const d=await api('/api/batches');const selected=existingBatch.value;existingBatch.innerHTML='<option value="">Crear lote nuevo</option>'+d.batches.map(b=>'<option value="'+b.name+'">'+b.name+'</option>').join('');existingBatch.value=selected}
    document.querySelector('#saveApiKey').addEventListener('click',async()=>{const key=document.querySelector('#apiKey').value.trim();const ch=document.querySelector('#configHint');if(!key){ch.textContent='Pega una API key primero.';return}await api('/api/config',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({virushare_api_key:key})});document.querySelector('#apiKey').value='';ch.textContent='Key guardada localmente.';await refreshConfig()});
    document.querySelector('#saveOptions').addEventListener('click',async()=>{const selected=[];document.querySelectorAll('.imageAlgorithm').forEach(c=>{if(c.checked)selected.push(c.dataset.algorithm)});if(!selected.length){optionsHint.textContent='Marca al menos un tipo de imagen.';return}await api('/api/config',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({skip_processed_hash:document.querySelector('#skipProcessedHash').checked,selected_image_algorithms:selected})});optionsHint.textContent='Opciones guardadas.';await refreshConfig()});
    document.querySelector('#hashFile').addEventListener('change',async(e)=>{const f=e.target.files[0];if(!f)return;document.querySelector('#hashes').value=await f.text();hint.textContent='Archivo cargado: '+f.name});
    document.querySelector('#stopJobs').addEventListener('click',async()=>{jobsHint.textContent='Deteniendo...';try{await api('/api/control/stop',{method:'POST'});jobsHint.textContent='Procesamiento detenido.';await refresh()}catch(e){jobsHint.textContent=e.message}});
    document.querySelector('#shutdownLab').addEventListener('click',async()=>{if(!confirm('Esto terminara el servidor del laboratorio. Puedes volver a iniciarlo con start_lab_docker.cmd.'))return;jobsHint.textContent='Terminando laboratorio...';try{await api('/api/control/shutdown',{method:'POST'});jobsHint.textContent='Laboratorio detenido.'}catch(e){jobsHint.textContent=e.message}});
    existingBatch.addEventListener('change',()=>{batchName.disabled=!!existingBatch.value;if(existingBatch.value)batchName.value=''});
    document.querySelector('#clearJobs').addEventListener('click',async()=>{if(!confirm('Esto limpiara solo la lista de trabajos. No borra imagenes ni carpetas de lotes.'))return;jobsHint.textContent='Limpiando...';try{await api('/api/jobs/clear',{method:'POST'});selectedJobId=null;jobsHint.textContent='Lista limpia.';await refresh()}catch(e){jobsHint.textContent=e.message}});
    function fmtSeconds(s){s=Math.max(0,Math.floor(s||0));const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),sec=s%60;return (h?h+'h ':'')+(m||h?m+'m ':'')+sec+'s'}
    function fmtEpoch(e){return e?new Date(e*1000).toLocaleString():'-'}
    function renderSummary(s){if(!s){summaryEl.innerHTML='';return}summaryEl.innerHTML='<div class="summary"><div class="metric"><span>Inicio</span><strong>'+fmtEpoch(s.started_at)+'</strong></div><div class="metric"><span>Restante</span><strong>'+fmtSeconds(s.remaining_seconds)+'</strong></div><div class="metric"><span>Final estimado</span><strong>'+fmtEpoch(s.estimated_finish_at)+'</strong></div><div class="metric"><span>Progreso</span><strong>'+s.completed+'/'+s.total+' ok, '+s.skipped+' saltados, '+s.failed+' fallidos</strong></div></div>'}
    async function refresh(){const d=await api('/api/jobs');renderSummary(d.batch_summary);if(!d.jobs.length){jobsEl.innerHTML='<p class="hint">Sin trabajos todavia.</p>';detailsEl.innerHTML='';return}
      jobsEl.innerHTML='<table><thead><tr><th>Lote</th><th>Hash</th><th>Estado</th><th>Imagenes</th><th>Actualizado</th></tr></thead><tbody>'+d.jobs.map(j=>'<tr><td>'+((j.batch_name||j.batch_dir)||'-')+'</td><td><a href="#" data-job-id="'+j.id+'"><code>'+j.hash+'</code></a></td><td>'+pill(j.status)+'</td><td>'+j.image_count+'</td><td>'+new Date(j.updated_at).toLocaleString()+'</td></tr>').join('')+'</tbody></table>';
      jobsEl.querySelectorAll('a[data-job-id]').forEach(l=>l.addEventListener('click',e=>{e.preventDefault();selectedJobId=l.dataset.jobId;loadDetails(selectedJobId)}));if(selectedJobId)loadDetails(selectedJobId)}
    function fmtTimestamp(ts){const n=Number(ts);if(!Number.isFinite(n)||n<=0)return '-';return new Date(n*1000).toLocaleString()+' UTC'}
    function fmtCreateDate(v){if(!v)return '';const m=String(v).match(/^(\\d{4}):(\\d{2}):(\\d{2}) (\\d{2}:\\d{2}:\\d{2})/);return m?m[1]+'-'+m[2]+'-'+m[3]+' '+m[4]:String(v)}
    function analysisDate(s){return s.create_date?fmtCreateDate(s.create_date):fmtTimestamp(s.timestamp)}
    function renderAnalysis(a){if(!a)return '<div class="analysis"><h2>Analisis estatico</h2><p class="hint">Sin analisis estatico guardado para este trabajo.</p></div>';if(a.error)return '<div class="analysis"><h2>Analisis estatico</h2><p class="hint">No se pudo leer: '+esc(a.error)+'</p></div>';const s=a.summary||{};const yara=(s.yara_matches||[]).join(', ')||'sin coincidencias';const pdf=(s.is_pdf?'si, '+(s.pdf_risk_flags||[]).length+' alertas':'no');return '<div class="analysis"><h2>Analisis estatico</h2><div class="analysis-grid"><div><span>Tamano</span><strong>'+esc(s.size_bytes??'-')+' bytes</strong></div><div><span>Entropia</span><strong>'+esc(s.entropy??'-')+'</strong></div><div><span>Fecha</span><strong>'+esc(analysisDate(s))+'</strong></div><div><span>Fuente fecha</span><strong>'+esc(s.date_source||'-')+'</strong></div><div><span>Tipo</span><strong>'+esc(s.file_type||'-')+'</strong></div><div><span>MIME</span><strong>'+esc(s.mime_type||'-')+'</strong></div><div><span>Strings</span><strong>'+esc(s.strings_total??0)+' detectadas</strong></div><div><span>IOCs</span><strong>'+esc(s.ioc_total??0)+' detectados</strong></div><div><span>PDF</span><strong>'+esc(pdf)+'</strong></div><div><span>YARA</span><strong>'+esc(s.yara_match_count??0)+' reglas</strong></div><div><span>PE</span><strong>'+(s.is_pe?esc(s.pe_sections)+' secciones, '+esc(s.pe_import_dlls)+' DLLs':'no')+'</strong></div><div><span>ELF</span><strong>'+(s.is_elf?'si':'no')+'</strong></div><div><span>ExifTool</span><strong>'+(s.exiftool_available?'disponible':'no disponible')+'</strong></div></div><p class="hint">YARA: '+esc(yara)+'</p><p class="hint">JSON completo: <a href="'+esc(a.artifact)+'" target="_blank">analysis/static_analysis.json</a></p><p><code>'+esc(s.sha256||'')+'</code></p></div>'}
    async function loadDetails(id){const d=await api('/api/jobs/'+id+'/sample');detailsEl.innerHTML='<h2>Detalle</h2><p><code>'+esc(d.job.hash)+'</code></p><p class="hint">Lote: '+esc((d.job.batch_name||d.job.batch_dir)||'-')+'</p>'+(d.job.error?'<p class="hint">Error: '+esc(d.job.error)+'</p>':'')+'<p class="hint">Carpeta en contenedor: <code>'+esc(d.job.sample_dir)+'</code></p>'+renderAnalysis(d.analysis)+'<div class="images">'+d.images.map(src=>'<a href="'+esc(src)+'" target="_blank"><img src="'+esc(src)+'" alt=""></a>').join('')+'</div>'}
    submit.addEventListener('click',async()=>{submit.disabled=true;hint.textContent='Encolando...';try{const result=await api('/api/jobs',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({hashes:document.querySelector('#hashes').value,batch_name:batchName.value,append_batch:existingBatch.value})});hint.textContent=result.created.length+' trabajo(s) creados en '+result.batch+'.';document.querySelector('#hashes').value='';batchName.value='';await refreshBatches();await refresh()}catch(e){hint.textContent=e.message}finally{submit.disabled=false}});
    refreshConfig();refreshBatches();refresh();setInterval(refresh,2500);
  </script>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/":
            return self.send_text(page(), "text/html; charset=utf-8")
        if self.path == "/api/jobs":
            jobs = read_jobs()
            return self.send_json({"jobs": jobs, "batch_summary": batch_summary(jobs)})
        if self.path == "/api/config":
            return self.send_json(public_config())
        if self.path == "/api/batches":
            return self.send_json({"batches": list_batches()})
        if self.path.startswith("/api/jobs/") and self.path.endswith("/sample"):
            job_id = self.path.split("/")[3]
            job = next((item for item in read_jobs() if item["id"] == job_id), None)
            if not job:
                return self.send_json({"error": "No encontrado"}, 404)
            return self.send_json({"job": job, "images": collect_images(job), "analysis": collect_analysis(job)})
        if self.path.startswith("/artifacts/"):
            return self.send_artifact()
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:
        if self.path == "/api/control/stop":
            return self.send_json(stop_processing())
        if self.path == "/api/control/shutdown":
            return self.send_json(shutdown_laboratory())
        if self.path == "/api/jobs/clear":
            if not clear_job_list():
                return self.send_json({"error": "Hay un trabajo activo. Detenlo antes de limpiar la lista."}, 409)
            return self.send_json({"ok": True})
        if self.path == "/api/config":
            length = int(self.headers.get("content-length", "0"))
            body = json.loads(self.rfile.read(length) or b"{}")
            config = read_config()
            changed = False
            if "virushare_api_key" in body:
                api_key = str(body.get("virushare_api_key", "")).strip()
                if not api_key:
                    return self.send_json({"error": "API key vacia."}, 400)
                config["virushare_api_key"] = api_key
                changed = True
            if "skip_processed_hash" in body:
                config["skip_processed_hash"] = bool(body.get("skip_processed_hash"))
                changed = True
            if "selected_image_algorithms" in body:
                selected = body.get("selected_image_algorithms", [])
                if not isinstance(selected, list):
                    return self.send_json({"error": "selected_image_algorithms debe ser una lista."}, 400)
                selected = [algorithm for algorithm in selected if algorithm in ALGORITHMS]
                if not selected:
                    return self.send_json({"error": "Selecciona al menos un tipo de imagen."}, 400)
                config["selected_image_algorithms"] = selected
                changed = True
            if not changed:
                return self.send_json({"error": "No hay cambios de configuracion."}, 400)
            write_config(config)
            return self.send_json({"ok": True, **public_config()})
        if self.path != "/api/jobs":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("content-length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        hashes = normalize_hashes(body.get("hashes", ""))
        if not hashes:
            return self.send_json({"error": "No encontre hashes validos."}, 400)
        batch_name = str(body.get("batch_name", "")).strip()
        append_batch = str(body.get("append_batch", "")).strip()
        try:
            created = create_jobs(hashes, batch_name, append_batch)
        except ValueError as exc:
            return self.send_json({"error": str(exc)}, 400)
        self.send_json({"created": created, "batch": created[0].get("batch_name") if created else ""}, 201)

    def send_text(self, body: str, content_type: str = "text/plain; charset=utf-8") -> None:
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, value: dict, status: int = 200) -> None:
        data = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_artifact(self) -> None:
        relative = unquote(self.path.replace("/artifacts/", "", 1))
        target = (DATA_DIR / relative).resolve()
        if not str(target).startswith(str(DATA_DIR.resolve())) or not target.exists() or target.is_dir():
            self.send_response(404)
            self.end_headers()
            return
        if target.suffix.lower() == ".png":
            content_type = "image/png"
        elif target.suffix.lower() == ".json":
            content_type = "application/json; charset=utf-8"
        else:
            content_type = "text/plain; charset=utf-8"
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args) -> None:
        print(fmt % args, flush=True)


if __name__ == "__main__":
    print(f"Lab listo en http://localhost:{PORT}/", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
