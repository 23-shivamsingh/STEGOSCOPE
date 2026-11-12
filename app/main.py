"""STEGOSCOPE local FastAPI server. Start on 127.0.0.1, never expose publicly."""
from __future__ import annotations

import atexit
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import engine

ROOT = Path(__file__).resolve().parent.parent
MAX_UPLOAD = 32 * 1024 * 1024
MAX_SESSIONS = 8
WORK = tempfile.TemporaryDirectory(prefix='stegoscope-')
atexit.register(WORK.cleanup)
STORE: dict[str, dict[str, Any]] = {}

TOOLS = {
    'exiftool': ('exiftool', 'EXIF / metadata'),
    'binwalk': ('binwalk', 'Embedded signature scan'),
    'zsteg': ('zsteg', 'PNG/BMP LSB scan'),
    'steghide_info': ('steghide', 'Steghide probe'),
    'steghide_extract': ('steghide', 'Steghide extraction'),
    'stegseek': ('stegseek', 'Steghide wordlist recovery'),
    'ffprobe': ('ffprobe', 'Media streams metadata'),
    'zbarimg': ('zbarimg', 'QR/barcode decoding'),
    'tesseract': ('tesseract', 'Image OCR'),
}
app = FastAPI(title='STEGOSCOPE Local CTF Steganography Workbench', version='1.0.0', docs_url='/api/docs', redoc_url=None)


@app.middleware('http')
async def safety_headers(request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Cache-Control'] = 'no-store'
    return response


def installed_tools():
    return [{'id': key, 'name': item[1], 'binary': item[0], 'installed': shutil.which(item[0]) is not None}
            for key, item in TOOLS.items()]


def add_record(data: bytes, filename: str) -> dict[str, Any]:
    if len(STORE) >= MAX_SESSIONS:
        oldest_id = next(iter(STORE))
        old = STORE.pop(oldest_id)
        shutil.rmtree(old['directory'], ignore_errors=True)
    record_id = uuid.uuid4().hex
    directory = Path(WORK.name) / record_id
    directory.mkdir(mode=0o700)
    suffix = Path(filename).suffix.lower()
    if not re.fullmatch(r'\.[a-z0-9]{1,10}', suffix):
        suffix = '.bin'
    path = directory / ('evidence' + suffix)
    path.write_bytes(data)
    result = engine.analyze(data, filename)
    result['id'] = record_id
    STORE[record_id] = {'data': data, 'path': path, 'directory': directory, 'result': result, 'created': time.time()}
    return result


def get_record(record_id: str) -> dict[str, Any]:
    item = STORE.get(record_id)
    if not item:
        raise HTTPException(status_code=404, detail='Evidence not found; re-upload the file')
    return item


def bytes_response(data: bytes, filename: str, mime: str = 'application/octet-stream'):
    safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)[:90]
    return Response(data, media_type=mime, headers={'Content-Disposition': f'attachment; filename="{safe_name}"'})


@app.get('/api/health')
def health():
    return {'status': 'ready', 'name': 'STEGOSCOPE', 'version': '1.0.0', 'local_only': True,
            'upload_limit_mb': MAX_UPLOAD // (1024 * 1024), 'tools': installed_tools(),
            'active_sessions': len(STORE)}


@app.post('/api/analyze')
async def upload(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(400, 'Missing filename')
    data = await file.read(MAX_UPLOAD + 1)
    await file.close()
    if not data:
        raise HTTPException(400, 'Empty file')
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, 'Maximum file size is 32 MiB')
    try:
        return add_record(data, file.filename)
    except Exception as e:
        raise HTTPException(422, f'Unable to inspect file: {type(e).__name__}') from e


@app.post('/api/demo')
def demo():
    return add_record(engine.make_demo(), 'ctf-lsb-demo.png')


@app.get('/api/evidence/{record_id}')
def evidence(record_id: str):
    return get_record(record_id)['result']


@app.get('/api/image/{record_id}/preview')
def preview(record_id: str):
    try:
        return Response(engine.image_preview(get_record(record_id)['data']), media_type='image/png')
    except (ValueError, OSError) as e:
        raise HTTPException(400, str(e)) from e


@app.get('/api/image/{record_id}/plane')
def plane(record_id: str, channel: str = 'R', bit: int = Query(0, ge=0, le=7)):
    try:
        return Response(engine.image_plane(get_record(record_id)['data'], channel, bit), media_type='image/png')
    except (ValueError, OSError) as e:
        raise HTTPException(400, str(e)) from e


@app.get('/api/audio/{record_id}/spectrogram')
def spectrogram(record_id: str):
    try:
        return Response(engine.audio_spectrogram(get_record(record_id)['data']), media_type='image/png')
    except (ValueError, OSError, EOFError) as e:
        raise HTTPException(400, str(e)) from e


@app.get('/api/download/{record_id}/lsb')
def lsb(record_id: str, channels: str = 'RGB', bits: int = Query(1, ge=1, le=4), order: str = 'msb'):
    try:
        data = engine.lsb_extract(get_record(record_id)['data'], channels, bits, order)
        return bytes_response(data, 'lsb_' + channels + '_' + str(bits) + 'bit.bin')
    except (ValueError, OSError) as e:
        raise HTTPException(400, str(e)) from e


@app.get('/api/download/{record_id}/audio-lsb')
def audio_lsb(record_id: str):
    try:
        return bytes_response(engine.wav_lsb(get_record(record_id)['data']), 'audio_lsb.bin')
    except (ValueError, OSError, EOFError) as e:
        raise HTTPException(400, str(e)) from e


@app.get('/api/download/{record_id}/carve')
def carve(record_id: str, offset: int = Query(..., ge=0), length: int = Query(0, ge=0, le=MAX_UPLOAD)):
    raw = get_record(record_id)['data']
    if offset >= len(raw):
        raise HTTPException(400, 'Offset exceeds file size')
    length = min(len(raw) - offset, length or len(raw) - offset, MAX_UPLOAD)
    return bytes_response(raw[offset:offset + length], f'carved_{offset:08x}.bin')


@app.get('/api/download/{record_id}/report')
def report(record_id: str):
    result = get_record(record_id)['result']
    data = json.dumps({'tool': 'STEGOSCOPE 1.0.0', 'disclaimer': 'Heuristic indicators are not confirmed steganography.',
                       'analysis': result}, indent=2, ensure_ascii=False).encode('utf-8')
    return bytes_response(data, 'stegoscope-report.json', 'application/json')


@app.get('/api/download/{record_id}/artifact/{artifact_id}')
def artifact(record_id: str, artifact_id: str):
    item = get_record(record_id)
    artifacts = item.get('artifacts', {})
    path = artifacts.get(artifact_id)
    if path is None or not path.is_file():
        raise HTTPException(404, 'Artifact not found')
    if path.stat().st_size > MAX_UPLOAD:
        raise HTTPException(413, 'Artifact too large to download')
    return FileResponse(path, media_type='application/octet-stream', filename=path.name)


class ToolRequest(BaseModel):
    tool: str
    passphrase: str = Field(default='', max_length=180)
    wordlist: str = Field(default='', max_length=120_000)


def run_binary(argv: list[str], cwd: Path, timeout: int = 15) -> dict[str, Any]:
    # Never use shell=True. Execute only fixed allowlisted binaries with user content passed as file paths.
    start = time.monotonic()
    try:
        completed = subprocess.run(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   timeout=timeout, check=False)
        output = completed.stdout[:60_000].decode('utf-8', 'replace')
        return {'exit_code': completed.returncode, 'output': output,
                'duration_seconds': round(time.monotonic() - start, 2), 'timed_out': False}
    except subprocess.TimeoutExpired as e:
        partial = (e.stdout or b'')[:8000]
        return {'exit_code': None, 'output': partial.decode('utf-8', 'replace') + '\n[Timed out]',
                'duration_seconds': round(time.monotonic() - start, 2), 'timed_out': True}
    except OSError as e:
        return {'exit_code': None, 'output': f'Could not start tool: {type(e).__name__}',
                'duration_seconds': 0, 'timed_out': False}


@app.post('/api/tools/{record_id}/run')
def execute_tool(record_id: str, payload: ToolRequest):
    item = get_record(record_id)
    tool = payload.tool
    if tool not in TOOLS:
        raise HTTPException(400, 'Tool not in allowlist')
    bin_name = TOOLS[tool][0]
    path = shutil.which(bin_name)
    if path is None:
        raise HTTPException(409, f'{bin_name} is not installed on this machine')
    kind = item['result']['kind']
    if tool == 'zsteg' and kind not in ('PNG image', 'BMP image'):
        raise HTTPException(400, 'zsteg is for PNG/BMP images')
    if tool in ('steghide_info', 'steghide_extract', 'stegseek') and kind not in ('JPEG image', 'BMP image', 'WAV audio'):
        raise HTTPException(400, 'Steghide adapters require JPEG, BMP or WAV')
    if tool in ('zbarimg', 'tesseract') and not item['result']['image']:
        raise HTTPException(400, 'This adapter requires an image')
    source, directory = str(item['path']), item['directory']
    argv: list[str]
    artifact_path = None
    if tool == 'exiftool':
        argv = [path, '-json', '-G1', '-a', source]
    elif tool == 'binwalk':
        argv = [path, source]
    elif tool == 'zsteg':
        argv = [path, '-a', source]
    elif tool == 'steghide_info':
        argv = [path, 'info', '-sf', source, '-p', '']
    elif tool == 'steghide_extract':
        artifact_path = directory / 'steghide_extracted.bin'
        artifact_path.unlink(missing_ok=True)
        argv = [path, 'extract', '-sf', source, '-p', payload.passphrase, '-xf', str(artifact_path), '-f']
    elif tool == 'stegseek':
        lines = [s.strip() for s in payload.wordlist.splitlines() if s.strip()]
        if not 1 <= len(lines) <= 10000:
            raise HTTPException(400, 'Provide 1–10,000 candidate words, one per line')
        word_file = directory / 'candidates.txt'
        word_file.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        word_file.chmod(0o600)
        artifact_path = directory / 'stegseek_extracted.bin'
        artifact_path.unlink(missing_ok=True)
        argv = [path, '-f', '-n', '-t', '2', source, str(word_file), str(artifact_path)]
    elif tool == 'ffprobe':
        argv = [path, '-v', 'error', '-show_format', '-show_streams', '-of', 'json', source]
    elif tool == 'zbarimg':
        argv = [path, '-q', source]
    else:
        argv = [path, source, 'stdout']
    execution = run_binary(argv, directory, 27 if tool in ('stegseek', 'zsteg') else 15)
    execution['tool'] = tool
    execution['artifact'] = None
    if artifact_path and artifact_path.is_file():
        if artifact_path.stat().st_size > MAX_UPLOAD:
            artifact_path.unlink(missing_ok=True)
            execution['output'] += '\nOutput exceeded 32 MiB and was removed.'
        else:
            artifact_id = uuid.uuid4().hex
            item.setdefault('artifacts', {})[artifact_id] = artifact_path
            execution['artifact'] = {'id': artifact_id, 'name': artifact_path.name,
                                     'bytes': artifact_path.stat().st_size,
                                     'url': f'/api/download/{record_id}/artifact/{artifact_id}'}
    # Do not include actual command argv (may include a passphrase), and do not store wordlists in reports.
    return execution


app.mount('/static', StaticFiles(directory=ROOT / 'static'), name='static')


@app.get('/')
def homepage():
    return FileResponse(ROOT / 'static' / 'index.html')
