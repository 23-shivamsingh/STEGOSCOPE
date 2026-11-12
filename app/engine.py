"""Local, non-executing steganography triage primitives.

Never execute embedded data. Inputs are bounded by the API's upload limit.
"""
from __future__ import annotations

import base64
import hashlib
import io
import math
import re
import struct
import wave
import zipfile
import zlib
import warnings
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image, ImageDraw, UnidentifiedImageError

Image.MAX_IMAGE_PIXELS = 20_000_000
MAGICS = [
    (b'\x89PNG\r\n\x1a\n', 'PNG image'), (b'\xff\xd8\xff', 'JPEG image'),
    (b'GIF87a', 'GIF image'), (b'GIF89a', 'GIF image'),
    (b'BM', 'BMP image'), (b'PK\x03\x04', 'ZIP archive'),
    (b'%PDF-', 'PDF document'), (b'7z\xbc\xaf\x27\x1c', '7z archive'),
    (b'Rar!\x1a\x07', 'RAR archive'), (b'\x1f\x8b\x08', 'GZIP stream'),
    (b'\x7fELF', 'ELF executable'), (b'OggS', 'Ogg audio'),
    (b'ID3', 'MP3 ID3 tag'), (b'fLaC', 'FLAC audio'),
    (b'RIFF', 'RIFF container'), (b'ftyp', 'MP4/HEIF marker'),
    (b'SQLite format 3\x00', 'SQLite database'),
]
FLAG_RE = re.compile(rb'\b(?:flag|ctf|picoctf|htb|thm|spooky|corctf|actf|uiuctf|[a-z0-9_]{3,18})\{[^\r\n\x00\x7f-\xff]{3,160}\}', re.I)
PRINTABLE_RE = re.compile(rb'[\x20-\x7e]{6,}')
B64_RE = re.compile(rb'(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{4}){7,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
HEX_RE = re.compile(rb'(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])')


def entropy(raw: bytes) -> float:
    if not raw:
        return 0.0
    counts = np.bincount(np.frombuffer(raw, dtype=np.uint8), minlength=256)
    probs = counts[counts > 0] / len(raw)
    return round(float(-(probs * np.log2(probs)).sum()), 4)


def entropy_profile(raw: bytes, points: int = 64) -> list[dict[str, float | int]]:
    if not raw:
        return []
    stride = max(1, math.ceil(len(raw) / points))
    return [{'offset': i, 'entropy': entropy(raw[i:i + stride])} for i in range(0, len(raw), stride)]


def recognize(raw: bytes) -> str:
    if raw.startswith(b'RIFF') and len(raw) >= 12 and raw[8:12] == b'WAVE':
        return 'WAV audio'
    if raw.startswith(b'RIFF') and len(raw) >= 12 and raw[8:12] == b'WEBP':
        return 'WebP image'
    if raw[4:8] == b'ftyp':
        return 'ISO media (MP4/HEIF)'
    for signature, name in MAGICS:
        if raw.startswith(signature):
            return name
    if raw and b'\x00' not in raw[:4096]:
        try:
            sample = raw[:4096].decode('utf-8-sig')
            printable = sum(ch.isprintable() or ch.isspace() or ch in ('\u200b', '\u200c', '\u200d') for ch in sample)
            if sample and printable / len(sample) > .94:
                return 'Text / encoded data'
        except UnicodeDecodeError:
            pass
    return 'Unknown binary'


def find_signatures(raw: bytes, cap: int = 80) -> list[dict[str, Any]]:
    hits = []
    for sig, name in MAGICS:
        start = 0
        while len(hits) < cap:
            pos = raw.find(sig, start)
            if pos < 0:
                break
            if sig == b'ftyp' and pos != 4:
                start = pos + 1
                continue
            if sig == b'BM':
                # Two-byte magic is too weak without a valid-looking bitmap header.
                if pos + 26 > len(raw):
                    start = pos + 1
                    continue
                bmp_size = int.from_bytes(raw[pos+2:pos+6], 'little')
                pixel_offset = int.from_bytes(raw[pos+10:pos+14], 'little')
                dib_size = int.from_bytes(raw[pos+14:pos+18], 'little')
                if bmp_size < 26 or bmp_size > len(raw) - pos or pixel_offset < 26 or dib_size not in (12,40,52,56,64,108,124):
                    start = pos + 1
                    continue
            hits.append({'offset': pos, 'hex': f'0x{pos:X}', 'type': name, 'embedded': pos > 0})
            start = pos + 1
    # Signature scanning is heuristic. Bytes inside compressed files may coincidentally match.
    return sorted(hits, key=lambda row: (row['offset'], row['type']))[:cap]


def find_strings(raw: bytes, cap: int = 180) -> list[dict[str, Any]]:
    rows = []
    for match in PRINTABLE_RE.finditer(raw):
        value = match.group(0)
        rows.append({'offset': match.start(), 'text': value[:210].decode('ascii', errors='replace')})
        if len(rows) >= cap:
            break
    return rows


def find_flags(raw: bytes, cap: int = 25) -> list[str]:
    seen = set()
    for match in FLAG_RE.finditer(raw):
        seen.add(match.group().decode('ascii', 'replace'))
        if len(seen) >= cap:
            break
    return sorted(seen)


def decode_hints(raw: bytes, cap: int = 12) -> list[dict[str, str]]:
    result = []
    for match in B64_RE.finditer(raw):
        val = match.group()[:256]
        try:
            decoded = base64.b64decode(val, validate=True)
        except (ValueError, base64.binascii.Error):
            continue
        if not decoded:
            continue
        readable = sum(32 <= x < 127 or x in (9, 10, 13) for x in decoded) / len(decoded)
        if readable >= .8:
            entry = {'offset': str(match.start()), 'method': 'base64', 'encoded': val[:90].decode('ascii'), 'decoded': decoded[:160].decode('utf-8', 'replace')}
            if entry not in result:
                result.append(entry)
        if len(result) >= cap:
            break
    for match in HEX_RE.finditer(raw):
        if len(result) >= cap:
            break
        value = match.group()[:512]
        try:
            decoded = bytes.fromhex(value.decode('ascii'))
        except ValueError:
            continue
        if not decoded:
            continue
        ratio = sum(32 <= x < 127 or x in (9, 10, 13) for x in decoded) / len(decoded)
        if ratio >= .85:
            result.append({'offset': str(match.start()), 'method': 'hex', 'encoded': value[:90].decode('ascii'),
                           'decoded': decoded[:160].decode('utf-8', 'replace')})
    return result


def text_stego(raw: bytes) -> dict[str, Any] | None:
    # Restrict to plausible UTF-8 text to avoid random binary lookalikes.
    try:
        source = raw.decode('utf-8-sig')
    except UnicodeDecodeError:
        return None
    if not source or len(source) > 3_000_000:
        return None
    zero_width = [ch for ch in source if ch in ('\u200b', '\u200c', '\u200d')]
    payload = ''
    if len(zero_width) >= 8:
        bits = ''.join('0' if ch == '\u200b' else '1' for ch in zero_width if ch in ('\u200b', '\u200c'))
        if len(bits) >= 8:
            payload = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits) - 7, 8))[:200]
    # Invisible trailing spaces and tabs sometimes encode 0/1; provide a clue, not a confirmed message.
    lines = source.splitlines()
    tails = [re.search(r'[ \t]+$', line) for line in lines[:3000]]
    trailing = sum(bool(x) for x in tails)
    result = {'zero_width_count': len(zero_width), 'trailing_whitespace_lines': trailing,
              'zero_width_decoded': payload if payload and sum(32 <= ord(ch) < 127 for ch in payload) / len(payload) > .65 else ''}
    return result if zero_width or trailing >= 3 else None


def png_chunks(raw: bytes) -> dict[str, Any]:
    rows = []
    if not raw.startswith(b'\x89PNG\r\n\x1a\n'):
        return {'chunks': rows, 'trailing_bytes': 0, 'trailing_offset': None}
    pos = 8
    end = None
    for _ in range(256):
        if pos + 12 > len(raw):
            break
        n = int.from_bytes(raw[pos:pos + 4], 'big')
        if n > 30_000_000 or pos + 12 + n > len(raw):
            rows.append({'type': 'INVALID', 'offset': pos, 'size': n, 'crc': 'invalid bounds'})
            break
        chunk = raw[pos + 4:pos + 8]
        payload = raw[pos + 8:pos + 8 + n]
        actual_crc = int.from_bytes(raw[pos + 8 + n:pos + 12 + n], 'big')
        expected_crc = zlib.crc32(chunk + payload) & 0xffffffff
        item: dict[str, Any] = {'type': chunk.decode('ascii', 'replace'), 'offset': pos, 'size': n,
                                'crc': 'valid' if actual_crc == expected_crc else 'mismatch'}
        if chunk in (b'tEXt', b'iTXt'):
            item['text_preview'] = payload[:220].decode('utf-8', 'replace').replace('\x00', ' · ')
        rows.append(item)
        pos += 12 + n
        if chunk == b'IEND':
            end = pos
            break
    return {'chunks': rows, 'trailing_bytes': len(raw) - end if end is not None else 0, 'trailing_offset': end}


def jpeg_tail(raw: bytes) -> dict[str, int | None]:
    if not raw.startswith(b'\xff\xd8'):
        return {'trailing_bytes': 0, 'trailing_offset': None}
    pos = raw.rfind(b'\xff\xd9')
    if pos < 0:
        return {'trailing_bytes': 0, 'trailing_offset': None}
    end = pos + 2
    return {'trailing_bytes': len(raw) - end, 'trailing_offset': end}


def zip_inspection(raw: bytes) -> dict[str, Any] | None:
    if not zipfile.is_zipfile(io.BytesIO(raw)):
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            entries = zf.infolist()[:80]
            return {'count': len(zf.infolist()), 'uncompressed_bytes': sum(x.file_size for x in zf.infolist()),
                    'encrypted_entries': sum(bool(x.flag_bits & 1) for x in zf.infolist()),
                    'files': [{'name': x.filename[:140], 'bytes': x.file_size} for x in entries]}
    except (ValueError, RuntimeError, OSError, zipfile.BadZipFile):
        return None


def image_details(raw: bytes) -> dict[str, Any] | None:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(raw)) as im:
                if im.format not in {'PNG', 'JPEG', 'GIF', 'BMP', 'WEBP', 'TIFF'}:
                    return None
                if im.width * im.height > 20_000_000:
                    raise ValueError('Image exceeds the 20 megapixel processing limit')
                details = {'format': im.format, 'mode': im.mode, 'width': im.width, 'height': im.height,
                           'frames': getattr(im, 'n_frames', 1)}
                if im.info:
                    details['metadata'] = {str(k)[:60]: str(v)[:180] for k, v in im.info.items() if k.lower() not in {'icc_profile', 'exif'}}
                try:
                    exif = im.getexif()
                    if exif:
                        details['exif_tags'] = {str(k): str(v)[:180] for k, v in list(exif.items())[:30]}
                except (OSError, ValueError):
                    pass
                # For quick triage, only evaluate a bounded sample of pixels.
                thumb = im.convert('RGB')
                thumb.thumbnail((768, 768))
                pixels = np.array(thumb, dtype=np.uint8)
                lsbs = (pixels & 1).mean(axis=(0, 1))
                details['lsb_one_ratio'] = {c: round(float(v), 4) for c, v in zip('RGB', lsbs)}
                return details
    except (Image.DecompressionBombError, Image.DecompressionBombWarning, UnidentifiedImageError, OSError, ValueError, SyntaxError) as e:
        return {'error': str(e)[:200]}


def image_obj(raw: bytes) -> Image.Image:
    with warnings.catch_warnings():
        warnings.simplefilter('error', Image.DecompressionBombWarning)
        with Image.open(io.BytesIO(raw)) as im:
            if im.format not in {'PNG', 'JPEG', 'GIF', 'BMP', 'WEBP', 'TIFF'}:
                raise ValueError('Unsupported image format')
            if im.width * im.height > 20_000_000:
                raise ValueError('Image exceeds limit')
            return im.convert('RGB')


def image_preview(raw: bytes) -> bytes:
    im = image_obj(raw)
    im.thumbnail((1120, 760))
    out = io.BytesIO()
    im.save(out, 'PNG')
    return out.getvalue()


def image_plane(raw: bytes, channel: str = 'R', bit: int = 0) -> bytes:
    if channel.upper() not in ('R', 'G', 'B', 'RGB') or not 0 <= bit <= 7:
        raise ValueError('Invalid plane parameters')
    im = image_obj(raw)
    im.thumbnail((950, 850))
    arr = np.asarray(im, dtype=np.uint8)
    mask = np.uint8(1 << bit)
    if channel.upper() == 'RGB':
        output = np.where((arr & mask) > 0, 255, 0).astype(np.uint8)
    else:
        idx = 'RGB'.index(channel.upper())
        output = np.where((arr[:, :, idx] & mask) > 0, 255, 0).astype(np.uint8)
    im_out = Image.fromarray(output)
    buff = io.BytesIO()
    im_out.save(buff, format='PNG')
    return buff.getvalue()


def lsb_extract(raw: bytes, channels: str = 'RGB', bits: int = 1, order: str = 'msb', max_bytes: int = 262144) -> bytes:
    if not channels or len(channels) > 3 or len(set(channels)) != len(channels) or not all(c in 'RGB' for c in channels):
        raise ValueError('Channels must be a unique selection of RGB')
    if bits not in (1, 2, 3, 4) or order not in ('msb', 'lsb'):
        raise ValueError('Invalid bit selection')
    im = image_obj(raw)
    arr = np.asarray(im, dtype=np.uint8).reshape(-1, 3)[:, ['RGB'.index(c) for c in channels]]
    # Take only as many pixels as needed to keep memory bounded.
    take = min(len(arr), (max_bytes * 8 + bits * len(channels) - 1) // (bits * len(channels)))
    arr = arr[:take]
    selectors = range(bits - 1, -1, -1) if order == 'msb' else range(bits)
    rows = [((arr >> b) & 1).astype(np.uint8).reshape(-1) for b in selectors]
    # pixel-major, channel-major, then bit-major
    stream = np.stack(rows, axis=1).reshape(len(arr), len(channels), bits).reshape(-1)
    packed = np.packbits(stream, bitorder='big' if order == 'msb' else 'little')
    return packed.tobytes()[:max_bytes]


def lsb_preview(raw: bytes) -> list[dict[str, Any]]:
    results = []
    for channels in ('R', 'G', 'B', 'RGB'):
        for order in ('msb', 'lsb'):
            part = lsb_extract(raw, channels=channels, bits=1, order=order, max_bytes=2048)
            printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in part[:200]) / max(1, len(part[:200]))
            strings = find_strings(part, cap=4)
            results.append({'channels': channels, 'order': order, 'printable_ratio': round(printable, 3),
                            'text': strings[0]['text'][:110] if strings else '', 'flags': find_flags(part, 4),
                            'magic': recognize(part[:20]) if recognize(part[:20]) != 'Unknown binary' else ''})
    return results


def wav_details(raw: bytes) -> dict[str, Any] | None:
    if len(raw) < 12 or raw[:4] != b'RIFF' or raw[8:12] != b'WAVE':
        return None
    try:
        with wave.open(io.BytesIO(raw), 'rb') as w:
            channels, sample_rate, width, frames = w.getnchannels(), w.getframerate(), w.getsampwidth(), w.getnframes()
            return {'channels': channels, 'sample_rate': sample_rate, 'sample_width': width,
                    'frames': frames, 'duration_seconds': round(frames / max(1, sample_rate), 3)}
    except (wave.Error, EOFError, ValueError):
        return {'error': 'Unsupported or malformed WAV'}


def wav_pcm(raw: bytes, limit: int = 1_800_000) -> tuple[np.ndarray, int]:
    with wave.open(io.BytesIO(raw), 'rb') as w:
        width, channels, rate = w.getsampwidth(), w.getnchannels(), w.getframerate()
        if width not in (1, 2, 4):
            raise ValueError('Spectrogram supports 8/16/32-bit PCM WAV; use ffmpeg to convert other codecs')
        frames = w.readframes(min(w.getnframes(), limit))
    dtype = {1: np.uint8, 2: '<i2', 4: '<i4'}[width]
    samples = np.frombuffer(frames, dtype=dtype)
    if len(samples) < channels or channels <= 0:
        raise ValueError('Not enough audio samples')
    samples = samples[:len(samples) // channels * channels].reshape(-1, channels)
    samples = samples.astype(np.float32).mean(axis=1)
    if width == 1:
        samples = samples - 128
    return samples, rate


def wav_lsb(raw: bytes, max_bytes: int = 131072) -> bytes:
    with wave.open(io.BytesIO(raw), 'rb') as w:
        frames = w.readframes(min(w.getnframes(), max_bytes * 8 // max(1, w.getnchannels())))
        width = w.getsampwidth()
    if width not in (1, 2, 4):
        raise ValueError('WAV LSB supports 8/16/32-bit PCM')
    raw_samples = np.frombuffer(frames[:len(frames) // width * width], dtype={1: np.uint8, 2: '<i2', 4: '<i4'}[width])
    return np.packbits((raw_samples & 1).astype(np.uint8)).tobytes()[:max_bytes]


def audio_spectrogram(raw: bytes) -> bytes:
    samples, rate = wav_pcm(raw)
    if samples.size < 512:
        raise ValueError('Audio sample too short for spectrogram')
    # Bound the computation and show the first ~1.8 million samples.
    hop = max(256, (len(samples) - 512) // 1000)
    starts = np.arange(0, len(samples) - 512, hop)[:1000]
    windows = np.lib.stride_tricks.sliding_window_view(samples, 512)[starts]
    spectrum = np.abs(np.fft.rfft(windows * np.hanning(512), axis=1)).T
    db = 20 * np.log10(spectrum + 1e-6)
    lo, hi = np.percentile(db, [10, 99.7])
    values = np.clip((db - lo) / max(hi - lo, 1), 0, 1)
    values = (np.flipud(values) * 255).astype(np.uint8)
    # No external plot lib required; gradient false-color for visual text / patterns.
    rgb = np.stack([np.clip(values * 1.1, 0, 255), np.clip((values.astype(float) ** 1.3) / 255 ** .3 * .75, 0, 255),
                    np.clip(255 - np.abs(values.astype(float) - 175) * 1.1, 0, 255)], axis=-1).astype(np.uint8)
    out = Image.fromarray(rgb, 'RGB').resize((1000, 480), Image.Resampling.BILINEAR)
    buffer = io.BytesIO()
    out.save(buffer, format='PNG')
    return buffer.getvalue()


def hex_view(raw: bytes, offset: int = 0, length: int = 512) -> list[dict[str, str]]:
    output = []
    for i in range(offset, min(len(raw), offset + length), 16):
        piece = raw[i:i + 16]
        output.append({'offset': f'{i:08X}', 'hex': ' '.join(f'{x:02X}' for x in piece),
                       'ascii': ''.join(chr(x) if 32 <= x <= 126 else '.' for x in piece)})
    return output


def guidance(result: dict[str, Any]) -> list[dict[str, str]]:
    mime = result['kind']
    rows = []
    if result['flags']:
        rows.append({'title': 'Flag-like string detected', 'detail': 'Inspect context before submitting; a signature match is not proof of a valid flag.', 'priority': 'high'})
    if result['trailing_bytes']:
        rows.append({'title': 'Appended data beyond file end', 'detail': f"{result['trailing_bytes']:,} bytes follow the detected image end. Carve using the suggested offset.", 'priority': 'high'})
    if any(s['offset'] > 0 for s in result['signatures']):
        rows.append({'title': 'Secondary byte signatures', 'detail': 'Inspect signatures and offsets; embedded markers may be coincidental.', 'priority': 'medium'})
    if mime.endswith('image') or result['image']:
        rows.append({'title': 'Inspect color planes', 'detail': 'Switch through R/G/B bit 0–7. Lossless image LSB previews are available under Extraction.', 'priority': 'medium'})
        if mime in ('JPEG image', 'BMP image'):
            rows.append({'title': 'Try Steghide / Stegseek', 'detail': 'A valid passphrase or a supplied CTF wordlist may reveal a Steghide payload.', 'priority': 'medium'})
        if mime in ('PNG image', 'BMP image'):
            rows.append({'title': 'Try zsteg', 'detail': 'Analyze PNG/BMP LSB channel layouts; use the integration when installed.', 'priority': 'medium'})
    if result['audio']:
        rows.append({'title': 'Inspect spectrogram and PCM LSB', 'detail': 'Look for letters, shapes, QR patterns, or recoverable least-significant-bit streams.', 'priority': 'medium'})
    if result.get('text_stego'):
        rows.append({'title': 'Invisible text markers', 'detail': 'Inspect zero-width characters and line-ending whitespace in the text evidence.', 'priority': 'medium'})
    if result['decoded']:
        rows.append({'title': 'Encoded text candidates', 'detail': 'Review base64-decoded previews; these are heuristic hits.', 'priority': 'low'})
    rows.append({'title': 'Run metadata + signature adapters', 'detail': 'ExifTool and Binwalk can provide extra clues when installed. External execution is manual, never automatic.', 'priority': 'low'})
    return rows[:8]


def analyze(raw: bytes, filename: str) -> dict[str, Any]:
    kind = recognize(raw)
    image = image_details(raw) if kind.endswith('image') or kind == 'WebP image' else None
    audio = wav_details(raw)
    png = png_chunks(raw) if kind == 'PNG image' else None
    tail = png if png is not None else jpeg_tail(raw)
    trailing = tail['trailing_bytes']
    signatures = find_signatures(raw)
    flags = find_flags(raw)
    decoded = decode_hints(raw)
    for clue in decoded:
        flags.extend(find_flags(clue['decoded'].encode('utf-8')))
    invisible = text_stego(raw) if kind == 'Text / encoded data' else None
    if invisible and invisible['zero_width_decoded']:
        flags.extend(find_flags(invisible['zero_width_decoded'].encode('utf-8')))
    lsb = []
    if image and 'error' not in image and image['format'] in ('PNG', 'BMP'):
        try:
            lsb = lsb_preview(raw)
            for row in lsb:
                flags.extend(row['flags'])
        except (ValueError, OSError):
            pass
    result: dict[str, Any] = {
        'filename': Path(filename).name[:180], 'bytes': len(raw), 'kind': kind,
        'sha256': hashlib.sha256(raw).hexdigest(), 'md5': hashlib.md5(raw).hexdigest(),  # forensic identifier only
        'entropy': entropy(raw), 'entropy_profile': entropy_profile(raw),
        'signatures': signatures, 'strings': find_strings(raw), 'flags': sorted(set(flags)),
        'decoded': decoded, 'text_stego': invisible, 'image': image, 'audio': audio, 'png': png,
        'zip': zip_inspection(raw) if kind == 'ZIP archive' or raw.endswith(b'PK\x05\x06' + b'\x00' * 18) else None,
        'trailing_bytes': trailing, 'trailing_offset': tail['trailing_offset'],
        'hex': hex_view(raw), 'lsb': lsb,
    }
    if audio and 'error' not in audio:
        try:
            result['audio_lsb'] = {'strings': find_strings(wav_lsb(raw), 8), 'flags': find_flags(wav_lsb(raw))}
            result['flags'] = sorted(set(result['flags'] + result['audio_lsb']['flags']))
        except (ValueError, wave.Error):
            result['audio_lsb'] = None
    else:
        result['audio_lsb'] = None
    result['guidance'] = guidance(result)
    return result


def make_demo() -> bytes:
    """Synthetic PNG with known flag in the red channel's LSB (for demonstrations)."""
    width, height = 400, 260
    rng = np.random.default_rng(42)
    x = np.linspace(0, 1, width)[None, :]
    y = np.linspace(0, 1, height)[:, None]
    arr = np.zeros((height, width, 3), dtype=np.uint8)
    arr[:, :, 0] = np.clip(15 + 45 * x + 24 * y, 0, 255).astype(np.uint8)
    arr[:, :, 1] = np.clip(32 + 28 * x + 55 * y, 0, 255).astype(np.uint8)
    arr[:, :, 2] = np.clip(75 + 85 * x + 65 * y, 0, 255).astype(np.uint8)
    arr = np.clip(arr.astype(np.int16) + rng.integers(-8, 9, arr.shape), 0, 255).astype(np.uint8)
    message = b'flag{stegoscope_lsb_demo}\n'
    bits = np.unpackbits(np.frombuffer(message, dtype=np.uint8))
    # Write LSBs into successive red pixels, ordered top-to-bottom row-major.
    flat = arr.reshape(-1, 3)
    flat[:len(bits), 0] = (flat[:len(bits), 0] & 254) | bits
    img = Image.fromarray(arr, 'RGB')
    buff = io.BytesIO()
    img.save(buff, 'PNG')
    return buff.getvalue()
