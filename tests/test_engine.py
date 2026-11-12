import io
import struct
import wave
from PIL import Image
import numpy as np
import pytest
from app import engine


def test_demo_lsb_recovers_known_flag():
    raw = engine.make_demo()
    result = engine.analyze(raw, 'demo.png')
    assert result['kind'] == 'PNG image'
    assert 'flag{stegoscope_lsb_demo}' in result['flags']
    assert engine.lsb_extract(raw, channels='R', bits=1).startswith(b'flag{stegoscope_lsb_demo}')
    assert result['png']['chunks'][-1]['type'] == 'IEND'
    assert all(chunk['crc'] == 'valid' for chunk in result['png']['chunks'])


def test_appended_payload_is_located():
    raw = engine.make_demo()
    result = engine.analyze(raw + b'ZIPDATA', 'evidence.png')
    assert result['trailing_bytes'] == 7
    assert result['trailing_offset'] == len(raw)


def test_bytes_offsets_and_flag_pattern():
    raw = b'\x00\x00PK\x03\x04xxx some flag{test_123} end'
    result = engine.analyze(raw, 'odd.bin')
    assert result['signatures'][0]['offset'] == 2
    assert result['flags'] == ['flag{test_123}']
    assert result['hex'][0]['offset'] == '00000000'


def test_entropy_limits():
    assert engine.entropy(b'') == 0
    assert engine.entropy(b'\x00' * 512) == 0
    assert 7.9 <= engine.entropy(bytes(range(256))) <= 8.0
    assert len(engine.entropy_profile(bytes(range(256)))) <= 64


def test_plane_png_and_args_validation():
    raw = engine.make_demo()
    data = engine.image_plane(raw, 'R', 0)
    with Image.open(io.BytesIO(data)) as im:
        assert im.size == (400, 260)
        assert im.mode == 'L'
    for channels in ('', 'RR', 'A', 'RGBB'):
        with pytest.raises(ValueError):
            engine.lsb_extract(raw, channels)
    with pytest.raises(ValueError):
        engine.image_plane(raw, 'X', 0)


def test_corrupt_png_is_not_falsely_accepted_as_valid():
    raw = engine.make_demo()
    broken = bytearray(raw)
    broken[45] ^= 1
    result = engine.analyze(bytes(broken), 'corrupt.png')
    assert result['kind'] == 'PNG image'
    assert any(c['crc'] == 'mismatch' for c in result['png']['chunks'])


def test_wav_lsb_and_spectrogram():
    sample_rate = 8000
    count = sample_rate // 2
    values = (10000 * np.sin(np.arange(count) * 2 * np.pi * 700 / sample_rate)).astype('<i2')
    # Embed eight bytes into the least significant bit of the first PCM samples.
    wanted = b'CTF DEMO'
    bits = np.unpackbits(np.frombuffer(wanted, dtype=np.uint8))
    values[:len(bits)] = (values[:len(bits)] & ~1) | bits.astype(np.int16)
    buff = io.BytesIO()
    with wave.open(buff, 'wb') as w:
        w.setnchannels(1)
        w.setframerate(sample_rate)
        w.setsampwidth(2)
        w.writeframes(values.tobytes())
    wav = buff.getvalue()
    assert engine.recognize(wav) == 'WAV audio'
    assert engine.wav_lsb(wav).startswith(wanted)
    report = engine.analyze(wav, 'tone.wav')
    assert report['audio']['sample_rate'] == sample_rate
    assert engine.audio_spectrogram(wav).startswith(b'\x89PNG')


def test_no_crash_on_malformed_unknown_file():
    r = engine.analyze(b'\x00\xff\x04\x01' * 800, 'unknown.bin')
    assert r['kind'] == 'Unknown binary'
    assert r['image'] is None
    assert not r['flags']


def test_b64_hint_is_heuristic():
    token = b'Y3RmIHRlc3Qgc2VjcmV0IG1lc3NhZ2U='
    hints = engine.decode_hints(b'prefix ' + token + b' suffix')
    assert any('ctf test secret message' in x['decoded'] for x in hints)


def test_hex_decoding_clue():
    hints = engine.decode_hints(b'666c61677b6865785f746573747d')
    assert any(x['method'] == 'hex' and x['decoded'] == 'flag{hex_test}' for x in hints)


def test_zero_width_binary_text_steganography():
    message = b'flag{zw_test}'
    bits = np.unpackbits(np.frombuffer(message, dtype=np.uint8))
    text = 'normal visible text' + ''.join('\u200c' if bit else '\u200b' for bit in bits)
    report = engine.analyze(text.encode('utf-8'), 'clue.txt')
    assert report['text_stego']['zero_width_decoded'] == 'flag{zw_test}'
    assert 'flag{zw_test}' in report['flags']
