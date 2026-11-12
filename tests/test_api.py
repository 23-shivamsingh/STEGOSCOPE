from fastapi.testclient import TestClient
from app.main import app
from app.engine import make_demo

client = TestClient(app)


def test_health_and_main_page():
    health = client.get('/api/health')
    assert health.status_code == 200
    assert health.json()['local_only'] is True
    assert len(health.json()['tools']) >= 8
    page = client.get('/')
    assert page.status_code == 200 and 'STEGOSCOPE' in page.text
    assert client.get('/static/app.js').status_code == 200


def test_upload_demo_plane_report_carve_and_lsb():
    up = client.post('/api/analyze', files={'file': ('demo.png', make_demo(), 'image/png')})
    assert up.status_code == 200, up.text
    result = up.json()
    record_id = result['id']
    assert len(record_id) == 32
    assert client.get(f'/api/image/{record_id}/preview').content.startswith(b'\x89PNG')
    assert client.get(f'/api/image/{record_id}/plane?channel=G&bit=3').status_code == 200
    assert client.get(f'/api/download/{record_id}/lsb?channels=R').content.startswith(b'flag{stegoscope_lsb_demo}')
    assert client.get(f'/api/download/{record_id}/carve?offset=0&length=8').content == make_demo()[:8]
    assert 'analysis' in client.get(f'/api/download/{record_id}/report').json()
    assert client.get(f'/api/evidence/{record_id}').json()['sha256'] == result['sha256']


def test_reject_bad_file_requests():
    assert client.post('/api/analyze', files={'file': ('empty.bin', b'', 'application/octet-stream')}).status_code == 400
    assert client.get('/api/download/no_such_record/report').status_code == 404
    result = client.post('/api/demo').json()
    record_id = result['id']
    assert client.get(f'/api/download/{record_id}/carve?offset=9999999999').status_code == 400
    assert client.get(f'/api/image/{record_id}/plane?channel=BAD').status_code == 400
    assert client.get(f'/api/download/{record_id}/lsb?channels=RR').status_code == 400
    assert client.post(f'/api/tools/{record_id}/run', json={'tool': 'arbitrary-command'}).status_code == 400
    assert client.get(f'/api/download/{record_id}/artifact/../../etc/passwd').status_code in (400, 404)


def test_demo_route_matches_expected_puzzle():
    result = client.post('/api/demo').json()
    assert result['filename'] == 'ctf-lsb-demo.png'
    assert 'flag{stegoscope_lsb_demo}' in result['flags']
