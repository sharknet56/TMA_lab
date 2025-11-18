from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import json
from pathlib import Path
import subprocess
from typing import List, Optional
import os
from datetime import datetime


API_TOKEN = os.environ.get('BACKEND_TOKEN', 'changeme')
LOG_PATH = Path(__file__).resolve().parent / 'actions.log'

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / 'data.json'

app = FastAPI(title='Router Network Monitor')

app.add_middleware(
    CORSMiddleware,
    allow_origins=['http://localhost:5173', 'http://127.0.0.1:5173'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)


def read_data():
    try:
        return json.loads(DATA_PATH.read_text())
    except Exception:
        return {'groups': {}, 'blocked': []}


def write_data(obj):
    DATA_PATH.write_text(json.dumps(obj, indent=2))


def log_action(action: str, name: str, ips: List[str], results: List[dict]):
    try:
        entry = {
            'time': datetime.utcnow().isoformat() + 'Z',
            'action': action,
            'name': name,
            'ips': ips,
            'results': results,
        }
        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def verify_token(request: Request):
    # check x-api-key header or Authorization: Bearer <token>
    token = request.headers.get('x-api-key')
    if not token:
        auth = request.headers.get('authorization')
        if auth and auth.lower().startswith('bearer '):
            token = auth.split(' ', 1)[1].strip()
    if token != API_TOKEN:
        raise HTTPException(status_code=401, detail='Unauthorized')


class BlockRequest(BaseModel):
    name: str


class UnblockRequest(BaseModel):
    # either name or ips
    name: Optional[str] = None
    ips: Optional[List[str]] = None


@app.get('/api/list')
def get_list():
    return read_data()


@app.get('/api/logs')
def get_logs(token: None = Depends(verify_token)):
    # return last 200 lines of log (simple)
    if not LOG_PATH.exists():
        return {'logs': []}
    lines = []
    with open(LOG_PATH, 'r') as f:
        for l in f:
            try:
                lines.append(json.loads(l))
            except Exception:
                continue
    return {'logs': lines[-200:]}


@app.post('/api/block')
def block_group(req: BlockRequest, token: None = Depends(verify_token)):
    data = read_data()
    name = req.name
    if name not in data.get('groups', {}):
        raise HTTPException(status_code=404, detail='Group not found')

    ips = data['groups'][name] or []
    results = []

    for ip in ips:
        cmd = ['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP']
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode == 0:
                results.append({'ip': ip, 'ok': True, 'simulated': False, 'output': proc.stdout})
            else:
                # likely permission or missing iptables -> simulate
                results.append({'ip': ip, 'ok': False, 'simulated': True, 'stderr': proc.stderr or proc.stdout})
        except FileNotFoundError as e:
            results.append({'ip': ip, 'ok': False, 'simulated': True, 'error': str(e)})
        except Exception as e:
            results.append({'ip': ip, 'ok': False, 'simulated': True, 'error': str(e)})

    # update blocked list idempotently
    blocked = set(data.get('blocked', []))
    blocked.update(ips)
    data['blocked'] = list(blocked)
    write_data(data)

    # log action
    try:
        log_action('block', name, ips, results)
    except Exception:
        pass

    return {'ok': True, 'name': name, 'ips': ips, 'results': results}


@app.post('/api/unblock')
def unblock_group(req: UnblockRequest, token: None = Depends(verify_token)):
    data = read_data()
    ips_to_unblock: List[str] = []
    if req.name:
        if req.name not in data.get('groups', {}):
            raise HTTPException(status_code=404, detail='Group not found')
        ips_to_unblock = list(data['groups'][req.name])
    elif req.ips:
        ips_to_unblock = list(req.ips)
    else:
        raise HTTPException(status_code=400, detail='Provide name or ips to unblock')

    results = []
    for ip in ips_to_unblock:
        cmd = ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode == 0:
                results.append({'ip': ip, 'ok': True, 'simulated': False, 'output': proc.stdout})
            else:
                results.append({'ip': ip, 'ok': False, 'simulated': True, 'stderr': proc.stderr or proc.stdout})
        except FileNotFoundError as e:
            results.append({'ip': ip, 'ok': False, 'simulated': True, 'error': str(e)})
        except Exception as e:
            results.append({'ip': ip, 'ok': False, 'simulated': True, 'error': str(e)})

    # remove from blocked list
    blocked = set(data.get('blocked', []))
    for ip in ips_to_unblock:
        blocked.discard(ip)
    data['blocked'] = list(blocked)
    write_data(data)

    try:
        log_action('unblock', req.name or '', ips_to_unblock, results)
    except Exception:
        pass

    return {'ok': True, 'ips': ips_to_unblock, 'results': results}


if __name__ == '__main__':
    # run with: python backend/app.py  OR use uvicorn: uvicorn backend.app:app --host 0.0.0.0 --port 3000
    try:
        import uvicorn

        uvicorn.run('app:app', host='0.0.0.0', port=3000, reload=True)
    except Exception:
        print('uvicorn not available. Run with: uvicorn backend.app:app --host 0.0.0.0 --port 3000')
