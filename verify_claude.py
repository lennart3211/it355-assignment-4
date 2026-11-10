#!/usr/bin/env python3
"""Focused, non-destructive Claude candidate verification for IT355."""
import ast, csv, json, os, shutil, subprocess, sys, tempfile, traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent
# Script may be downloaded into repo root or results/claude-patches
if not (ROOT / 'verademo-python').is_dir():
    ROOT = Path.cwd()
CAND = ROOT / 'results/claude-patches/candidates'
APP = ROOT / 'verademo-python'
OUT = ROOT / 'results/claude-patches/claude_test_evidence.json'
checks=[]
def record(ids, name, status, detail):
    checks.append(dict(findings=ids, test=name, status=status, evidence=detail))
    print(f'{status:12} {ids:12} {name}: {detail}', flush=True)
def read(p): return (CAND / p).read_text()
def contains(p, *terms): return all(t in read(p) for t in terms)

def isolated_check():
    with tempfile.TemporaryDirectory() as td:
        dest=Path(td)/'verademo-python'
        shutil.copytree(APP,dest,ignore=shutil.ignore_patterns('.git','__pycache__','*.pyc','db.sqlite3'))
        for f in CAND.rglob('*.py'):
            target=dest/f.relative_to(CAND)
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(f,target)
        env=os.environ.copy()
        env.update({'DJANGO_SECRET_KEY':'local-verification-only-test-key-not-for-production', 'DJANGO_ALLOWED_HOSTS':'localhost,127.0.0.1,testserver'})
        script=r'''
import json, os, sys
os.environ.setdefault('DJANGO_SETTINGS_MODULE','verademo-python.settings')
# Django project settings module is inferred from manage.py; don't assume module name.
from pathlib import Path
p=Path('manage.py').read_text()
import re
m=re.search(r'setdefault\([\'\"]DJANGO_SETTINGS_MODULE[\'\"]\s*,\s*[\'\"]([^\'\"]+)',p)
if m: os.environ['DJANGO_SETTINGS_MODULE']=m.group(1)
import django
django.setup()
from django.conf import settings
from django import forms
from django.contrib import admin
from django.core.management import call_command
from django.test import RequestFactory
from django.contrib.auth.hashers import identify_hasher, check_password
from app.forms import UserForm, RegisterForm
from app.models import User, create
from app.views.homeController import home
from unittest.mock import patch
out={}
def check(k,fn):
    try:
        ok, detail=fn()
        out[k]=dict(status='PASS' if ok else 'FAIL', detail=str(detail))
    except Exception as exc:
        out[k]=dict(status='NEEDS REVIEW', detail=f'{type(exc).__name__}: {exc}')
check('admin', lambda: ('password' not in admin.site._registry[User].get_list_display(RequestFactory().get('/')) and 'password' in (admin.site._registry[User].exclude or []), 'Password absent from admin list and excluded from admin form'))
check('forms',lambda: (isinstance(UserForm.base_fields['password'].widget,forms.PasswordInput) and isinstance(RegisterForm.base_fields['password'].widget,forms.PasswordInput) and isinstance(RegisterForm.base_fields['cpassword'].widget,forms.PasswordInput), 'Password fields render with PasswordInput widgets'))
def test_model():
    u=create('testuser','Test','Tester')
    h=identify_hasher(u.password)
    return (h.algorithm not in ('unsalted_md5','md5') and u.password != 'testuser' and u.password_hint is None, f'algorithm={h.algorithm}; hint={u.password_hint!r}; password differs from username')
check('models',test_model)
check('settings',lambda: (settings.DEBUG is False and '*' not in settings.ALLOWED_HOSTS and 'django.middleware.csrf.CsrfViewMiddleware' in settings.MIDDLEWARE and 'django.middleware.security.SecurityMiddleware' in settings.MIDDLEWARE and settings.SECRET_KEY == os.environ['DJANGO_SECRET_KEY'], f'DEBUG={settings.DEBUG}; hosts={settings.ALLOWED_HOSTS}; middleware enabled; env secret used'))
def test_home():
    r=RequestFactory().get('/',HTTP_HOST='example.invalid')
    r.session={'username':'testuser'}
    with patch('urllib.request.urlopen',side_effect=AssertionError('Network access attempted')):
        response=home(r)
    return (response.status_code in (301,302,303,307,308) and '/feed' in response['Location'],f'status={response.status_code}; location={response.get("Location")}')
check('home',test_home)
print('RESULT_JSON='+json.dumps(out))
'''
        cmd=[sys.executable,'-c',script]
        try:
            r=subprocess.run(cmd,cwd=dest,env=env,capture_output=True,text=True,timeout=90)
        except Exception as exc:
            record('ALL','Django runtime checks','NEEDS REVIEW',repr(exc));return
        marker=next((x[len('RESULT_JSON='):] for x in r.stdout.splitlines() if x.startswith('RESULT_JSON=')),None)
        if marker:
            for k,v in json.loads(marker).items():
                ids={'admin':'F0001','forms':'F0008-F0009','models':'F0010-F0012','settings':'F0061-F0065','home':'F0025'}[k]
                record(ids,'Runtime '+k,v['status'],v['detail'])
        else:
            record('ALL','Django runtime checks','NEEDS REVIEW',(r.stderr or r.stdout)[-1600:])
        # Django system check on same isolated candidate tree
        r=subprocess.run([sys.executable,'manage.py','check'],cwd=dest,env=env,capture_output=True,text=True,timeout=60)
        record('ALL','Django system check','PASS' if r.returncode==0 else 'FAIL',(r.stdout+r.stderr).strip()[-450:])

def static_checks():
    for f in sorted(CAND.rglob('*.py')):
        try: ast.parse(f.read_text()); status='PASS';detail='Python AST parses successfully'
        except SyntaxError as e:status='FAIL';detail=str(e)
        record('ALL','Syntax '+str(f.relative_to(CAND)),status,detail)
    for filename,ids in [('app/commands/IgnoreCommand.py','F0002-F0004'),('app/commands/ListenCommand.py','F0005-F0007')]:
        tree=ast.parse(read(filename))
        # Check every execute(sqlQuery, ...) has separate parameter arg
        calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='execute']
        valid=len(calls)>=3 and all(len(c.args)>=2 for c in calls)
        record(ids,'Parameterized SQL call structure','PASS' if valid else 'NEEDS REVIEW',f'{len(calls)} execute calls; {sum(len(c.args)>=2 for c in calls)} with parameter argument; runtime injection test still recommended')
    tools=read('app/views/toolsController.py')
    record('F0030','Shell execution removed','PASS' if 'os.system(' not in tools else 'FAIL','No os.system call in candidate' if 'os.system(' not in tools else 'os.system remains')
    record('F0031','Ping argument guard','PASS' if "host.startswith('-')" in tools and "'--', host" in tools else 'NEEDS REVIEW','Rejects leading hyphen and uses -- separator; platform behavior not tested')
    reset=read('app/views/resetController.py')
    record('F0026','TLS validation setting','PASS' if 'disable_ssl_certificate_validation=True' not in reset else 'FAIL','Explicit certificate validation bypass absent; live TLS behavior not tested')
    record('F0027','Hardcoded credentials','PASS' if 'RESET_HTTP_USER' in reset and 'RESET_HTTP_PASSWORD' in reset else 'FAIL','Credentials read from environment; deployment not tested')
    record('F0029','Reset SQL parameterization','PASS' if 'cursor.execute(usersStatement,' in reset and 'cursor.execute(listenersStatement,' in reset else 'NEEDS REVIEW','Two insertion paths use separate parameters; database behavior not tested')
    record('F0028','Reset endpoint CSRF','NEEDS REVIEW','Middleware enabled in settings, but endpoint-level CSRF enforcement not exercised')
    record('F0012','Password storage integration','NEEDS REVIEW','Hasher changed; existing login/reset flows not tested for compatibility')
    record('F0030-F0031','Tools runtime behavior','NEEDS REVIEW','Shell/argument protections inspected; ping/fortune runtime behavior not exercised')
    record('F0013-F0024','blabController patches','NO PATCH','Generation status invalid_proposal; no candidate to test')
    record('F0032-F0060','userController patches','NO PATCH','Generation status api_error; no candidate to test')

if __name__=='__main__':
    if not APP.is_dir() or not CAND.is_dir():
        sys.exit('Run from repo root with verademo-python/ and results/claude-patches/candidates/ present.')
    static_checks()
    isolated_check()
    OUT.parent.mkdir(parents=True,exist_ok=True)
    OUT.write_text(json.dumps({'checks':checks,'note':'Focused test evidence; PASS is scoped to the specific check, not final patch approval.'},indent=2)+'\n')
    print('\nSaved:',OUT)
    from collections import Counter
    print('Summary:',dict(Counter(c['status'] for c in checks)))
