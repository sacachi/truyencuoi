"""Download and restore a password-encrypted SAHARAA handover. No account credentials required."""
from pathlib import Path,PurePosixPath
from urllib.request import urlopen
from urllib.parse import urljoin,urlparse
import argparse,base64,getpass,hashlib,json,stat,struct,subprocess,sys,tempfile,zipfile,io
from concurrent.futures import ThreadPoolExecutor

MAGIC=b'SAHARAA-GCM-V1\n'
def sha_file(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as f:
  while chunk:=f.read(2**20):h.update(chunk)
 return h.hexdigest()
def load_json(location):
 if urlparse(location).scheme in ('https','http'):
  with urlopen(location,timeout=60) as r:return json.load(r)
 return json.loads(Path(location).read_text())
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--manifest',required=True,help='Published transfer-manifest.json URL or local path')
 p.add_argument('--destination',default='.',help='Parent folder for SAHARAA-V3')
 p.add_argument('--password-file',help='Read the handover password from a private text file, instead of prompting')
 args=p.parse_args()
 try:
  from cryptography.hazmat.primitives.ciphers.aead import AESGCM
 except ImportError:
  sys.exit('Install the decryption dependency first: python3 -m pip install cryptography')
 manifest=load_json(args.manifest)
 if manifest.get('format')!='SAHARAA-ENCRYPTED-HANDOVER-1':sys.exit('Unsupported handover manifest')
 destination=Path(args.destination).resolve();project=destination/'SAHARAA-V3'
 if project.exists():sys.exit('Destination already contains SAHARAA-V3. Choose another destination to preserve existing edits.')
 cache=Path(tempfile.gettempdir())/('saharaa-transfer-'+manifest['encrypted_sha256'][:16]);cache.mkdir(exist_ok=True)
 is_web=urlparse(args.manifest).scheme in ('https','http')
 def get(part):
  name=part['name']
  if PurePosixPath(name).name!=name or '\\' in name:raise ValueError('Invalid part name')
  target=cache/name
  if target.is_file() and target.stat().st_size==part['bytes'] and sha_file(target)==part['sha256']:return target
  temporary=target.with_suffix('.partial')
  source=urljoin(args.manifest,name) if is_web else Path(args.manifest).resolve().parent/name
  if is_web:
   with urlopen(source,timeout=90) as r,temporary.open('wb') as f:
    while chunk:=r.read(2**20):f.write(chunk)
  else:
   with Path(source).open('rb') as r,temporary.open('wb') as f:
    while chunk:=r.read(2**20):f.write(chunk)
  if temporary.stat().st_size!=part['bytes'] or sha_file(temporary)!=part['sha256']:raise ValueError('Part checksum mismatch: '+name)
  temporary.replace(target);print('DOWNLOADED',name,part['bytes'],'bytes',flush=True);return target
 with ThreadPoolExecutor(max_workers=3) as pool:paths=list(pool.map(get,manifest['parts']))
 encrypted=b''.join(path.read_bytes() for path in paths)
 if hashlib.sha256(encrypted).hexdigest()!=manifest['encrypted_sha256']:sys.exit('Encrypted archive checksum mismatch')
 if not encrypted.startswith(MAGIC):sys.exit('Invalid encrypted archive header')
 pos=len(MAGIC);length=struct.unpack('>I',encrypted[pos:pos+4])[0];pos+=4
 if not 0<length<4096:sys.exit('Invalid archive header length')
 header=encrypted[pos:pos+length];pos+=length;info=json.loads(header)
 if info['algorithm']!='AES-256-GCM' or not 100000<=info['iterations']<=1000000:sys.exit('Unsupported encryption parameters')
 password=Path(args.password_file).read_text().strip() if args.password_file else getpass.getpass('Handover password: ')
 key=hashlib.pbkdf2_hmac('sha256',password.encode(),base64.b64decode(info['salt']),info['iterations'],dklen=32)
 try:plain=AESGCM(key).decrypt(base64.b64decode(info['nonce']),encrypted[pos:],header)
 except Exception:sys.exit('Unable to decrypt: incorrect password or modified encrypted data.')
 if hashlib.sha256(plain).hexdigest()!=manifest['archive_sha256']:sys.exit('Decrypted ZIP checksum mismatch')
 with zipfile.ZipFile(io.BytesIO(plain)) as archive:
  total=0
  for item in archive.infolist():
   path=PurePosixPath(item.filename);mode=item.external_attr>>16;total+=item.file_size
   if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0]!='SAHARAA-V3' or '\\' in item.filename or stat.S_ISLNK(mode):sys.exit('Unsafe ZIP entry')
  if total>2*1024**3:sys.exit('Archive exceeds the expected project size')
  destination.mkdir(parents=True,exist_ok=True)
  archive.extractall(destination)
 subprocess.run([sys.executable,str(project/'verify.py')],check=True)
 print('RESTORED',project)
 print('Next: read BAT-DAU-O-DAY.md and BAN-GIAO-V3.md; run setup.py --install. Nothing has been published.')
if __name__=='__main__':main()
