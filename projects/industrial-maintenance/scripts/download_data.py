"""Fetch the public UCI benchmark and verify the exact tested CSV checksum."""
import hashlib
import io
from pathlib import Path
import urllib.request
import zipfile
url='https://archive.ics.uci.edu/static/public/601/ai4i+2020+predictive+maintenance+dataset.zip'
expected='dc6630cd9b1f0f853922fad78a1b6436570d3f1ec863f1dd5c4340ac56bc8a8e'
with urllib.request.urlopen(url,timeout=30) as response:
    archive=response.read()
with zipfile.ZipFile(io.BytesIO(archive)) as z:
    data=z.read('ai4i2020.csv')
if hashlib.sha256(data).hexdigest()!=expected:
    raise ValueError('Dataset version changed; inspect before using')
path=Path(__file__).resolve().parents[1]/'data'/'ai4i2020.csv'
path.parent.mkdir(exist_ok=True);path.write_bytes(data)
print(path)
