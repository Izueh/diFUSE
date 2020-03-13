import socket
from header_structs import difuse_request, difuse_response
from json import loads, dumps
from base64 import b64encode, b64decode
from hashlib import sha1
from time import time
import logging
import sys


# TODO: add salted hash
# TODO: add function to remove node if connection terminated

def list_dir(fd, addr, req):
    ips = hash2ip.values()
    file_list = []
    for ip in ips:
        with socket.create_connection((ip, 8080)) as s:
            req = {}
            req['op'] = 0x18
            req['length'] = 0
            req = difuse_request.build(req)
            s.sendall(req)
            res = difuse_response.parse(s.recv(difuse_response.sizeof()))
            file_list += loads(s.recv(res.length))

    data = dumps(file_list).encode('utf-8')
    res = {}
    res['status'] = 0
    res['length'] = len(data)
    fd.sendall(difuse_response.build(res)+data)


def lookup(fd, addr, req):
    print('lookup', req['file'])
    filename = req['file']
    file_hash = sha1(filename.encode('utf-8')).digest()
    file_hash = int.from_bytes(file_hash, byteorder='little')
    print(file_hash)
    ip = host_list[0]
    for h in host_list:
        if file_hash < h:
            ip = h
            break
    ip = hash2ip[ip]
    data = (dumps({'ip': ip})).encode('utf-8')
    res = {}
    res['status'] = 0
    res['length'] = len(data)
    res = difuse_response.build(res)
    fd.sendall(res+data)


def create(fd, addr, req):
    file_ip[req['file']] = [addr[0], 8080]
    file_list.append(req['file'])
    res = {}
    res['status'] = 0
    res['length'] = 0
    fd.sendall(difuse_response.build(res))


def remove(fd, addr, req):
    del file_ip[req['file']]
    file_list.remove(req['file'])
    res = {}
    res['status'] = 0
    res['length'] = 0
    fd.sendall(difuse_response.build(res))


def rename(fd, addr, req):
    file_ip[req['newname']] = file_ip[req['file']]
    file_list.append(req['newname'])
    del file_ip[req['file']]
    file_list.remove(req['file'])
    res = {}
    res['status'] = 0
    res['length'] = 0
    fd.sendall(difuse_response.build(res))


def join(fd, addr, req):
    t = str(time()).encode('utf-8')
    logging.debug(t)
    logging.debug(f'address = {addr[0]}')
    ip_hash = sha1(addr[0].encode('utf-8') + t).digest()
    logging.debug(f'hash = {ip_hash}')
    ip_hash = int.from_bytes(ip_hash, byteorder='little')
    logging.debug(f'hash = {ip_hash}')
    host_list.append(ip_hash)
    host_list.sort()
    hash2ip[ip_hash] = addr[0]
    # send ip of successor
    data = {'id': ip_hash}
    if len(host_list) > 1:
        index = (host_list.index(ip_hash) + 1) % len(host_list)
        data['ip'] = hash2ip[host_list[index]]
    data = dumps(data)
    data = data.encode('utf-8')
    res = {}
    res['status'] = 0
    res['length'] = len(data)
    fd.sendall(difuse_response.build(res) + data)


def leave(fd, addr, req):
    global file_ip
    file_ip = {k: v for k, v in file_ip.items() if v == addr}
    res = {}
    res['status'] = 0
    res['length'] = 0
    ip_hash = [key for key, value in hash2ip.items() if value == addr[0]][0]
    index = (host_list.index(ip_hash) + 1) % len(host_list)
    succ = hash2ip[host_list[index]]
    host_list.remove(ip_hash)
    del hash2ip[ip_hash]
    # send ip of successor to migrate
    # send ip of successor
    data = {'id': ip_hash}
    if len(host_list) > 0:
        data['ip'] = succ
    data = dumps(data)
    data = data.encode('utf-8')
    res = {}
    res['status'] = 0
    res['length'] = len(data)
    fd.sendall(difuse_response.build(res) + data)


if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('0.0.0.0', 8081))
        sock.listen()

        file_list = []
        file_ip = {}
        host_list = []
        hash2ip = {}
        size = difuse_request.sizeof()

        handle = {
            0x01: list_dir,
            0x02: lookup,
            0x03: join,
            0x04: leave,
            0x05: create,
            0x06: remove,
            0x07: rename
        }

        while 0xDEAD:
            fd, addr = sock.accept()
            header = difuse_request.parse(fd.recv(size))
            payload = None
            print(header)
            if header.length:
                payload = fd.recv(header.length)
                payload = loads((payload).decode('utf-8'))
            handle[header.op](fd, addr, payload)
            fd.close()
