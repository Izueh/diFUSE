import socket
from json import dumps, loads
from header_structs import difuse_request, difuse_response
import os
from sys import argv
from threading import Thread
from hashlib import sha1
from base64 import b64encode, b64decode
import select
import logging
import signal
import sys


# TODO: add file migration functionality
def reqboot(op, data):
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.connect((argv[1], int(argv[2])))

    data = dumps(data).encode('utf-8')
    res = {}
    res['op'] = op
    res['length'] = len(data)
    request = difuse_request.build(res)
    serversocket.sendall(request + data)


def join():
    global my_id
    s = socket.socket()
    s.connect((argv[1], int(argv[2])))
    h = difuse_request.build({'op': 0x3, 'length': 0})
    s.sendall(h)
    h = s.recv(difuse_response.sizeof())
    h = difuse_response.parse(h)
    data = s.recv(h.length)
    logging.debug(f'data: {data}')
    data = loads(data.decode('utf-8'))
    my_id = data['id']
    if 'ip' in data:
        recv_files(data['ip'], data['id'])

    # TODO: receive and call recv_files


def leave():
    s = socket.socket()
    s.connect((argv[1], int(argv[2])))
    h = difuse_request.build({'op': 0x4, 'length': 0})
    s.sendall(h)
    h = s.recv(difuse_response.sizeof())
    h = difuse_response.parse(h)
    data = s.recv(h.length)
    data = loads(data.decode('utf-8'))
    print('leave', data)
    if data:
        s = socket.socket()
        s.connect((data['ip'], 8080))
        data = dumps({'hash': myhash}).encode('utf-8')
        h = difuse_request.build({'op': 0x17, 'length': len(data)})
        s.sendall(h + data)


def read(fd, req, addr):
    with open('/'.join((file_dir, req['file'])), 'rb') as f:
        f.seek(req['offset'])
        data = f.read(req['size'])
        res = {}
        res['status'] = 0
        res['length'] = len(data)
        fd.sendall(difuse_response.build(res) + data)


def create(fd, req, addr):
    f = open('/'.join((file_dir, req['file'])), 'w')
    f.close()
    res = {'status': 0, 'length': 0}
    fd.sendall(difuse_response.build(res))



def write(fd, req, addr):
    with open('/'.join((file_dir, req['file'])), 'r+b') as f:
        f.seek(req['offset'])
        data = req['data'].encode('utf-8')
        data = b64decode(data)
        f.write(data)
        res = {}
        res['status'] = 0
        res['length'] = 0
        fd.sendall(difuse_response.build(res))


def list_files(fd, req, addr):
    data = dumps(os.listdir(file_dir)).encode('utf-8')
    res = {}
    res['status'] = 0
    res['length'] = len(data)
    res = difuse_response.build(res)
    fd.sendall(res + data)


def truncate(fd, req, addr):
    with open('/'.join((file_dir, req['file'])), 'w+') as f:
        f.truncate(req['size'])
        res = {}
        res['status'] = 0
        res['length'] = 0
        fd.sendall(difuse_response.build(res))


def rename(fd, req, addr):
    os.rename('/'.join((file_dir, req['file'])),
              '/'.join((file_dir, req['newname'])))

    res = {}
    res['status'] = 0
    res['length'] = 0
    h = difuse_response.build(res)
    fd.sendall(h)


def stat(fd, req, addr):
    filepath = '/'.join((file_dir, req['file']))
    data = {}
    if(os.path.isfile(filepath)):
            info = os.stat(filepath)
            stat = dict(st_mode=info.st_mode, st_nlink=info.st_nlink,
                        st_size=info.st_size, st_ctime=info.st_ctime,
                        st_mtime=info.st_mtime, st_atime=info.st_atime)
            data = stat
    data = dumps(data).encode('utf-8')
    res = {}
    res['status'] = 0
    res['length'] = len(data)
    h = difuse_response.build(res)
    fd.sendall(h + data)

def rm(fd, req, addr):
    data = {'file': req['file']}
    os.unlink('/'.join((file_dir, req['file'])))

    res = {}
    res['status'] = 0
    res['length'] = 0
    h = difuse_response.build(res)
    fd.sendall(h)


def recv_help(ip, my_hash):
    logging.debug(f'ip: {ip}')
    logging.debug(f'hash: {my_hash}')
    s = socket.create_connection((ip, 8080))
    listenfd = socket.socket()
    listenfd.bind(('0.0.0.0', 0))
    listenfd.listen()
    port = listenfd.getsockname()
    logging.debug(f'port: {port[1]}')
    data = dumps({'port': port[1], 'hash': my_hash}).encode('utf-8')
    req = {}
    req['op'] = 0x16
    req['length'] = len(data)
    req = difuse_request.build(req)
    s.sendall(req+data)
    s.close()
    s, conn = listenfd.accept()
    while(1):
        h = s.recv(difuse_request.sizeof())
        if not h:
            break
        h = difuse_request.parse(h)
        data = s.recv(h.length)
        data = loads(data)
        data['data'] = data['data'].encode('utf-8')
        data['data'] = b64decode(data['data'])
        f = open(data['fname'], 'wb')
        f.write(data['data'])
        f.close()
    s.close()
    listenfd.close()


def recv_files(ip, ip_hash):
    t = Thread(target=recv_help, args=[ip, ip_hash])
    t.start()


def get_files(fd, req, addr):
    print('ehehe', req, addr)
    t = Thread(target=recv_help, args=[addr[0], req['hash']])
    t.start()


def send_help(ip, port, other_hash):
    files = os.listdir(file_dir)
    logging.debug(f'port: {port}')
    with socket.create_connection((ip, port)) as s:
        for fname in files:
            h = sha1(fname.encode('utf-8')).digest()
            h = int.from_bytes(h, byteorder='little')
            print(h)
            if other_hash > my_id:
                if my_id < h < other_hash or leaving:
                    fname = '/'.join((file_dir, fname))
                    f = open(fname, 'rb')
                    data = b64encode(f.read())
                    data = data.decode('utf-8')
                    f.close()
                    os.unlink(fname)
                    data = (dumps({'fname': fname, 'data': data})).encode('utf-8')
                    req = {'op': 0, 'length': len(data)}
                    req = difuse_request.build(req)
                    s.sendall(req+data)
            else:
                if h < other_hash or h > my_id or leaving:
                    fname = '/'.join((file_dir, fname))
                    f = open(fname, 'rb')
                    data = b64encode(f.read())
                    data = data.decode('utf-8')
                    f.close()
                    os.unlink(fname)
                    data = (dumps({'fname': fname, 'data': data})).encode('utf-8')
                    req = {'op': 0, 'length': len(data)}
                    req = difuse_request.build(req)
                    s.sendall(req+data)


def send_files(fd, req, addr):
    global done
    t = Thread(target=send_help, args=[addr[0], req['port'], req['hash']])
    t.start()
    if left:
        t.join()
        done = True


def sig_int(signum, frame):
    global leaving
    leaving = True


if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('0.0.0.0', 8080))
        sock.listen()
        myhash = 0
        size = difuse_request.sizeof()
        done = False
        leaving = False
        left = False
        r, w = os.pipe()
        os.set_blocking(w, False)
        signal.set_wakeup_fd(w)
        signal.signal(signal.SIGINT, sig_int)
        handle = {
            0x10: stat,
            0x11: read,
            0x12: write,
            0x13: truncate,
            0x14: rm,
            0x15: rename,
            0x16: send_files,
            0x17: get_files,
            0x18: list_files,
            0x19: create
        }

        file_dir = 'difuse.local'

        join()

        while not done:
            read, _, _ = select.select([sock, r], [], [])
            if leaving and not left:
                leave()
                leaving = False
                left = True
                continue
            elif sock in read:
                fd, addr = sock.accept()
                payload = None
                header = difuse_request.parse(fd.recv(size))
                if left and header.op != 0x16:
                    res = {}
                    res['status'] = -1
                    res['length'] = 0
                    res = difuse_response.build(res)
                    fd.sendall(res)
                    fd.close()
                    continue
                if header.length:
                    payload = fd.recv(header.length)
                    payload = loads((payload).decode('utf-8'))
                handle[header.op](fd, payload, addr)
                fd.close()
        logging.debug('leaving')
