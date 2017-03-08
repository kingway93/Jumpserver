#!/usr/bin/env python
# _*_encoding:utf-8_*_

import os
import json
import time
import subprocess
import SocketServer

def send_data(request, code, data="", offset=-1):
    msg = {}
    if code == 200:
        msg["length"] = len(data)
    else:
        msg["data"] = data
    msg["offset"] = offset
    msg["code"] = code
    request.sendall('next')
    request.recv(1024)
    request.sendall(json.dumps(msg))
    if code == 200:
        request.recv(1024)
        request.sendall(data)


def log_handle(request, data):
    file_path = data.get("file_path")
    offset = int(data.get("offset"))
    try:
        with open(file_path) as f:
            if offset == -1:
                f.seek(0,2)
                offset = f.tell()
                send_data(request=request, code=300, offset=offset)
            else:
                f.seek(offset)
                while True:
                    line = f.readline()
                    if line:
                        print line
                        send_data(request=request, data=line, code=200)
                    else:
                        offset = f.tell()
			send_data(request=request, code=300, offset=offset)
                        break
    except IOError, e:
        print e
        line = "日志路径不存在"
        send_data(request=request, data=line, code=400)


class MyServer(SocketServer.BaseRequestHandler):

    def handle(self):
        conn = self.request
        recv_data = conn.recv(1024)
        data = json.loads(recv_data)
        types = data.get("type")
        if types == "log":
            log_handle(conn, data)
        conn.close()


if __name__ == '__main__':
    server = SocketServer.ThreadingTCPServer(('0.0.0.0',11311), MyServer)
    server.serve_forever()
