import sys
import socket
import struct
import yaml
import hashlib

'''Constants'''
INT_LENGTH = 4
BACKEND_STATUS = ["INIT", "UP", "WAITING", "DOWN"]
BACKEND_ROLE = ["MASTER", "SLAVE"]

PCP_MD5_SALT = 'M'
PCP_MD5_AUTH = 'R'
PCP_NODE_INFO = 'I'
PCP_NODE_COUNT = 'L'
PCP_WATCHDOG_INFO = 'W'
PCP_DETATCH_NDOE = 'D'
PCP_ATTACH_NODE = 'C'
PCP_POOL_STATUS = 'B'
PCP_SYNC_NODE = 'S'
PCP_CLOSE_CONN = 'X'

PCP_AUTH_OK = "AuthenticationOK"
PCP_CMD_COMPLETE = "CommandComplete"
PCP_CMD_PROC = "ProcessCommand"
PCP_CMD_FAILED = "Failed"
PCP_CMD_ERR = "STDERR"

'''Error Handling'''
class PCPConnError(Exception):
    def __init__(self, message=""):
        self.cause = "PCP_Conn_Error"
        self.message = message
    def __str__(self):
        return "{}: {}".format(self.cause, self.message)

class PCPResError(Exception):
    def __init__(self, message=""):
        self.cause = "PCP_Res_Error"
        self.message = message
    def __str__(self):
        return "{}: {}".format(self.cause, self.message)

class PCPAuthError(Exception):
    def __init__(self, message=""):
        self.cause = "PCP_Auth_Error"
        self.message = message
    def __str__(self):
        return "{}: {}".format(self.cause, self.message)

class PCPSyncError(Exception):
    def __init__(self, message=""):
        self.cause = "PCP_Sync_Error"
        self.message = message
    def __str__(self):
        return "{}: {}".format(self.cause, self.message)

'''Main Library'''
class pcp:
    def __init__(self, host="127.0.0.1", port=9898, user="", pwd=""):
        self.host = host
        self.port = port
        self.user = user
        self.pwd = pwd
        
        self.fd = self.connect()
        
    def connect(self):
        try:
            fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error, e:
            raise PCPConnError(e)
        
        try:
            fd.connect((self.host, self.port))
        except socket.gaierror, e:
            raise PCPConnError(e)
        except socket.error, e:
            raise PCPConnError(e)
        
        return fd
    
    def md5_encrypt(self, pwd, salt):
        enc = hashlib.md5()
        enc.update("{}{}".format(pwd, salt))
        return enc.hexdigest()
    
    def authorize(self):
        msg = "{}{}".format(PCP_MD5_SALT, struct.pack("!i", INT_LENGTH))
        self.fd.send(msg)
        self.response(PCP_MD5_SALT)

        encrypt = self.md5_encrypt(self.pwd, "")
        encrypt = self.md5_encrypt(encrypt, self.user)
        encrypt = self.md5_encrypt(encrypt, self.salt)

        wsize = (len(self.user) + 1 + len(encrypt) +1) + INT_LENGTH
        wsize = struct.pack("!i", wsize)
        msg = "{}{}{}{}{}{}".format(PCP_MD5_AUTH, wsize, self.user, chr(0), encrypt, chr(0))
        self.fd.send(msg)
        self.response(PCP_MD5_AUTH)
    
    def node_info(self, sn):
        self.authorize()
        sn = list(str(sn))
        wsize = len(sn) + 1 + INT_LENGTH;
        wsize = struct.pack("!i", wsize)
        msg = "{}{}".format(PCP_NODE_INFO, wsize)
        for n in sn:
            msg = "{}{}".format(msg, n)
        msg = "{}{}".format(msg, chr(0))
        self.fd.send(msg)
        self.response(PCP_NODE_INFO)
        ret = self.normalization(PCP_NODE_INFO)
        msg = "{}{}".format(PCP_CLOSE_CONN, struct.pack("!i", INT_LENGTH))
        self.fd.send(msg)
        return ret
        
    def node_count(self):
        self.authorize()
        msg = "{}{}".format(PCP_NODE_COUNT, struct.pack("!i", INT_LENGTH))
        self.fd.send(msg)
        self.response(PCP_NODE_COUNT)
        ret = self.normalization(PCP_NODE_COUNT)
        msg = "{}{}".format(PCP_CLOSE_CONN, struct.pack("!i", INT_LENGTH))
        self.fd.send(msg)
        return ret
        
    def watchdog_info(self, sn=-1):
        self.authorize()
        sn = list(str(sn))
        wsize = len(sn) + 1 + INT_LENGTH;
        wsize = struct.pack("!i", wsize)
        msg = "{}{}".format(PCP_WATCHDOG_INFO, wsize)
        for n in sn:
            msg = "{}{}".format(msg, n)
        msg = "{}{}".format(msg, chr(0))
        self.fd.send(msg)
        self.response(PCP_WATCHDOG_INFO)
        ret = self.normalization(PCP_WATCHDOG_INFO)
        msg = "{}{}".format(PCP_CLOSE_CONN, struct.pack("!i", INT_LENGTH))
        self.fd.send(msg)
        return ret
    
    def detach_node(self, sn):
        self.authorize()
        sn = list(str(sn))
        wsize = len(sn) + 1 + INT_LENGTH;
        wsize = struct.pack("!i", wsize)
        msg = "{}{}".format(PCP_DETATCH_NDOE, wsize)
        for n in sn:
            msg = "{}{}".format(msg, n)
        msg = "{}{}".format(msg, chr(0))
        self.fd.send(msg)
        self.response(PCP_DETATCH_NDOE)
        ret = self.normalization(PCP_DETATCH_NDOE)
        msg = "{}{}".format(PCP_CLOSE_CONN, struct.pack("!i", INT_LENGTH))
        self.fd.send(msg)
        return ret
    
    def attach_node(self, sn):
        self.authorize()
        sn = list(str(sn))
        wsize = len(sn) + 1 + INT_LENGTH
        wsize = struct.pack("!i", wsize)
        msg = "{}{}".format(PCP_ATTACH_NODE, wsize)
        for n in sn:
            msg = "{}{}".format(msg, n)
        msg = "{}{}".format(msg, chr(0))
        self.fd.send(msg)
        self.response(PCP_ATTACH_NODE)
        ret = self.normalization(PCP_ATTACH_NODE)
        msg = "{}{}".format(PCP_CLOSE_CONN, struct.pack("!i", INT_LENGTH))
        self.fd.send(msg)
        return ret
        
    def pool_status(self):
        self.authorize()
        self.data = []
        msg = "{}{}".format(PCP_POOL_STATUS, struct.pack("!i", INT_LENGTH))
        self.fd.send(msg)
        self.response(PCP_POOL_STATUS)
        ret = self.normalization(PCP_POOL_STATUS)
        msg = "{}{}".format(PCP_CLOSE_CONN, struct.pack("!i", INT_LENGTH))
        self.fd.send(msg)
        return ret
    
    def sync_node(self, ip):
        self.authorize()
        self.data = []
        wsize = len(ip) + 1 + INT_LENGTH
        wsize = struct.pack("!i", wsize)
        msg = "{}{}{}{}".format(PCP_SYNC_NODE, wsize, ip, chr(0))
        self.fd.send(msg)
        self.response(PCP_SYNC_NODE)
        ret = self.normalization(PCP_SYNC_NODE)
        msg = "{}{}".format(PCP_CLOSE_CONN, struct.pack("!i", INT_LENGTH))
        self.fd.send(msg)
        return ret
    
    def response(self, cmd):
        cmd_recv = self.fd.recv(1)
        
        buf = self.fd.recv(INT_LENGTH)
        rsize = struct.unpack("!i", buf)[0]
        
        buf = self.fd.recv(rsize - INT_LENGTH)
        
        if cmd == PCP_MD5_SALT:      #get md5 salt from PCP server
            if cmd_recv != PCP_MD5_SALT.lower():
                err_msg = buf.split('\x00')
                raise PCPResError("{}({})"\
                                  .format(err_msg[2][1:], err_msg[3][1:]))
            self.salt = buf
                
        elif cmd == PCP_MD5_AUTH:    #get authorization result from PCP server
            if cmd_recv != PCP_MD5_AUTH.lower() or \
            not PCP_AUTH_OK in buf:
                err_msg = buf.split('\x00')
                raise PCPResError("{}({})"\
                                  .format(err_msg[2][1:], err_msg[3][1:]))

        elif cmd == PCP_NODE_INFO:    #get node_info from PCP server
            if cmd_recv != PCP_NODE_INFO.lower():
                err_msg = buf.split('\x00')
                raise PCPResError("{}({})"\
                                  .format(err_msg[2][1:], err_msg[3][1:]))
            if PCP_CMD_COMPLETE in buf:
                self.data = buf.split('\x00')
        
        elif cmd == PCP_NODE_COUNT:    #get total node number from PCP server
            if cmd_recv != PCP_NODE_COUNT.lower():
                err_msg = buf.split('\x00')
                raise PCPResError("{}({})"\
                                  .format(err_msg[2][1:], err_msg[3][1:]))
            if PCP_CMD_COMPLETE in buf:
                self.data = buf.split('\x00')
            
        elif cmd == PCP_DETATCH_NDOE:    #ask PCP server to distach a node
            if cmd_recv != PCP_DETATCH_NDOE.lower():
                err_msg = buf.split('\x00')
                raise PCPResError("{}({})"\
                                  .format(err_msg[2][1:], err_msg[3][1:]))
            if PCP_CMD_COMPLETE in buf:
                self.data = buf.split('\x00')
            
        elif cmd == PCP_ATTACH_NODE:    #ask PCP server to attach a node
            if cmd_recv != PCP_ATTACH_NODE.lower():
                err_msg = buf.split('\x00')
                raise PCPResError("{}({})"\
                                  .format(err_msg[2][1:], err_msg[3][1:]))
            if PCP_CMD_COMPLETE in buf:
                self.data = buf.split('\x00')
            
        elif cmd == PCP_POOL_STATUS:    #get pool_status from PCP server
            if cmd_recv != PCP_POOL_STATUS.lower():
                err_msg = buf.split('\x00')
                raise PCPResError("{}({})"\
                                  .format(err_msg[2][1:], err_msg[3][1:]))
            if "ArraySize" in buf:
                self.response(cmd)
            elif not PCP_CMD_COMPLETE in buf:
                self.data.append(buf.split('\x00'))
                self.response(cmd)
                
        elif cmd == PCP_WATCHDOG_INFO:  #get watchdog_info from PCP server
            if cmd_recv != PCP_WATCHDOG_INFO.lower():
                err_msg = buf.split('\x00')
                raise PCPResError("{}({})"\
                                  .format(err_msg[2][1:], err_msg[3][1:]))
            if PCP_CMD_COMPLETE in buf:
                self.data = buf.split('\x00')
                
        elif cmd == PCP_SYNC_NODE:      #synchronize node database with remote server
            if cmd_recv != PCP_SYNC_NODE.lower():
                err_msg = buf.split('\x00')
                raise PCPResError("{}({})"\
                                  .format(err_msg[2][1:], err_msg[3][1:]))
            if PCP_CMD_PROC in buf:
                self.response(cmd)
            elif PCP_CMD_ERR in buf:
                print repr(buf)
                msg = buf.split('\x00')[1].strip()
                msg = msg.split(': ')[1]
                self.data.append(msg)
                self.response(cmd)
            elif PCP_CMD_COMPLETE in buf:
                self.data = True
            elif PCP_CMD_FAILED in buf:
                raise PCPSyncError(self.data[0])
                
    def normalization(self, cmd):
        ret = None
        if cmd == PCP_MD5_SALT or cmd == PCP_MD5_AUTH:
            ret = None
        elif cmd == PCP_NODE_INFO:
            ret = {}
            ret["host"] = self.data[1]
            ret["port"] = self.data[2]
            ret["status"] = BACKEND_STATUS[int(self.data[3])]
            ret["weight"] = float(self.data[4]) - 1073741823.0
            ret["role"] = BACKEND_ROLE[int(self.data[5])]
        elif cmd == PCP_NODE_COUNT:
            ret = int(self.data[1])
        elif cmd == PCP_DETATCH_NDOE:
            ret = self.data[0] == PCP_CMD_COMPLETE
        elif cmd == PCP_ATTACH_NODE:
            ret = self.data[0] == PCP_CMD_COMPLETE
        elif cmd == PCP_POOL_STATUS:
            ret = {}
            for d in self.data:
                #config = {"name": d[1], "value": d[2], "desc": d[3]}
                #ret .append(config)
                try:
                    value = int(d[2])
                    ret[d[1]] = value
                except ValueError:
                    ret[d[1]] = d[2]
        elif cmd == PCP_WATCHDOG_INFO:
            ret = yaml.safe_load(self.data[1])
        elif cmd ==PCP_SYNC_NODE:
            ret = self.data
        else:
            ret = None
                
        return ret
    
    def close(self):
        self.fd.close()

def pcp_node_info(ip, port, user, pwd, sn):
    try:
        p = pcp(ip, port, user, pwd)
        ret = p.node_info(sn)
        p.close()
        return ret
    except:
        t, v, tb =sys.exc_info()
        raise t, v, tb
    
def pcp_node_count(ip, port, user, pwd):
    try:
        p = pcp(ip, port, user, pwd)
        ret = p.node_count()
        p.close()
        return ret
    except:
        t, v, tb = sys.exc_info()
        raise t, v, tb
    
def pcp_pool_status(ip, port, user, pwd):
    try:
        p = pcp(ip, port, user, pwd)
        ret = p.pool_status()
        p.close()
        return ret
    except:
        t, v, tb = sys.exc_info()
        raise t, v, tb
    
def pcp_watchdog_info(ip, port, user, pwd, sn=-1):
    try:
        p = pcp(ip, port, user, pwd)
        ret = p.watchdog_info(sn)
        p.close()
        return ret
    except:
        t, v, tb = sys.exc_info()
        raise t, v, tb
    
def pcp_sync_node(ip, port, user, pwd, db_host):
    try:
        p = pcp(ip, port, user, pwd)
        ret = p.sync_node(db_host)
        p.close()
        return ret
    except:
        t, v, tb = sys.exc_info()
        raise t, v, tb
        