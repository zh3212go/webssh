import io
import socket
import logging
import traceback
import weakref
import paramiko
from tornado.web import RequestHandler, authenticated
from tornado.websocket import WebSocketHandler
from tornado.ioloop import IOLoop
from worker import Worker
from dbutil import Mysql

workers = {}
DELAY = 3


def recycle(worker):
    if worker.handler:
        return
    logging.debug('Recycling worker {}'.format(worker.id))
    workers.pop(worker.id, None)
    worker.close()


class MixinHandler(object):

    def __init__(self, *args, **kwargs):
        super(MixinHandler, self).__init__(*args, **kwargs)

    def get_client_addr(self):
        ip = self.request.headers.get('X-Real-Ip')
        port = self.request.headers.get('X-Real-Port')
        addr = None

        if ip and port:
            addr = (ip, int(port))
        elif ip or port:
            logging.warn('Wrong nginx configuration.')

        return addr


class BaseHandler(RequestHandler):
    def get_current_user(self):
        return self.get_secure_cookie("username_cookie")


class IndexHandler(MixinHandler, BaseHandler):
    def get_privatekey(self):
        try:
            data = self.request.files.get('privatekey')[0]['body']
        except TypeError:
            return
        return data.decode('utf-8')

    def get_specific_pkey(self, pkeycls, privatekey, password):
        logging.info('Trying {}'.format(pkeycls.__name__))
        try:
            pkey = pkeycls.from_private_key(io.StringIO(privatekey),
                                            password=password)
        except paramiko.PasswordRequiredException:
            raise ValueError('Need password to decrypt the private key.')
        except paramiko.SSHException:
            pass
        else:
            return pkey

    def get_pkey(self, privatekey, password):
        password = password.encode('utf-8') if password else None

        pkey = self.get_specific_pkey(paramiko.RSAKey, privatekey, password)\
            or self.get_specific_pkey(paramiko.DSSKey, privatekey, password)\
            or self.get_specific_pkey(paramiko.ECDSAKey, privatekey, password)\
            or self.get_specific_pkey(paramiko.Ed25519Key, privatekey,
                                      password)
        if not pkey:
            raise ValueError('Not a valid private key file or '
                             'wrong password for decrypting the private key.')
        return pkey

    def get_port(self):
        value = self.get_value('port')
        try:
            port = int(value)
        except ValueError:
            port = 0

        if 0 < port < 65536:
            return port

        raise ValueError('Invalid port {}'.format(value))

    def get_value(self, name):
        value = self.get_argument(name)
        if not value:
            raise ValueError('Empty {}'.format(name))
        return value

    def get_args(self):
        hostname = self.get_value('hostname')
        port = self.get_port()
        username = self.get_value('username')
        password = self.get_argument('password')
        privatekey = self.get_privatekey()
        pkey = self.get_pkey(privatekey, password) if privatekey else None
        args = (hostname, port, username, password, pkey)
        logging.debug(args)
        return args

    def get_client_addr(self):
        return super(IndexHandler, self).get_client_addr() or self.request.\
                connection.stream.socket.getpeername()

    def ssh_connect(self):
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        args = self.get_args()
        dst_addr = (args[0], args[1])
        logging.info('Connecting to {}:{}'.format(*dst_addr))
        try:
            ssh.connect(*args, timeout=6)
        except socket.error:
            raise ValueError('Unable to connect to {}:{}'.format(*dst_addr))
        except paramiko.BadAuthenticationType:
            raise ValueError('Authentication failed.')
        chan = ssh.invoke_shell(term='xterm')
        chan.setblocking(0)
        worker = Worker(ssh, chan, dst_addr)
        IOLoop.current().call_later(DELAY, recycle, worker)
        return worker

    @authenticated
    def get(self):
        self.render('index.html', user=self.current_user)

    def post(self):
        worker_id = None
        status = None

        try:
            worker = self.ssh_connect()
        except Exception as e:
            logging.error(traceback.format_exc())
            status = str(e)
        else:
            worker.src_addr = self.get_client_addr()
            worker_id = worker.id
            workers[worker_id] = worker

        self.write(dict(id=worker_id, status=status))


class LoginHandler(MixinHandler, BaseHandler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.get_argument("username")
        password = self.get_argument("password")
        db = Mysql()
        user_infos = db.get_all("select * from td_user_info where username = '" + username + "'")
        if user_infos:
            db_pwd = user_infos[0][2]
            if db_pwd == password:
                self.set_secure_cookie("username_cookie", self.get_argument("username"))
                self.write("1")
            else:
                self.write('-2')
        else:
            self.write('-1')


class LogoutHandler(BaseHandler):
    def get(self):
        if self.get_argument("logout", True):
            self.clear_cookie("username_cookie")
            self.redirect("/")

class WsockHandler(MixinHandler, WebSocketHandler):

    def __init__(self, *args, **kwargs):
        self.loop = IOLoop.current()
        self.worker_ref = None
        super(WsockHandler, self).__init__(*args, **kwargs)

    def get_client_addr(self):
        return super(WsockHandler, self).get_client_addr() or self.stream.\
                socket.getpeername()

    def open(self):
        self.src_addr = self.get_client_addr()
        logging.info('Connected from {}:{}'.format(*self.src_addr))
        worker = workers.get(self.get_argument('id'), None)
        if worker and worker.src_addr[0] == self.src_addr[0]:
            workers.pop(worker.id)
            self.set_nodelay(True)
            worker.set_handler(self)
            self.worker_ref = weakref.ref(worker)
            self.loop.add_handler(worker.fd, worker, IOLoop.READ)
        else:
            self.close()

    def on_message(self, message):
        logging.debug('"{}" from {}:{}'.format(message, *self.src_addr))
        worker = self.worker_ref()
        worker.data_to_dst.append(message)
        worker.on_write()

    def on_close(self):
        logging.info('Disconnected from {}:{}'.format(*self.src_addr))
        worker = self.worker_ref() if self.worker_ref else None
        if worker:
            worker.close()
