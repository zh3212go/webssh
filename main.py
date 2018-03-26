import logging
import os.path
import uuid

import tornado.web
from tornado.ioloop import IOLoop
from tornado.options import options

from config import config_file
from handlers import IndexHandler, LoginHandler, LogoutHandler, WsockHandler


def main():
    settings = {
        'template_path': os.path.join(os.path.dirname(__file__), 'templates'),
        'static_path': os.path.join(os.path.dirname(__file__), 'static'),
        'cookie_secret': uuid.uuid1().hex,
        'xsrf_cookies': True,
        "login_url": '/login',
    }

    handlers = [
        (r'/',   IndexHandler),
        (r'/login', LoginHandler),
        (r'/logout', LogoutHandler),
        (r'/ws', WsockHandler)
    ]
    logging.info('Load config file from : {}'.format(config_file))
    settings.update(debug=options.debug)
    app = tornado.web.Application(handlers, **settings)
    app.listen(options.port, options.address)
    logging.info('Listening on {}:{}'.format(options.address, options.port))
    IOLoop.current().start()


if __name__ == '__main__':
    main()
