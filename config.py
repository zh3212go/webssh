from tornado.options import define, options

config_file='webssh.conf'

def load_conf():
    define_server_conf()
    define_db_conf()
    options.parse_config_file(config_file, final=True)

def define_server_conf():
    define('address', default='127.0.0.1', help='listen address')
    define('port', default=9999, help='listen port', type=int)
    define('debug', default=False, help='debug mode', type=bool)

def define_db_conf():
    define('mysql_host', default='127.0.0.1', help='mysql host')
    define('mysql_port', default=3306, help='mysql port', type=int)
    define('mysql_user', default='test', help='mysql user')
    define('mysql_passwd', default='test', help='mysql password')
    define('mysql_database', default='test', help='mysql database')
    define('mysql_charset', default='utf8', help='mysql charset')

load_conf()

