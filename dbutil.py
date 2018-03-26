import pymysql
from tornado.options import options


class Mysql():
    def __init__(self):
        conn = pymysql.connect(host=options.mysql_host,
                               port=options.mysql_port,
                               user=options.mysql_user,
                               passwd=options.mysql_passwd,
                               db=options.mysql_database,
                               charset=options.mysql_charset)
        self.cur = conn.cursor()

    def get_all(self, sql):
        self.cur.execute(sql)
        return self.cur.fetchall()

