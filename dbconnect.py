import MySQLdb

def connection():
    """
    conn = MySQLdb.connect(host="sql2.freemysqlhosting.net",
                           user="sql2230462",
                           passwd="zC2%fW8%",
                           db="sql2230462",
                           port=3306)
    """
    conn = MySQLdb.connect(host="localhost",
                           user="wkelly",
                           passwd="Darthoco1",
                           db="flaskapp",
                           port=3306)

    c = conn.cursor()
    return c, conn