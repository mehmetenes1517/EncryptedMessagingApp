import sqlite3



db_con=sqlite3.connect("messages.db")

db_con.execute("CREATE TABLE 'keys' ('id'	INTEGER,'d'	TEXT,'e'	TEXT,'n'	TEXT,'p'	TEXT,'q'	TEXT);")
db_con.execute("CREATE TABLE 'messages' ('id'	INTEGER,'word'	TEXT,'header'	TEXT,'body'	TEXT);")
db_con.commit()