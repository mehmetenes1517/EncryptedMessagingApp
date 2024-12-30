import rsa
from hashlib import md5
import sqlite3
from flask import Flask,request 

import sys



app=Flask(__name__)
app.secret_key=str(sys.argv[1])
@app.route("/APIv2024/SendMessage",methods=["POST"])
def SendMessage():
    db_connection=sqlite3.connect("messages.db")


    #CREATING PUBLIC AND PRIVATE KEY FOR RSA ENCRYPTION
    pub_key,priv_key=rsa.newkeys(256)
    #RECEIVING MESSAGE FROM USER AND ENCRYPTING IT . THEN SAVING IT TO DATABASE
    message_index=db_connection.execute("SELECT * FROM messages")
    index_m=message_index.fetchall().__len__()
    
    #CONVERTING SPECIAL WORD TO MD5 HASH
    #ENCRYPTING HEADER AND BODY WITH RESPECT TO PUBLIC KEY  
    msg_object={
        "word":md5(str(request.json["word"]).encode()).hexdigest(),
        "header":rsa.encrypt(str(request.json["header"]).encode(),pub_key).hex(),
        "body":rsa.encrypt(str(request.json["body"]).encode(),pub_key).hex()
    }
    print(rsa.encrypt(str(request.json["header"]).encode("utf-8"),pub_key).hex())
    print(rsa.encrypt(str(request.json["body"]).encode("utf-8"),pub_key).hex())
    add_message=db_connection.execute("INSERT INTO messages VALUES({},'{}','{}','{}')".format(index_m,msg_object["word"],msg_object["header"],msg_object["body"]))
    db_connection.commit()


    #SAVING PRIVATE KEY TO DATABASE
    key_index=db_connection.execute("SELECT * FROM keys")
    index_k=key_index.fetchall().__len__()
    add_key=db_connection.execute("INSERT INTO keys VALUES({},'{}','{}','{}','{}','{}');".format(index_k,priv_key.d,priv_key.e,priv_key.n,priv_key.p,priv_key.q))
    db_connection.commit()

   
    
    

    message_index.close()
    add_key.close()
    key_index.close()
    db_connection.close()




    return msg_object,200

@app.route("/APIv2024/ReceiveMessage",methods=["POST"])
def ReceiveMessage():
    
    db_connection=sqlite3.connect("messages.db")
    
    #CONVERTING WORD TO MD5 HASH
    check_obj={
        "id":request.json["id"],
        "word":md5(str(request.json["word"]).encode()).hexdigest()
    }
    #CHECKING is there any message with keyword and index
    messages=db_connection.execute("SELECT * FROM messages WHERE id={} AND word='{}'".format(check_obj["id"],check_obj["word"]))
    message_list=messages.fetchall()
    if message_list.__len__()==0:
        return "not ok",500
    
    #GETTING ALL ATTRIBUTES OF MESSAGE
    message_obj={
        "id":message_list[0][0],
        "word":request.json["word"],
        "header":message_list[0][2],
        "body":message_list[0][3]
    }

    #GETTING PRIVATE KEY FROM KEYS TABLE
    priv_key=db_connection.execute("SELECT * FROM keys WHERE id={}".format(message_obj["id"]))
    priv_key=priv_key.fetchone()
    key_obj={
        "d":int(priv_key[1]),
        "e":int(priv_key[2]),
        "n":int(priv_key[3]),
        "p":int(priv_key[4]),
        "q":int(priv_key[5])
    }

    #GETTİNG HEX BODY AND HEADER , CONVERTING THEM TO NORMAL NOTATION FROM HEXADECIMAL;  AND DECRYPTING THEM
    print(bytes.fromhex(message_obj["header"]))
    print(rsa.decrypt((bytes.fromhex(message_obj["header"])),rsa.PrivateKey(key_obj["n"],key_obj["e"],key_obj["d"],key_obj["p"],key_obj["q"])).decode("utf-8"))
    message_obj["header"]=rsa.decrypt((bytes.fromhex(message_obj["header"])),rsa.PrivateKey(key_obj["n"],key_obj["e"],key_obj["d"],key_obj["p"],key_obj["q"])).decode("utf-8")

    message_obj["body"]=rsa.decrypt(bytes.fromhex(message_obj["body"]),rsa.PrivateKey(key_obj["n"],key_obj["e"],key_obj["d"],key_obj["p"],key_obj["q"])).decode("utf-8")


    db_connection.close()
    return message_obj,200








if __name__=="__main__":
    app.run(port=int(sys.argv[2]))



