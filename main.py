import sqlite3
import rsa
import hashlib
import sqlite3

#How keys were generated
#(pubkey, privkey) = rsa.newkeys(1024, os.cpu_count())

#publicKeyPkcs1PEM = pubkey.save_pkcs1().decode('utf8')
#privateKeyPkcs1PEM = privkey.save_pkcs1().decode('utf8') 

#with open('publicKeyPkcs1PEM', 'wb+') as f:
    #pk = pubkey.save_pkcs1(format='PEM')
    #f.write(pk)

#with open('privateKeyPkcs1PEM', 'wb+') as f:
    #pk = privkey.save_pkcs1(format='PEM')
    #f.write(pk)

with open('privateKeyPkcs1PEM', mode='rb') as privatefile:
    keydata = privatefile.read()
privkey = rsa.PrivateKey.load_pkcs1(keydata)

with open('publicKeyPkcs1PEM', mode='rb') as privatefile:
    keydata = privatefile.read()
pubkey = rsa.PublicKey.load_pkcs1(keydata)

global passhash 
passhash = hashlib.sha256()
global pass_checker 
pass_checker = hashlib.sha256()
con = sqlite3.connect('passwords.db')
global pass_temp

global user_pass 

cursor = con.cursor()


command1 = """CREATE TABLE IF NOT EXISTS
stores(name TEXT,passEncrypt BLOB)"""

cursor.execute(command1)

command2 = """CREATE TABLE IF NOT EXISTS
    hash(hashedPass BLOB)"""

cursor.execute(command2)

def checkIfEmpty():
     cursor.execute("""SELECT * FROM hash""")
     full = cursor.fetchall()
     return(full)


def createMasterPass():

    print("Please create a master password")

    pass_entr = input()

    pass_entr = pass_entr.encode('utf-8')

    passhash.update(pass_entr)

    passTuple = (passhash.hexdigest(),)

    cursor.execute("INSERT INTO hash VALUES(?)", (passTuple))
    con.commit()



def passVer(passD):
    passW = hashlib.sha256()
    passW.update(passD)
    return (passW.hexdigest())



def masterPassChecker():
    while True:
        print("Enter your master password")

        passnew = input()

        passnew = passnew.encode('utf-8')

        pass_checker = passVer(passnew)

        cursor.execute("""SELECT * FROM hash""")
        full = cursor.fetchall()

        importedHash = full[0][0]
 
        if(pass_checker == importedHash):
            print("Access Granted.")
            break

        else:
            print("Wrong Password, please try again.")

        



def passCreation():
    print("What application would you like to save a password for?")
    user_pass = input()

    print("Enter the password you'd like to save:")

    pass_temp = input()

    pass_temp = pass_temp.encode('utf-8')

    pass_encryptor = rsa.encrypt(pass_temp, pubkey)

    cursor = con.cursor()

    sql_insert = """INSERT INTO stores (name,passEncrypt) values(?,?);"""

    dataSet = (user_pass,pass_encryptor)
    cursor.execute(sql_insert, dataSet)
    con.commit()

 

def callPass():
    cursor = con.cursor()
    print("What account would you like to retrieve your password for?")

    getNames = "SELECT name FROM stores"

    cursor.execute(getNames)
    retNames = cursor.fetchall()

    print("List of Accounts:")
    for rows in retNames:
        for x in rows:
          print(x)

    servName = input()

    cursor.execute("""SELECT name, passEncrypt FROM stores WHERE name = ?;""",(servName,))
    full = cursor.fetchone()

    garPass = full[1]

    realPass = rsa.decrypt(garPass, privkey)
    print("The password is:")
    print(realPass.decode('utf-8'))

   

def main():
    hasChecker = checkIfEmpty()
    
    if not hasChecker:
        createMasterPass()

    masterPassChecker()

    while 1:
        option = input("Enter 0 to Enter a Password, 1 to Retrieve One, or 2 to Exit \n")

        option = int(option)

        if option == 0:
         passCreation()

        elif option == 1:
         callPass()
    
        elif option == 2:
            exit(0)





main()









