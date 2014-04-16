import ecdsa
import ecdsa.der
import ecdsa.util
import hashlib
import os
import re
import struct
import requests
import json
import math
import pickle
from bitcoin import *

b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


subkey_complexity=32

standard_fee=0.00005
minincrement=0.01  #min BTC per address (smallest addresses)
increment_base=2

def base58encode(n):
    result = ''
    while n > 0:
        result = b58[n%58] + result
        n /= 58
    return result

def base256decode(s):
    result = 0
    for c in s:
        result = result * 256 + ord(c)
    return result

def countLeadingChars(s, ch):
    count = 0
    for c in s:
        if c == ch:
            count += 1
        else:
            break
    return count

# https://en.bitcoin.it/wiki/Base58Check_encoding
def base58CheckEncode(version, payload):
    s = chr(version) + payload
    checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[0:4]
    result = s + checksum
    leadingZeros = countLeadingChars(result, '\0')
    return '1' * leadingZeros + base58encode(base256decode(result))

def privateKeyToWif(key_hex):    
    return base58CheckEncode(0x80, key_hex.decode('hex'))
    
def privateKeyToPublicKey(s):
    sk = ecdsa.SigningKey.from_string(s.decode('hex'), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return ('\04' + sk.verifying_key.to_string()).encode('hex')
    
def pubKeyToAddr(s):
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(s.decode('hex')).digest())
    return base58CheckEncode(0, ripemd160.digest())

def keyToAddr(s):
    return pubKeyToAddr(privateKeyToPublicKey(s))

# Generate a random private key
def generate_subkeys():
    a=[]
    a.append(os.urandom(subkey_complexity).encode('hex')) #subkey1
    a.append(os.urandom(subkey_complexity).encode('hex')) #subkey2
    return a

def generate_privatekey(subkey1,subkey2):
    keysum=subkey1+subkey2
    secret_exponent=hashlib.sha256(keysum).hexdigest()
    
    privkey=privateKeyToWif(secret_exponent)
    return privkey

def generate_publicaddress(subkey1,subkey2):
    keysum=subkey1+subkey2
    secret_exponent=hashlib.sha256(keysum).hexdigest()
    address=keyToAddr(secret_exponent)
    return address

def check_address(public_address):
    p='https://blockchain.info/q/addressbalance/'
    p=p+public_address
    h=requests.get(p)
    if h.status_code==200:
        return h.content
    else:
        return -1

def check_address_subkeys(subkey1,subkey2):
    global h
    address=generate_publicaddress(subkey1,subkey2)
    
    return check_address(address)

def generate_receiving_address(destination_address):
    global g,r
    a='https://blockchain.info/api/receive?method=create&address='
    a=a+destination_address
    r=requests.get(a)
    receiving_address=''
    if r.status_code==200:
        g=json.loads(str(r.content))
        receiving_address=g['input_address']
        return str(receiving_address)
    else:
        return "ERROR"
        
        
    #'$receiving_address&callback=$callback_url

class subkeypair:
    subkey1=''  #user
    subkey2=''  #swiftcoin
    referenceid=''
    publicaddress=''
    balance=0
    myuser=''

    def __init__(self):
        self.subkey1=os.urandom(subkey_complexity).encode('hex')
        self.subkey2=os.urandom(subkey_complexity).encode('hex')
        self.referenceid=os.urandom(subkey_complexity).encode('hex')
        self.publicaddress=generate_publicaddress(self.subkey1,self.subkey2)
        #return self.publicaddress
        
    def private_key(self):
        return generate_privatekey(self.subkey1,self.subkey2)

def roundfloat(s, decimals):
    n=s
    n=n*math.pow(10,decimals)
    n=int(n)
    n=float(n/math.pow(10,decimals))
    return n

def split_logarithmically(amt,base, min):
    global r,s
    s=amt
    h=s%min
    s=s-h
    r=int(math.log(amt/min,base))
    a=[0]*(r+1)
    g=0
    v=0
    while s>0.000000001:
        #print s
        g=0
        while g<r+1 and s+min/100>=math.pow(base,g)*min:
            a[g]=a[g]+1
            v=v+1
            s=s-math.pow(base,g)*min
            g=g+1
    #print v
    return a

def split_n(amt,base,min):
    r=int(math.log(amt/min,base))
    a=[0]*(r+1)
    g=0
    v=0
    s=amt
    while s>0.000000001:
        g=0
        #print s
        while g<r+1 and s+min/100>=float(math.pow(base,g)*min):
            a[g]=a[g]+1
            v=v+1
            s=s-float(int(math.pow(base,g)))*min
            g=g+1
    return v

def assemble_logarithmically(amt,base,min, storedset):
    s=amt
    a=[0]*len(storedset)
    c=[]
    for x in storedset:
        c.append(x)

    g=len(storedset)-1
    while g>-1:
        if c[g]>0 and s>=math.pow(base,g):
            n=int(s/math.pow(base,g))
            if n>c[g]:
                n=c[g]
            c[g]=c[g]-n
            a[g]=a[g]+n
            print s
            s=s-math.pow(base,g)*n
        g=g-1

    
    return a
    
a=split_logarithmically(100,2,1)

def convert_to_base(x,base):
    a=''
    n=30
    found=False
    while n>-1:
        r=math.pow(base,n)
        
        #print r
        b=int(x/r)
        if b>0:
            found=True
        if found==True:
            a=a+str(b)
        x=x-b*r
        

        n=n-1

    return a

class user:
    name=''
    totalbalance=0
    inputaddress=''
    inputsecretexponent='' #passphrase not yet hashed
    #outputaddress==''
    subkeypairs=[]
    

    def __init__(self):
        self.inputsecretexponent=os.urandom(subkey_complexity).encode('hex')
        self.inputaddress=generate_publicaddress(self.inputsecretexponent,'')

    def generate_subaddresses(self, amt):
        a=0
        n=split_n(amt,increment_base,minincrement)
        while a<n:
            #print a
            k=subkeypair()
            #UPLOAD SUBKEY2 TO OUR DATABASE AND BACK UP
            #k.subkey2=''
            self.subkeypairs.append(k)
            a=a+1

    def checkinputaddress(self):
        return check_address(self.inputaddress)

    def check_and_split(self): #splits input address BTC into new subkeypairs, subkeypairs must already exist
        newsum=float(self.checkinputaddress())/100000000
        newsum=newsum/(1+split_n(newsum,increment_base,minincrement)*standard_fee)
        if newsum>0:
            splitsums=split_logarithmically(newsum,increment_base,minincrement)
            self.totalbalance=self.totalbalance+newsum
        else:
            splitsums=[]
        a=0
        while a<len(splitsums):#for each digit in splitsums
            amt=minincrement*math.pow(increment_base,a)+standard_fee
            h=0
            while h<splitsums[a]:#repeat that many times a transaction to a separate addres
                k=0
                j=-1
                while k<len(self.subkeypairs):  #find empty spot in personal subkeypairs list
                    if self.subkeypairs[k].balance==0:
                        j=k
                        k=len(self.subkeypairs)
                        
                    k=k+1
                dest=self.subkeypairs[j].publicaddress
                
                send_transaction(self.inputaddress,amt,dest,standard_fee,hashlib.sha256(self.inputsecretexponent).hexdigest())
                self.subkeypairs[j].balance=amt

                h=h+1
                
            a=a+1

def isinside(small,big):
    a=len(small)
    b=len(big)
    f=0
    found=False
    while f<b-a:
        g=''
        for x in big[f:f+a]:
            g=g+str(x.lower())
        if g==small:
            f=b-a
            found=True
        f=f+1

    return found

def find_vanity(vanity,n):
    k=math.pow(26,n)
    a=0
    while a<k:
        print math.log(a+1,36)
        d=os.urandom(subkey_complexity).encode('hex')
        b=generate_publicaddress(d,'')
        if isinside(vanity,b):
            a=k
            print "secret exponent: "+str(d)
            print "public address: "+str(b)
        a=a+1

def send_transaction(fromaddress,amount,destination, fee, privatekey):
    try:
        global ins, outs,h, tx, tx2
        fee=int(fee*100000000)
        amount=int(amount*100000000)
        h=unspent(fromaddress)
        ins=[]
        ok=False
        outs=[]
        totalfound=0
        for x in h:
            if not ok:
                ins.append(x)
                if x['value']>=fee+amount-totalfound:
                    outs.append({'value':amount,'address':destination})
                    if x['value']>fee+amount-totalfound:
                        outs.append({'value':x['value']-amount-fee,'address':fromaddress})
                    ok=True
                    totalfound=fee+amount
                else:
                    outs.append({'value':x['value'],'address':destination})
                    totalfound=totalfound+x['value']
                
                
            
        
        tx=mktx(ins,outs)
        tx2=sign(tx,0,privatekey)
        #tx3=sign(tx2,1,privatekey)
        
        pushtx(tx2)
        print "Sending "+str(amount)+" from "+str(fromaddress)+" to "+str(destination)+" with fee= "+str(fee)+" and secret exponent= "+str(privatekey)
        
        #a='https://blockchain.info/pushtx/'
        #b=requests.get(a+tx3)
        #if b.response_code==200:
        #    print b.content
    except:
        print "failed"

def send(fromaddr, amt, destination, fee, subkey1, subkey2):
    pk=hashlib.sha256(subkey1+subkey2).hexdigest()
    send_transaction(fromaddr,amt,destination,fee,pk)


users=[]

def add_user():
    global users
    a=user()
    print a.inputaddress
    k=len(users)
    users.append(a)
    return k

def load_user_db():
    global users
    filename='users.data'
    try:
        users=pickle.load(open(filename,'rb'))
        print str(len(users))+" users loaded"
    except:
        print "failed loading"

def save():
    filename='users.data'
    pickle.dumps(users,open('users.data','wb'))

load_user_db()

