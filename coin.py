# user1 Ribeiro Helou Blockchain implementation
from datetime import datetime
from typing import Type
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA384
from tabulate import tabulate
import json



transaction_queue = []


#define generic class to simulate wallet.
class User:
    def __init__(self, password):
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.public_key()
        self.password = password
#users hold all the users in the program
users = []

#create users
genesis = User('admin')
user1 = User('user1123')
user2 = User('user2123')
user3 = User('user3123')
user4 = User('user4123')

#users append
users.append(genesis)
users.append(user1)
users.append(user2)
users.append(user3)
users.append(user4)


#create table to display how much money each public key Has. Can't identify the owner. If it was a real application, it would append not found public keys in their first transaction
table_money = [
    [
        'PK',
        'Amount USC'
    ],
    [
        genesis.public_key.exportKey(),
        5000
    ],
    [
        user1.public_key.exportKey(),
        0
    ],
    [
        user2.public_key.exportKey(),
        0
    ],
    [
        user3.public_key.exportKey(),
        0
    ],
    [
        user4.public_key.exportKey(),
        0
    ],
]






# not necessary anymore
validators_in_network = ['101','1024','1027','1251']


#define the block info. THe block info is mainly made by an index, a hash to identify it, a reference to the previous hash, a data, validators and a timestamp
class Block:
    def __init__(self,index, hash, previous_hash, data, signature):
        self.index = index
        self.hash = hash
        self.previous_hash = previous_hash
        self.data = data
        self.timestamp = datetime.now()
        self.validator_public_key = 'none'
        self.signature = signature

block0 = Block(0, 0, 0, 0, 0)
block_chain=[block0]


class Data:
    def __init__(self, sender, receiver, amount, fee):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.fee = fee
     

def newBlock(index, hash, previous_hash, data, validator):
    block = Block(index, hash, previous_hash, data, validator)
    return block


def getChain():

    print("HASH\t SENDER\t RECEIVER\t AMOUNT\n")
    for i in block_chain:
        if i.index != 0:
            print(i.hash.hexdigest(),i.data.sender, i.data.receiver, i.data.amount,'\n')
    return block_chain



def validate(hashed_message , signature, public_key):
    #for i in len(validators_address):
    #verify signature
    try:
        verifier  = pkcs1_15.new(public_key)
        verifier.verify(hashed_message, signature)
        print('Verified, \n')
        return True
    except(ValueError, TypeError):
        print("signature not valid. Abort\n")
        return False



def transaction(sender, receiver, amount):
    is_trasfered = False
    sender_money = 0
    receiver_money=0
    #finds sender and receiver current currency
    for i in range(len(table_money)):
        if table_money[i][0] == sender.exportKey():
            sender_money = table_money[i][1]
        if table_money[i][0] == receiver.exportKey():
            receiver_money = table_money[i][1]
    
    #operates
    if sender_money >= float(amount):
        sender_money  = sender_money-float(amount)
        receiver_money = receiver_money+float(amount)
        is_trasfered = True

    
    #update table
    for i in range(len(table_money)):
        if table_money[i][0] == sender.exportKey():
            table_money[i][1] = sender_money
        if table_money[i][0] == receiver.exportKey():
            table_money[i][1] = receiver_money
    
    return is_trasfered
    



def new_transaction(user_loged):
    receiver_password = input("Please, enter the receiver password address\n")
    amount = input("please, enter the amount you desire to transfer\n")
    fee = float(amount)*0.005
    print("your transaction is being validated, please wait\n")
    
    for i in users:
        if(i.password == receiver_password):
            receiver = i.public_key

    user = user_loged    
    sender  = user.public_key
    data = Data(sender, receiver, amount, float(fee))
    message = (str(data.amount)+str(data.fee)+str(data.receiver)+str(data.sender)+str(datetime.now())).encode("utf8")
    
    #signing message
    hashed_message = SHA384.new(message)
    signer = pkcs1_15.new(user.private_key)
    print(signer.can_sign())
    signature = signer.sign(hashed_message)
 
    new_block  = newBlock(len(block_chain), hashed_message, block_chain[len(block_chain)-1].hash, data, signature)
    transaction_queue.append(new_block)
    #queue blocks awaiting for a validator to insert it over the blockchain



def validator():
    validator_public_key =''
    block = transaction_queue.pop()
    user_pass = input("Input your password to star validating\n")
    for i in users:
        if i.password == user_pass:
            validator_public_key = i.public_key
        else:
            break
    if validate(block.hash, block.signature, block.data.sender):
        if transaction(block.data.sender, block.data.receiver, block.data.amount):
            block.validator_public_key = validator_public_key
            block_chain.append(block)
            print("transaction validated\n")
        else:
            print("Fraud Detected\n")
    else:
        print("doesnt have the ammount to transfer")
   



while 1==1:

    routine = input("Type 1 for new transaction and 2 to verify blockchain. 3 if you want to see money table. 4 if you want to validate a block and receive a reward\n")


    if(routine == '1'):
        user_password = input("Please, enter userpassword to start transaction\n")
        
        for i in users:
            if(i.password == user_password):
                new_transaction(i)
                routine == '4'
                break
        print("incorrect password")
        
    
    if(routine == '2'):
        getChain()
    
    if(routine == '3'):
        print(tabulate(table_money))

    if(routine == '4'):
        validator()
        
