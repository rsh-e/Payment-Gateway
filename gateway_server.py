import hashlib
import socket
import time

# This is the gateway class
class GatewayServer:
    # These are the attributes used in the program, most of them are breaking apart the message
    def __init__(self, details) -> None:
        self.message_type = details[0] #
        self.check_data = details[1:61] #
        self.hashed_data = details[61:93] # 
        self.issuing_bank = details[2:7] #
        self.card_no = details[1:17]#
        self.cvv = details[17:20]#
        self.expiry = details[20:24]#
        self.date = details[24:30]#
        self.time = details[30:36]#
        self.card_order_no = details[36:42]#
        self.funds = details[42:46]#
        self.merchant_bank = details[46:51]#
        self.merchantID = details[51:61]#
        self.merchant_address = None # Add this later so we know where to direct the message to
        self.funds_held = False
        self.no_blacklist = False
        self.true_OTP = False
    
    # The following get the type of message recieved and the IDs of the client and merchant banks along with the details to be checked, the hash and the card no
    def getMessageType(self):
        return self.message_type
    
    def getIssuingBank(self):
        return self.issuing_bank
    
    def getCardNo(self):
        return self.card_no
    
    def getMerchantBank(self):
        return self.merchant_bank
    
    def getCheckDetails(self):
        return self.check_data
    
    def getHashedDetails(self):
        return self.hashed_data

    # This checks whether the card number is a valid one
    def checkCard(self, card):
        card = str(card)
        checksum = int(card[-1])
        payload = card[0:15]
        sum = 0

        for i in range(len(payload) - 1, 0, -2):
            doubled = int(payload[i]) * 2
            if len(str(doubled)) == 2:
                doubled_sum = int(str(doubled)[0]) + int(str(doubled)[1])
                sum = sum + doubled_sum
            else:
                sum = sum + doubled

        doubled = int(payload[0]) * 2
        if len(str(doubled)) == 2:
            doubled_sum = int(str(doubled)[0]) + int(str(doubled)[1])
            sum = sum + doubled_sum
        else:
            sum = sum + doubled

        for i in range(len(payload) - 2, 0, -2):
            sum = sum + int(payload[i])

        if sum % 10 == 0:
            recieved_check = 0
        else:
            recieved_check = 10 - (sum % 10)

        if recieved_check == checksum:
            return True
        else:
            return False

    # This checkes whether the details recieved match the hash
    def checkHash(self, check, hashed):
        # check the limit for the part of data we'll use
        check_hash = hashlib.md5(check.encode()).hexdigest()
        if check_hash == hashed:
            return True
        else:
            return False

    # This is an SQL query which adds the data recieved in the processor_record database
    def addEntry(card_no, date, time, merchant_ID, issuing_ID, funds, hashed_details):
        # recheck the below
        cursor.execute(
            """
            INSERT INTO Processor_Record (CardNo, Date, Time, MerchantBank, MerchantID, IssuingBankID, Funds, Hash),
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s),
            """(
                self.card_order_no,
                self.date,
                self.time,
                self.merchant_bank,
                self.merchantID,
                self.issuing_bank,
                self.funds,
                self.hashed_details,
            )
        )
    
    # This checks whether the banks mentioned in the message exist
    def checkBanks(self, bank1, bank2):
        # Use this when you create the databases
        '''
        cursor.execute(
            """
            SELECT BankID
            FROM Banks_List
            WHERE BankID = "BANK1"
            """
        )

        for i in cursor:
            pass
        # basically check whether anything is there or not
        
        cursor.execute(
            """
            SELECT BankID
            FROM Banks_List
            WHERE BankID = "BANK2"
            """
        )

        for i in cursor:
            pass
        '''
        banks = [53981, 55440]
        bank_a = int(bank1)
        bank_b = int(bank2)
        if (bank_a in banks) and (bank_b in banks):
            return True 
        else:
            return False
            # If both the banks exist in the database
        # basically check whether anything is there or not

    def encryptBankA(self, msg):
        cipher = ""
        e = 604710583306877
        N = 403246574997455042743991405701

        for c in msg:
            m = ord(c)
            cipher += str(pow(m, e, N)) + " "

        return cipher


    def encryptBankB(self, msg):
        cipher = ""
        e = 751530808771457
        N = 799152948108675269481101450069

        for c in msg:
            m = ord(c)
            cipher += str(pow(m, e, N)) + " "

        return cipher

    '''
    # This encrypts messages according to the bank code 
    def encryptMessage(message, bank_code):
        if bank_code == 53981:
            encrypted_message = self.encryptBankA(message)
        elif bank_code == 55440:
            encrypted_message = self.encryptBankB(message)
        else:
            return False
        return encrypted_message
    '''

    def decryptMessage(cipher):
        msg = ""
        d = 420963772587006044991205558799
        N = 747992601946009934875593562007

        parts = cipher.split()
        for part in parts:
            if part:
                c = int(part)
                msg += chr(pow(c, d, N))

        return msg

    # This sends and authorisation request to the issuing bank
    def sendAuthRequest(self, message, issuing_id):
        #encrypted_message = encryptMessage(message, merchant_id)
        '''
        cursor.execute(
            """
            SELECT SocketID
            FROM Banks_Table
            WHERE BankID = ISSUING_ID
            """
        )
        for i in cursor:
            socket = i
        
        cursor.execute(
            """
            SELECT IP
            FROM Banks_Table
            WHERE BankID = ISSUING_ID
            """
        )
        for i in cursor:
            ip = i
        '''
        

        #sendMessage(message, issuing_id, socket) should be used but for testing i'm using the one below
        #sendMessage(message, socket, ip)
        if int(issuing_id) == 55440:
            print("original (to be enc):",message)
            encrypted_message = self.encryptBankB(message)
            print("encrypted:",encrypted_message)
            self.sendMessage(encrypted_message, 8086, "192.168.0.100")
        elif int(issuing_id) == 53981:
            encrypted_message = self.encryptBankA(message)
            self.sendMessage(encrypted_message, 8082, "192.168.0.100")

    # This sends a settlement request to the issuing bank
    def sendSettleRequest(self, message, issuing_id):
        '''
        cursor.execute(
            """
            SELECT SocketID
            FROM Banks_Table
            WHERE BankID = ISSUING_ID
            """
        )
        for i in cursor:
            socket = i
        
        cursor.execute(
            """
            SELECT IP
            FROM Banks_Table
            WHERE BankID = ISSUING_ID
            """
        )
        for i in cursor:
            ip = i
        '''
        if int(issuing_id) == 55440:
            print("original (to be enc):",message)
            encrypted_message = self.encryptBankB(message)
            print("encrypted:",encrypted_message)
            self.sendMessage(encrypted_message, 8086, "192.168.0.100")
        elif int(issuing_id) == 53981:
            encrypted_message = self.encryptBankA(message)
            self.sendMessage(encrypted_message, 8082, "192.168.0.100")

        #sendMessage(message, issuing_id, socket) should be used but for testing i'm using the one below
        #sendMessage(message, socket, ip)
    
    def sendHoldConfirmation(self, message, merchant_id):
        #encrypted_message = encryptMessage(message, merchant_id)
        '''
        cursor.execute(
            """
            SELECT SocketID
            FROM Banks_Table
            WHERE BankID = ISSUING_ID
            """
        )
        for i in cursor:
            socket = i
        
        cursor.execute(
            """
            SELECT IP
            FROM Banks_Table
            WHERE BankID = ISSUING_ID
            """
        )
        for i in cursor:
            ip = i
        '''
        if int(merchant_id) == 55440:
            print("original (to be enc):",message)
            encrypted_message = self.encryptBankB(message)
            print("encrypted:",encrypted_message)
            self.sendMessage(encrypted_message, 8086, "192.168.0.100")
        elif int(merchant_id) == 53981:
            print("original (to be enc):",message)
            encrypted_message = self.encryptBankA(message)
            print("encrypted:",encrypted_message)
            self.sendMessage(encrypted_message, 8082, "192.168.0.100")


    def sendApproval(self, message, merchant_id):
        if int(merchant_id) == 55440:
            print("original (to be enc):",message)
            encrypted_message = self.encryptBankB(message)
            print("encrypted:",encrypted_message)
            data = encrypted_message.encode()
            bankb_connection_socket.send(data)
            #self.sendMessage(encrypted_message, 8086, "192.168.0.100")
        elif int(merchant_id) == 53981:
            print("original (to be enc):",message)
            encrypted_message = self.encryptBankA(message)
            print("encrypted:",encrypted_message)
            data = encrypted_message.encode()
            banka_connection_socket.send(data)
            #self.sendMessage(encrypted_message, 8082, "192.168.0.100")

    '''
    # This sends an approval message to the merchant bank
    def sendApproval(self, message, merchant_id):
        encrypted_message = self.encryptMessage(message)
        data = encrypted_message.encode()
        if int(merchant_id) == 53981:
            print("sending to a")
            banka_connection_socket.send(data)
        elif int(merchant_id) == 55440:
            bankb_connection_socket.send(data)
    '''

    # This sends a disapproval message to the merchant bank
    def sendDisapproval(self, message, merchant_id):
        encrypted_message = self.encryptMessage(merchant_id)
        data = encrypted_message.encode()
        if int(merchant_id) == 53981:
            banka_connection_socket.send(data)
        elif int(merchant_id) == 55440:
            bankb_connection_socket.send(data)

    # This sends a message to any bank needed
    def sendMessage(self, message, socket_no, ip):
        # adjust this to include multiple banks
        data = message.encode()
        if socket_no == 8086:
            bankb_connection_socket.send(data)
        elif socket_no == 8082:
            banka_connection_socket.send(data)
        print(data)


if __name__ == "__main__":
    print("This is the gateway server")
    # Getting data from the mercahnt bank and sending it to the issuing bank

    # this connects the server to Bank B
    bankb_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bankb_socket.bind(("192.168.0.100", 8086))
    bankb_socket.listen()
    print("Waiting for socket...")
    bankb_connection_socket, address = bankb_socket.accept()
    print("Client connected")

    # this connects the server to Bank A
    banka_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    banka_socket.bind(("192.168.0.100", 8082))
    banka_socket.listen()
    print("Waiting for socket...")
    banka_connection_socket, address = banka_socket.accept()
    print("Client connected")

    # The program waits for bank A to send a message
    message= banka_connection_socket.recv(30000).decode()

    #message_b = bankb_socket.recv(1024).decode()
    #if len(message_a) > len(message_b):
    #    message = message_b
    #else:
    #    message = message_a
    print(message)
    # decrypt the data
    print("Recieved message")

    # The message recieved is given as a parameter to the recursive function below
    def main(message):
        # This gets all the nessacary variables for the function
        decrypted_message = GatewayServer.decryptMessage(message) # Find me
        print("decrypted:",decrypted_message)
        print("length:", len(message))
        gateway = GatewayServer(decrypted_message)
        message_type = gateway.getMessageType()
        print(message_type)
        issuing_bank = gateway.getIssuingBank()
        merchant_bank = gateway.getMerchantBank()
        check_details = gateway.getCheckDetails()
        hashed_details = gateway.getHashedDetails()
        print(merchant_bank)
        print(issuing_bank)
        # The hash and details are checked
        true_hash = gateway.checkHash(check_details, hashed_details)
        if true_hash == True:
            # If they're true then the card number is checked and the banks are checked
            print("Hash checked")
            card_no = gateway.getCardNo()
            valid_number = gateway.checkCard(card_no)
            print("Card number is", valid_number)
            valid_banks = gateway.checkBanks(issuing_bank, merchant_bank) # Assume the banks are in the database
            print("Banks are", valid_banks)
            # Once both are true, the message is classified based on it's type and are then sent to the required location
            if valid_number == True and valid_banks == True:
                print("Card and Banks are valid")
                # This is for authorisation
                if message_type == '9':
                    print("Recieved authorisation maessage")
                    #gateway.addEntry() # Assume the entry was added
                    print("Assume Entry Added")
                    gateway.sendAuthRequest(decrypted_message, issuing_bank)
                    # USE ERROR HANDLING AND CHECK IF A CONNECTION EXIST. DO THE SAME FOR MESSAGE_TYPE = 8
                    print("Waiting for response from Bank B... ")
                #try:
                    message = bankb_connection_socket.recv(30000).decode()
                    print("Recieved response from gateway:", message)
                    main(message)
                #except:
                    print("No response recieved")
                # This is settlement
                elif message_type == '8':
                    #gateway.addEntry() # Assume the entry was added
                    print("Assume Entry Added for settlement")
                    print("Decrypted message:",decrypted_message)
                    print("Issuing bank:", issuing_bank, "type:", type(issuing_bank))
                    gateway.sendSettleRequest(decrypted_message, issuing_bank)
                    print("Waiting for response from Bank B... ")
                    #try:
                    message = bankb_connection_socket.recv(30000).decode()
                    print("Recieved response from Bank B: ", message)
                    print("length:", len(message))
                    main(message)
                    #except:
                    #    print("No response recieved")
                # This is approval
                elif message_type == '7':
                    print("This is a hold confirmation")
                    print("Assume entry added")
                    gateway.sendHoldConfirmation(decrypted_message, merchant_bank)
                    print("Waiting for response from Bank A... ")
                    try:
                        message = banka_connection_socket.recv(30000).decode()
                        print("Recieved response from Bank A: ", message)
                        main(message)
                    except:
                        print("No response recieved")
                elif message_type == '1':
                    print("Recieved an approval message")
                    print("merchant:", merchant_bank)
                    gateway.sendApproval(decrypted_message, merchant_bank)
                    print("Sent approval")
                    ## How to always keep listening for approval and disapproval
                # This is dissaproval
                else:
                    print("Recieved disapproval message")
                    gateway.sendDisapproval(decrypted_message, merchant_bank)
                    print("Sent dissaproval message")
            else:
                gateway.sendDisapproval(decrypted_message, merchant_bank)
        else:
            gateway.sendDisapproval(decrypted_message, merchant_bank)
    
    main(message)



'''
decrypted_message = gateway.decryptData(code)
check_hash = gateway.checkHash(decyrpted_message)
if check_hash == True:
    (card, issuing_id, merchant_id, message_type, date, time, funds) = gateway.updateAttributes(decrypted_message)
    checkValidCard = gateway.authenticate(message, card_no, date, time, merchant_id, issuing_id, fund)
    if checkValidCard == True:
        encrypted_message = gateway.encryptMessage()
        message_sent = gateway.sendMessage(decrypted_message, merchant_id, issuing_id, message_type)

# Sending approval and disapproval messages
message_sent = gateway.sendMessage(decrypted_message, merchant_id, issuing_id, message_type)

# Recieving approval and disapproval message
encrypted_message = getCode()
gateway = GetwayServer(code)
decrypted_message = gateway.decryptData(code)
check_hash = gateway.checkHash(decyrpted_message)
if check_hash == True:
    message_sent = gateway.sendMessage(decrypted_message, merchant_id, issuing_id, message_type)
'''
