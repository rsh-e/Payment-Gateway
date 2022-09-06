import socket
import hashlib
import random
import time

# This is the Bank class. All bank functions are here.
class BankServer:
    # These are the variables that are used. Most of them are just the parts of the message stripped.
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

    # This returns the type of message (1, 0, 9, 8, 7)
    def getMessageType(self):
        return self.message_type
    
    # This returns the id of the issuing bank
    def getIssuingBank(self):
        return self.issuing_bank

    # This returns the id of the merchant bank
    def getMerchantBank(self):
        return self.merchant_bank

    # This returns the details sent (unhashed)
    def getCheckDetails(self):
        return self.check_data
    
    # This returns the hash of the details that are sent
    def getHashedDetails(self):
        return self.hashed_data

    # This returns the card number
    def get_CardNo(self):
        return self.card_no

    # This checks the whether the hashed details and details sent are the same
    def checkHash(self, check, hashed):
        check_hash = hashlib.md5(check.encode()).hexdigest()
        if check_hash == hashed:
            return True
        else:
            return False

    # This is an sql query which adds the data recieved into the Issuing ledger
    def addEntry(self):
        # recheck the below
        cursor.execute(
        '''
        INSERT INTO Issuing_Ledger (CardOrderID, Date, Time, CardNo, Funds, MerchantBankID, MerchantID, Hash),
        VALUES (%s, %s, %s, %s, %s, %s),
        '''
        (
                self.card_order_no,
                self.date,
                self.time,
                self.card_no,
                self.funds,
                self.MerchantBankID,
                self.MerchantID,
                self.hashed_data,
        )
        )

        return True

    # This encrypts the message with the gateways public key
    def encryptMessage(self, msg):
        cipher = ""
        gateway_encrypt = 666192648131279
        gateway_N = 747992601946009934875593562007

        for c in msg:
            m = ord(c)
            cipher += str(pow(m, gateway_encrypt, gateway_N)) + " "

        return cipher
        # Basically encrypts the message with the banks public key

    def decryptMessage(cipher):
        msg = ""
        bankA_private = 147276700497160985403069405313 
        bankA_N = 403246574997455042743991405701 

        parts = cipher.split()
        for part in parts:
            if part:
                c = int(part)
                msg += chr(pow(c, bankA_private, bankA_N))

        return msg
        # Basically decrypts the message recieved with it's own private key

    # This is sends data to the gateway
    def sendToGateway(self, message):
        bank2gate_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bank2gate_socket.connect(("192.168.0.100", 8086))
        print("connected")

        data = message.encode()
        bank2gate_socket.send(data)

    # This checks whether the card details are in the bank's database
    def checkDetails(self):
        card_no = self.card_no
        cvv = self.cvv
        expiry = self.expiry

        '''
        cursor.execute(  # CARD_NO IS A VARIABLE WE WILL INSERT IN THE QUERY
            """
            SELECT CARD_NO, CVV, EXPIRY 
            FROM Card_Details
            WHERE CardNo = 'CARD_NO'
            """
        )
        for i in cursor:
            if card_no in i:
                if cvv in i:
                    if expiry in i:
                        return True
                    else:
                        return False
                else:
                    return False
            else:
                return False
        '''
        if card_no == "4554402769419581" and cvv == "434" and expiry == "1223":
            return True
        else:
            return False

    # This checks whether the details are blacklisted
    def checkBlacklist(card_no):
        cursor.execute(
            """
            SELECT CARD_NO 
            FROM Black_List
            WHERE CardNo = 'CARD_NO'
            """
        )

        for i in cursor:
            if i != None:
                return False
        return True

    # This checks whether the card is valid or not
    def checkValidity(expiry):
        # if date today is greater than expiry
        # return false
        # else
        # return true
        None

    # This checks whether there are any funds in the account. It's an sql query.
    def checkFunds(required_funds, card_no):
        cursor.execute(
            """
            SELECT Funds,
            FROM Card_Details,
            WHERE CardNo = 'CARD_NO'
            """
        )
        # Verify whether the required funds are present
        for i in cursor:
            if required_funds <= i:
                return True

    # This checks whether all the details provided are valid
    def validDetails(card_no, cvv, expiry, required_funds):
        if checkDetails(card_no, cvv, expiry):
            if checkValidity(expiry):
                if checkFunds(required_funds, card_no):
                    if checkBlacklist(card_no):
                        return True
                    else:
                        return False
                else:
                    return False
            else:
                return False
        else:
            return False

    # This generates and sends OTPs to the client. It also recieves the OTPs
    def sendOTP(self, card_no):
        print("generating an OTP....")
        '''
        cursor.execute(
            """ 
            SELECT ContactNo
            FROM Bank_Details
            WHERE CardNo= CARD_NO
            """
        )
        for i in cursor:
            contact_no = i
        '''
        otp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        otp_socket.connect(("192.168.0.100", 8084))

        sent_OTP = str(random.randint(100000, 999999))
        data = sent_OTP.encode()
        # encrypted_data = encrypt(data)
        # client2bank_socket.send(encrypted_data) use these when the encryption is sorted out
        otp_socket.send(data)
        print("OTP sent")
        recieved_OTP = otp_socket.recv(10)
        print("OTP recieved")
        return sent_OTP, recieved_OTP
    
    # This verifies whether the OTP provided by the client is valid
    def verifyOTP(self, OTPSent, OTPRecieved):
        print(OTPSent, type(OTPSent))
        print(OTPRecieved, type(OTPRecieved))
        if int(OTPSent) == int(OTPRecieved):
            return True
        else:
            return False

    # This is an SQL theory which holds funds in the card details database
    def holdFunds(Funds, CardNo):
        cursor.execute(
            """
            UPDATE HoldFunds
            FROM Card_Details
            SET HoldFunds = FUNDS
            SET Funds = Funds - HoldFunds
            WHERE CardNo = CARD_NO
            """
        )

    # The following 2 functions use the same code, make it a little more effiecient to differentiate. They send (dis)approval messages.
    def sendApproval(self, message, port_no):
        #encrypted_message = encryptMessage(message)
        new_message = "1" + str(message[1:])
        data = new_message.encode()
        if port_no == 8081:
            client2bank_connection_socket.send(data)
        elif port_no == 8082:
            gateway_socket.send(data)
        print("Sent approval")
    
    def sendDisapproval(self, message, port_no):
        #encrypted_message = encryptMessage(message)
        new_message = "0" + str(message[1:])
        data = message.encode()
        if port_no == 8081:
            client2bank_connection_socket.send(data)
        elif port_no == 8082:
            gateway_socket.send(data)
    
    def checkAuthorisedPayments(self):
        '''
        hashed_data = self.hashed_data
        cursor.execute(  # HASHED_DATA IS A VARIABLE WE WILL INSERT IN THE QUERY, 
            """
            SELECT Hash
            FROM Authorised_Payments
            WHERE Hash = 'HASHED_DATA'
            """
        )
        for i in cursor:
            return True
        else:
            return False
        '''
        print("Payment exists")
        return True
    
    def transferHoldToVisa(self):
        '''
        cursor.execute(
            """
            
            """
        )
        '''
        print("Funds in hold transferred to Visa Reserve")
        return True

    def transferVisaToMerchant(self):
        '''
        cursor.execute(
            """
            
            """
        )
        '''
        print("Funds in Visa Reserve transferred to Merchant Acc")
        return True
    
    # Funds transferred directly from customer to merchant account if they're in the same bank
    def directFundTransfer(self):
        '''
        cursor.execute(
            """
            
            """
        )
        '''
        print("Funds in Client Acc DIRECTLY transferred to Merchant Acc")
        return True

# This is the main part of the code
if __name__ == "__main__":
    
    print("This is the bank server")
    # The socket for client to bank
    client2bank_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client2bank_socket.bind(("192.168.0.100", 8081))
    client2bank_socket.listen()
    print("Waiting for client socket...")
    client2bank_connection_socket, address = client2bank_socket.accept()
    print("Client connected")
    client_data = client2bank_connection_socket.recv(30000).decode()
    
    # This is the socket for bank to gateway
    gateway_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    gateway_socket.connect(("192.168.0.100", 8082))
    print("Gateway connected")
    #gateway_data = gateway_socket.recv(750)
    #gateway_message = gateway_data.decode()
    #final_message = gateway_message
    

    # ok seperate gatweay vars and and client vars, keep both always listening. keep the client listening for otp as well. after that it should be done.

    # This allows the program to always keep listening, but it probably needs to be changed
    
    # It first checks whether it has recieved any message from the client
    '''
    print("I have got to here")
    client_data = client2bank_connection_socket.recv(750)
    if client_data:
        print(client_data)
        final = client_data.decode()
        final_message = client_message
    # If no message has come from the client, the program listens for the gateway
    else:
        print("I came here")
        gateway_data = gateway_socket.recv(750)
        gateway_message = gateway_data.decode()
        final_message = gateway_message
    '''
    # decrypted_message = data.decrypt(full_message)
    # Bank = BankServer(decrypted_message) use these 2 lines once the encryption is sorted out. Put the encryption in it's own class. So, class Encryption.
    
    print("message has been recieved")
    
    # The message recieved is passed through this function which is used for recursion.
    def main(client_data):
        # The message is taken in as a paremeter by the BankServer class and
        decrypted_data = BankServer.decryptMessage(client_data)
        Bank = BankServer(decrypted_data)
        print(decrypted_data)
        message_type = BankServer.getMessageType(Bank)
        print(message_type)
        issuing_bank = BankServer.getIssuingBank(Bank)
        merchant_bank = BankServer.getMerchantBank(Bank)
        card_no = BankServer.get_CardNo(Bank)
        print(card_no)
        print("the method works")

        # If the message type is 1, then an approval message is sent. Needs edits. 
        if message_type == "1":
            print("Sending approval message....")
            encrypted_message = Bank.encryptMessage(decrypted_data)
            Bank.sendApproval(encrypted_message, 8081)
            print("sent approval")
            print("Waiting for gateway to send message: ")
        #try:
            message = gateway_socket.recv(30000).decode()
            print("message:", message)
            decrypted_message = Bank.decryptMessage(message)
            print("Recieved response from gateway:", decrypted_message)
            main(message)
        #except:
            print("No message recieved")
            
        
        elif message_type == "0":
            print("Sending dissaproval message....")
            # Figure out a way to decide where to send approval messages to via databases
            #if issuing_bank == merchant_bank:
            #    Bank.sendDisapproval(decrypted_message, 8081)
            encrypted_message = Bank.encryptMessage(decrypted_data)
            Bank.sendDisapproval(encrypted_message, 8081)
            print("Sent disapproval")
            print("Waiting for gateway to send message: ")
            try:
                message = gateway_socket.recv(30000).decode()
                decrypted_message = Bank.decryptMessage(message)
                print("Recieved response from gateway:", decrypted_message)
                main(message)
            except:
                print("No message recieved")

        # If the message type is 9, then it's an authorisaton message
        elif message_type == "9":
            print("Recieved an authorisation message")
            # It checks whether the issuing bank is the same bank the message has been sent. If it isn't, the details are sent to the gateway
            if issuing_bank != "53981":
                print("Customer details are not in this bank")
                # We get the details to be checked and the hash and then check both of them
                check_details = BankServer.getCheckDetails(Bank) 
                hashed_details = BankServer.getHashedDetails(Bank)
                true_hash = Bank.checkHash(check_details, hashed_details)
                # If the hash is true, then the details are sent to the gateway after being added into the database
                if true_hash == True:
                    #new_entry = Bank.addEntry()
                    print("Assume entry added")
                    encrypted_message = Bank.encryptMessage(decrypted_data).encode()
                    print(decrypted_data)
                    print(encrypted_message)
                    gateway_socket.send(encrypted_message)
                    print("Message sent to the gateway")
                    print("Waiting for response from gateway...")
                    try:
                        message = gateway_socket.recv(30000).decode()
                        print("Recieved response from gateway:", message)
                        main(message)
                    except:
                        print("No response recieved")
                else:
                    print(False)
            # If the issuing bank and merchant bank are the same and it's this bank, the rest of the verification is done here
            elif issuing_bank == merchant_bank or issuing_bank == "53981": # when the merchant bank and issuing bank are the same, the communication is only between the merchant bank and client.
                print("Customer details are in this bank")
                # It checks the details in the message with the hash
                check_details = BankServer.getCheckDetails(Bank) 
                hashed_details = BankServer.getHashedDetails(Bank)
                true_hash = Bank.checkHash(check_details, hashed_details)
                if true_hash == True:
                    # if that is true, the details are checked in the bank
                    print("The hash is true")
                    valid_details = Bank.checkDetails()
                    if valid_details == True:
                        # if the details are valid, an OTP is generated and sent
                        print("The details are valid")
                        print("Generating an OTP....")
                        sent_OTP, recieved_OTP = Bank.sendOTP(card_no)
                        print("Checking OTP...")
                        valid_otp = Bank.verifyOTP(sent_OTP, recieved_OTP)
                        if valid_otp == True:
                            # If the OTP is valid then the funds are held and approval is sent.
                            print("OTP is true")
                            # funds_held = Bank.holdFunds(funds, card_no)
                            print("Assume funds held")
                            funds_held = True
                            if funds_held == True:
                                print("Assume entry is added")
                                print("Approval is being sent")
                                #new_entry = Bank.addEntry(message)
                                Bank.sendApproval(client_data, 8081)
                                #Bank.sendApproval(decrypted_message, 8081)
                            # If any of the above tests fail, a disapproval message is sent
                            else:
                                Bank.sendDisapproval(client_data, 8081)
                        else:
                            Bank.sendDisapproval(client_data, 8081)
                    else:
                        Bank.sendDisapproval(client_data, 8081)
                else:
                    Bank.sendDisapproval(client_data, 8081)
            # Check if you need this
            else: 
                check_details = BankServer.getCheckDetails(Bank) 
                hashed_details = BankServer.getHashedDetails(Bank)
                true_hash = Bank.checkHash(check_details, hashed_details)
                if true_hash == True:
                    valid_details = Bank.checkDetails()
                    if valid_details == True:
                        sent_OTP, recieved_OTP = Bank.OTP()
                        valid_otp = Bank.verifyOTP(sent_OTP, recieved_OTP)
                        if valid_otp == True:
                            funds_held = Bank.holdFunds(funds, card_no)
                            if funds_held == True:
                                new_entry = Bank.addEntry(message)
                                sendApproval(decrypted_message, 8082)
                            else:
                                sendDisapproval(decrypted_message, 8082)
                        else:
                            sendDisapproval(decrypted_message, 8082)
                    else:
                        sendDisapproval(decrypted_message, 8082)
                else:
                    sendDisapproval(decyrpted_message, 8082)

        elif message_type == "8":
            print("Recieved a settlement request")
            # It checks whether the issuing bank is the same bank the message has been sent. If it isn't, the details are sent to the gateway
            if issuing_bank != "53981":
                print("Customer details are not in this bank")
                # We get the details to be checked and the hash and then check both of them
                check_details = BankServer.getCheckDetails(Bank) 
                hashed_details = BankServer.getHashedDetails(Bank)
                true_hash = Bank.checkHash(check_details, hashed_details)
                # If the hash is true, then the details are sent to the gateway after being added into the database
                if true_hash == True:
                    #new_entry = Bank.addEntry()
                    print("Assume entry added")
                    encrypted_data = Bank.encryptMessage(decrypted_data)
                    print("Encrypted data:", encrypted_data)
                    message = encrypted_data.encode()
                    gateway_socket.send(message)
                    print("Message sent to the gateway")
                    print("Waiting for response from gateway")
                    try:
                        message = gateway_socket.recv(30000).decode()
                        print("Recieved response from gateway:", message)
                        main(message)
                    except:
                        print("No response recieved")
                else:
                    print(False)
            
            elif issuing_bank == merchant_bank and issuing_bank == "53981":
                print("Both customer and merchant are in this bank.\n Direct transfer will take place")
                check_details = BankServer.getCheckDetails(Bank) 
                hashed_details = BankServer.getHashedDetails(Bank)
                true_hash = Bank.checkHash(check_details, hashed_details)
                if true_hash is True:
                    # if that is true, the details are checked in the bank
                    print("The hash is true")
                    valid_payment = Bank.checkAuthorisedPayments()
                    if valid_payment is True:
                        direct_payment = Bank.directFundTransfer()
                        if direct_payment is True:
                            Bank.sendApproval(decrypted_message, 8082)
                        else:
                            Bank.sendDisapproval(decrypted_message, 8082)
                    else:
                        Bank.sendDisapproval(decrypted_message, 8082)
                else:
                    Bank.sendDisapproval(decrypted_message, 8082)

            ## RECHECK THIS BASED ON WHICH REQUEST GOES WHERE
            elif  issuing_bank == "53981": # when the merchant bank and issuing bank are the same, the communication is only between the merchant bank and client.
                print("Customer details are in this bank")
                # It checks the details in the message with the hash
                check_details = BankServer.getCheckDetails(Bank) 
                hashed_details = BankServer.getHashedDetails(Bank)
                true_hash = Bank.checkHash(check_details, hashed_details)
                if true_hash is True:
                    # if that is true, the details are checked in the bank
                    print("The hash is true")
                    valid_payment = Bank.checkAuthorisedPayments()
                    if valid_payment is True:
                        funds_transfered = Bank.transferHoldToVisa()
                        if funds_transfered is True:
                            encrypted_data = Bank.encryptMessage(client_data)
                            message = encrypted_data.encode()
                            gateway_socket.send(message)
                            print("Message sent to the gateway")
                            print("Waiting for response from gateway")
                            message = gateway_socket.recv(30000).decode()
                            print("Recieved response from gateway:", message)
                            main(message)
                        else:
                            Bank.sendDisapproval(client_data, 8081)
                    else:
                        Bank.sendDisapproval(client_data, 8081)
                else:
                    Bank.sendDisapproval(client_data, 8081)

        elif message_type == "7":
            print("Recieved hold transfer message")
            check_details = BankServer.getCheckDetails(Bank) 
            hashed_details = BankServer.getHashedDetails(Bank)
            true_hash = Bank.checkHash(check_details, hashed_details)
            if true_hash == True:
                print("The hash is true")
                valid_details = Bank.checkDetails()   
                if valid_details == True:
                    print("The details are valid")
                    funds_transfered = Bank.transferVisaToMerchant()
                    if funds_transfered == True:
                        print("Funds have been transferred, sending approval...")
                        Bank.sendApproval(client_data, 8081)
                    else:
                        Bank.sendDisapproval(client_data, 8082)
                else:
                    Bank.sendDisapproval(client_data, 8082)
            else:
                Bank.sendDisapproval(client_data, 8082)
            
    
    
    main(client_data)


    '''
        # This part is about getting details from the merchant and forwarding them to the gateway
        else:
            iso = Bank.iso()
            new_entry = Bank.addEntry()
            if new_entry == True:
                message = 9 + iso
                encrypted_message = Bank.encryptMessage()
                message_sent = Bank.sendToGateway(encrypted_message)
                if message_sent == True:
                    None
        
        # Recieveing an approval or dissaproval message
    '''
