import socket
import hashlib


def encrypt(e, N, msg):
    cipher = ""

    for c in msg:
        m = ord(c)
        cipher += str(pow(m, e, N)) + " "

    return cipher

def decrypt(d, N, cipher):
    msg = ""

    parts = cipher.split()
    for part in parts:
        if part:
            c = int(part)
            msg += chr(pow(c, d, N))

    return msg

if __name__ == "__main__":
    ### USE PRIORITY QUEUE TO SCHEDULE SETTLEMENTS, MERCHANT BANK FIRST, ISSUING NEXT ##


    bankA_public = 604710583306877
    bankA_N = 403246574997455042743991405701
    client_private = 601357889498540958036731116595
    client_N = 605412704415548500357091026483

    print("This is the client server")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("192.168.0.100", 8081))
    print("connected")

    card_no = "4554402769419581"
    cvv = "434"
    expiry = "1223"
    date = "130722"
    time = "202314"
    order_no = "000001"
    funds = "0400"
    merchant_bank = "53981"
    merchant_id = "1234567890"
    message = (card_no + cvv + expiry + date + time + order_no + funds + merchant_bank + merchant_id)

    hashed = hashlib.md5(message.encode()).hexdigest()
    message = "9" + message + str(hashed)
    print("Original:", message)
    encrypted_message = encrypt(bankA_public, bankA_N, message)

    data = encrypted_message.encode()
    client_socket.send(data)

    # This is for settlement
    '''
    print("Waiting for fund transfer message...")
    transfer_message = client_socket.recv(20000).decode()
    #decrypted_message = decrypt(client_private, client_N, transfer_message)

    print(transfer_message)
    if transfer_message[0] == '1':
        print("Funds have been transferred successfully. All accounts are settled.")
    else:
        print("Funds have not been transferred. Try again.")
    '''

    otp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    otp_socket.bind(("192.168.0.100", 8084))
    otp_socket.listen()
    print("Waiting for client socket...")
    otp_socket, address = otp_socket.accept()
    print("Client connected")

    print("Listening for otp....")
    data = otp_socket.recv(10)
    # encrypted_message = data.decode()
    # decypted_message = decrypt(encrypt_message)
    # print(decrypted_message) use this when the decryption is sorted out
    message = data.decode()
    print(message)
    otp_verification = str(int(input("Input the OTP: ")))
    data = otp_verification.encode()
    otp_socket.send(data)

    ''' DONT USE ME
    confirmation_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    confirmation_socket.bind(("192.168.0.100", 8085))
    confirmation_socket.listen()
    print("Waiting for client socket...")
    confirmation_socket, address = confirmation_socket.accept()
    print("Client connected") DONT USE ME
    ''' 

    print("Waiting for confirmation...")
    try:
        confirmation = client_socket.recv(750).decode()
        if confirmation[0] == '1':
            print(confirmation)
            print("Payment authorised")
        else:
            print(confirmation)
            print("Payment denied")
    except:
        print()
        print("Payment denied")

