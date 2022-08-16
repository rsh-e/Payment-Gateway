import socket
import hashlib

print("This is the client server")
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("192.168.0.22", 8081))
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
#ip_address = "192.168.0.102"
#port_no = "8081"
message = (card_no + cvv + expiry + date + time + order_no + funds + merchant_bank + merchant_id)# + ip_address + port_no)

hashed = hashlib.md5(message.encode()).hexdigest()
message = "9" + message + str(hashed)
print(message)
data = message.encode()
# encrypted_data = None 
#client_socket.send(encrypted_data) # use this once you work out the encryption
client_socket.send(data)


otp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
otp_socket.bind(("192.168.0.22", 8084))
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

'''
confirmation_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
confirmation_socket.bind(("192.168.0.22", 8085))
confirmation_socket.listen()
print("Waiting for client socket...")
confirmation_socket, address = confirmation_socket.accept()
print("Client connected")
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

