#caesar cipherr..........
def encrypt_caesar(text,shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char)-base + shift)%26 +base)
        else:
            result += char
    return result
    
def decrypt_caesar(text,shift):
     return encrypt_caesar(text, -shift)
        
def caesar_cipher_tool():
    print("Caesar cipher tool")
    choice = input("Do you want to (E)ncrypt or (D)ecrypt?").upper()
    message = input("Enter your message : ")
    shift = int(input("Enter the shift value ( eg ,3): "))

    if choice == 'E':
      encrypted = encrypt_caesar(message, shift)
      print("Encrypted Message:", encrypted)
    elif choice == 'D':
      decrypted = decrypt_caesar(message, shift)
      print("Decrypted Message:", decrypted)
    else:
     print("Invalid option!")


#port scanner..........
from tqdm import tqdm
import socket



def port_scanner():
    print("\n Port Scanner Tool ")
    target = input("Enter target IP or hostname: ")

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("Invalid hostname.")
        return
    
    start_port = int(input("Enter start port (eg. 1):"))
    end_port = int(input("Enter en port (eg 1024):"))

    print(f"\nScanning {target_ip} from port {start_port} to {end_port}....\n")

    for port in tqdm(range(start_port, end_port + 1), desc="Scanning Ports", ncols=75):
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((target_ip,port))

        if result == 0:
            print(f"\nPort {port} is OPEN")
        s.close()

    print("\nScan complete")


#password checker.........
import re
import getpass


def password_checker():
    print("\n Password Strength Checker")
    visible = input("Do you want the password to be visible as you type? (y/n): ").lower()

    if visible == 'y':
        password = input("Enter your password: ")
    else:
        password = getpass.getpass("Enter your password (it will be hidden): ")
   
    length_score = len(password)>=8
    upper_score = bool(re.search(r'[A-Z]',password))
    lower_score = bool(re.search(r'[a-z]',password))
    digit_score = bool(re.search(r'\d',password))
    symbol_score = bool(re.search(r'[!@#$%^&*(),.:{}|<>]',password))

    score = sum([length_score,lower_score,upper_score,digit_score,symbol_score])


    if score <=2:
        strength = "Weak"
        crack_time = "Instantly crackable "
    elif score ==3:
        strength= "Medium"
        crack_time = "Few mins to hours"
    elif score==4:
        strength="Strong"
        crack_time ="Days to months "
    else:
        strength="Very strong "
        crack_time="Years or longer"

    print(f"Password Strength : {strength}")
    print(f"Estimated Crack Time: {crack_time}")

#hash_generator....

import hashlib

def detect_algorithm_by_length(h):
    length = len(h)
    if length == 32:
        return "MD5"
    elif length == 40:
        return "SHA-1"
    elif length == 64:
        return "SHA-256"
    else:
        return "Unknown"

def hash_generator():
    print("\n Hash Generator / Checker")
    text = input("Enter the text to hash: ")

    print("Choose hashing algorithm:")
    print("1. MD5")
    print("2. SHA-1")
    print("3. SHA-256")

    algo_choice = input("Enter your choice (1/2/3): ")

    if algo_choice == "1":
        hashed = hashlib.md5(text.encode()).hexdigest()
        algo = "MD5"
    elif algo_choice == "2":
        hashed = hashlib.sha1(text.encode()).hexdigest()
        algo = "SHA-1"
    elif algo_choice == "3":
        hashed = hashlib.sha256(text.encode()).hexdigest()
        algo = "SHA-256"
    else:
        print(" Invalid choice.")
        return

    print(f"\n {algo} Hash: {hashed}")

    compare = input("\nDo you want to compare with another hash? (y/n): ").lower()
    if compare == 'y':
        same_msg = input("Is the other hash from the same message? (y/n): ").lower()
        other_hash = input("Enter the hash to compare with: ").strip().lower()

        entered_algo = detect_algorithm_by_length(other_hash)
        generated_algo = detect_algorithm_by_length(hashed)

        # Smart detection
        possible_matches = {
            "MD5": hashlib.md5(text.encode()).hexdigest().lower(),
            "SHA-1": hashlib.sha1(text.encode()).hexdigest().lower(),
            "SHA-256": hashlib.sha256(text.encode()).hexdigest().lower()
        }

        for algo_name, hash_val in possible_matches.items():
            if other_hash == hash_val and algo_name != generated_algo:
                print(f"\n Smart check: That hash is also from the same message but a different algorithm!")
                print(f" You generated with {generated_algo}, and entered a {algo_name} hash.")
                print(" They won’t match by design.")
                return

        if other_hash == hashed.lower():
            print(" Hashes MATCH!")
        else:
            print(" Hashes do NOT match.")



#xor encryption.......

def xor_encrypt_decrypt(text, key):
    result = []
    for i in range(len(text)):
        result.append(chr(ord(text[i]) ^ ord(key[i % len(key)])))
    return ''.join(result)

def hex_to_string(hex_str):
    try:
        bytes_obj = bytes.fromhex(hex_str)
        return bytes_obj.decode('utf-8', errors='ignore')
    except ValueError:
        print(" Invalid hex input.")
        return None

def xor_tool():
    print("\nXOR Encryptor/Decryptor")
    choice = input("Do you want to (E)ncrypt or (D)ecrypt? ").lower()
    if choice not in ['e', 'd']:
        print(" Invalid choice.")
        return

    message = input("Enter your message: ")
    key = input("Enter the key: ")
    if len(key) == 0:
        print(" Key cannot be empty.")
        return

    if choice == 'e':
        output = xor_encrypt_decrypt(message, key)
        encrypted_hex = output.encode('utf-8').hex()
        print(f" Encrypted message (hex): {encrypted_hex}")
    else:
        try:
            # Convert hex string back to XOR-encrypted text
            message = hex_to_string(message)
            if message is None:
                return
            decrypted = xor_encrypt_decrypt(message, key)
            print(f" Decrypted message: {decrypted}")
        except Exception as e:
            print(f" Error while decrypting: {e}")

def xor_encryptor():
    xor_tool()

#main ..........
def show_menu():
    print("\n Welcome to CyberToolkit ")
    print("1.Port Scanner")
    print("2.Hash Generator")
    print("3.Password Strength Checker")
    print("4.Caesar  Cipher tool")
    print("5.XOR Encryptor")
    print("0.Exit")

while True:
    show_menu()
    choice = input("Enter your choice :")

    if choice=="1":
        port_scanner()
    elif choice == "2":
        hash_generator()
    elif choice == "3":
        password_checker()
    elif choice == "4":
        caesar_cipher_tool()
    elif choice == "5":
        xor_encryptor()
    elif choice == "0":
        print("Exiting. Stay safe....")
        break
    else:
        print("invalid option. Try again..")



