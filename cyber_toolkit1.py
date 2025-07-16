import socket
import hashlib
import re
import getpass
from tqdm import tqdm
from colorama import Fore, Style, init
init(autoreset=True)

# Save file.........
def save_to_file(filename, content):
    try:
        with open(filename, 'a') as f:
            f.write(content + '\n')
        print(Fore.CYAN + f" Saved to {filename}")
    except Exception as e:
        print(Fore.RED + f" Error saving file: {e}")

# Caesar cipher..........
def encrypt_caesar(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def decrypt_caesar(text, shift):
    return encrypt_caesar(text, -shift)

def caesar_cipher_tool():
    print(Fore.CYAN + "\nCaesar Cipher Tool")
    choice = input("Do you want to (E)ncrypt or (D)ecrypt? ").upper()
    message = input("Enter your message: ")
    shift = int(input("Enter the shift value (e.g., 3): "))

    if choice == 'E':
        encrypted = encrypt_caesar(message, shift)
        print(Fore.GREEN + f"Encrypted Message: {encrypted}")
        if input("Save result to file? (y/n): ").lower() == 'y':
            save_to_file("caesar_output.txt", f"Encrypted: {encrypted}")
    elif choice == 'D':
        decrypted = decrypt_caesar(message, shift)
        print(Fore.GREEN + f"Decrypted Message: {decrypted}")
        if input("Save result to file? (y/n): ").lower() == 'y':
            save_to_file("caesar_output.txt", f"Decrypted: {decrypted}")
    else:
        print(Fore.RED + "Invalid option!")

#  Port Scanner ............
def port_scanner():
    print(Fore.CYAN + "\nPort Scanner Tool")
    target = input("Enter target IP or hostname: ")
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(Fore.RED + "Invalid hostname.")
        return

    start_port = int(input("Enter start port (e.g., 1): "))
    end_port = int(input("Enter end port (e.g., 1024): "))

    print(Fore.YELLOW + f"\nScanning {target_ip} from port {start_port} to {end_port}...\n")
    results = []
    for port in tqdm(range(start_port, end_port+1), desc="Scanning Ports", ncols=75):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((target_ip, port))
        if result == 0:
            open_port = f"Port {port} is OPEN"
            print(Fore.GREEN + open_port)
            results.append(open_port)
        s.close()

    print(Fore.CYAN + "\nScan complete")
    if results and input("Save results to file? (y/n): ").lower() == 'y':
        save_to_file("scan_results.txt", '\n'.join(results))

#Password Strength Checker .........
def password_checker():
    print(Fore.CYAN + "\nPassword Strenght Checker")
    visible = input("Show password while typing? (y/n): ").lower()
    password = input("Enter password: ") if visible == 'y' else getpass.getpass("Enter password (hidden): ")

    length = len(password) >= 8
    upper = bool(re.search(r'[A-Z]', password))
    lower = bool(re.search(r'[a-z]', password))
    digit = bool(re.search(r'\d', password))
    symbol = bool(re.search(r'[!@#$%^&*(),.:{}|<>]', password))
    score = sum([length, upper, lower, digit, symbol])

    if score <= 2:
        strength = "Weak"; crack = "Instantly crackable"
    elif score == 3:
        strength = "Medium"; crack = "Few minutes to hours"
    elif score == 4:
        strength = "Strong"; crack = "Days to months"
    else:
        strength = "Very Strong"; crack = "Years or longer"

    print(Fore.GREEN + f"Password Strength: {strength}")
    print(Fore.YELLOW + f"Estimated Crack Time: {crack}")

#  Hash Generator........... #
def detect_algorithm_by_length(h):
    return {32: "MD5", 40: "SHA-1", 64: "SHA-256"}.get(len(h), "Unknown")

def hash_generator():
    print(Fore.CYAN + "\nHash Generator/Checker")
    text = input("Enter the text to hash: ")
    print("Choose hashing algorithm:\n1. MD5\n2. SHA-1\n3. SHA-256")
    algo_choice = input("Enter your choice (1/2/3): ")

    if algo_choice == "1":
        hashed = hashlib.md5(text.encode()).hexdigest(); algo = "MD5"
    elif algo_choice == "2":
        hashed = hashlib.sha1(text.encode()).hexdigest(); algo = "SHA-1"
    elif algo_choice == "3":
        hashed = hashlib.sha256(text.encode()).hexdigest(); algo = "SHA-256"
    else:
        print(Fore.RED + "Invalid choice."); return

    print(Fore.GREEN + f"{algo} Hash: {hashed}")
    if input("Save result to file? (y/n): ").lower() == 'y':
        save_to_file("hash_output.txt", f"{algo} hash of '{text}' = {hashed}")

    if input("Compare with another hash? (y/n): ").lower() == 'y':
        other_hash = input("Enter the other hash: ").strip().lower()
        possible = {
            "MD5": hashlib.md5(text.encode()).hexdigest().lower(),
            "SHA-1": hashlib.sha1(text.encode()).hexdigest().lower(),
            "SHA-256": hashlib.sha256(text.encode()).hexdigest().lower()
        }
        for name, val in possible.items():
            if other_hash == val and name != algo:
                print(Fore.YELLOW + f"Same message, but different algorithm! ({algo} ≠ {name})")
                return
        if other_hash == hashed.lower():
            print(Fore.GREEN + "Hashes MATCH!")
        else:
            print(Fore.RED + "Hashes do NOT match.")

#  XOR Encryptor......
def xor_encrypt_decrypt(text, key):
    return ''.join(chr(ord(text[i]) ^ ord(key[i % len(key)])) for i in range(len(text)))

def hex_to_string(hex_str):
    try:
        return bytes.fromhex(hex_str).decode('utf-8', errors='ignore')
    except ValueError:
        print(Fore.RED + "Invalid hex input.")
        return None

def xor_tool():
    print(Fore.CYAN + "\nXOR Encryptor/Decryptor")
    choice = input("(E)ncrypt or (D)ecrypt? ").lower()
    if choice not in ['e', 'd']:
        print(Fore.RED + "Invalid choice."); return

    message = input("Enter your message: ")
    key = input("Enter the key: ")
    if not key:
        print(Fore.RED + "Key cannot be empty."); return

    if choice == 'e':
        output = xor_encrypt_decrypt(message, key)
        encrypted_hex = output.encode('utf-8').hex()
        print(Fore.GREEN + f"Encrypted (hex): {encrypted_hex}")
        if input("Save to file? (y/n): ").lower() == 'y':
            save_to_file("xor_output.txt", f"Encrypted: {encrypted_hex}")
    else:
        message = hex_to_string(message)
        if message is None:
            return
        decrypted = xor_encrypt_decrypt(message, key)
        print(Fore.GREEN + f"Decrypted message: {decrypted}")

#main.............
def show_menu():
    print(Fore.MAGENTA + """
  \U0001f4bb Welcome to CyberToolkit  
  ------------------------------
  1. Port Scanner
  2. Hash Generator / Checker
  3. Password Strength Checker
  4. Caesar Cipher
  5. XOR Encryptor
  0. Exit
""")

while True:
    show_menu()
    choice = input("Enter your choice: ")
    if choice == "1": port_scanner()
    elif choice == "2": hash_generator()
    elif choice == "3": password_checker()
    elif choice == "4": caesar_cipher_tool()
    elif choice == "5": xor_tool()
    elif choice == "0":
        print(Fore.CYAN + "Exiting. ")
        break
    else:
        print(Fore.RED + "Invalid choice. Please try again.")
