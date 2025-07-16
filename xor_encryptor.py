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

def main():
    xor_tool()

if __name__ == "__main__":
    main()
