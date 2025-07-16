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
        
def main():
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

if __name__=="__main__":
    main()
    