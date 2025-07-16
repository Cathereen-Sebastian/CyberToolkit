import hashlib

def main():
    print("\n Hash Generator/ Chceker")
    text = input("Enter the text to hash: ")

    print("Choose hashing algorithm:")
    print("1.MD5")
    print("2.SHA-1")
    print("3.SHA-256")

    algo_choice=input("Enter your choice 1/2/3 : ")

    if algo_choice=="1":
        hashed = hashlib.md5(text.encode()).hexdigest()
        algo="MD5"

    elif algo_choice=="2":
        hashed = hashlib.sha1(text.encode()).hexdigest()
        algo = "SHA-1"
    elif algo_choice=="3":
        hashed = hashlib.sha256(text.encode()).hexdigest()
        algo= "SHA-256"
    else:
        print("Invalid choice .")
        return
    
    print(f"\n {algo} Hash : {hashed}")

    compare = input("\n Do you want to compare with another hash? (y/n): ").lower()
    if compare=='y':
        other_hash = input("Enter hash to compare with: ")
        if len(other_hash.strip()) != len(hashed):
            print("Warning: Hash lengths are different.")
            print("You're likely comparing hashes from *different algorithms*.")
            print("They will not match.")
        if other_hash.lower() ==hashed.lower():
            print("Hashes match!")
        else:
            print("Hashes do not match.")

if __name__=="__main__":
    main()
    