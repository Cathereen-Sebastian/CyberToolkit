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

def main():
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

if __name__ == "__main__":
    main()
