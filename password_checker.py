import re
import getpass


def main():
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

if __name__=="__main__":
    main()
    
    