from tqdm import tqdm
import socket



def main():
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

if __name__=="__main__":
    main()
    