import bcrypt
import argparse
import datetime
import multiprocessing
import os
import signal
from tqdm import tqdm
import sys

# Untuk menangani interupsi (CTRL+C)
def init_worker():
    signal.signal(signal.SIGINT, signal.SIG_IGN)

# Fungsi pengecekan password terhadap hash
def check_password(args):
    password, target_hash = args
    try:
        if bcrypt.checkpw(password.encode('utf-8'), target_hash.encode('utf-8')):
            return password
    except:
        return None

# Fungsi utama brute force
def crack_bcrypt(target_hash, wordlist, max_processes):
    print(f"[+] Target Hash     : {target_hash}")
    print(f"[+] Wordlist File   : {wordlist}")
    print(f"[+] Max Processes   : {max_processes}")

    if not os.path.isfile(wordlist):
        print("[-] Error: Wordlist file not found.")
        sys.exit(1)

    with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
        passwords = [line.strip() for line in f if line.strip()]

    print(f"[+] Total Passwords : {len(passwords)}\n")

    start_time = datetime.datetime.now()

    pool = multiprocessing.Pool(processes=max_processes, initializer=init_worker)

    try:
        for result in tqdm(pool.imap_unordered(check_password, [(pwd, target_hash) for pwd in passwords]), 
                           total=len(passwords), desc="Cracking", unit="password"):
            if result:
                end_time = datetime.datetime.now()
                elapsed = end_time - start_time
                print(f"\n[+] Password Found  : {result}")
                print(f"[+] Time Taken      : {elapsed}")
                pool.terminate()
                pool.join()
                return result

    except KeyboardInterrupt:
        print("\n[-] Cracking interrupted by user.")
        pool.terminate()
        pool.join()

    print("\n[-] Password not found.")
    return None

# Fungsi main (argparse)
def main():
    parser = argparse.ArgumentParser(
        usage='python bcrypt_crack.py --hash <bcrypt_hash> --wordlist <wordlist.txt> --processes <num>',
        description='Brute-force Bcrypt Hash Cracker using multiprocessing',
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=True
    )

    parser.add_argument('hash', help='Hash bcrypt yang akan diretas')
    parser.add_argument('wordlist', help='Path to wordlist file')
    parser.add_argument('-p', '--processes', type=int, default=multiprocessing.cpu_count(), help='Number of processes to use (default: all cores)')

    args = parser.parse_args()

    # Validasi format hash
    if not args.hash.startswith("$2b$") and not args.hash.startswith("$2a$") and not args.hash.startswith("$2y$"):
        print("[-] Error: Invalid bcrypt hash format.")
        sys.exit(1)

    crack_bcrypt(args.hash, args.wordlist, args.processes)

if __name__ == '__main__':
    main()
