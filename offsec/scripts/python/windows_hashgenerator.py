#!/usr/bin/python3
import argparse
import binascii
from impacket.ntlm import compute_lmhash, compute_nthash

def get_hashes(password):
    lmhash = binascii.hexlify(compute_lmhash(password)).decode()
    nthash = binascii.hexlify(compute_nthash(password)).decode()
    print(lmhash +":" + nthash)

def get_arguments():
    parser = argparse.ArgumentParser(description="Generate Windows hashes (LM and NTHash) from a password.")
    parser.add_argument("-p", "--password", required=True, help="The password to hash")
    return parser.parse_args()

def main():
    args = get_arguments()
    get_hashes(args.password)

if __name__ == "__main__":
    main()
