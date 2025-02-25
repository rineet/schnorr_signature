import argparse, json, sys
from schnorr_lib import sha256, schnorr_sign

def main():
    parser = argparse.ArgumentParser(
        description='returns the signature and the public key from a private key and a message')
    parser.add_argument('-m', '--message', type=str, required=True, help='Message to be signed')
    args = parser.parse_args()
    msg = args.message
    i = 0 
    # Get keypair
    try:
        users = json.load(open("users.json", "r"))["users"]
    except Exception:
        print("[e] Error. File nonexistent, create it with create_keypair.py")
        sys.exit(2)

    # Signature
    try:
        M = sha256(msg.encode())

        sig = schnorr_sign(M, users[i]["privateKey"])

        print("> Message =", M.hex())
        print("> Signature =", sig.hex())
    except Exception as e:
            print("[e] Exception:", e)
            sys.exit(2)


if __name__ == "__main__":
    main()
