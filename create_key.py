import argparse, json, os

from schnorr_lib import n, has_even_y, pubkey_point_gen_from_int, bytes_from_point


def create_keypair(n_keys: int):
    users = {
        "$schema": "./users_schema.json",
        "users": []
    }

    privkey = os.urandom(32)
    privkey_int = int(privkey.hex(), 16) % n

    publickey = pubkey_point_gen_from_int(privkey_int)

        
    privkey_even = privkey_int if has_even_y(publickey) else n - privkey_int

    hex_privkey = hex(privkey_even).replace('0x', '').rjust(64, '0')
    users["users"].append({
    "privateKey": hex_privkey,
    "publicKey": bytes_from_point(publickey).hex()
    })
    return users


def main():
    users = create_keypair(1)

    json_object = json.dumps(users, indent=4)
    with open("users.json", "w") as f:
        f.write(json_object)

    print("Keypair generated:" )


if __name__ == "__main__":
    main()
