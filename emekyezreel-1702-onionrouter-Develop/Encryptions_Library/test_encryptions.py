import encryptions
import base64

def main():
    public_key, private_key = encryptions.rsa_generate_key_pair()
    print(f"PUB: {public_key} || PRI: {private_key}")
    msg = "ABC"

    sign = encryptions.rsa_sign(msg, public_key)
    print(f"Sign: {sign}")

    text = encryptions.rsa_verify("ABC", sign, public_key)
    print(f"Verify: {text}")


if __name__ == "__main__":
    main()