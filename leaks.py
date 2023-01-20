import requests
import hashlib
import sys
import argparse


def request_leakage_service(chars):
    response = requests.get('https://api.pwnedpasswords.com/range/' + chars)
    if response.status_code != 200:
        raise RuntimeError(f'Error fetching: {response.status_code}')
    return response


def get_password_leaks_count(hashes, hash_to_check):
    hashes = [line.split(':')[0] for line in hashes.text.splitlines()]
    if hash_to_check in hashes:
        return True
    return False


def is_pwned(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char = sha1password[:5]
    last5_char = sha1password[5:]
    response = request_leakage_service(first5_char)
    return get_password_leaks_count(response, last5_char)


def main(args):
    if args.get('i') is not None:
        for password in args.get('i'):
            if is_pwned(password):
                print(f'{password}: LEAKED!')
            else:
                print(f'{password}: NOT LEAKED')
    elif args.get('f') is not None:
        with open(args.get('f'), encoding='utf-8') as input_file:
            passwords = input_file.readlines()
            for password in passwords:
                password = password[:-1]
                if is_pwned(password):
                    print(f'{password}: LEAKED!')
                else:
                    print(f'{password}: NOT LEAKED')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Check passwords leakage.')
    parser.add_argument('-f', metavar='file_name.txt', type=str, help='read file mode')
    parser.add_argument('-i', metavar='password', type=str, nargs='+', help='input mode')
    args = parser.parse_args()
    sys.exit(main(vars(args)))
