import requests
import hashlib
import sys

"""
Evaluates the safety of passwords
:param str: text file with list of passwords
"""


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    
    if res.status_code != 200:
        raise RuntimeError(f'Fetching Error: {res.status_code}, check the API and please try again')
    return res
            
            
def test_password_safety(hash_list, my_hash):
    hashes = (line.split(':') for line in hash_list.text.splitlines())
    for h, count in hashes:
        if h == my_hash:
            return count
    return 0
        
    
def pwned_api_check(pwd):
    sha1pwd = hashlib.sha1(pwd.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1pwd[:5], sha1pwd[5:]
    hashes_list = request_api_data(first5_char)
    return test_password_safety(hashes_list, tail)


def main(av):
    for pwd in av:
        count = pwned_api_check(pwd)
        if not count:
            print(f'The password \'{pwd}\' is safe to use.')
        else:
            print("\033[91m{}\033[00m".format(f'The password \'{pwd}\' has been compromised {count} times.'))
    return 'Done!'    


if __name__ == '__main__':
    try:
        file = sys.argv[1]
        with open(f'{file}') as f:
            lines = f.readlines()
            password_list = []
            for password in lines:
                if password != "\n":
                    password_list.append(password.strip('\n'))
        sys.exit(main(password_list))
    except (IndexError, FileNotFoundError):
        print("Error: Invalid text file")
