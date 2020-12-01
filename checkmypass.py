# Password Checker Project - Create a tool which we can actually use in our life to check if our password is secure
# Check how many times a particular password has been hacked.

import requests
import hashlib
import sys


# Create a function to use password api which takes first 5 character of our hash password and returns the list
# of all tail hashes passwords which matches first 5 character of our hash password and also gives count which
# tells us how many times these passwords have been hacked
def request_api_data(query_char):
    # only first five characters of hash password to get response code 200 otherwise 400
    url = "https://api.pwnedpasswords.com/range/" + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
    return res


# get all response text
# def read_res(response):
#     print(response.text)  # gives all the hashes that match our beginning of hash password

# Create a function to check our own tail password hash (hash_to_check) and loop through all the tail of the
# hash password (hashes) and return the count of how many times this password has been leaked
def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())  # splitlines return a list of the lines in
    # the string, breaking at line boundaries
    for h, count in hashes:
        if h == hash_to_check:  # if the tail of the hash is equal to hash_to_check i.e., tail of our hash password
            return count  # how many times this password has been leaked
    return 0


# Create a function which converts our password to sha1 hash password using in-built hashlib library and split
# sha1 hash password in two parts. One part contain first 5 characters of sha1 password and other part contain
# rest of the sha1 hash password.
# Request api data using first 5 character of hash password which will return the list of all tail hashes passwords
# which matches first 5 character of our hash password and also gives count which tells us how many times these
# passwords have been hacked.
# Get password leak count by calling function which check our own password hash (hash_to_check) and loop through
# all the hash password (hashes)
def pwned_api_check(password):
    # print(hashlib.sha1(password.encode('utf-8')).hexdigest().upper())

    # hash.hexdigest() returned a string object of double length, containing only hexadecimal digits. To convert
    # HASH object obtained from print(hashlib.sha1(password.encode('utf-8'))) to hexadecimal digits use hexdigest().
    # Also upper case this to match with SHA1 hash password
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    # print(first5_char, tail)
    response = request_api_data(first5_char)  # call request_api_data function with first 5 characters of sha1 hash
    # password
    return get_password_leaks_count(response, tail)  # call function which check our own password hash
    # (hash_to_check) and loop through all the hash password (hashes)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... you should probably change your password!')
        else:
            print(f'{password} was NOT found. Carry on!')
    return 'done!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
