import requests
import hashlib
import sys

def request_api_pwned(sha_pwd):
  url = 'https://api.pwnedpasswords.com/range/' + sha_pwd
  res = requests.get(url)
  if res.status_code != 200:
    raise RuntimeError(f'Error fetching: {res.status_code}, ocurrió un problema con el API PWNEDPASSWORDS, vuelve a intentarlo!')
  return res


def get_password_leaks_count(hashes, hash_to_check):
  hashes = (line.split(':') for line in hashes.text.splitlines())
  for h, count in hashes:
    if h == hash_to_check:
      return count
  return 0


def pwned_api_check(password):
  sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
  first5_char, tail = sha1password[:5], sha1password[5:]
  response = request_api_pwned(first5_char)
  return get_password_leaks_count(response, tail)


def main(args):
  print(args)
  for password in args:
    count = pwned_api_check(password)
    if count:
      print(f'{password} encontrado {count} veces!...No se recomienda el uso de esta contraseña!')
    else:
      print(f'{password} no encontrado. Puedes usarlo!')
  return 'done!'


if __name__ == '__main__': 
  sys.exit(main(sys.argv[1:]))