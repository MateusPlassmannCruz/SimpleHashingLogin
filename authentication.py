"""
De: Mateus Plassmann Cruz
CASO NECESSÁRIO CRIAR ARQUIVO 'users.json' !!!!!!!!!!!
"""
import hashlib
import json
from getpass import getpass


def _generate_salt() -> str:
    new_salt = 'salt'

    return new_salt


def generate_hash(password: str) -> str:
    salt = _generate_salt()

    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    )

    return salt, key


def initialize_user_file():
    with open('users.json', 'w') as file:
        json.dump([], file)


def generate_user_file(username: str, salt: str, hash: str, attempts: int) -> None:
    user_file = read_file()

    for user in user_file:
        if user['username'] == username:
            print('Usuário já existe')
            break
    else:
        user_file.append({'username': username, 'salt': salt, 'hash': hash, 'attempts': attempts})
        _save_to_file(user_file)


def _save_to_file(user_file: str):
    with open('users.json', 'w') as file:
        json.dump(user_file, file)


def read_file():
    with open('users.json', 'r') as file:
        return json.load(file)
    

def get_attempts(username: str) -> str:
    users = read_file()
    for user in users:
        if user['username'] == username:
            return user['attempts']
    else:
        return 0


def authenticate_user(username: str, hash: str) -> bool:
    users_file = read_file()

    for user in users_file:
        if (user['username'] == username) and (user['hash'] == hash.hex()):
            return True
        elif (user['username'] == username) and (user['hash'] != hash.hex()):
            user['attempts'] += 1
            _save_to_file(users_file)


USER_CHOICE = """
1 -- Criar usuário
2 -- Fazer login

"""


def menu():
    try:
        read_file()
    except:
        initialize_user_file()

    option = int(input(USER_CHOICE))

    username = str(input('username: '))
    password = getpass()

    hash_generator = generate_hash(password)
    Salt = hash_generator[0]
    Key = hash_generator[1]

    if option == 1:
        attempts = get_attempts(username)
        generate_user_file(username, Salt, Key.hex(), attempts) 
    elif option == 2:
        user_attempts = get_attempts(username)

        if user_attempts < 5:
            if authenticate_user(username, Key) == True:
                print('Bem vindo, usuário! ')
            else:
                print('Login ou senha incorreto, tente novamente mais tarde ...')
        else:
            print('Usuário ultrapassou tentativas máximas de login! Bloqueado! ')
    else:
        print('Opção inválida, insira um número de 1 a 2 ...')
        

menu()