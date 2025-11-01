from cryptography.fernet import Fernet
import subprocess
import pyperclip
import bcrypt
import json
import os
import base64
import hashlib

user = str(subprocess.check_output(["whoami"]))[2:-3]

def gen_pass():
    def X_n_1(X_n):
        return ((2^16)*X_n)%((2^31))

    def random():
        semilla = int(str(subprocess.check_output(["date", "+%N"])).split()[0][2:-4])
        aux = semilla
        for i in range(150000):
            aux = X_n_1(aux)
        return aux

    charset = [
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '=', '_', '+', '>', '<', '/', '?' , '|'
        ]

    count = 0
    while(count < 82):
        n = random()
        m = 81 - random()
        aux = 0
        if n < 81 and m < 81:
            aux = charset[n]
            charset[n] = charset[m]
            charset[m] = aux
            count = count + 1

    lista = []
    count = 0
    while(count < 20):
        n = random()
        if n < 81:
            lista.append(charset[n]) 
            count = count + 1

    return "".join(lista)

def read():
    with open(f"/home/{user}/.local/share/PassBlitz/info.json", 'r') as info:
        datos = json.load(info)
    return datos

def writte(datos):
    with open(f"/home/{user}/.local/share/PassBlitz/info.json", 'w') as info:
         json.dump(datos, info)

def main_menu():
    print(f"""
-----Bienvenido al gestor de contrasenas-----
Seleccionar contrasena -> 1
Agregar contrasena -> 2""")

def create_new_user_password_menu():
    print(f"""-----Bienvenido al gestor de contrasenas-----
Desea generar una nueva contrasena ?
Si -> 1
No -> 2""")

def main():

    try:

        if os.stat(f"/home/{user}/.local/share/PassBlitz/info.json").st_size > 0:
            
            datos = read()

            if "userPass" not in set(datos.keys()):
                raise Exception(f" Formato incorrecto no se encuentra el campo userPass en -> /home/{user}/.local/share/PassBlitz/info.json")

            if datos["userPass"] == "":
                create_new_user_password_menu() 
                n = input("->")
                while n not in ("1","2"):
                    print("Inserte una opcion valida")
                    create_new_user_password_menu() 
                    n = input("->")
                if n == "1":
                    newPass = input("Inserte nueva contrasena -> ")
                    bytes = newPass.encode('utf-8')
                    salt = bcrypt.gensalt()
                    hash = bcrypt.hashpw(bytes, salt)
                    datos["userPass"] = str(hash)
                    writte(datos)
                else :
                    return

            else:

                key = input("Ingrese contrasena: ")
                hashed_key = hashlib.sha256(key.encode('UTF-8'))
                hashed_key_digest = hashed_key.digest()
                base64_key = base64.b64encode(hashed_key_digest)
                fernet = Fernet(base64_key)

                if bcrypt.checkpw(key.encode('UTF-8'), datos["userPass"][2:-1].encode('UTF-8')):
                    main_menu()
                    n = input("->")
                    while n not in ("1", "2"):
                        print("Inserte una opcion valida")
                        main_menu()
                        n = input("->")
                    if n == "1":
                        try:
                            name = input("Inserte el nombre de llave de la contrasena -> ")
                            passw = fernet.decrypt(datos[name][2:-1].encode('UTF-8')).decode()
                            pyperclip.copy(passw)
                            print("Copiado en portapaeles")
                        except:
                            raise Exception(f" Error, no existe una contrasena asociada a esa llave -> /home/{user}/.local/share/PassBlitz/info.json")
                    elif n == "2":
                        try:
                            key = input("Inserte la llave de la contrasena -> ")
                            npass = gen_pass() 
                            datos[key] = str(fernet.encrypt(npass.encode()))
                            writte(datos)
                            pyperclip.copy(npass)
                            print("Clave generada y copiado en portapaeles")
                        except:
                            raise Exception(f" Error generando la contrasena")
                else:
                    raise Exception(f"Contrasena incorrecta")
                    return
        else:
            writte({"userPass":""})
    except:
        raise Exception(f"Error ejecutando programa")

main()

