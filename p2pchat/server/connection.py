from socket import (
    socket,
    AF_INET,
    SOCK_STREAM,
    SOCK_DGRAM,
    gethostname,
    gethostbyname,
)
import logging
from threading import Thread, Lock, Timer

from .db import DB
from ..data import port_udp, port_tcp


tcp_threads = {}

db = DB()


class UDPClientThread(Thread):
    def __init__(self, ip: str, port: int, tcp_client_socket: socket):
        Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.tcp_client_socket = tcp_client_socket
        
        self.username = None
        self.is_online = True
        self.udp_server = None
        print("New thread started for " + ip + ":" + str(self.port))

    # main of the thread
    def run(self):
        # locks for thread which will be used for thread synchronization
        self.lock = Lock()
        print("Connection from: " + self.ip + ":" + str(self.port))
        print("IP Connected: " + self.ip)

        while True:
            try:
                # waits for incoming messages from peers
                message = self.tcp_client_socket.recv(1024).decode().split()
                logging.info(
                    "Received from "
                    + self.ip
                    + ":"
                    + str(self.port)
                    + " -> "
                    + " ".join(message)
                )
                #   JOIN    #
                if message[0] == "JOIN":
                    # join-exist is sent to peer,
                    # if an account with this username already exists
                    if db.is_account_exist(message[1]):
                        response = "join-exist"
                        print(
                            "From-> " + self.ip + ":" + str(self.port) + " " + response
                        )
                        logging.info(
                            "Send to "
                            + self.ip
                            + ":"
                            + str(self.port)
                            + " -> "
                            + response
                        )
                        self.tcp_client_socket.send(response.encode())
                    # join-success is sent to peer,
                    # if an account with this username is not exist, and the account is created
                    else:
                        db.register(message[1], message[2])
                        response = "join-success"
                        logging.info(
                            "Send to "
                            + self.ip
                            + ":"
                            + str(self.port)
                            + " -> "
                            + response
                        )
                        self.tcp_client_socket.send(response.encode())
                #   LOGIN    #
                elif message[0] == "LOGIN":
                    # login-account-not-exist is sent to peer,
                    # if an account with the username does not exist
                    if not db.is_account_exist(message[1]):
                        response = "login-account-not-exist"
                        logging.info(
                            "Send to "
                            + self.ip
                            + ":"
                            + str(self.port)
                            + " -> "
                            + response
                        )
                        self.tcp_client_socket.send(response.encode())
                    # login-online is sent to peer,
                    # if an account with the username already online
                    elif db.is_account_online(message[1]):
                        response = "login-online"
                        logging.info(
                            "Send to "
                            + self.ip
                            + ":"
                            + str(self.port)
                            + " -> "
                            + response
                        )
                        self.tcp_client_socket.send(response.encode())
                    # login-success is sent to peer,
                    # if an account with the username exists and not online
                    else:
                        # retrieves the account's password, and checks if the one entered by the user is correct
                        retrieved_pass = db.get_password(message[1])

                        # if password is correct, then peer's thread is added to threads list
                        # peer is added to db with its username, port number, and ip address
                        if retrieved_pass == message[2]:
                            self.username = message[1]
                            self.lock.acquire()
                            try:
                                tcp_threads[self.username] = self
                            finally:
                                self.lock.release()

                            db.user_login(message[1], self.ip, message[3])
                            # login-success is sent to peer,
                            # and a udp server thread is created for this peer, and thread is started
                            # timer thread of the udp server is started
                            response = "login-success"
                            logging.info(
                                "Send to "
                                + self.ip
                                + ":"
                                + str(self.port)
                                + " -> "
                                + response
                            )
                            self.tcp_client_socket.send(response.encode())
                            self.udp_server = UDPServer(
                                self.username, self.tcp_client_socket
                            )
                            self.udp_server.start()
                            self.udp_server.timer.start()
                        # if password not matches and then login-wrong-password response is sent
                        else:
                            response = "login-wrong-password"
                            logging.info(
                                "Send to "
                                + self.ip
                                + ":"
                                + str(self.port)
                                + " -> "
                                + response
                            )
                            self.tcp_client_socket.send(response.encode())
                #   LOGOUT  #
                elif message[0] == "LOGOUT":
                    # if user is online,
                    # removes the user from onlinePeers list
                    # and removes the thread for this user from tcpThreads
                    # socket is closed and timer thread of the udp for this
                    # user is cancelled
                    if (
                        len(message) > 1
                        and message[1] is not None
                        and db.is_account_online(message[1])
                    ):
                        db.user_logout(message[1])
                        self.lock.acquire()
                        try:
                            if message[1] in tcp_threads:
                                del tcp_threads[message[1]]
                        finally:
                            self.lock.release()
                        print(self.ip + ":" + str(self.port) + " is logged out")
                        self.tcp_client_socket.close()
                        self.udp_server.timer.cancel()
                        break
                    else:
                        self.tcp_client_socket.close()
                        break
                #   SEARCH  #
                elif message[0] == "SEARCH":
                    # checks if an account with the username exists
                    if db.is_account_exist(message[1]):
                        # checks if the account is online
                        # and sends the related response to peer
                        if db.is_account_online(message[1]):
                            peer_info = db.get_peer_ip_port(message[1])
                            response = "search-success " + peer_info[0] + ":" + peer_info[1]
                            logging.info(
                                "Send to "
                                + self.ip
                                + ":"
                                + str(self.port)
                                + " -> "
                                + response
                            )
                            self.tcp_client_socket.send(response.encode())
                        else:
                            response = "search-user-not-online"
                            logging.info(
                                "Send to "
                                + self.ip
                                + ":"
                                + str(self.port)
                                + " -> "
                                + response
                            )
                            self.tcp_client_socket.send(response.encode())
                    # enters if username does not exist
                    else:
                        response = "search-user-not-found"
                        logging.info(
                            "Send to "
                            + self.ip
                            + ":"
                            + str(self.port)
                            + " -> "
                            + response
                        )
                        self.tcp_client_socket.send(response.encode())
            except OSError as oErr:
                logging.error("OSError: {0}".format(oErr))

    # function for resettin the timeout for the udp timer thread
    def resetTimeout(self):
        self.udpServer.resetTimer()


class UDPServer(Thread):
    # udp server thread initializations
    def __init__(self, username: str, client_socket: socket):
        Thread.__init__(self)
        self.username = username
        # timer thread for the udp server is initialized
        self.timer = Timer(3, self.wait_for_hello)
        self.tcp_client_socket = client_socket

    # if hello message is not received before timeout
    # then peer is disconnected
    def wait_for_hello(self):
        if self.username is not None:
            db.user_logout(self.username)
            if self.username in tcp_threads:
                del tcp_threads[self.username]
        self.tcp_client_socket.close()
        print("Removed " + self.username + " from online peers")

    # resets the timer for udp server
    def reset_timer(self):
        self.timer.cancel()
        self.timer = Timer(3, self.wait_for_hello)
        self.timer.start()
