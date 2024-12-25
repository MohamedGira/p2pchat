import __init__
import traceback
import threading
import socket
import pickle
from time import sleep
from tabulate import tabulate
from typing import Union

from p2pchat.protocols.tcp_request_transceiver import (
    TCPRequestTransceiver,
    TCPRequestSecureTransciver,
)
from p2pchat.protocols.suap import SUAP_Request
from p2pchat.protocols.s4p import S4P_Request
from p2pchat.utils.colors import colorize
from p2pchat.utils.chat_history import (
    print_and_remember,
    print_in_constant_place,
    history,
)
from p2pchat.data import port_tcp, port_udp
import logging

# logging.basicConfig(level=logging.DEBUG)
from p2pchat.custom_logger import app_logger  # may use different loggers later
from p2pchat.globals import not_chatting, peer_left, ignore_input, is_in_chat
from p2pchat.utils.utils import validate_request
from p2pchat.security import security_manager


class KeepAliveThread(threading.Thread):
    """
    thread classs for the HELLO PULSE request, it sends a HELLO (LGDN) message every 20 seconds to the server
    ---if peer is signed in---
    """

    def __init__(self, server_address, server_port, interval=4, user=None):
        super().__init__()
        self.server_address = server_address
        self.server_port = server_port
        self.interval = interval
        self.user = user
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.shutdown_flag = threading.Event()

    def run(self):
        logging.info(f"UDP client thread started")
        while not self.shutdown_flag.is_set():
            try:
                if self.user:
                    message = pickle.dumps(
                        {
                            "header": "",
                            "body": SUAP_Request.is_logged_in_request(
                                self.user.get("username"), "whatever"
                            ),
                        }
                    )

                    self.client_socket.sendto(
                        message, (self.server_address, self.server_port)
                    )
                sleep(self.interval)
            except Exception as e:
                print("Exception Occued: ", traceback.print_exc(e))
                return None

    def stop(self):
        self.shutdown_flag.set()


class ClientUDPThread(threading.Thread):
    pass


class ClientTCPThread:
    """
    Responsible for establishing connections, sending the request,then recieving the response.
    for now, its a nonpersistent connection, single request/response cycle?

    """

    # TODO: change the name or make it a real thread
    def __init__(self, server_address, server_port):
        self.server_address = server_address
        self.server_port = server_port
        self.transceiver = TCPRequestTransceiver(None)
        self.client_auth = ClientAuth()  # instance

    def connect(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.server_address, self.server_port))
            self.transceiver.connection = self.client_socket
            return True
        except ConnectionRefusedError:
            app_logger.warning("Connection refused. Server may not be available.")
        except TimeoutError:
            app_logger.warning("Connection attempt timed out.")
        except OSError as e:
            app_logger.error("socket is already connected:", e)
            return True
        except Exception as e:
            app_logger.error("An error occurred during connection:", e)
        return False

    def login(self, username, password, tcp_port, udp_port):
        if not (self.connect()):
            return {
                "header": "",
                "body": {"is_success": False, "message": "Connection failed"},
            }
        self.transceiver.send_message(
            SUAP_Request.logn_request(username, password, tcp_port, udp_port)
        )
        response = self.transceiver.recieve_message()
        self.client_socket.close()
        return response

    def signup(self, username, password):
        if not (self.connect()):
            return {
                "header": "",
                "body": {"is_success": False, "message": "Connection failed"},
            }
        self.transceiver.send_message(SUAP_Request.rgst_request(username, password))
        response = self.transceiver.recieve_message()
        self.client_socket.close()
        return response

    def logout(self, username):
        if not (self.connect()):
            return {
                "header": "",
                "body": {"is_success": False, "message": "Connection failed"},
            }
        self.transceiver.send_message(
            SUAP_Request.clear_session_request(username, "whatever")
        )
        response = self.transceiver.recieve_message()
        self.client_socket.close()
        return response

    def get_online_peers(self):
        if not (self.connect()):
            return {
                "header": "",
                "body": {"is_success": False, "message": "Connection failed"},
            }
        self.transceiver.send_message(
            {"type": "GTOP", "username": self.client_auth.user["username"]}
        )
        response = self.transceiver.recieve_message()
        self.client_socket.close()
        return response

    def get_chatroom(self, chatroom_key):
        if not (self.connect()):
            return {
                "header": "",
                "body": {"is_success": False, "message": "Connection failed"},
            }
        self.transceiver.send_message(
            S4P_Request.gtrm_request(self.client_auth.user, chatroom_key)
        )
        response = self.transceiver.recieve_message()
        self.client_socket.close()
        return response


def requires_signin(func):
    def wrapper(self, *args, **kwargs):
        if getattr(self, "user", None) is not None:
            return func(self, *args, **kwargs)
        else:
            print(
                colorize(
                    f"Operation Reqires user to be logged in,{self.to_dict()}", "red"
                )
            )
            return {
                "header": "",
                "body": {"is_success": False, "message": "User not logged in"},
            }

    return wrapper


class ClientAuth:
    _clientAuth = None

    def __new__(cls):
        if not cls._clientAuth:
            cls._clientAuth = super().__new__(cls)
            cls._clientAuth._initialized = False
        return cls._clientAuth

    def __init__(self):
        if not self._initialized:
            self._initialized = True
            self.user = None
            self.available_rooms = []  # all chatrooms, updated by a thread
            self.current_chatroom = None
            self.current_chatroom_peers = None
            self.client_tcp_thread = ClientTCPThread("127.0.0.1", port_tcp)
            self.keep_alive_thread = None

    def login(self, username: str, password: str, tcp_port: int, udp_port=None) -> dict:
        """
        takes username and password, sends a login request to the server, and returns the response
        if request is successful, keep alive thread is started, user is returnred in client.user object.
        response dictionary is returnred as well
        """
        response = self.client_tcp_thread.login(username, password, tcp_port, udp_port)
        if response.get("body", {}).get("is_success"):
            self.user = response.get("body").get("data")
            self.keep_alive_thread = KeepAliveThread(
                "127.0.0.1", port_udp, user=self.user
            )
            self.keep_alive_thread.user = self.user
            self.keep_alive_thread.start()
        else:
            logging.info(f"Failed to login: {response.get('body',{}).get('message')}")
        return response

    def signup(self, username: str, password: str) -> dict:
        """
        takes username and password, sends a signup request to the server, and returns the response in {header:"",body:{}} format
        """
        return self.client_tcp_thread.signup(username, password)

    def logout(self):
        """
        sends a logout request to the server, and returns the response in {header:"",body:{}} format
        """
        self.client_tcp_thread.logout(self.user.get("username"))
        self.keep_alive_thread.stop()
        self.user = None
        self.keep_alive_thread.user = None

    def get_online_peers(self):
        """
        sends a get online peers request to the server, and returns the response in {header:"",body:{}} format
        """

        if not self.user:
            print(colorize("User not logged in", "red"))
            return {
                "header": "",
                "body": {"is_success": False, "message": "User not logged in"},
            }

        response = self.client_tcp_thread.get_online_peers()
        if response.get("body", {}).get("is_success"):
            return response.get("body", {}).get("data", {}).get("users", [])
        else:
            print(f"Failed to find peers: {response.get('body',{}).get('message')}")
            return []

    @requires_signin
    def create_chatroom(self, chatroom_key):
        response = self.client_tcp_thread.create_chatroom(chatroom_key)
        if response.get("body", {}).get("is_success"):
            print(colorize("Chat room created successfully", "green"))
        else:
            print(
                colorize(
                    f"Chat room creation failed. {response.get('body',{}).get('message')}",
                    "red",
                )
            )

    @requires_signin
    def get_chatrooms(self) -> list:
        response = self.client_tcp_thread.get_chatrooms()

        if response.get("body", {}).get("is_success"):
            self.available_rooms = (
                response.get("body", {}).get("data", {}).get("rooms", [])
            )

        return self.available_rooms

    @requires_signin
    def admit_user_to_chatroom(self, user, chatroom_key):
        """called by room owner to admit a user to a chatroom"""
        return self.client_tcp_thread.admit_user_to_chatroom(user, chatroom_key)

    @requires_signin
    def get_chatroom(self, chatroom_key) -> Union[None, list]:
        # get most recent chatroom members info
        return self.client_tcp_thread.get_chatroom(chatroom_key)

    @requires_signin
    def update_room_local_table(self, user):
        history.clear_volatile_messages()
        for i, member in enumerate(self.current_chatroom_peers):
            if member.get("username") == user.get("username"):
                self.current_chatroom_peers[i] = self.update_chatroom_entry(
                    member, user
                )
                return
        # user is new, update local table
        self.current_chatroom_peers = self._get_chatroom_table(self.current_chatroom)

    @requires_signin
    def _get_chatroom_table(self, chatroom_key):
        response = self.get_chatroom(chatroom_key)
        other_members = []
        if response.get("body", {}).get("is_success"):
            chatroom_members = (
                response.get("body", {}).get("data", {}).get("members", [])
            )  # array of user dicts
            other_members = [
                member
                for member in chatroom_members
                if member.get("username") != self.user.get("username")
            ]
        else:
            print(
                colorize(
                    f"Chat room entry failed. {response.get('body',{}).get('message')}",
                    "red",
                )
            )
            return None
        return other_members

    def update_chatroom_entry(self, entry, user):
        for i in ["IP", "PORT", "PORT_UDP", "is_active"]:
            entry[i] = user[i]
        return entry


class PeerClient:
    """connect to other client to send requests
    will probably change to static"""

    def __init__(self):
        self.peer_socket = None
        self.transceiver = TCPRequestSecureTransciver(self.peer_socket)
        self.client_auth_instance = ClientAuth()

    def enter_chat(self, me, recepient):
        """
        return chat room key if successful, else
        """
        if not (self.connect(recepient)):
            print(colorize("could not connect to user", "red"))
            return None
        key = security_manager.KeyExchange().initiate_exchange()
        self.transceiver.send_message(
            S4P_Request.privrm_request(self.client_auth_instance.user, recepient, key)
        )
        response = self.transceiver.recieve_message()
        if response and response.get("body").get("code") == 57:
            security_manager.KeyExchange().complete_exchange(
                peer_public_key_bytes=response.get("body").get("data").get("key"),
                encrypted_fernet_key= response.get("body").get("data").get("symmetric_key")
            )
        ##exchange keys here
        return PeerClient.process_response(response)

    def chat(self, me, recipient, chat_key):
        """
        will handle all messaging related stuff
        """
        # user started chatting, used to pause the cli loop
        # TODO: remove self.client_auth_instance.user, use client_auth_instance.user instead
        try:
            me_prompt_text = "you >> "
            not_chatting.clear()
            peer_left.clear()
            is_in_chat.set()
            print_and_remember(
                colorize(f"Chat started with {recipient.get('username')}", "green"),
                colorize("write exit_ to exit", "magenta"),
            )
            while not not_chatting.is_set():  # I know...
                if not ignore_input.is_set():
                    if not (self.connect(recipient)):
                        # won't work if outside the loop
                        print(colorize("could not connect to user", "red"))
                        return None
                    message = input(me_prompt_text)
                    if ignore_input.is_set():
                        continue
                    # if chat endded ignore the input
                    if peer_left.is_set():
                        not_chatting.set()
                        break
                    self.transceiver.send_message(
                        S4P_Request.sndmsg_smpl_request(
                            message, chat_key, self.client_auth_instance.user, recipient
                        )
                    )
                    if message == "exit_":
                        is_in_chat.clear()
                        history.reset_history()
                        security_manager.SecurityManager().reset()
                        security_manager.KeyExchange().reset()
                        print(colorize(f"You left the conversation.", "green"))
                        break
                    print_and_remember(
                        colorize(
                            f"{self.client_auth_instance.user['username']} >> ", "green"
                        )
                        + message
                    )
        finally:
            not_chatting.set()
            peer_left.set()
            print(
                colorize(
                    f"Chat ended with {recipient.get('username')}  Press enter to continue.",
                    "magenta",
                )
            )

    def _refresh_uses_table(self):
        print_and_remember("?")
        while not not_chatting.is_set():
            active_usersnames = [
                colorize(i.get("username"), "green")
                for i in self.client_auth_instance.current_chatroom_peers
                if i.get("is_active")
            ]
            offline_usersnames = [
                colorize(i.get("username"), "red")
                for i in self.client_auth_instance.current_chatroom_peers
                if not i.get("is_active")
            ]
            print_in_constant_place(
                tabulate(
                    [[", ".join(active_usersnames), ", ".join(offline_usersnames)]],
                    headers=["ACTIVE USERS", "OFFLINE USERS"],
                    tablefmt="pretty",
                ),
                key="peers status",
                ending_line="you >> ",
            )
            sleep(5)

    def connect(self, user):
        try:
            # before connecting to someone, make sure to close any previous connection
            self.disconnect()
            self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.peer_socket.connect((user["IP"], user["PORT"]))
            self.transceiver.connection = self.peer_socket
            return True
        except ConnectionRefusedError:
            logging.warning(
                f"Connection refused. Server at {user['IP']}:{user['PORT']} may not be available."
            )
        except TimeoutError:
            logging.warning("Connection attempt timed out.")
        except OSError as e:
            logging.error("socket is already connected:", e)
            return True
        except Exception as e:
            logging.error("An error occurred during connection:", e)
        return True

    def disconnect(self):
        try:
            self.peer_socket.close()
            self.peer_socket = None
        except Exception as e:
            logging.debug(f"An error occurred during disconnection: {e}")
            pass

    @staticmethod
    def process_response(response):
        if not response:
            print(colorize("empty response", "red"))
            return None
        message = response.get("body", {}).get("message", None)
        if not response or not response.get("body", {}).get("is_success"):
            print(colorize(message if message else "request failed", "red"))
            input(colorize("\n\nPress enter to go back to continue.", "yellow"))
        else:
            print(colorize(message if message else "request succeeded", "green"))

        return response
