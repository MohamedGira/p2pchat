import socket
import logging
import select
import threading
import traceback
from time import sleep

from p2pchat.server.server import SockerManager
from p2pchat.utils.colors import colorize
from p2pchat.utils.utils import validate_request, get_unique_id
from p2pchat.protocols.s4p import S4P_Response
from p2pchat.utils.chat_history import (
    history,
    print_and_remember,
    print_volatile_message,
)
from p2pchat.globals import is_in_chat, ignore_input, not_chatting, peer_left

from p2pchat.peer.peer_client import (
    PeerClient,
    ClientAuth,
)
from p2pchat.protocols.tcp_request_transceiver import (
    UDPRequestTransceiver,
    TCPRequestSecureTransciver,
)
from p2pchat.security import security_manager


class PeerTCPManager(SockerManager):
    def __init__(self, address):
        self.address = address
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((address, 0))
        self.port = self.socket.getsockname()[1]
        self.chat_thread = None
        self.chat_key = None
        self.user = None

    def handle_request(self):
        try:
            peer_socket, address = self.socket.accept()
            transciver = TCPRequestSecureTransciver(peer_socket)
            request = transciver.recieve_message()
            if request:
                if request.get("body", {}).get("type") == "PRIVRM":
                    res = self.handle_new_chat_request(request).to_dict()
                    if res.get("code") == 52:

                        security_manager.KeyExchange().complete_exchange(
                            peer_public_key_bytes=request.get("body").get("key"),
                        )
                        transciver.send_message(
                            S4P_Response.KEYXCHGD(
                                "key exchanged",
                                {
                                    "key": security_manager.SecurityManager().get_public_key_bytes(),
                                    "symmetric_key": security_manager.KeyExchange().encrypt_fernet_key(
                                        security_manager.SecurityManager().symmetric_key,
                                    ),
                                },
                            ).to_dict()
                        )
                    security_manager.KeyExchange().setup_peer_fernet(security_manager.SecurityManager().symmetric_key)
                    client = PeerClient()
                    self.chat_thread = threading.Thread(
                        target=client.chat,
                        args=(
                            self.user,
                            request.get("body").get("sender"),
                            self.chat_key,
                        ),
                    )
                    self.chat_thread.start()
                elif request.get("body", {}).get("type") == "SNDMSG":
                    res = self.handle_send_message_request(request).to_dict()
                    transciver.send_message(res)
        except Exception as e:
            print("Exception Occued: ", e, traceback.print_exc())
            return None

    def handle_new_chat_request(self, request):
        sender = request.get("body").get("sender").get("username")
        if is_in_chat.is_set():
            print_volatile_message(colorize(f"{sender} tried to contact you", "blue"))
            threading.Timer(5, history.clear_volatile_messages).start()
            return S4P_Response.RCPNTREF("Already in chat")
        if not validate_request(request["body"], ["sender", "recipient"]):
            return S4P_Response.INCRAUTH(
                "Invalid Request, Enter chat must have username"
            )
        print(f"Incoming request? Press enter to continue")
        ignore_input.set()
        not_chatting.clear()
        a = input(f"{sender} wants to chat with you? (y/n): ")
        while a not in ["y", "n"]:
            print(colorize("invalid input", "red"))
            a = input(f"{sender} wants to chat with you? (y/n): ")
        response = None
        if a == "y":
            is_in_chat.set()
            history.reset_history()
            key = get_unique_id()
            self.chat_key = key
            response = S4P_Response.CREATDRM(f"your request was accepted", {"key": key})
        elif a == "n":
            not_chatting.set()
            response = S4P_Response.RCPNTREF(
                f"your private room request has been rejected "
            )
        ignore_input.clear()
        return response

    def handle_send_message_request(self, request):
        """handles reciving message requests"""
        if not is_in_chat.is_set():
            print(colorize("can't send while user not in chat", "red"))
            return S4P_Response.UNKWNERR(f"can't send while user not in chat")

        # if not request or request.get("body", {}).get("key") != self.chat_key:
        #    print(colorize("Invalid Request, no or invalid key", "red"), request)
        #    return S4P_Response.INCRAUTH("Invalid Request, no or invalid key")

        sender = request.get("body", {}).get("sender").get("username", "unknown")
        message = request.get("body", {}).get("message", "")
        if message == "exit_":
            peer_left.set()
            self.end_chat()
            security_manager.SecurityManager().reset()
            security_manager.KeyExchange().reset()
            print(
                colorize(
                    f"{sender} left the conversation. Press enter to continue... ",
                    "green",
                )
            )
            return S4P_Response.MESGSENT(f"message recieved ;)", None)
        print_and_remember(
            f"{colorize(f'{sender} >> ', 'yellow')} {message}", ending_line="you >> "
        )
        return S4P_Response.MESGSENT(f"message recieved", None)

    def start_socket(self):
        self.socket.listen(20)

    def setup_chat(self, chat_key):
        self.chat_key = chat_key
        is_in_chat.set()
        not_chatting.clear()
        peer_left.clear()

    def end_chat(self):
        self.chat_key = None
        is_in_chat.clear()

    def deactivate(self):
        self.socket.close()

    def handle_join_room_request(self, request):
        if not request or not validate_request(
            request.get("body", {}), ["sender", "chatroom_key"]
        ):
            print(colorize("Invalid Request", "red"), request)
            return S4P_Response.INCRAUTH("Invalid Request, no or invalid key")

        sender = request.get("body", {}).get("sender", {})
        chatroom_key = request.get("body", {}).get("chatroom_key")
        print_volatile_message(f"Incoming request? Press enter to continue")
        ignore_input.set()
        a = input(
            colorize(
                f"{sender.get('username')} wants to join {chatroom_key}? (y/n): ",
                "blue",
            )
        )
        while a not in ["y", "n"]:
            print_volatile_message(colorize("invalid input", "red"))
            a = input(f"{sender.get('username')} wants to join {chatroom_key}? (y/n): ")
        res = None
        if a == "y":
            me_to_server_client = ClientAuth()
            response = me_to_server_client.admit_user_to_chatroom(sender, chatroom_key)
            if response.get("body").get("is_success"):
                print_volatile_message(
                    colorize(
                        f"{sender.get('username')} was added to chatroom \"{chatroom_key}\" successfully.",
                        "green",
                    )
                )
                res = S4P_Response.JOINEDRM(
                    f"your request was accepted", {"key": chatroom_key}
                )
            else:
                print_volatile_message(
                    colorize("couldn't admit user to chatroom.", "green")
                )
                res = S4P_Response.UNKWNERR(
                    f"Couldn't join chatroom, try again later, or may be you are already registerd"
                )
            sleep(2)
            history.clear_volatile_messages()
            print_and_remember("")
        else:
            res = S4P_Response.RCPNTREF(f"your private room request has been rejected ")
        ignore_input.clear()
        return res



class PeerServer(threading.Thread):
    def __init__(self, address="127.0.0.1"):
        super().__init__()
        self.tcp_manager = PeerTCPManager(address)
        self.peer_credentials = None
        logging.info(f"peer tcp port: {self.tcp_manager.port}")
        self.work_event = threading.Event()
        self.server_thread = None

    def set_user(self, user):
        self.tcp_manager.user = user

    def setup_chat(self, chat_key):
        self.tcp_manager.setup_chat(chat_key)
        self.tcp_manager

    def end_chat(self):
        self.tcp_manager.end_chat()

    def _activate(self):
        self.tcp_manager.start_socket()

    def _deactivate(self):
        self.tcp_manager.deactivate()

    def run(self):
        self.work_event.set()
        self._activate()
        socket_to_manager = {
            mngr.socket: mngr for mngr in [self.tcp_manager]
        }

        self.server_thread = threading.current_thread()

        socks = list(socket_to_manager.keys())
        while socks and self.work_event.is_set():
            try:
                readable, _, _ = select.select(socks, [], [], 1)
                for s in readable:
                    threading.Thread(target=socket_to_manager[s].handle_request).start()
            except OSError as e:
                logging.error(f"Error in select operation: {e}")
                break

    def stop(self):
        # Wait for the server thread to finish
        self.work_event.clear()

        if self.server_thread:
            self.server_thread.join()

        self._deactivate()
        for manager in [self.tcp_manager, self.udp_manager]:
            if manager.socket:
                manager.socket.close()
