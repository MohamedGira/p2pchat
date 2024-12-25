import pickle
import logging
import socket
import json
from p2pchat.utils.colors import colorize
from p2pchat.data import header_size, max_udp_packet_size
from p2pchat.security import security_manager
from p2pchat.utils.utils import exception_wrapper

class RequestTransceiver:
    header_size = header_size
    max_udp_packet_size = max_udp_packet_size
    packet_size = max(20, header_size)

    def __init__(self):
        self.message = None
        self.full_message = None
        self.new_message = True
        self.message_length = None

    def recieve_message(self) -> dict:
        raise NotImplementedError

    def send_message(self, message: dict):
        raise NotImplementedError

    @staticmethod
    def _gather_message(dest=None, message=None):
        if message is None:
            return dest
        if dest is None:
            dest = message
        else:
            dest += message
        return dest

    @staticmethod
    def _add_header(message: any) -> bytes:
        raise NotImplementedError


class TCPRequestTransceiver(RequestTransceiver):
    """
    this is intended to be a class that wraps the socket.recv/socket.send TCP functions
    it will be used to:
    1-send and recieve requests/responses to/from  the server

    *** the messages will be in the form of a dictionary (can be actually any picklable object but naah)***
    usage:
    send_message(message:dict)->None
    recieve_message()->dict or None
    """

    def __init__(self, connection: socket.socket):
        super().__init__()
        self.connection = connection

    def recieve_message(self) -> dict:
        """Recieve message from the server

        Returns:
            dict: message recieved
        """
        try:
            if self.new_message:
                header = self.connection.recv(self.header_size)
                if not len(header):
                    return None
                self.message_length = int(header)
                self.new_message = False
            while True:
                self.full_message = self._gather_message(
                    self.full_message, self.connection.recv(self.packet_size)
                )
                if len(self.full_message) > self.message_length:
                    logging.WARN("hmmm, check this out")
                if len(self.full_message) == self.message_length:
                    self.message = pickle.loads(self.full_message)
                    break
            self.full_message = None
            self.new_message = True
            return {"header": header, "body": self.message}
        except Exception as e:
            print("Connection broken: ", e)
            return None

    @staticmethod
    def _add_header(message: bytes) -> bytes:
        """Add header to the message

        Args:
            message (bytes): message to be sent
        """
        message_size = f"{len(message):<{TCPRequestTransceiver.header_size}}"
        return bytes(message_size, "utf-8") + message

    def send_message(self, message: dict):
        """Send message to the server

        Args:
            message (dict): message to be sent
        """
        #print("message", message)
        message_in_bytes = pickle.dumps(message)
        self.connection.send(self._add_header(message_in_bytes))


class UDPRequestTransceiver(RequestTransceiver):
    def __init__(self, receiving_socket=None):
        """Initialize the UDPRequestTransceiver

        Args:
            receiving_socket (socket.socket, optional): socket to recieve messages from. Defaults to None.
        """
        super().__init__()
        self.sender_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.receiving_socket = receiving_socket

    def recieve_message(self) -> dict:
        """Recieve message from the receiving socket

        Returns:
            dict: message recieved
        """
        if not self.receiving_socket:
            print(colorize("No receiving socket", "yellow"))
            return None
        message, address = self.receiving_socket.recvfrom(
            RequestTransceiver.max_udp_packet_size
        )
        message_in_bytes = pickle.loads(message)
        return message_in_bytes, address

    @staticmethod
    def _add_header(message: dict) -> bytes:
        """Add header to the message

        Args:
            message (dict): message to be sent

        Returns:
            dict: message with header
        """
        message = {
            "header": f"{len(message):<{RequestTransceiver.header_size}}",
            "body": message,
        }

        return message

    def send_message(self, message: dict, dest):
        """Send message to destination

        Args:
            message (dict): message to be sent
            dest (tuple): destination address
        """
        message_in_bytes = pickle.dumps(self._add_header(message))

        if len(message_in_bytes) > RequestTransceiver.max_udp_packet_size:
            print(
                colorize(
                    f"Message too large to send over UDP,Max allowed size {RequestTransceiver.max_udp_packet_size}, message size {len(message_in_bytes)}",
                    "red",
                )
            )
        self.sender_socket.sendto(message_in_bytes, dest)


class TCPRequestSecureTransciver(TCPRequestTransceiver):
    """
    this is intended to be a class that wraps the socket.recv/socket.send TCP functions
    it will be used to:
    1-send and recieve requests/responses to/from  the server

    *** the messages will be in the form of a dictionary (can be actually any picklable object but naah)***
    usage:
    send_message(message:dict)->None
    recieve_message()->dict or None
    """

    def __init__(self, connection: socket.socket):
        super().__init__(connection)
    @exception_wrapper
    def recieve_message(self) -> dict:
        """Recieve message from the server

        Returns:
            dict: message recieved
        """
        if (
            security_manager.KeyExchange().peer_public_key is None
            or security_manager.KeyExchange().peer_fernet_key is None
        ):
            return super().recieve_message()
        received_message = super().recieve_message()
        
        import ast
        return {
                "header": received_message["header"],
                "body": ast.literal_eval(
                    security_manager.SecurityManager().decrypt_message(
                        received_message["body"],
                        security_manager.KeyExchange().peer_public_key_bytes,
                    )
                ),
            }
    @exception_wrapper
    def send_message(self, message: dict):
        """Send message to the server

        Args:
            message (dict): message to be sent
        """
        if (
            security_manager.KeyExchange().peer_public_key is None
            or security_manager.KeyExchange().peer_fernet_key is None
        ):
            super().send_message(message)
            return
        message_in_bytes = pickle.dumps(
            security_manager.SecurityManager().encrypt_message(str(message))
        )
        self.connection.send(self._add_header(message_in_bytes))
