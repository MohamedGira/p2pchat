import __init__
from p2pchat.protocols.base_protocol import BaseResponse


class S4P_Response(BaseResponse):
    """
    S4P Response
    """

    success_codes = {
        50: ("SYNCHACK", "synchronization is successful"),
        51: ("NOCHANGE", "local data is up to date"),
        52: ("CREATDRM", "room creation is successful"),
        53: ("JOINEDRM", "joining the room is successful"),
        54: ("RMSLISTS", "listing available rooms is successful"),
        55: ("MESGSENT", "message is sent"),
        56: ("MSGSAVED", "message is saved on the server"),
    }

    failure_codes = {
        70: ("INCRAUTH", "auth is incorrect, key mismatch"),
        71: ("UNKACCNT", "auth is incorrect, unknown username"),
        72: ("UNKNWNRM", "room ID was not found"),
        73: ("UNKRCPNT", "recipient doesn't exist"),
        731: ("RCPNTREF", "recipient refused connection"),
        74: ("RCPNTOFF", "recipient is offline"),
        75: ("RMNOTACK", "room ID was not found in the user's joined rooms"),
        76: ("ALLRMOFF", "all the members of the room are offline"),
        77: ("UNKNWNDR", "unknown directive"),
        78: ("ISIDLERM", "user is already inside the room"),
        79: ("UNKWNERR", "unknown error happened"),
    }

    all_codes = {**success_codes, **failure_codes}

    def __init__(self, code: int, message: str, is_success: bool, data=None):
        super().__init__(self.success_codes, self.failure_codes)
        self.code, self.message, self.is_success, self.data = (
            code,
            message,
            is_success,
            data if isinstance(data, dict) else {},
        )

    # success codes

    @staticmethod
    def SYNCHACK(message: str, data=None):
        return S4P_Response(50, message, True, data)

    @staticmethod
    def NOCHANGE(message: str, data=None):
        return S4P_Response(51, message, True, data)

    @staticmethod
    def CREATDRM(message: str, data=None):
        return S4P_Response(52, message, True, data)

    @staticmethod
    def JOINEDRM(message: str, data=None):
        return S4P_Response(53, message, True, data)

    @staticmethod
    def RMSLISTS(message: str, data=None):
        return S4P_Response(54, message, True, data)

    @staticmethod
    def MESGSENT(message: str, data=None):
        return S4P_Response(55, message, True, data)

    @staticmethod
    def MSGSAVED(message: str, data=None):
        return S4P_Response(56, message, True, data)

    @staticmethod
    def OK(message: str, data=None):
        return S4P_Response(57, message, True, data)

    # failure codes

    @staticmethod
    def INCRAUTH(message: str):
        return S4P_Response(70, message, False)

    @staticmethod
    def UNKACCNT(message: str):
        return S4P_Response(71, message, False)

    @staticmethod
    def UNKNWNRM(message: str):
        return S4P_Response(72, message, False)

    @staticmethod
    def UNKRCPNT(message: str):
        return S4P_Response(73, message, False)

    @staticmethod
    def RCPNTREF(message: str):
        return S4P_Response(731, message, False)

    @staticmethod
    def RCPNTOFF(message: str):
        return S4P_Response(74, message, False)

    @staticmethod
    def RMNOTACK(message: str):
        return S4P_Response(75, message, False)

    @staticmethod
    def ALLRMOFF(message: str):
        return S4P_Response(76, message, False)

    @staticmethod
    def UNKNWNDR(message: str):
        return S4P_Response(77, message, False)

    @staticmethod
    def ISIDLERM(message: str):
        return S4P_Response(78, message, False)

    @staticmethod
    def UNKWNERR(message: str):
        return S4P_Response(79, message, False)

    def __str__(self):
        return f"{self.code} {self.message}"

    def __repr__(self):
        return f"<S4P_Response code={self.code} message={self.message} is_success={self.is_success} data={self.data}>"

    def to_dict(self):
        return {
            "code": self.code,
            "message": self.message,
            "is_success": self.is_success,
            "data": self.data,
        }

    @staticmethod
    def init_from_dict(data: dict):
        return S4P_Response(
            data["code"], data["message"], data["is_success"], data["data"]
        )


class S4P_Request:
    # RECH <<username>> requests private chat with a user
    # - Returns 52 CREATDRM: If room creation is successful.
    # -
    # SYNCHR - Synchronize data
    # Syntax: SYNC <<username>> Synchronizes user's data from the server
    # - Returns 50 SYNCHACK: If the auth is correct.
    # - Returns 51 NOCHANGE: If the local data is up to date.
    # - Returns 70 INCRAUTH: If auth is incorrect, key mismatch.
    # - Returns 71 UNKACCNT: If auth is incorrect, unknown username.
    # RMCTRL - Room Control
    # Syntax: RMCTRL <<kind>>
    # Manipulates rooms, either listing, joining or creating by specifying kind as:
    # - MAKERM <<room_name>> - Creates a new room
    # - Returns 52 CREATDRM: If room creation is successful.
    # - Returns 79 UNKWNERR: If an unknown error happened.
    # - JOINRM <<auth>> <<room_id>> - Joins a room
    # - Returns 53 JOINEDRM: If the process of joining the room is successful.
    # - Returns 72 UNKNWNRM: If the room ID was not found
    # - Returns 78 ISIDLERM: If the user is already inside the room
    # - Returns auth errors
    # - LISTRM <<auth>> - Lists available rooms
    # - Returns 54 RMSLISTS: If auth is successful, shows all the rooms
    # - Returns auth errors
    # SNDMSG - Send a message
    # Syntax: SNDMSG <<auth>> <<type>> Sends a message to a specific directive
    # - PRIVRCP <<recipient>> - Sends a private message to a private recipient
    # - Returns 55 MESGSENT: If the message was sent.
    # - Returns 73 UNKRCPNT: If the recipient doesn't exist.
    # - Returns 74 RCPNTOFF: If the recipient is offline, should be accompanied by another request with type
    # PRIVSRVR.
    # - Returns auth errors.
    # - TOAVLRM <<room_id> - Sends a message to an available room
    # - Returns 55 MESGSENT: If the message was sent.
    # - Returns 75 RMNOTACK: If the room ID was not found in the user's joined rooms (but might exist
    # elsewhere).
    # - Returns 76 ALLRMOFF: If all the members of the room are offline, should be accompanied by another
    # request with type ROOMSRVR.
    # - Returns auth errors
    # - PRIVSVR <<recipient>> - Sends a private message to server
    # - Returns 56 MSGSAVED: If the message was saved on the server.
    # - Returns 73 UNKRCPNT: If the recipient doesn't exist.
    # - Returns auth errors
    # - TOPRVRM <<room_id>> - Sends a public room message to server
    # - Returns 56 MSGSAVED: If the message was saved on the server.
    # - Returns 75 RMNOTACK: If the room ID was not found in the user's joined rooms (but might exist
    # elsewhere).
    # - Returns auth errors
    types = {"SYNC", "RMCTRL", "SNDMSG", "PRIVRM"}

    def __init__(self, connection):
        self.connection = connection
        self.request_type = None

    @staticmethod
    def sync_request(username: str):
        return {
            "type": "SYNC",
            "username": username,
        }

    @staticmethod
    def rmctrl_request(
        kind: str, auth: str, room_id: str = None, room_name: str = None
    ):
        if kind == "MAKERM":
            return {
                "type": "RMCTRL",
                "kind": kind,
                "room_name": room_name,
            }
        elif kind == "JOINRM":
            return {
                "type": "RMCTRL",
                "kind": kind,
                "auth": auth,
                "room_id": room_id,
            }
        elif kind == "LISTRM":
            return {
                "type": "RMCTRL",
                "kind": kind,
                "auth": auth,
            }
        else:
            raise ValueError(f"Unknown kind {kind}")

    @staticmethod
    def privrm_request(sender, recipient):
        """p2p protocol"""
        return {
            "type": "PRIVRM",
            "sender": sender,
            "recipient": recipient,
        }

    @staticmethod
    def gtrm_request(sender, chatroom_key):
        """p2p protocol"""
        return {"type": "GTRM", "caller": sender, "chatroom_key": chatroom_key}

    @staticmethod
    def joinrm_request(sender, chatroom_key):
        """p2p protocol"""
        return {"type": "JOINRM", "sender": sender, "chatroom_key": chatroom_key}

    @staticmethod
    def sndmsg_smpl_request(message, key, sender, recepient=None):
        return {
            "type": "SNDMSG",
            "message": message,
            "key": key,
            "recipient": recepient,
            "sender": sender,
        }

    @staticmethod
    def sndmsg_request(
        message: str, auth: str, type_: str, recipient: str = None, room_id: str = None
    ):
        if type_ == "PRIVRCP":
            return {
                "type": "SNDMSG",
                "message": message,
                "auth": auth,
                "type": type_,
                "recipient": recipient,
            }
        elif type_ == "TOAVLRM":
            return {
                "type": "SNDMSG",
                "message": message,
                "auth": auth,
                "type": type_,
                "room_id": room_id,
            }
        elif type_ == "PRIVSVR":
            return {
                "type": "SNDMSG",
                "message": message,
                "auth": auth,
                "type": type_,
                "recipient": recipient,
            }
        elif type_ == "TOPRVRM":
            return {
                "type": "SNDMSG",
                "message": message,
                "auth": auth,
                "type": type_,
                "room_id": room_id,
            }
        else:
            raise ValueError(f"Unknown type {type_}")
