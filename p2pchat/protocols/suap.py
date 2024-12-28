import __init__


class SUAP_Response:
    success_codes = {
        10: ("NEWLOG", "login is successful"),
        11: ("OLDLOG", "user is already logged in"),
        12: ("NEWREG", "register is successful"),
        13: ("LGDOUT", "logout is successful"),
    }

    failure_codes = {
        20: ("MSMTCH", "username-password mismatch"),
        21: ("CNFLCT", "username already exists in database"),
        22: ("UNKACC", "username wasn't found in database"),
        23: ("INTCPT", "the request seems to be intercepted"),
        24: ("LGDOUT", "user is not logged in"),
    }
    error_codes = {
        30: ("ENTRNL", "internal server error"),
    }
    all_codes = {
        **success_codes,
        **failure_codes,
        **error_codes,
    }

    @staticmethod
    def get_code(str_code: str) -> int:
        """Returns the int code from the str code, -1 otherwise"""
        # Search for the code
        for code, (str_code_, code_def) in SUAP_Response.all_codes.items():
            if str_code_ == str_code:
                return code

        # Otherwise
        raise NotImplementedError(f"Code {str_code} is not currently supported")

    @staticmethod
    def render_code(str_code: str) -> str:
        # Get the code
        code = SUAP_Response.get_code(str_code)

        alias, description = SUAP_Response.all_codes[code]

        return f"{code} {alias} when {description.lower()}"

    def __init__(self, code: int, message: str, is_success: bool, data=None) -> None:
        self.code = code
        self.message = message
        self.is_success = is_success
        self.data = data if isinstance(data, dict) else {}

    @staticmethod
    def NEWLOG(message: str, data) -> "SUAP_Response":
        return SUAP_Response(10, message, True, data)

    @staticmethod
    def ENTRNL(message: str, data=None) -> "SUAP_Response":
        return SUAP_Response(30, message, False, data)

    @staticmethod
    def OLDLOG(message: str) -> "SUAP_Response":
        return SUAP_Response(11, message, True)

    @staticmethod
    def NEWREG(message: str) -> "SUAP_Response":
        return SUAP_Response(12, message, True)

    @staticmethod
    def PBKEY(message: str,data) -> "SUAP_Response":
        return SUAP_Response(10, message, True,data)
    
    @staticmethod
    def LGDOUT(message: str) -> "SUAP_Response":
        return SUAP_Response(13, message, True)

    @staticmethod
    def MSMTCH(message: str) -> "SUAP_Response":
        return SUAP_Response(20, message, False)

    @staticmethod
    def CNFLCT(message: str) -> "SUAP_Response":
        return SUAP_Response(21, message, False)

    @staticmethod
    def UNKACC(message: str) -> "SUAP_Response":
        return SUAP_Response(22, message, False)

    @staticmethod
    def INTCPT(message: str) -> "SUAP_Response":
        return SUAP_Response(23, message, False)

    def __str__(self) -> str:
        return f"{self.code} {self.message}"

    def __repr__(self) -> str:
        return f"<SUAP_Response code={self.code} message={self.message} is_success={self.is_success} data={self.data}>"

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "message": self.message,
            "is_success": self.is_success,
            "data": self.data,
        }

    @staticmethod
    def init_from_dict(data: dict) -> "SUAP_Response":
        return SUAP_Response(
            data["code"], data["message"], data["is_success"], data["data"]
        )


"""
I think this class should be responsible for preparing the soap request not handling them
Moved the functionalities within to the AuthenticationManager class
"""


class SUAP_Request:
    types = {"PBKY","RGST", "LOGN", "LGDN", "CLRS"}

    def __init__(self, connection):
        self.connection = connection
        self.type = None

    @staticmethod
    def pbky_request() -> dict:
        return {"type": "PBKY"}

    @staticmethod
    def rgst_request(username: str, password: str) -> dict:
        return {"type": "RGST", "username": username, "password": password}

    @staticmethod
    def logn_request(
        username: str, password: str, port_tcp: int, port_udp: int
    ) -> dict:
        return {
            "type": "LOGN",
            "username": username,
            "password": password,
            "tcp_port": port_tcp,
            "udp_port": port_udp,
        }

    @staticmethod
    def is_logged_in_request(username: str, key: str) -> dict:
        return {"type": "LGDN", "username": username, "key": key}

    @staticmethod
    def clear_session_request(username: str, key: str) -> dict:
        return {"type": "CLRS", "username": username, "key": key}
