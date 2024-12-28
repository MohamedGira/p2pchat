import __init__
from p2pchat.protocols.suap import SUAP_Response
from p2pchat.server.request_handler import handler_factory


class AuthenticationManager:
    """Handles the authentication-related requests from the clients.

    1. Registration
    2. Login
    3. Logout

    Threading was used to handle many concurrent requests along with
    handle_request(request). This class is not responsible for sending
    the response to the client, it only handles the requests and returns
    the SUAP_Reponse object. The server will then interact with the class
    to extract the required data and abstract it to the client.

    A request is a dictionary with the following form:
    >>> req = {
    ...     "header": <<header_info>>,
    ...     "data": {
    ...         "type": <<request_type>>,
    ...         "username": <<username>>
    ...         ...
    ...     }
    ... }
    """

    types = {
        "RGST",
        "LOGN",
        "LGDN",
        "CLRS",
        "GTOP",
        "CRTM",
        "LISTRM",
        "ADMTUSR",
        "GTRM",
        "PBKY"
    }

    def __init__(self, connection_address):
        self.connection_address = connection_address
        self.type = None

    def handle_request(self, request) -> SUAP_Response:
        """
        parses the recieved request and handle it accordingly
        """
        if (
            not request.get("body", {}).get("type")
            or request.get("body", {}).get("type") not in self.types
        ):
            raise Exception("handle_request: Invalid Request")
        request_handler = handler_factory(request.get("body").get("type"))
        return request_handler.handle_request(self.connection_address, request)


if __name__ == "__main__":
    AM = AuthenticationManager(("localhost", 8000))
    print(
        AM.handle_request(
            {
                "header": "",
                "data": {"type": "RGST", "username": "user", "password": "pass"},
            }
        )
    )
    print(
        AM.handle_request(
            {
                "header": "",
                "data": {"type": "LOGN", "username": "user", "password": "pass"},
            }
        )
    )
    print(
        AM.handle_request({"header": "", "data": {"type": "LGDN", "username": "user"}})
    )
    print(
        AM.handle_request({"header": "", "data": {"type": "CLRS", "username": "user"}})
    )
