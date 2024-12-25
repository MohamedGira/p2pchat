import bcrypt

from p2pchat.protocols.suap import SUAP_Response
from p2pchat.protocols.s4p import S4P_Response
from p2pchat.utils.utils import validate_request

from p2pchat.server.server_db import myDB as DB


class RequestHandler:
    """
    class that is responsible for handling an incoming (SAUP) requests
    """

    @staticmethod
    def handle_request(connection_address, request) -> SUAP_Response:
        raise NotImplementedError


class RegisterationRequestHandler(RequestHandler):
    """
    class that is responsible for handling an incoming registeration request
    """

    def handle_request(connection_address, request) -> SUAP_Response:
        """
        parses the recieved request and handle it accordingly
        """
        if not validate_request(request["body"], ["username", "password"]):
            raise Exception(
                "Invalid Request, Registration mush have username and password"
            )
        username = request.get("body").get("username")
        password = request.get("body").get("password")
        # Check if account with such username already exists
        if DB.account_exists(username):
            return SUAP_Response.CNFLCT("Username already exists")

        DB.register_user(
            username, bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        )
        return SUAP_Response.NEWREG(f"Account {username} created successfully")


class LoginRequestHandler(RequestHandler):
    def handle_request(connection_address, request):
        f"""Logs in a user using username and password

        Returns
        -------
        SUAP_Response
            Returns a SUAP_Response with codes:
                {SUAP_Response.render_code("NEWLOG")}
                {SUAP_Response.render_code("OLDLOG")}
                {SUAP_Response.render_code("MSMTCH")}
                {SUAP_Response.render_code("UNKACC")}
        """
        if not validate_request(
            request["body"], ["username", "password", "tcp_port", "udp_port"]
        ):
            raise ValueError("Invalid Request, Login must have username and password")
        username = request.get("body").get("username")
        password = request.get("body").get("password")
        tcp_port = request.get("body").get("tcp_port")
        udp_port = request.get("body").get("udp_port")
        # Check if account with such username exists
        user = DB.find("users", {"username": username})
        if not len(user):
            return SUAP_Response.UNKACC(
                f"Username {username} doesn't exist, please register first"
            )
        user = user[0]
        # Check if the password is correct
        if not bcrypt.checkpw(password.encode("utf-8"), user["password"]):
            return SUAP_Response.MSMTCH(f"Invalid username or password")

        # Check if the user is already logged in
        user_logged_in = DB.find("users", {"is_active": 1, "username": username})
        if len(user_logged_in):
            user = user_logged_in[0]
            # Check if the user is logged in from the same address
            if user.get("IP") == connection_address[0]:
                return SUAP_Response.CNFLCT(f"User {username} is already logged in")

            # Logout the user from the previous address
            DB.logout(username)

            # Login the user using the current address
            DB.login(username, connection_address[0], tcp_port, udp_port)
            user = {
                **user,
                "IP": connection_address[0],
                "PORT": tcp_port,
                "PORT_UDP": udp_port,
                "is_active": 1,
            }

            # Return a Response object

            return SUAP_Response.NEWLOG(
                f"User {username} logged in successfully", data=user
            )

        # Log in the user
        DB.login(username, connection_address[0], tcp_port, udp_port)
        user = {
            **user,
            "IP": connection_address[0],
            "PORT": tcp_port,
            "PORT_UDP": udp_port,
            "is_active": 1,
        }

        # Return a Response object
        return SUAP_Response.NEWLOG(
            f"User {username} logged in successfully", data=user
        )


class IsLoggedRequestHandler(RequestHandler):
    def handle_request(connection_address, request):
        f"""
        Verifies the current login status of the client.
        maybe we can use this along with the HELLO message to refresh clients

        Returns
        -------
        SUAP_Response
            Returns a SUAP_Response with codes:
                {SUAP_Response.render_code("OLDLOG")}
                {SUAP_Response.render_code("INTCPT")}
                {SUAP_Response.render_code("UNKACC")}
        """
        if not validate_request(request["body"], ["username"]):
            raise ValueError("Invalid Request, Login check must have username")
        username = request.get("body").get("username")
        # Check if account with such username exists
        if not DB.account_exists(username):
            return SUAP_Response.UNKACC(
                f"Username {username} doesn't exist, please register first"
            )

        # Check if the user is already logged in
        user = DB.find("users", {"username": username, "is_active": 1})
        if len(user):
            user = user[0]
            # Check if the user is logged in from the same address
            if user["IP"] == connection_address[0]:
                DB.set_last_seen(username)
                return SUAP_Response.OLDLOG(f"User {username} is logged in")

            # Return a Response object
            return SUAP_Response.INTCPT(
                f"User {username} is not logged in from this address"
            )

        # Return a Response object that user is not logged in
        return SUAP_Response.LGDOUT(f"User {username} is not logged in")


class ClearSessionRequestHandler(RequestHandler):
    @staticmethod
    def handle_request(connection_address, request):
        f"""Clears the session of the user with the provided username.

        Returns
        -------
        SUAP_Response
            Returns a SUAP_Response with codes:
                {SUAP_Response.render_code("LGDOUT")}
                {SUAP_Response.render_code("INTCPT")}
                {SUAP_Response.render_code("UNKACC")}
                {SUAP_Response.render_code("LGDOUT")}
        """
        if not validate_request(request["body"], ["username"]):
            raise ValueError("Invalid Request, clearing session requires a username")
        username = request.get("body").get("username")
        # Check if account with such username exists
        if not DB.account_exists(username):
            return SUAP_Response.UNKACC(
                f"Username {username} doesn't exist, please register first"
            )

        # Check if the user is already logged in
        user = DB.find("users", {"username": username, "is_active": 1})
        if len(user):
            user = user[0]
            # Check if the user is logged in from the same address
            if user["IP"] == connection_address[0]:
                # Logout the user
                DB.logout(username)

                # Return a Response object
                return SUAP_Response.LGDOUT(f"User {username} logged out successfully")

            # Return a Response object
            return SUAP_Response.INTCPT(
                f"User {username} is not logged in from this address, please login first"
            )

        # Return a Response object that user is not logged in
        return SUAP_Response.LGDOUT(f"User {username} is not logged in")


class GetOnlinePeersHandler(RequestHandler):
    @staticmethod
    def handle_request(connection_address, request):
        if not validate_request(request["body"], ["username"]):
            raise ValueError(
                "Invalid Request, getting online peers requires a username"
            )
        users = DB.find("users", {"is_active": 1})
        for user in users:
            user.pop("password")
            if user["username"] == request["body"]["username"]:
                users.remove(user)
        return SUAP_Response.NEWLOG(f"Online users ", data={"users": users})







def handler_factory(request_type) -> RequestHandler:
    handlers = {
        "RGST": RegisterationRequestHandler,
        "LOGN": LoginRequestHandler,
        "LGDN": IsLoggedRequestHandler,
        "CLRS": ClearSessionRequestHandler,
        "GTOP": GetOnlinePeersHandler,
    }
    if request_type in handlers:
        return handlers.get(request_type)
    raise Exception("Request Type not supproted")
