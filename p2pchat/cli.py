import __init__
from tabulate import tabulate
from time import sleep
import uuid
import logging
from pwinput import pwinput

from p2pchat.custom_logger import app_logger
from p2pchat.peer.peer_client import PeerClient, ClientAuth
from p2pchat.peer.peer_server import PeerServer
from p2pchat.utils.colors import colorize
from p2pchat.utils.chat_history import history, print_and_remember, clear_console
from p2pchat.globals import not_chatting, ignore_input

logging.basicConfig(level=logging.DEBUG)

IDLE_WAIT = 1  # change to 3 for slower changing between screens


MAIN_MENU_TEXT = f"""
{colorize(f'{colorize("Welcome to Our chat", "bold")} - {colorize("Main Menu", "bold")}', 'underline')}

Choices:
    {colorize('1', 'green')}. List online users
    {colorize('2', 'green')}. Send a private message
    {colorize('3', 'red')}. Logout
"""


def show_profile(username, id, communicated_with):
    print(f"Username: {username}")
    print(f"ID: {id}")

    communicated_with = communicated_with

    if communicated_with:
        print("Users You've Chat With:")
        for user in communicated_with:
            print(user)
    else:
        print("No chat history yet.")


def print_menu(choice):
    if choice == "chatroom_menu":
        print(
            f"""
{colorize('Create a chatroom', 'yellow')}

{colorize('Enter chatroom name to create: ', 'green')}""",
            end="",
        )


class App:
    def __init__(self):
        self.client_auth = ClientAuth()
        self.incorrect_attempt = {"incorrect_attempt": 0}
        self.active_peers = []
        self.client_auth.available_rooms = []
        self.peer_server = None
        self.peer_client = None

    def welcome_state(self):
        clear_console()
        print(colorize(colorize("Welcome to Our chat", "underline"), "magenta"))
        print()
        has_account = input(
            f"Do you have an account? ({colorize('y', 'green')}/{colorize('n', 'red')}): "
        )

        while has_account not in ["y", "n"]:
            clear_console()
            print(
                colorize("Please enter a valid response, as", "yellow"),
                colorize(f"{has_account}", "red"),
                colorize("is not a valid response", "yellow"),
            )
            has_account = input("Do you have an account? (y/n): ")

        if has_account in ["y", "n"]:
            return {"y": "Login", "n": "Sign Up"}[has_account]

    def login_state(self):
        if self.client_auth.user is not None:
            return "Main Menu"

        if (
            "incorrect_attempt" in self.incorrect_attempt
            and self.incorrect_attempt["incorrect_attempt"] >= 3
        ):
            print(colorize("Account locked. Try again in 1 minute.", "red"))
            return None

        if (
            "incorrect_attempt" in self.incorrect_attempt
            and self.incorrect_attempt["incorrect_attempt"]
        ):
            print(colorize("Incorrect username or password", "red"))
            print()

        if self.incorrect_attempt["incorrect_attempt"] > 0:
            print(
                colorize("Type ", "magenta")
                + colorize("!exit", "red")
                + colorize(" if you want to go back to the previous menu", "magenta")
            )
        username = input("Username: ")

        if username == "!exit":
            return "Welcome"

        password = pwinput("Password: ")

        self.peer_server = PeerServer()
        self.peer_client = PeerClient()

        response = self.client_auth.login(
            username,
            password,
            self.peer_server.tcp_manager.port,
        )
        if response.get("body", {}).get("is_success"):
            self.peer_server.start()
            self.peer_server.set_user(self.client_auth.user)
            self.incorrect_attempt["incorrect_attempt"] = 0

            print(colorize(f"Welcome {username}!", "green"))

            return "Main Menu"
        else:
            self.incorrect_attempt["incorrect_attempt"] = (
                self.incorrect_attempt.get("incorrect_attempt", 0) + 1
            )
            return "Login"

    def signup_state(self):
        print(colorize("Create an account!", "yellow"))

        print(
            colorize(
                "Type '!exit' if you want to go back to the previous menu", "magenta"
            )
        )
        username = input("Username: ")
        if username == "!exit":
            return "Welcome"
        password = pwinput("Password: ")

        """ if not re.match(r"^\w+@\w+\.\w+$", email):
            print("Invalid email address.")
            return "Sign Up" """

        """ if len(password) < 6:
            print("Invalid password. Password must be at least 6 digits long.")
            return "Sign Up" """
        response = self.client_auth.signup(username, password)
        app_logger.debug(response)
        if response.get("body", {}).get("is_success") == False:
            print(response.get("body", {}).get("message"))
            return "Sign Up"

        print(
            colorize(
                f"Account created successfully! You will be redirected in {IDLE_WAIT} seconds.",
                "green",
            )
        )

        return "Welcome"

    def menu_state(self):
        print(MAIN_MENU_TEXT)

        choice = input("Please enter your choice: ")
        if choice == "1":
            return "list users"
        elif choice == "2":
            return "send msg"
        elif choice == "3":
            return "exit"
        else:
            return "Main Menu"


    def send_msg_state(self):
        recipient_username = input("Enter the username of the recipient: ")
        if recipient_username not in [user["username"] for user in self.active_peers]:
            self.active_peers = self.client_auth.get_online_peers()
            if recipient_username not in [
                user["username"] for user in self.active_peers
            ]:
                print(
                    "User with username",
                    recipient_username,
                    "is either offline or not found.",
                )
                return "Main Menu"
        user = next(
            user for user in self.active_peers if user["username"] == recipient_username
        )
        self.recipient = user
        history.reset_history()
        response = self.peer_client.enter_chat(self.client_auth.user, user)
        if response and response.get("body").get("code") == 57:  # shof tare2a a7san
            key = response.get("body").get("data").get("key")

            self.peer_server.setup_chat(key)
            # print_and_remember(colorize("you are the client", "blue"))
            self.peer_client.chat(self.client_auth.user, user, key)
            self.peer_server.end_chat()
        else:
            print(colorize("couldn't connect", "red"))
        return "Main Menu"

    def list_state(self):
        clear_console()
        online_users = self.client_auth.get_online_peers()
        print(colorize("List of online users", "yellow"))

        if len(online_users):
            self.active_peers = online_users
            for user in online_users:
                print(f"- {user['username']}")
        else:
            print("No users are currently online.")

        input(colorize("\n\nPress enter to go back to the main menu.", "yellow"))
        return "Main Menu"

    def exit_state(self):
        self.client_auth.logout()
        self.peer_server.stop()

        print("Goodbye!")
        return "Welcome"

    def main(self):
        state = "Welcome"
        while True:
            not_chatting.wait()
            if ignore_input.is_set():
                continue
            if state == "Welcome":
                next_state = self.welcome_state()
            elif state == "Login":
                next_state = self.login_state()
            elif state == "Sign Up":
                next_state = self.signup_state()
            elif state == "Main Menu":
                next_state = self.menu_state()
                if next_state == "send msg":
                    next_state = self.send_msg_state()
                elif next_state == "list users":
                    next_state = self.list_state()
                elif next_state == "exit":
                    next_state = self.exit_state()
            elif next_state is None:
                if self.client_auth.user is not None:
                    next_state = "Main Menu"
                else:
                    # sleep(2)
                    self.incorrect_attempt["incorrect_attempt"] = 0
                    next_state = "Login"

            sleep(IDLE_WAIT)
            if not ignore_input.is_set():
                pass
                clear_console()
            state = next_state


if __name__ == "__main__":
    while True:
        my_app = App()
        my_app.main()
