import re
import time
import uuid  # Import the UUID module


def welcome_state():
    print("Welcome to Our chat")
    print()

    has_account = input("Do you have an account? (y/n): ")

    if has_account == "y":
        return "Login"
    elif has_account == "n":
        return "Sign Up"


def login_state():
    if "incorrect_attempt" in state_data and state_data["incorrect_attempt"] >= 3:
        print("Account locked. Try again in 1 minute.")
        return None

    if "incorrect_attempt" in state_data and state_data["incorrect_attempt"]:
        print("Incorrect username or password")
        print()

    username = input("Username: ")
    password = input("Password: ")

    if len(password) < 6:
        print("Invalid password. Password must be at least 6 digits long.")
        return "Login"

    if (username == "hanna" and password == "123456") or (
        username == "ziad" and password == "456789"
    ):
        state_data["incorrect_attempt"] = 0
        state_data["user"]["username"] = username  # Store username in state_data
        state_data["user"]["id"] = state_data["users"][username][
            "id"
        ]  # Store user ID in state_data
        return "Main Menu"
    else:
        state_data["incorrect_attempt"] = state_data.get("incorrect_attempt", 0) + 1
        return "Login"


def signup_state():
    email = input("Email: ")
    username = input("Username: ")
    password = input("Password: ")

    if not re.match(r"^\w+@\w+\.\w+$", email):
        print("Invalid email address.")
        return "Sign Up"

    if username in usernames:
        print("Username already exists.")
        return "Sign Up"

    if len(password) < 6:
        print("Invalid password. Password must be at least 6 digits long.")
        return "Sign Up"

    usernames.add(username)
    state_data["users"][email] = {"username": username, "password": password}
    # Generate a unique ID for the user
    user_id = str(uuid.uuid4())
    state_data["user"]["username"] = username
    state_data["user"]["id"] = user_id

    print("Account created successfully!")

    return "Main Menu"


def menu_state():
    print("Main Menu")
    print("1. Show your profile")
    print("2. Show others' profiles")
    print("3. Send a private message")
    print("4. Join Available Rooms")
    print("5. List online users")
    print("6. Exit")

    choice = input("Please enter your choice: ")
    if choice == "1":
        return "show your profile"
    elif choice == "2":
        return "show others' profile"
    elif choice == "3":
        return "send msg"
    elif choice == "4":
        return "join"
    elif choice == "5":
        return "list"
    elif choice == "6":
        return "exit"


def show_your_profile_state():
    print("Your Profile")

    if "username" in state_data["user"]:
        print(f"Username: {state_data['user']['username']}")
        print(f"ID: {state_data['user']['id']}")

        communicated_with = state_data["user"].get("communicated_with", set())

        if communicated_with:
            print("Users You've Chat With:")
            for user in communicated_with:
                print(user)
        else:
            print("No chat history yet.")
    else:
        print("Username not found.")
        if state_data["users"]:
            print("Generating your profile...")
            username = state_data["users"]["email"]["username"]
            user_id = str(uuid.uuid4())  # Generate a random UUID for ID

            state_data["user"]["username"] = username
            state_data["user"]["id"] = user_id

            print("Your Profile:")
            print(f"Username: {state_data['user']['username']}")
            print(f"ID: {state_data['user']['id']}")
        else:
            print("Please sign up to create your profile.")

    return "Main Menu"


def show_others_profile_state():
    print("Show Others' Profile")

    profile_username = input("Enter the username of the profile you want to view: ")
    if profile_username in usernames:
        print(f"Profile of {profile_username}:")
        print(f"Username: {state_data['users'][profile_username]['username']}")
        print(f"ID: {state_data['users'][profile_username]['id']}")
    else:
        print(f"User with username {profile_username} not found.")

    return "Main Menu"


def send_msg_state():
    recipient_username = input("Enter the username of the recipient: ")
    if recipient_username not in usernames:
        print("User with username", recipient_username, "not found.")
    else:
        message = input("Enter your message: ")
        print("Message sent successfully!")

        if "communicated_with" not in state_data["user"]:
            state_data["user"]["communicated_with"] = set()

        state_data["user"]["communicated_with"].add(recipient_username)

    return "Main Menu"


def join_room_state():
    available_rooms = ["General", "Sports", " politics"]

    print("Available Rooms:")
    for i, room_name in enumerate(available_rooms, start=1):
        print(f"{i}. {room_name}")

    choice = int(input("Enter the number of the room you want to join: "))

    try:
        if not 1 <= choice <= len(available_rooms):
            print("Invalid room number. Please try again.")
            return "Main Menu"
    except ValueError:
        print("Invalid input. Please enter a number.")
        return "Main Menu"

    joined_room = available_rooms[choice - 1]
    print(f"You have successfully joined the '{joined_room}' room.")

    while True:
        user_input = (
            input("Use SEND to send a message or EXIT to leave the room: ")
            .strip()
            .upper()
        )

        if user_input.startswith("SEND"):
            choice = input("Enter your message:")
            print(f"Your message has been sent.")

        elif user_input == "EXIT":
            print(f"You have left the '{joined_room}' room.")
            break
        else:
            print("Invalid input. Please try again.")

    return "Main Menu"


def list_state():
    online_users = ["hanna", "ziad", "gira"]
    print("Online Users:")
    if online_users:
        for user in online_users:
            print(f"{user}")
    else:
        print("No users are currently online.")

    return "Main Menu"


def exit_state():
    return "Welcome"


chat_history = []
state_data = {
    "incorrect_attempt": 0,
    "users": {
        "hanna": {"username": "hanna", "password": "123456", "id": "112233"},
        "ziad": {"username": "ziad", "password": "456789", "id": "332211"},
    },
    "user": {},
}
usernames = set(state_data["users"].keys())
state_data["user"]["chat_history"] = {}


def main():
    state = "Welcome"

    while True:
        choice = None
        if state == "Welcome":
            next_state = welcome_state()
        elif state == "Login":
            next_state = login_state()
        elif state == "Sign Up":
            next_state = signup_state()
        elif state == "Main Menu":
            next_state = menu_state()
            if next_state == "show your profile":
                next_state = show_your_profile_state()
            elif next_state == "show others' profile":
                next_state = show_others_profile_state()
            elif next_state == "send msg":
                next_state = send_msg_state()
            elif next_state == "join":
                next_state = join_room_state()
            elif next_state == "list":
                next_state = list_state()
            elif next_state == "exit":
                next_state = exit_state()

        elif next_state is None:
            time.sleep(60)
            state_data["incorrect_attempt"] = 0
            next_state = "Login"

        state = next_state


if __name__ == "__main__":
    main()
