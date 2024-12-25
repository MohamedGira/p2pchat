import __init__
import threading
import time

from p2pchat.server.server_db import myDB as DB
from p2pchat.utils.utils import get_timesamp


class UsersMonitor(threading.Thread):
    def __init__(self, interval=5):
        super().__init__()
        self.interval = interval
        self.keep_monitoring = True

    def run(self):
        while self.keep_monitoring:
            users = DB.find("users", {"is_active": 1})
            for user in users:
                try:
                    if user.get("last_seen") is None:
                        DB.logout(user.get("username"))
                    if (get_timesamp() - user.get("last_seen")) > 12:
                        DB.logout(user.get("username"))
                except Exception as e:
                    pass
            time.sleep(self.interval)

    def stop_monitoring(self):
        self.keep_monitoring = False

    def deactivate(self):
        self.stop_monitoring()
        self.join()
