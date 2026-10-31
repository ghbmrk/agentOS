"""PLANT for #4331's proof run: writes a fixed path and binds a fixed port; reverted before merge."""
import socket
import unittest


class Plant(unittest.TestCase):
    def test_plant(self):
        with open("/tmp/agentos-clash-plant", "w") as f:
            f.write("x")
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", 47331))
        except OSError:
            pass
        finally:
            s.close()
