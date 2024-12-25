import unittest
from s4p import S4P_Response, S4P_Request
import __init__
class TestS4P_Response(unittest.TestCase):
    def test_success_responses(self):
        response = S4P_Response.SYNCHACK("Synchronized successfully")
        self.assertEqual(response.code, 50)
        self.assertTrue(response.is_success)
        self.assertEqual(response.message, "Synchronized successfully")

        # Add similar tests for other success responses
        response = S4P_Response.CREATDRM("Room created successfully")
        self.assertEqual(response.code, 52)
        self.assertTrue(response.is_success)
        self.assertEqual(response.message, "Room created successfully")

    def test_failure_responses(self):
        response = S4P_Response.INCRAUTH("Incorrect authentication")
        self.assertEqual(response.code, 70)
        self.assertFalse(response.is_success)
        self.assertEqual(response.message, "Incorrect authentication")

        # Add similar tests for other failure responses
        response = S4P_Response.UNKACCNT("Unknown account")
        self.assertEqual(response.code, 71)
        self.assertFalse(response.is_success)
        self.assertEqual(response.message, "Unknown account")

    def test_response_data(self):
        # Test data handling in responses
        data_dict = {"key": "value"}
        response = S4P_Response.SYNCHACK("Synchronized successfully", data=data_dict)
        self.assertEqual(response.data, data_dict)

    def test_response_to_dict(self):
        data_dict = {"key": "value"}
        response = S4P_Response(50, "Test Response", True, data_dict)
        expected_dict = {
            "code": 50,
            "message": "Test Response",
            "is_success": True,
            "data": data_dict,
        }
        self.assertDictEqual(response.to_dict(), expected_dict)

    def test_response_init_from_dict(self):
        data_dict = {
            "code": 50,
            "message": "Test Response",
            "is_success": True,
            "data": {"key": "value"},
        }
        response = S4P_Response.init_from_dict(data_dict)
        self.assertEqual(response.code, 50)
        self.assertEqual(response.message, "Test Response")
        self.assertTrue(response.is_success)
        self.assertEqual(response.data, {"key": "value"})


class TestS4P_Request(unittest.TestCase):
    def test_sync_request(self):
        request = S4P_Request.sync_request("username")
        self.assertEqual(request["type"], "SYNC")
        self.assertEqual(request["username"], "username")

        # Add similar tests for other request types
        request = S4P_Request.privrm_request("sender", "recipient")
        self.assertEqual(request["type"], "PRIVRM")
        self.assertEqual(request["sender"], "sender")
        self.assertEqual(request["recipient"], "recipient")

    def test_privrm_request(self):
        request = S4P_Request.privrm_request("sender", "recipient")
        self.assertEqual(request["type"], "PRIVRM")
        self.assertEqual(request["sender"], "sender")
        self.assertEqual(request["recipient"], "recipient")

    def test_sndmsg_smpl_request(self):
        request = S4P_Request.sndmsg_smpl_request("Hello", "key", "sender", "recipient")
        self.assertEqual(request["type"], "SNDMSG")
        self.assertEqual(request["message"], "Hello")
        self.assertEqual(request["key"], "key")
        self.assertEqual(request["sender"], "sender")
        self.assertEqual(request["recipient"], "recipient")



if __name__ == '__main__':
    unittest.main()
    
