# -*- coding: utf-8 -*-
from __future__ import unicode_literals  # string literals are all unicode
from __future__ import division # if python 2, force truediv division (default in 3)

import base64
import logging
import unittest
import uuid

from . import bridge


class TestBridge(unittest.TestCase):
    """ Assumes there's a bridge server running at DEFAULT_SERVER_PORT """

    @classmethod
    def setUpClass(cls):
        TestBridge.test_bridge = bridge.BridgeClient(
            connect_to_port=bridge.DEFAULT_SERVER_PORT, loglevel=logging.DEBUG)

    def test_import(self):

        mod = TestBridge.test_bridge.remote_import("base64")
        self.assertTrue(mod is not None)

    def test_call_no_args(self):

        mod = TestBridge.test_bridge.remote_import("uuid")

        result = mod.uuid4()

        self.assertTrue(result is not None)

    def test_call_arg(self):
        # also tests call with bytestring arg

        mod = TestBridge.test_bridge.remote_import("base64")

        test_str = str(uuid.uuid4())
        result = mod.b64encode(test_str.encode("utf-8"))

        result_str = base64.b64decode(result).decode("utf-8")

        self.assertEqual(test_str, result_str)

    def test_call_multi_args(self):
        mod = TestBridge.test_bridge.remote_import("re")

        remote_obj = mod.compile("foo", mod.IGNORECASE)

        self.assertTrue(remote_obj is not None)

        self.assertTrue(remote_obj.match("FOO") is not None)

    def test_call_with_remote_obj(self):

        mod = TestBridge.test_bridge.remote_import("uuid")

        remote_obj = mod.uuid4()
        result = str(remote_obj)
        self.assertTrue(result is not None)
        self.assertTrue("-" in result and "4" in result)

    def test_call_with_str(self):
        """ also tests calling str() on remote obj """

        mod = TestBridge.test_bridge.remote_import("uuid")

        test_uuid_str = "00010203-0405-0607-0809-0a0b0c0d0e0f"

        remote_uuid = mod.UUID(test_uuid_str)
        self.assertTrue(remote_uuid is not None)
        result = str(remote_uuid)
        self.assertEqual(test_uuid_str, result)

    # bool, int, list, tuple, dict, bytes, bridge object, callback, exception, none
    # set a function into the remote __main__/globals() to call
    # callback as key func in list.sort

    def test_call_kwargs(self):
        self.skipTest("Not implemented yet")

    def test_get(self):
        mod = TestBridge.test_bridge.remote_import("uuid")
        remote_doc = mod.__doc__
        self.assertTrue("RFC 4122" in remote_doc)

    def test_set(self):
        test_string = "hello world"
        mod = TestBridge.test_bridge.remote_import("__main__")
        mod.test = test_string

        self.assertEqual(test_string, mod.test)

    def test_get_non_existent(self):
        """ Check that requesting a non-existent attribute over the bridge raises an attributeerror """
        mod = TestBridge.test_bridge.remote_import("re")

        remote_obj = mod.compile("foo")

        with self.assertRaises(AttributeError):
            remote_obj.doesnt_exist

    def test_get_callable(self):
        mod = TestBridge.test_bridge.remote_import("re")

        remote_obj = mod.compile("foo")

        remote_callable = remote_obj.search
        self.assertTrue(isinstance(remote_callable, bridge.BridgedCallable))

    def test_callable(self):
        mod = TestBridge.test_bridge.remote_import("re")

        remote_obj = mod.compile("foo")

        remote_callable = remote_obj.match

        self.assertTrue(remote_callable("fooa") is not None)

    def test_serialize_deserialize_types(self):
        mod = TestBridge.test_bridge.remote_import("__main__")
        remote_list = mod.__builtins__.list

        # assemble a list of different types
        # Note: we include False now to detect failure to correctly unpack "False" strings into bools
        test_list = [1, 0xFFFFFFFF, True, False, "string", "unicode_string🐉🔍",
                     (1, 2, 3), [4, 5, 6], {7: 8, 9: 10}, uuid.uuid4(), pow, 1.5]
        # send the list in to create a remote list (which comes straight back)s
        created_list = remote_list(test_list)

        # check it's the same
        self.assertEqual(test_list, created_list)

    def test_serialize_deserialize_bytes(self):
        """ byte strings across 2<->3 bridges will be forced to strings (because py2 treats bytes and strs as the same thing """
        mod = TestBridge.test_bridge.remote_import("__main__")
        remote_list = mod.__builtins__.list

        test_list = [b"bytes"]

        # send the list in to create a remote list (which comes straight back)s
        created_list = remote_list(test_list)

        # check it's the same, either as a byte or normal string
        self.assertTrue(created_list[0] == test_list[0]
                        or created_list[0] == test_list[0].decode("utf-8"))

    def test_serialize_deserialize_bridge_object(self):
        # bridge objects TODO
        self.skipTest("Not implemented yet")

    def test_none_result(self):
        mod = TestBridge.test_bridge.remote_import("re")

        remote_obj = mod.compile("foo")

        remote_callable = remote_obj.search

        self.assertTrue(remote_callable("abar") is None)

    def test_exception(self):
        self.skipTest("Not implemented yet")

    def test_callback(self):
        """ Test we correctly handle calling back to here from across the bridge """
        def sort_fn(val):
            return len(val)

        mod = TestBridge.test_bridge.remote_import("__main__")
        remote_sorted = mod.__builtins__.sorted

        test_list = ["aaa", "bb", "c"]
        sorted_list = remote_sorted(test_list, key=sort_fn)

        self.assertEqual(sorted(test_list, key=sort_fn), sorted_list)

    def test_remote_iterable(self):
        """ Test we can access values from a remote iterable """
        mod = TestBridge.test_bridge.remote_import("__main__")
        remote_range = mod.__builtins__.range

        remote_it = remote_range(4, 10, 2)

        it_values = list(remote_it)

        self.assertEqual(list(range(4, 10, 2)), it_values)

    def test_remote_iterable_for(self):
        """ Test we can access values from a remote iterable with a for loop """
        mod = TestBridge.test_bridge.remote_import("__main__")
        remote_range = mod.__builtins__.range

        remote_it = remote_range(4, 10, 2)
        it_values = list()
        for value in remote_it:
            it_values.append(value)

        self.assertEqual(list(range(4, 10, 2)), it_values)

    def test_float(self):
        """ Test we can sent a float value """
        remote_time = TestBridge.test_bridge.remote_import("time")
        remote_time.sleep(0.1)

    def test_is_bridged_object(self):
        remote_uuid = TestBridge.test_bridge.remote_import("uuid")

        remote_obj = remote_uuid.uuid4()
        local_obj = uuid.uuid4()

        self.assertTrue(bridge._is_bridged_object(remote_obj))
        self.assertFalse(bridge._is_bridged_object(local_obj))

    def test_bridged_isinstance(self):
        mod = TestBridge.test_bridge.remote_import("__main__")
        remote_float = mod.__builtins__.float
        remote_int = mod.__builtins__.int
        remote_uuid = TestBridge.test_bridge.remote_import("uuid")
        remote_class = remote_uuid.UUID
        remote_obj = remote_uuid.uuid4()
        local_class = uuid.UUID
        local_obj = uuid.uuid4()

        # local obj, local class
        self.assertTrue(bridge.bridged_isinstance(local_obj, local_class))
        self.assertFalse(bridge.bridged_isinstance(local_obj, float))

        # local obj, fully local tuple
        self.assertTrue(bridge.bridged_isinstance(
            local_obj, (float, local_class)))
        self.assertFalse(bridge.bridged_isinstance(local_obj, (float, int)))

        # local obj, mixed tuple
        self.assertTrue(bridge.bridged_isinstance(
            local_obj, (remote_class, float, local_class)))
        self.assertFalse(bridge.bridged_isinstance(
            local_obj, (remote_float, float, int)))

        # local obj, remote class
        self.assertFalse(bridge.bridged_isinstance(local_obj, remote_class))

        # local obj, fully remote tuple
        self.assertFalse(bridge.bridged_isinstance(
            local_obj, (remote_float, remote_class)))

        # remote obj, local class
        self.assertFalse(bridge.bridged_isinstance(remote_obj, local_class))

        # remote obj, fully local tuple
        self.assertFalse(bridge.bridged_isinstance(
            remote_obj, (float, local_class)))

        # remote obj, mixed tuple
        self.assertTrue(bridge.bridged_isinstance(
            remote_obj, (remote_class, float, local_class)))
        self.assertFalse(bridge.bridged_isinstance(
            remote_obj, (remote_float, float, int)))

        # remote obj, remote class
        self.assertTrue(bridge.bridged_isinstance(remote_obj, remote_class))
        self.assertFalse(bridge.bridged_isinstance(remote_obj, remote_float))

        # remote obj, fully remote tuple
        self.assertTrue(bridge.bridged_isinstance(
            remote_obj, (remote_float, remote_class)))
        self.assertFalse(bridge.bridged_isinstance(
            remote_obj, (remote_float, remote_int)))

    def test_bridged_get_type(self):
        """ Make sure we can get an object representing the type of a bridged object """
        remote_uuid = TestBridge.test_bridge.remote_import("uuid")
        remote_obj = remote_uuid.uuid4()

        self.assertEquals(str(remote_obj._bridged_get_type()),
                          "<class 'uuid.UUID'>")
        self.assertEquals(
            str(remote_obj._bridged_get_type()._bridged_get_type()), "<type 'type'>")

    def test_remote_eval(self):
        self.assertEquals(3, TestBridge.test_bridge.remote_eval("1+2"))

    def test_remote_eval_bad_code(self):
        with self.assertRaises(bridge.BridgeException):
            TestBridge.test_bridge.remote_eval("1+x")

    def test_remote_eval_kwargs(self):
        self.assertEquals(3, TestBridge.test_bridge.remote_eval("x+y", x=1, y=2))

    def test_remote_eval_timeout(self):
        remote_time = TestBridge.test_bridge.remote_import("time")

        # check that it times out if not enough time allocated
        with self.assertRaises(Exception):
            TestBridge.test_bridge.remote_eval("sleep(2)", timeout_override=1, sleep=remote_time.sleep)

        # check that it works with enough time
        TestBridge.test_bridge.remote_eval("sleep(2)", timeout_override=3, sleep=remote_time.sleep)

    def test_operators(self):
        # check we can handle operator comparisons, addition, etc
        remote_datetime = TestBridge.test_bridge.remote_import("datetime")
        td1 = remote_datetime.timedelta(1)
        td2 = remote_datetime.timedelta(2)

        self.assertTrue(td1 < td2)
        self.assertTrue(td2 >= td1)
        self.assertEquals(remote_datetime.timedelta(3), td1 + td2)
        self.assertEquals(td1, td2//2) # we use floordiv here, truediv tested below
        
    def test_truediv(self):
        # check we cleanly fallback from truediv to div
        # timedelta in jython2.7 implements __div__ but not __truediv__
        remote_datetime = TestBridge.test_bridge.remote_import("datetime")
        td1 = remote_datetime.timedelta(1)
        td2 = remote_datetime.timedelta(2)
        self.assertEquals(td1, td2/2) 
        
    def test_len(self):
        # check we can handle len
        remote_collections = TestBridge.test_bridge.remote_import("collections")
        dq = remote_collections.deque()
        dq.append(1)
        dq.append(2)
        dq.append(3)
        self.assertEquals(3, len(dq))
