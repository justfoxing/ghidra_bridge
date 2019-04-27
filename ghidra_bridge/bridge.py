# -*- coding: utf-8 -*-
""" Handles converting data back and forward between 2 and 3 """

from __future__ import unicode_literals  # string literals are all unicode
try:
    import SocketServer as socketserver  # py2
except Exception:
    import socketserver  # py3

import logging
import unittest
import traceback
import json
import base64
import uuid
import threading
import importlib
import socket
import struct
import time
import weakref

# from six.py's strategy
INTEGER_TYPES = None
try:
    INTEGER_TYPES = (int, long)
except NameError:  # py3 has no long
    INTEGER_TYPES = (int,)

STRING_TYPES = None
try:
    STRING_TYPES = (str, unicode)
except NameError:  # py3 has no unicode
    STRING_TYPES = (str,)


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    # prevent server threads hanging around and stopping python from closing
    daemon_threads = True


DEFAULT_HOST = "127.0.0.1"
DEFAULT_SERVER_PORT = 34940

TYPE = "type"
VALUE = "value"
KEY = "key"
TUPLE = "tuple"
LIST = "list"
DICT = "dict"
INT = "int"
BOOL = "bool"
STR = "str"
BYTES = "bytes"
NONE = "none"
BRIDGED = "bridged"
EXCEPTION = "exception"
OBJ = "obj"
CALLABLE_OBJ = "callable_obj"

HOST = "host"
PORT = "port"
MESSAGE = "message"
CMD = "cmd"
ID = "ID"
ARGS = "args"
GET = "get"
SET = "set"
CALL = "call"
IMPORT = "import"
DEL = "del"
RESULT = "result"
ERROR = "error"

HANDLE = "handle"
NAME = "name"
ATTRS = "attrs"

KWARGS = "kwargs"

BRIDGE_PREFIX = "_bridge"


class BridgeException(Exception):
    pass


SIZE_FORMAT = "!I"


def write_size_and_data_to_socket(sock, data):
    """ Utility function to pack the size in front of data and send it off """

    # pack the size as network-endian
    size_bytes = struct.pack(SIZE_FORMAT, len(data))
    # send it all off
    sock.sendall(size_bytes + data)


def read_exactly(sock, num_bytes):
    """ Utility function to keep reading from the socket until we get the desired number of bytes """
    data = b''
    while num_bytes > 0:
        new_data = sock.recv(num_bytes)
        num_bytes = num_bytes - len(new_data)
        data += new_data

    return data


def read_size_and_data_from_socket(sock):
    """ Utility function to read the size of a data block, followed by all of that data """

    size_bytes = read_exactly(sock, struct.calcsize(SIZE_FORMAT))
    size = struct.unpack(SIZE_FORMAT, size_bytes)[0]

    data = read_exactly(sock, size)
    data = data.strip()

    return data


class BridgeCommandHandler(socketserver.BaseRequestHandler):
    ERROR_RESULT = json.dumps({ERROR: True})

    def handle(self):
        """ handle a new client connection coming in - continue trying to read/service requests in a loop until we fail to send/recv """
        connection = None
        try:
            self.server.bridge.logger.info(
                "Handling connection from {}".format(self.request.getpeername()))
            while True:
                # self.request is the TCP socket connected to the client
                try:
                    self.data = read_size_and_data_from_socket(self.request)
                except socket.timeout:
                    # client didn't have anything to say - just wait some more
                    time.sleep(0.1)
                    continue

                if connection is None:
                    connection = self.server.bridge.create_connection(
                        self.data)

                result = BridgeCommandHandler.ERROR_RESULT
                try:
                    result = connection.handle_command(self.data)
                except Exception as e:
                    self.server.bridge.logger.error(
                        "Unexpected exception: {}".format(e))

                write_size_and_data_to_socket(self.request, result)
        except Exception:
            # something's failed - most likely, the client has closed the connection
            self.server.bridge.logger.info(
                "Closing connection from {}".format(self.request.getpeername()))
            # we're out of the loop now, so the connection object will get told to delete itself, which will remove its references to any objects its holding onto


class BridgeHandle(object):
    def __init__(self, local_obj):
        self.handle = str(uuid.uuid4())
        self.local_obj = local_obj
        self.attrs = dir(local_obj)

    def to_dict(self):
        return {HANDLE: self.handle, TYPE: type(self.local_obj).__name__, ATTRS: self.attrs}

    def __str__(self):
        return "BridgeHandle({}: {})".format(self.handle, self.local_obj)


class BridgeConn(object):
    """ Internal class, representing a connection to a remote bridge that serves our requests """

    def __init__(self, bridge, connect_to_host, connect_to_port):
        """ Set up the bridge connection - only instantiates a connection as needed """
        self.host = connect_to_host
        self.port = connect_to_port

        # get a reference to the bridge's logger for the connection
        self.logger = bridge.logger

        self.logger.info(
            "Creating BridgeConn for {}:{}".format(self.host, self.port))

        self.handle_dict = {}

        self.sock = None
        self.comms_lock = threading.RLock()
        self.handle_lock = threading.Lock()

        # record the server info, to stamp into all commands
        # TODO get the server host on the receiver end (e.g., it'll be the same address as the request originated from)
        self.server_host, self.server_port = bridge.get_server_info()

    def __del__(self):
        """ On teardown, make sure we close our socket to the remote bridge """
        self.logger.info(
            "Deleting BridgeConn for {}:{}".format(self.host, self.port))
        with self.comms_lock:
            if self.sock is not None:
                self.sock.close()

    def create_handle(self, obj):
        bridge_handle = BridgeHandle(obj)

        with self.handle_lock:
            self.handle_dict[bridge_handle.handle] = bridge_handle

        self.logger.debug(
            "Handle created {} for {}".format(bridge_handle.handle, obj))

        return bridge_handle

    def get_object_by_handle(self, handle):
        with self.handle_lock:
            if handle not in self.handle_dict:
                raise Exception("Old/unknown handle {}".format(handle))

            return self.handle_dict[handle].local_obj

    def release_handle(self, handle):
        with self.handle_lock:
            if handle in self.handle_dict:
                del self.handle_dict[handle]

    def serialize_to_dict(self, data):
        serialized_dict = None

        # note: this needs to come before int, because apparently bools are instances of int (but not vice versa)
        if isinstance(data, bool):
            serialized_dict = {TYPE: BOOL, VALUE: str(data)}
        elif isinstance(data, INTEGER_TYPES):
            serialized_dict = {TYPE: INT, VALUE: str(data)}
        elif isinstance(data, STRING_TYPES):  # all strings are coerced to unicode
            serialized_dict = {TYPE: STR, VALUE: base64.b64encode(
                data.encode("utf-8")).decode("utf-8")}
        elif isinstance(data, bytes):  # py3 only, bytestring in 2 is str
            serialized_dict = {TYPE: BYTES,
                               VALUE: base64.b64encode(data).decode("utf-8")}
        elif isinstance(data, list):
            serialized_dict = {TYPE: LIST, VALUE: [
                self.serialize_to_dict(v) for v in data]}
        elif isinstance(data, tuple):
            serialized_dict = {TYPE: TUPLE, VALUE: [
                self.serialize_to_dict(v) for v in data]}
        elif isinstance(data, dict):
            serialized_dict = {TYPE: DICT, VALUE: [{KEY: self.serialize_to_dict(
                k), VALUE: self.serialize_to_dict(v)} for k, v in data.items()]}
        elif isinstance(data, Exception):
            # treat the exception object as an object
            value = self.create_handle(data).to_dict()
            # then wrap the exception specifics around it
            serialized_dict = {TYPE: EXCEPTION, VALUE: value, MESSAGE: self.serialize_to_dict(
                getattr(data, "message", ""))}
        elif isinstance(data, BridgedObject):
            # passing back a reference to an object on the other side
            # e.g., bridge_obj1.do_thing(bridge_obj2)
            serialized_dict = {TYPE: BRIDGED, VALUE: data._bridge_handle}
        elif isinstance(data, type(None)):
            serialized_dict = {TYPE: NONE}
        else:
            # it's an object. assign a reference
            obj_type = CALLABLE_OBJ if callable(data) else OBJ
            serialized_dict = {TYPE: obj_type,
                               VALUE: self.create_handle(data).to_dict()}

        return serialized_dict

    def deserialize_from_dict(self, serial_dict):
        if serial_dict[TYPE] == INT:  # int, long
            return int(serial_dict[VALUE])
        elif serial_dict[TYPE] == BOOL:
            return bool(serial_dict[VALUE])
        elif serial_dict[TYPE] == STR:
            return base64.b64decode(serial_dict[VALUE]).decode("utf-8")
        elif serial_dict[TYPE] == BYTES:
            return base64.b64decode(serial_dict[VALUE])
        elif serial_dict[TYPE] == LIST:
            return [self.deserialize_from_dict(v) for v in serial_dict[VALUE]]
        elif serial_dict[TYPE] == TUPLE:
            return tuple(self.deserialize_from_dict(v) for v in serial_dict[VALUE])
        elif serial_dict[TYPE] == DICT:
            result = dict()
            for kv in serial_dict[VALUE]:
                key = self.deserialize_from_dict(kv[KEY])
                value = self.deserialize_from_dict(kv[VALUE])
                result[key] = value

            return result
        elif serial_dict[TYPE] == EXCEPTION:
            raise BridgeException(self.deserialize_from_dict(serial_dict[MESSAGE]), BridgedObject(
                self, serial_dict[VALUE]))
        elif serial_dict[TYPE] == BRIDGED:
            return self.get_object_by_handle(serial_dict[VALUE])
        elif serial_dict[TYPE] == NONE:
            return None
        elif serial_dict[TYPE] == OBJ:
            return BridgedObject(self, serial_dict[VALUE])
        elif serial_dict[TYPE] == CALLABLE_OBJ:
            return BridgedCallable(self, serial_dict[VALUE], )

        raise Exception("Unhandled data {}".format(serial_dict))

    def get_socket(self):
        with self.comms_lock:
            if self.sock is None:
                # Create a socket (SOCK_STREAM means a TCP socket)
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(10)
                self.sock.connect((self.host, self.port))

            return self.sock

    def send_cmd(self, command_dict):
        self.logger.debug("Sending {}".format(command_dict))
        envelope_dict = {HOST: self.server_host,
                         PORT: self.server_port, MESSAGE: command_dict}
        data = json.dumps(envelope_dict).encode("utf-8")

        received = None
        result = {}

        with self.comms_lock:
            sock = self.get_socket()

            # send the data
            write_size_and_data_to_socket(sock, data)

            # get the response
            received = read_size_and_data_from_socket(sock)

        if received is not None:
            self.logger.debug("Received: {}".format(received))
            response_dict = json.loads(received.decode("utf-8"))
            if RESULT in response_dict:
                result = response_dict[RESULT]

        return result

    def remote_get(self, handle, name):
        self.logger.debug("remote_get: {}.{}".format(handle, name))
        command_dict = {CMD: GET, ARGS: {HANDLE: handle, NAME: name}}
        return self.deserialize_from_dict(self.send_cmd(command_dict))

    def local_get(self, args_dict):
        handle = args_dict[HANDLE]
        name = args_dict[NAME]
        self.logger.debug("local_get: {}.{}".format(handle, name))

        target = self.get_object_by_handle(handle)
        try:
            result = getattr(target, name)
        except Exception as e:
            result = e
            traceback.print_exc()

        return self.serialize_to_dict(result)

    def remote_set(self, handle, name, value):
        self.logger.debug(
            "remote_set: {}.{} = {}".format(handle, name, value))
        command_dict = {CMD: SET, ARGS: {HANDLE: handle,
                                         NAME: name, VALUE: self.serialize_to_dict(value)}}
        self.deserialize_from_dict(self.send_cmd(command_dict))

    def local_set(self, args_dict):
        handle = args_dict[HANDLE]
        name = args_dict[NAME]
        value = self.deserialize_from_dict(args_dict[VALUE])
        self.logger.debug(
            "local_set: {}.{} = {}".format(handle, name, value))

        target = self.get_object_by_handle(handle)
        result = None
        try:
            result = setattr(target, name, value)
        except Exception as e:
            result = e
            traceback.print_exc()

        return self.serialize_to_dict(result)

    def remote_call(self, handle, *args, **kwargs):
        self.logger.debug(
            "remote_call: {}({},{})".format(handle, args, kwargs))

        serial_args = self.serialize_to_dict(args)
        serial_kwargs = self.serialize_to_dict(kwargs)
        command_dict = {CMD: CALL, ARGS: {HANDLE: handle,
                                          ARGS: serial_args, KWARGS: serial_kwargs}}

        return self.deserialize_from_dict(self.send_cmd(command_dict))

    def local_call(self, args_dict):
        handle = args_dict[HANDLE]

        args = self.deserialize_from_dict(args_dict[ARGS])
        kwargs = self.deserialize_from_dict(args_dict[KWARGS])

        self.logger.debug(
            "local_call: {}({},{})".format(handle, args, kwargs))
        result = None
        try:
            target_callable = self.get_object_by_handle(handle)
            result = target_callable(*args, **kwargs)
        except Exception as e:
            result = e
            traceback.print_exc()

        response = self.serialize_to_dict(result)
        return response

    def remote_del(self, handle):
        self.logger.debug("remote_del {}".format(handle))
        command_dict = {CMD: DEL, ARGS: {HANDLE: handle}}
        self.send_cmd(command_dict)

    def local_del(self, args_dict):
        handle = args_dict[HANDLE]
        self.logger.debug("local_del {}".format(handle))
        self.release_handle(handle)

    def remote_import(self, module_name):
        self.logger.debug("remote_import {}".format(module_name))
        command_dict = {CMD: IMPORT, ARGS: {NAME: module_name}}
        return self.deserialize_from_dict(self.send_cmd(command_dict))

    def local_import(self, args_dict):
        name = args_dict[NAME]

        self.logger.debug("local_import {}".format(name))
        result = None
        try:
            result = importlib.import_module(name)
        except Exception as e:
            result = e
            traceback.print_exc()

        return self.serialize_to_dict(result)

    def handle_command(self, data):
        envelope_dict = json.loads(data.decode("utf-8"))
        command_dict = envelope_dict[MESSAGE]

        response_dict = dict()

        response_dict[RESULT] = {}
        if command_dict[CMD] == GET:
            response_dict[RESULT] = self.local_get(command_dict[ARGS])
        elif command_dict[CMD] == SET:
            response_dict[RESULT] = self.local_set(command_dict[ARGS])
        elif command_dict[CMD] == CALL:
            response_dict[RESULT] = self.local_call(command_dict[ARGS])
        elif command_dict[CMD] == DEL:
            self.local_del(command_dict[ARGS])
        elif command_dict[CMD] == IMPORT:
            response_dict[RESULT] = self.local_import(command_dict[ARGS])

        return json.dumps(response_dict).encode("utf-8")


class Bridge(object):
    """ Python2Python RPC bridge """

    def __init__(self, server_host="127.0.0.1", server_port=0, connect_to_host="127.0.0.1", connect_to_port=None, start_in_background=True, loglevel=None):
        """ Set up the bridge.

            server_host/port: host/port to listen on to serve requests. If not specified, defaults to 127.0.0.1:0 (random port - use get_server_info() to find out where it's serving)
            connect_to_host/port - host/port to connect to run commands. If host not specified, is 127.0.0.1. If port not specified, is a pure server.
            start_in_background - if true, start a thread to serve on before returning. If false, caller will need to start manually

            """

        # init the server
        self.server = ThreadingTCPServer(
            (server_host, server_port), BridgeCommandHandler)
        # the server needs to be able to get back to the bridge to handle commands, but we don't want that reference keeping the bridge alive
        self.server.bridge = weakref.proxy(self)
        self.server.timeout = 1
        self.server_thread = None
        self.is_serving = False

        logging.basicConfig()
        self.logger = logging.getLogger(__name__)
        if loglevel is None:  # we don't want any logging - ignore everything
            loglevel = logging.CRITICAL+1

        self.logger.setLevel(loglevel)

        self.connect_to_host = None
        if connect_to_port is not None:
            self.connect_to_host = connect_to_host
            self.connect_to_port = connect_to_port
            self.client = BridgeConn(self, connect_to_host, connect_to_port)

        if start_in_background:
            self.start_on_thread()

    def get_server_info(self):
        """ return where the server is serving on """
        return self.server.socket.getsockname()

    def start(self):
        self.logger.info("serving!")
        self.is_serving = True
        self.server.serve_forever()
        self.logger.info("stopped serving")

    def start_on_thread(self):
        self.server_thread = threading.Thread(target=self.start)
        self.server_thread.daemon = True
        self.server_thread.start()

    def __del__(self):
        self.shutdown()

    def shutdown(self):
        self.logger.info("Shutting down bridge")
        if self.is_serving:
            self.is_serving = False
            self.server.server_close()

    def create_connection(self, data):
        """ Create a bridge connection based on a request that's come in """
        envelope_dict = json.loads(data.decode("utf-8"))

        conn_host = envelope_dict[HOST]
        conn_port = envelope_dict[PORT]

        connection = None
        if self.connect_to_host == conn_host and self.connect_to_port == conn_port:
            # this is a connection back from the bridge we're already connected to, so reuse that connection to make sure the handles are the same
            connection = self.client
        else:
            connection = BridgeConn(self, conn_host, conn_port)

        return connection

    def remote_import(self, module_name):
        return self.client.remote_import(module_name)


class BridgedObject(object):
    """ An object you can only interact with on the opposite side of a bridge """

    def __init__(self, bridge_conn, obj_dict):
        self._bridge_conn = bridge_conn
        self._bridge_handle = obj_dict[HANDLE]
        self._bridge_type = obj_dict[TYPE]
        self._bridge_attrs = obj_dict[ATTRS]

    def __getattribute__(self, attr):
        if attr.startswith(BRIDGE_PREFIX) or attr == "__class__":
            result = object.__getattribute__(self, attr)
        else:
            result = self._bridged_get(attr)
        return result

    def __setattr__(self, attr, value):
        if attr.startswith(BRIDGE_PREFIX):
            object.__setattr__(self, attr, value)
        else:
            self._bridged_set(attr, value)

    def _bridged_get(self, name):
        return self._bridge_conn.remote_get(self._bridge_handle, name)

    def _bridged_set(self, name, value):
        return self._bridge_conn.remote_set(self._bridge_handle, name, value)

    def __del__(self):
        self._bridge_conn.remote_del(self._bridge_handle)

    def __str__(self):
        return self._bridged_get("__str__")()

    def __repr__(self):
        return "<BridgedObject({}, handle={})>".format(self._bridge_type, self._bridge_handle)


class BridgedCallable(BridgedObject):
    def __call__(self, *args, **kwargs):
        return self._bridge_conn.remote_call(self._bridge_handle, *args, **kwargs)


class TestBridge(unittest.TestCase):
    """ Assumes there's a bridge server running at DEFAULT_SERVER_PORT """

    @classmethod
    def setUpClass(cls):
        TestBridge.test_bridge = Bridge(connect_to_port=DEFAULT_SERVER_PORT)

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
        pass

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
        mod = TestBridge.test_bridge.remote_import("re")

        remote_obj = mod.compile("foo")

        with self.assertRaises(BridgeException):
            remote_obj.doesnt_exist

    def test_get_callable(self):
        mod = TestBridge.test_bridge.remote_import("re")

        remote_obj = mod.compile("foo")

        remote_callable = remote_obj.search
        self.assertTrue(isinstance(remote_callable, BridgedCallable))

    def test_callable(self):
        mod = TestBridge.test_bridge.remote_import("re")

        remote_obj = mod.compile("foo")

        remote_callable = remote_obj.match

        self.assertTrue(remote_callable("fooa") is not None)

    def test_serialize_deserialize_types(self):
        mod = TestBridge.test_bridge.remote_import("__main__")
        remote_list = mod.__builtins__.list

        # assemble a list of different types
        test_list = [1, 0xFFFFFFFF, True, "string", "unicode_string🐉🔍",
                     (1, 2, 3), [4, 5, 6], {7: 8, 9: 10}, uuid.uuid4(), pow]

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
        pass

    def test_none_result(self):
        mod = TestBridge.test_bridge.remote_import("re")

        remote_obj = mod.compile("foo")

        remote_callable = remote_obj.search

        self.assertTrue(remote_callable("abar") is None)

    def test_exception(self):
        pass

    def test_multiple_clients(self):
        pass

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
