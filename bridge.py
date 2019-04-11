# -*- coding: utf-8 -*-
""" Handles converting data back and forward between 2 and 3 """

from __future__ import unicode_literals  # string literals are all unicode
try:
    import SocketServer as socketserver  # py2
except Exception:
    import socketserver  # py3

import unittest
import traceback
import json
import base64
import uuid
import threading
import importlib
import socket
import struct

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
    pass


DEFAULT_HOST = "localhost"
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
SHUTDOWN = "shutdown"
RESET = "reset"
GET = "get"
SET = "set"
CALL = "call"
IMPORT = "import"
DEL = "del"
RESULT = "result"

HANDLE = "handle"
NAME = "name"
ATTRS = "attrs"

KWARGS = "kwargs"

BRIDGE_PREFIX = "_bridge"


class BridgeException(Exception):
    pass


SIZE_FORMAT = "!I"


def write_size_and_data_to_socket(socket, data):
    """ Utility function to pack the size in front of data and send it off """

    # pack the size as network-endian
    size_bytes = struct.pack(SIZE_FORMAT, len(data))
    # send it all off
    socket.sendall(size_bytes + data)


def read_exactly(socket, num_bytes):
    """ Utility function to keep reading from the socket until we get the desired number of bytes """
    data = b''
    while num_bytes > 0:
        new_data = socket.recv(num_bytes)
        num_bytes = num_bytes - len(new_data)
        data += new_data

    return data


def read_size_and_data_from_socket(socket):
    """ Utility function to read the size of a data block, followed by all of that data """

    size_bytes = read_exactly(socket, struct.calcsize(SIZE_FORMAT))
    size = struct.unpack(SIZE_FORMAT, size_bytes)[0]

    data = read_exactly(socket, size)
    data = data.strip()

    return data


class BridgeCommandHandler(socketserver.BaseRequestHandler):

    def handle(self):
        # self.request is the TCP socket connected to the client
        self.data = read_size_and_data_from_socket(self.request)

        write_size_and_data_to_socket(
            self.request, self.server.bridge.handle_command(self.data))


class BridgeHandle(object):
    def __init__(self, bridge, local_obj):
        self.bridge = bridge
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
        self.bridge = bridge
        self.host = connect_to_host
        self.port = connect_to_port
        self.handle_dict = {}

        # record the server info, to stamp into all commands
        # TODO get the server host on the receiver end (e.g., it'll be the same address as the request originated from)
        self.server_host, self.server_port = self.bridge.get_server_info()

    def create_handle(self, obj):
        bridge_handle = BridgeHandle(self, obj)

        self.handle_dict[bridge_handle.handle] = bridge_handle

        #print("Handle created {}".format(bridge_handle.handle))

        return bridge_handle

    def get_object_by_handle(self, handle):
        if handle not in self.handle_dict:
            raise Exception("Old/unknown handle {}".format(handle))

        return self.handle_dict[handle].local_obj

    def release_handle(self, handle):
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
        # print(serial_dict)
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

    def send_cmd(self, command_dict):
        #print("sending {}".format(command_dict))
        envelope_dict = {HOST: self.server_host,
                         PORT: self.server_port, MESSAGE: command_dict}
        data = json.dumps(envelope_dict).encode("utf-8")

        # Create a socket (SOCK_STREAM means a TCP socket)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        received = None
        result = {}
        try:
            # Connect to server and send data
            sock.settimeout(10)
            sock.connect((self.host, self.port))
            write_size_and_data_to_socket(sock, data)

            # Receive data from the server and shut down
            received = read_size_and_data_from_socket(sock)
        finally:
            sock.close()

        if received is not None:
            #print("Received: {}".format(received))
            response_dict = json.loads(received)
            if RESULT in response_dict:
                result = response_dict[RESULT]

        return result

    def remote_shutdown(self):
        #print("Asking remote to stop")
        self.send_cmd({CMD: SHUTDOWN})

    def remote_get(self, handle, name):
        #print("RGet: {}.{}".format(handle, name))
        command_dict = {CMD: GET, ARGS: {HANDLE: handle, NAME: name}}
        return self.deserialize_from_dict(self.send_cmd(command_dict))

    def local_get(self, args_dict):
        handle = args_dict[HANDLE]
        name = args_dict[NAME]
        #print("LGet: {}.{}".format(handle, name))

        target = self.get_object_by_handle(handle)
        try:
            result = getattr(target, name)
        except Exception as e:
            result = e
            traceback.print_exc()

        return self.serialize_to_dict(result)

    def remote_set(self, handle, name, value):
        #print("RSet: {}.{} = {}".format(handle, name, value))
        command_dict = {CMD: SET, ARGS: {HANDLE: handle,
                                         NAME: name, VALUE: self.serialize_to_dict(value)}}
        self.deserialize_from_dict(self.send_cmd(command_dict))

    def local_set(self, args_dict):
        handle = args_dict[HANDLE]
        name = args_dict[NAME]
        value = self.deserialize_from_dict(args_dict[VALUE])
        #print("LSet: {}.{} = {}".format(handle, name, value))

        target = self.get_object_by_handle(handle)
        result = None
        try:
            result = setattr(target, name, value)
        except Exception as e:
            result = e
            traceback.print_exc()

        # print(result)

        return self.serialize_to_dict(result)

    def remote_call(self, handle, *args, **kwargs):
        #print("RCall: {}({},{})".format(handle, args, kwargs))

        serial_args = self.serialize_to_dict(args)
        serial_kwargs = self.serialize_to_dict(kwargs)
        command_dict = {CMD: CALL, ARGS: {HANDLE: handle,
                                          ARGS: serial_args, KWARGS: serial_kwargs}}

        return self.deserialize_from_dict(self.send_cmd(command_dict))

    def local_call(self, args_dict):
        handle = args_dict[HANDLE]

        args = self.deserialize_from_dict(args_dict[ARGS])
        kwargs = self.deserialize_from_dict(args_dict[KWARGS])

        #print("LCall: {}({},{})".format(handle, args, kwargs))
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
        #print("RDel {}".format(handle))
        command_dict = {CMD: DEL, ARGS: {HANDLE: handle}}
        self.send_cmd(command_dict)

    def local_del(self, args_dict):
        handle = args_dict[HANDLE]
        #print("LDel {}".format(handle))
        self.release_handle(handle)

    def remote_import(self, module_name):
        command_dict = {CMD: IMPORT, ARGS: {NAME: module_name}}
        return self.deserialize_from_dict(self.send_cmd(command_dict))

    def local_import(self, args_dict):
        name = args_dict[NAME]

        result = None
        try:
            result = importlib.import_module(name)
        except Exception as e:
            result = e
            traceback.print_exc()

        return self.serialize_to_dict(result)


class Bridge(object):
    """ Python2Python RPC bridge """

    def __init__(self, server_host="localhost", server_port=0, connect_to_host="localhost", connect_to_port=None):
        """ Set up the bridge. 

            server_host/port: host/port to listen on to serve requests. If not specified, defaults to localhost:0 (random port - use get_server_info() to find out where it's serving)
            connect_to_host/port - host/port to connect to run commands. If host not specified, is localhost. If port not specified, is a pure server. """
        self.handle_dict = dict()
        self.lock = threading.Lock()

        # init the server
        self.server = ThreadingTCPServer(
            (server_host, server_port), BridgeCommandHandler)
        self.server.bridge = self
        self.server.timeout = 1
        self.server_thread = None
        self.is_serving = False
        # TODO note: we still need to start the server (especially for client servers. How do

        self.connections = dict()
        if connect_to_port is not None:
            self.client = BridgeConn(self, connect_to_host, connect_to_port)

            self.connections[connect_to_host] = dict()
            self.connections[connect_to_host][connect_to_port] = self.client

    def get_server_info(self):
        """ return where the server is serving on """
        return self.server.socket.getsockname()

    def start(self):
        print("serving!")
        self.is_serving = True
        self.server.serve_forever()
        print("stopped serving")

    def start_on_thread(self):
        self.server_thread = threading.Thread(target=self.start)
        self.server_thread.daemon = True
        self.server_thread.start()

    def reset(self):
        """ Blow away all the handles we have """
        self.handle_dict = dict()

    def __del__(self):
        self.shutdown()

    def shutdown(self):
        if self.is_serving:
            self.server.shutdown()
        # tell the other end to blow away its handles so we don't leak memory
        #self.send_cmd({CMD: RESET})

    def handle_command(self, data):

        envelope_dict = json.loads(data)

        conn_host = envelope_dict[HOST]
        conn_port = envelope_dict[PORT]

        # see if we've already got a connection object for this client
        connection = None
        if conn_host in self.connections:
            if conn_port in self.connections[conn_host]:
                connection = self.connections[conn_host][conn_port]
        else:
            self.connections[conn_host] = dict()

        # if not, create one and store
        if connection is None:
            connection = BridgeConn(self, conn_host, conn_port)
            self.connections[conn_host][conn_port] = connection

        command_dict = envelope_dict[MESSAGE]

        response_dict = dict()

        response_dict[RESULT] = {}
        if command_dict[CMD] == SHUTDOWN:
            self.shutdown()
        elif command_dict[CMD] == RESET:
            self.reset()
        elif command_dict[CMD] == GET:
            response_dict[RESULT] = connection.local_get(command_dict[ARGS])
        elif command_dict[CMD] == SET:
            response_dict[RESULT] = connection.local_set(command_dict[ARGS])
        elif command_dict[CMD] == CALL:
            response_dict[RESULT] = connection.local_call(command_dict[ARGS])
        elif command_dict[CMD] == DEL:
            connection.local_del(command_dict[ARGS])
        elif command_dict[CMD] == IMPORT:
            response_dict[RESULT] = connection.local_import(command_dict[ARGS])

        return json.dumps(response_dict).encode("utf-8")

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

    def test_call_with_obj(self):
        pass

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
