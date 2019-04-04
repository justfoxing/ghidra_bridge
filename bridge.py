""" Handles converting data back and forward between 2 and 3 """

from __future__ import unicode_literals  # string literals are all unicode
try:
    import SocketServer as socketserver  # py2
except Exception:
    import socketserver  # py3

import traceback
import json
import base64
import uuid
import threading
import importlib
import socket

# from six.py's strategy
INTEGER_TYPES = None
try:
    INTEGER_TYPES = (int, long)
except NameError: # py3 has no long
    INTEGER_TYPES = (int,)


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


DEFAULT_HOST = "localhost"
DEFAULT_SERVER_PORT = 34982
DEFAULT_CLIENT_PORT = DEFAULT_SERVER_PORT+1


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
CALLABLES = "callables"
OTHER_ATTRS = "other_attrs"

KWARGS = "kwargs"

BRIDGE_PREFIX = "_bridge"

MAX_CMD_SIZE = 10240


class BridgeException(Exception):
    pass


class BridgeCommandHandler(socketserver.BaseRequestHandler):

    def handle(self):
        # self.request is the TCP socket connected to the client
        self.data = self.request.recv(MAX_CMD_SIZE).strip()
        self.request.sendall(self.server.bridge.handle_command(self.data))


class BridgeCommand(object):
    def __init__(self, bridge, command, args):
        self.bridge = bridge
        self.cmd_id = uuid.uuid4()
        self.command = command
        self.args = args

    def send(self):
        pass


class BridgeHandle(object):
    def __init__(self, bridge, local_obj):
        self.bridge = bridge
        self.handle = str(uuid.uuid4())
        self.local_obj = local_obj

        #self.callables = []
        #self.other_attrs = []

        """for attr_name in dir(local_obj):
            try:
                if callable(getattr(local_obj, attr_name)):
                    self.callables.append(attr_name)
                else:
                    self.other_attrs.append(attr_name)
            except Exception as e:
                print("Error checking attribute {}: {}".format(attr_name, e))
        """
                
    def to_dict(self):
        return {HANDLE: self.handle, TYPE: type(self.local_obj).__name__} #, CALLABLES: self.callables, OTHER_ATTRS: self.other_attrs}

    def __str__(self):
        return "BridgeHandle({}: {})".format(self.handle, self.local_obj)


class Bridge(object):
    def __init__(self, host, server_port, client_port):
        self.handle_dict = dict()
        self.lock = threading.Lock()
        self.host = host
        self.client_port = client_port

        self.server = ThreadingTCPServer(
            (host, server_port), BridgeCommandHandler)
        self.server.bridge = self
        self.server.timeout = 1
        self.server_thread = None

    def start(self):
        print("serving!")
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
        self.server.shutdown()
        # tell the other end to blow away its handles so we don't leak memory
        self.send_cmd({CMD: RESET})

    def create_handle(self, obj):
        bridge_handle = BridgeHandle(self, obj)

        self.handle_dict[bridge_handle.handle] = bridge_handle

        print("Handle created {}".format(bridge_handle.handle))

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
        elif isinstance(data, str):
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
            serialized_dict = {TYPE: EXCEPTION, VALUE: self.create_handle(
                data).to_dict(), MESSAGE: self.serialize_to_dict(getattr(data, "message", ""))}
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
        print(serial_dict)
        if serial_dict[TYPE] == INT:  # int, long
            return int(serial_dict[VALUE])
        elif serial_dict[TYPE] == BOOL:
            return bool(serial_dict[VALUE])
        elif serial_dict[TYPE] == STR:
            return base64.b64decode(serial_dict[VALUE])
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
                self, self.deserialize_from_dict(serial_dict[VALUE])))
        elif serial_dict[TYPE] == BRIDGED:
            return self.get_object_by_handle(serial_dict[VALUE])
        elif serial_dict[TYPE] == NONE:
            return None
        elif serial_dict[TYPE] == OBJ:
            return BridgedObject(self, serial_dict[VALUE])
        elif serial_dict[TYPE] == CALLABLE_OBJ:
            return BridgedCallable(self, serial_dict[VALUE], )

        raise Exception("Unhandled data {}".format(serial_dict))

    def handle_command(self, data):
        command_dict = json.loads(data)

        response_dict = dict()

        response_dict[RESULT] = {}
        if command_dict[CMD] == SHUTDOWN:
            self.shutdown()
        elif command_dict[CMD] == RESET:
            self.reset()
        elif command_dict[CMD] == GET:
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

    def send_cmd(self, command_dict):
        #print("sending {}".format(command_dict))
        data = json.dumps(command_dict).encode("utf-8")

        # Create a socket (SOCK_STREAM means a TCP socket)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        received = None
        result = {}
        try:
            # Connect to server and send data
            sock.settimeout(10)
            sock.connect((self.host, self.client_port))
            sock.sendall(data)

            # Receive data from the server and shut down
            received = sock.recv(MAX_CMD_SIZE)
        finally:
            sock.close()

        if received is not None:
            #print("Received: {}".format(received))
            response_dict = json.loads(received)
            if RESULT in response_dict:
                result = response_dict[RESULT]

        return result

    def remote_shutdown(self):
        print("Asking remote to stop")
        self.send_cmd({CMD: SHUTDOWN})

    def remote_get(self, handle, name):
        print("RGet: {}.{}".format(handle, name))
        command_dict = {CMD: GET, ARGS: {HANDLE: handle, NAME: name}}
        return self.deserialize_from_dict(self.send_cmd(command_dict))

    def local_get(self, args_dict):
        handle = args_dict[HANDLE]
        name = args_dict[NAME]
        print("LGet: {}.{}".format(handle, name))

        target = self.get_object_by_handle(handle)
        try:
            result = getattr(target, name)
        except Exception as e:
            result = e
            traceback.print_exc()

        return self.serialize_to_dict(result)

    def remote_set(self, handle, name, value):
        print("RSet: {}.{} = {}".format(handle, name, value))
        command_dict = {CMD: SET, ARGS: {HANDLE: handle,
                                         NAME: name, VALUE: self.serialize_to_dict(value)}}
        self.deserialize_from_dict(self.send_cmd(command_dict))

    def local_set(self, args_dict):
        handle = args_dict[HANDLE]
        name = args_dict[NAME]
        value = self.deserialize_from_dict(args_dict[VALUE])
        print("LSet: {}.{} = {}".format(handle, name, value))

        target = self.get_object_by_handle(handle)
        result = None
        try:
            result = setattr(target, name, value)
        except Exception as e:
            result = e
            traceback.print_exc()

        print(result)

        return self.serialize_to_dict(result)

    def remote_call(self, handle, *args, **kwargs):
        print("RCall: {}({},{})".format(handle, args, kwargs))

        serial_args = self.serialize_to_dict(args)
        serial_kwargs = self.serialize_to_dict(kwargs)
        command_dict = {CMD: CALL, ARGS: {HANDLE: handle,
                                          ARGS: serial_args, KWARGS: serial_kwargs}}

        return self.deserialize_from_dict(self.send_cmd(command_dict))

    def local_call(self, args_dict):
        handle = args_dict[HANDLE]

        args = self.deserialize_from_dict(args_dict[ARGS])
        kwargs = self.deserialize_from_dict(args_dict[KWARGS])

        print("LCall: {}({},{})".format(handle, args, kwargs))
        target_callable = self.get_object_by_handle(handle)
        result = target_callable(*args, **kwargs)
        response = self.serialize_to_dict(result)
        return response

    def remote_del(self, handle):
        #print("RDel {}".format(handle))
        command_dict = {CMD: DEL, ARGS: {HANDLE: handle}}
        self.send_cmd(command_dict)

    def local_del(self, args_dict):
        handle = args_dict[HANDLE]
        print("LDel {}".format(handle))
        self.release_handle(handle)

    def remote_import(self, module_name):
        command_dict = {CMD: IMPORT, ARGS: {NAME: module_name}}
        return self.deserialize_from_dict(self.send_cmd(command_dict))

    def local_import(self, args_dict):
        name = args_dict[NAME]
        return self.serialize_to_dict(importlib.import_module(name))


class BridgedObject(object):
    """ An object you can only interact with on the opposite side of a bridge """

    def __init__(self, bridge, obj_dict):
        self._bridge = bridge
        self._bridge_handle = obj_dict[HANDLE]
        self._bridge_type = obj_dict[TYPE]
        #self._bridge_callables = obj_dict[CALLABLES]
        #self._bridge_other_attrs = obj_dict[OTHER_ATTRS]

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
        return self._bridge.remote_get(self._bridge_handle, name)

    def _bridged_set(self, name, value):
        return self._bridge.remote_set(self._bridge_handle, name, value)

    """def _bridged_call(self, name, *args, **kwargs):
        return self._bridge.remote_call(self._bridge_handle, name, *args, **kwargs)
    """

    def __del__(self):
        self._bridge.remote_del(self._bridge_handle)

    def __str__(self):
        return "BridgedObject({})".format(self._bridge_type)

    def __repr__(self):
        return object.__getattribute__(self, "__str__")()


class BridgedCallable(BridgedObject):
    def __call__(self, *args, **kwargs):
        return self._bridge.remote_call(self._bridge_handle, *args, **kwargs)
