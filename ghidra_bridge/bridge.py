""" Handles converting data back and forward between 2 and 3 """

from __future__ import unicode_literals  # string literals are all unicode
try:
    import SocketServer as socketserver  # py2
except Exception:
    import socketserver  # py3

import logging
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
import functools


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
DEFAULT_SERVER_PORT = 4768  # "Gh"

VERSION = "v"
MAX_VERSION = "max_v"
MIN_VERSION = "min_v"
COMMS_VERSION_1 = 1
COMMS_VERSION_2 = 2
TYPE = "type"
VALUE = "value"
KEY = "key"
TUPLE = "tuple"
LIST = "list"
DICT = "dict"
INT = "int"
FLOAT = "float"
BOOL = "bool"
STR = "str"
BYTES = "bytes"
NONE = "none"
BRIDGED = "bridged"
EXCEPTION = "exception"
OBJ = "obj"
CALLABLE_OBJ = "callable_obj"
BASES = "bases"
REPR="repr"

MESSAGE = "message"
CMD = "cmd"
ID = "ID"
ARGS = "args"
GET = "get"
GET_ALL = "get_all"
CREATE_TYPE = "create_type"
SET = "set"
ISINSTANCE = "isinstance"
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

# Comms v2 (alpha) completely restructures the comms layer, breaking backwards compatability :(
MIN_SUPPORTED_COMMS_VERSION = COMMS_VERSION_2
MAX_SUPPORTED_COMMS_VERSION = COMMS_VERSION_2

DEFAULT_RESPONSE_TIMEOUT = 1  # seconds


class BridgeException(Exception):
    pass


class BridgeClosedException(Exception):
    pass


SIZE_FORMAT = "!I"


def write_size_and_data_to_socket(sock, data):
    """ Utility function to pack the size in front of data and send it off """

    # pack the size as network-endian
    data_size = len(data)
    size_bytes = struct.pack(SIZE_FORMAT, len(data))
    package = size_bytes + data
    total_size = len(size_bytes) + data_size

    sent = 0
    # noted errors sending large blobs of data with sendall, so we'll send as much as send() allows and keep trying
    while sent < total_size:
        # send it all off
        bytes_sent = sock.send(package[sent:])
        sent = sent + bytes_sent


def read_exactly(sock, num_bytes):
    """ Utility function to keep reading from the socket until we get the desired number of bytes """
    data = b''
    while num_bytes > 0:
        new_data = sock.recv(num_bytes)
        if new_data is None:
            # most likely reason for a none here is the socket being closed on the remote end
            raise BridgeClosedException()
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


def can_handle_version(message_dict):
    """ Utility function for checking we know about this version """
    return (message_dict[VERSION] <= MAX_SUPPORTED_COMMS_VERSION) and (message_dict[VERSION] >= MIN_SUPPORTED_COMMS_VERSION)


class BridgeCommandHandlerThread(threading.Thread):
    """ Thread that checks for commands to handle and serves them """

    bridge_conn = None
    threadpool = None

    ERROR_RESULT = json.dumps({ERROR: True})

    def __init__(self, threadpool):
        super(BridgeCommandHandlerThread, self).__init__()

        self.bridge_conn = threadpool.bridge_conn
        # make sure this thread doesn't keep the threadpool alive
        self.threadpool = weakref.proxy(threadpool)

        # don't let the command handlers keep us alive
        self.daemon = True

    def run(self):
        try:
            cmd = self.threadpool.get_command()  # block, waiting for first command
            while cmd is not None:  # get_command returns none if we should shut down
                # handle a command and write back the response
                # TODO make this return an error tied to the cmd_id, so it goes in the response mgr
                result = BridgeCommandHandlerThread.ERROR_RESULT
                try:
                    result = self.bridge_conn.handle_command(cmd)
                except Exception as e:
                    self.bridge_conn.logger.error(
                        "Unexpected exception for {}: {}".format(cmd, e))

                try:
                    write_size_and_data_to_socket(
                        self.bridge_conn.get_socket(), result)
                except socket.error:
                    # Other end has closed the socket before we can respond. That's fine, just ask me to do something then ignore me. Jerk. Don't bother staying around, they're probably dead
                    break

                cmd = self.threadpool.get_command()  # block, waiting for next command
        except ReferenceError:
            # expected, means the connection has been closed and the threadpool cleaned up
            pass


class BridgeCommandHandlerThreadPool(object):
    """ Takes commands and handles spinning up threads to run them. Will keep the threads that are started and reuse them before creating new ones """
    bridge_conn = None
    # semaphore indicating how many threads are ready right now to grab a command
    ready_threads = None
    command_list = None  # store the commands that need to be handled
    command_list_read_lock = None  # just for reading the list
    command_list_write_lock = None  # for writing the list
    shutdown_flag = False

    def __init__(self, bridge_conn):
        self.thread_count = 0
        self.bridge_conn = bridge_conn
        self.ready_threads = threading.Semaphore(
            0)  # start the ready threads at 0
        self.command_list = list()
        self.command_list_read_lock = threading.Lock()
        self.command_list_write_lock = threading.Lock()

    def handle_command(self, msg_dict):
        """ Give the threadpool a command to handle """
        # test if there are ready_threads waiting
        if not self.ready_threads.acquire(blocking=False):
            # no ready threads waiting - create a new one
            self.thread_count += 1
            self.bridge_conn.logger.debug(
                "Creating thread - now {} threads".format(self.thread_count))
            new_handler = BridgeCommandHandlerThread(self)
            new_handler.start()
        else:
            self.ready_threads.release()

        # take out the write lock, we're adding to the list
        with self.command_list_write_lock:
            self.command_list.append(msg_dict)
            # the next ready thread will grab the command

    def get_command(self):
        """ Threads ask for commands to handle - a thread stuck waiting here is counted in the ready threads """
        # release increments the ready threads count
        self.ready_threads.release()

        try:
            while not self.shutdown_flag:
                # get the read lock, so we can see if there's anything to do
                with self.command_list_read_lock:
                    if len(self.command_list) > 0:
                        # yes! grab the write lock (only thing that can have the write lock without the read lock is commands being added, so we won't deadlock/have to wait long)
                        with self.command_list_write_lock:
                            # yes! give back the first command
                            return self.command_list.pop()
                # wait a little before we try again
                time.sleep(0.01)
        finally:
            # make sure the thread "acquires" the semaphore (decrements the ready_threads count)
            self.ready_threads.acquire(blocking=False)

        # if we make it here, we're shutting down. return none and the thread will pack it in
        return None

    def __del__(self):
        """ We're done with this threadpool, tell the threads to start packing it in """
        self.shutdown_flag = True


class BridgeReceiverThread(threading.Thread):
    """ class to handle running a thread to receive bridge commands/responses and direct accordingly """

    # If we don't know how to handle the version, reply back with an error and the highest version we do support
    ERROR_UNSUPPORTED_VERSION = json.dumps(
        {ERROR: True, MAX_VERSION: MAX_SUPPORTED_COMMS_VERSION, MIN_VERSION: MIN_SUPPORTED_COMMS_VERSION})

    def __init__(self, bridge_conn):
        super(BridgeReceiverThread, self).__init__()

        self.bridge_conn = bridge_conn

        # don't let the recv loop keep us alive
        self.daemon = True

    def run(self):
        # threadpool to handle creating/running threads to handle commands
        threadpool = BridgeCommandHandlerThreadPool(self.bridge_conn)

        while True:  # TODO shutdown flag
            try:
                data = read_size_and_data_from_socket(
                    self.bridge_conn.get_socket())
            except socket.timeout:
                # client didn't have anything to say - just wait some more
                time.sleep(0.1)
                continue

            try:
                msg_dict = json.loads(data.decode("utf-8"))
                self.bridge_conn.logger.debug(
                    "Recv loop received {}".format(msg_dict))

                if can_handle_version(msg_dict):
                    if msg_dict[TYPE] == RESULT:
                        # handle a response
                        self.bridge_conn.response_mgr.add_response(msg_dict)
                    else:
                        # queue this and hand off to a worker threadpool
                        threadpool.handle_command(msg_dict)
                else:
                    # bad version
                    write_size_and_data_to_socket(
                        self.bridge_conn.get_socket(), BridgeReceiverThread.ERROR_UNSUPPORTED_VERSION)
            except Exception as e:
                # eat exceptions and continue, don't want a bad message killing the recv loop
                self.bridge_conn.logger.exception(e)


class BridgeCommandHandler(socketserver.BaseRequestHandler):

    def handle(self):
        """ handle a new client connection coming in - continue trying to read/service requests in a loop until we fail to send/recv """
        self.server.bridge.logger.warn(
            "Handling connection from {}".format(self.request.getpeername()))
        try:
            # run the recv loop directly
            BridgeReceiverThread(BridgeConn(
                self.server.bridge, self.request, response_timeout=self.server.bridge.response_timeout)).run()
        except BridgeClosedException:
            pass  # expected - the client has closed the connection
        except Exception as e:
            # something weird went wrong?
            self.server.bridge.logger.exception(e)
        finally:
            self.server.bridge.logger.warn(
                "Closing connection from {}".format(self.request.getpeername()))
            # we're out of the loop now, so the connection object will get told to delete itself, which will remove its references to any objects its holding onto


class BridgeHandle(object):
    def __init__(self, local_obj):
        self.handle = str(uuid.uuid4())
        self.local_obj = local_obj
        self.attrs = dir(local_obj)

    def to_dict(self):
        return {HANDLE: self.handle, TYPE: type(self.local_obj).__name__, ATTRS: self.attrs, REPR: repr(self.local_obj)}

    def __str__(self):
        return "BridgeHandle({}: {})".format(self.handle, self.local_obj)


class BridgeResponse(object):
    """ Utility class for waiting for and receiving responses """
    event = None  # used to flag whether the response is ready
    response = None

    def __init__(self):
        self.event = threading.Event()

    def set(self, response):
        """ store response data, and let anyone waiting know it's ready """
        self.response = response
        # trigger the event
        self.event.set()

    def get(self, timeout=None):
        """ wait for the response """
        if not self.event.wait(timeout):
            raise Exception()

        return self.response


class BridgeResponseManager(object):
    """ Handles waiting for and receiving responses """
    response_dict = None  # maps response ids to a BridgeResponse
    response_lock = None

    def __init__(self):
        self.response_dict = dict()
        self.response_lock = threading.Lock()

    def add_response(self, response_dict):
        """ response received - register it, then set the event for it """
        with self.response_lock:
            response_id = response_dict[ID]
            if response_id not in self.response_dict:
                # response hasn't been waited for yet. create the entry
                self.response_dict[response_id] = BridgeResponse()

            # set the data and trigger the event
            self.response_dict[response_id].set(response_dict)

    def get_response(self, response_id, timeout=None):
        """ Register for a response and wait until received """
        with self.response_lock:
            if response_id not in self.response_dict:
                # response hasn't been waited for yet. create the entry
                self.response_dict[response_id] = BridgeResponse()
            response = self.response_dict[response_id]

        data = None
        try:
            # wait for the data
            data = response.get(timeout)
        except:
            raise Exception(
                "Didn't receive response {} before timeout".format(response_id))

        with self.response_lock:
            # delete the entry, we're done here
            del self.response_dict[response_id]

        return data


class BridgeConn(object):
    """ Internal class, representing a connection to a remote bridge that serves our requests """

    def __init__(self, bridge, sock=None, connect_to_host=None, connect_to_port=None, response_timeout=DEFAULT_RESPONSE_TIMEOUT):
        """ Set up the bridge connection - only instantiates a connection as needed """
        self.host = connect_to_host
        self.port = connect_to_port

        # get a reference to the bridge's logger for the connection
        self.logger = bridge.logger

        self.handle_dict = {}

        self.sock = sock
        self.comms_lock = threading.RLock()
        self.handle_lock = threading.Lock()

        self.response_mgr = BridgeResponseManager()
        self.response_timeout = response_timeout

    def __del__(self):
        """ On teardown, make sure we close our socket to the remote bridge """
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
        elif isinstance(data, float):
            serialized_dict = {TYPE: FLOAT, VALUE: str(data)}
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
        elif serial_dict[TYPE] == FLOAT:
            return float(serial_dict[VALUE])
        elif serial_dict[TYPE] == BOOL:
            return serial_dict[VALUE] == "True"
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
        elif serial_dict[TYPE] == OBJ or serial_dict[TYPE] == CALLABLE_OBJ:
            if serial_dict[TYPE] == CALLABLE_OBJ:
                # note: assumes we're not going to get something that's iterable and callable at the same time (except types ... which aren't actually iterable, they may just have __iter__)
                assert "__iter__" not in serial_dict[VALUE][
                    ATTRS] or "type" == serial_dict[VALUE][TYPE], "Found something callable and iterable at the same time"
                return BridgedCallable(self, serial_dict[VALUE])
            elif "__iter__" in serial_dict[VALUE][ATTRS] and ("__next__" in serial_dict[VALUE][ATTRS] or "next" in serial_dict[VALUE][ATTRS]):
                return BridgedIterableIterator(self, serial_dict[VALUE])
            elif "__iter__" in serial_dict[VALUE][ATTRS]:
                return BridgedIterable(self, serial_dict[VALUE])
            elif "__next__" in serial_dict[VALUE][ATTRS] or "next" in serial_dict[VALUE][ATTRS]:
                return BridgedIterator(self, serial_dict[VALUE])
            else:
                # just an object
                return BridgedObject(self, serial_dict[VALUE])

        raise Exception("Unhandled data {}".format(serial_dict))

    def get_socket(self):
        with self.comms_lock:
            if self.sock is None:
                self.logger.debug(
                    "Creating socket to {}:{}".format(self.host, self.port))
                # Create a socket (SOCK_STREAM means a TCP socket)
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(10)
                self.sock.connect((self.host, self.port))
                # spin up the recv loop thread in the background
                BridgeReceiverThread(self).start()

            return self.sock

    def send_cmd(self, command_dict, get_response=True):
        """ Package and send a command off. If get_response set, wait for the response and return it. Else return none """
        cmd_id = str(uuid.uuid4())  # used to link commands and responses
        envelope_dict = {VERSION: COMMS_VERSION_2,
                         ID: cmd_id,
                         TYPE: CMD,
                         CMD: command_dict}
        self.logger.debug("Sending {}".format(envelope_dict))
        data = json.dumps(envelope_dict).encode("utf-8")

        with self.comms_lock:
            sock = self.get_socket()

        # send the data
        write_size_and_data_to_socket(sock, data)

        if get_response:
            result = {}
            # wait for the response
            response_dict = self.response_mgr.get_response(
                cmd_id, timeout=self.response_timeout)

            if response_dict is not None:
                if RESULT in response_dict:
                    result = response_dict[RESULT]
            return result
        else:
            return None

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
            # don't display StopIteration exceptions, they're totally normal
            if not isinstance(e, StopIteration):
                traceback.print_exc()

        response = self.serialize_to_dict(result)
        return response

    def remote_del(self, handle):
        self.logger.debug("remote_del {}".format(handle))
        command_dict = {CMD: DEL, ARGS: {HANDLE: handle}}
        self.send_cmd(command_dict, get_response=False)

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

    def remote_get_type(self, handle):
        self.logger.debug(
            "remote_get_type {}".format(handle))
        command_dict = {CMD: TYPE, ARGS: {HANDLE: handle}}
        return self.deserialize_from_dict(self.send_cmd(command_dict))

    def local_get_type(self, args_dict):
        handle = args_dict[HANDLE]
        self.logger.debug("local_get_type {}".format(handle))

        target_obj = self.get_object_by_handle(handle)

        try:
            result = type(target_obj)
        except Exception as e:
            result = e
            traceback.print_exc()

        return self.serialize_to_dict(result)

    def remote_create_type(self, name, bases, dct):
        self.logger.debug(
            "remote_create_type {}, {}, {}".format(name, bases, dct))
        command_dict = {CMD: CREATE_TYPE, ARGS: {NAME: name, BASES: self.serialize_to_dict(
            bases), DICT: self.serialize_to_dict(dct)}}
        return self.deserialize_from_dict(self.send_cmd(command_dict))

    def local_create_type(self, args_dict):
        name = args_dict[NAME]
        bases = self.deserialize_from_dict(args_dict[BASES])
        dct = self.deserialize_from_dict(args_dict[DICT])

        self.logger.debug(
            "local_create_type {}, {}, {}".format(name, bases, dct))
        result = None

        try:
            result = type(name, bases, dct)
        except Exception as e:
            result = e
            traceback.print_exc()

        return self.serialize_to_dict(result)

    def remote_get_all(self, handle):
        self.logger.debug("remote_get_all {}".format(handle))
        command_dict = {CMD: GET_ALL, ARGS: {HANDLE: handle}}
        return self.deserialize_from_dict(self.send_cmd(command_dict))

    def local_get_all(self, args_dict):
        handle = args_dict[HANDLE]
        self.logger.debug("local_get_all {}".format(handle))

        target_obj = self.get_object_by_handle(handle)
        result = {name: getattr(target_obj, name) for name in dir(target_obj)}

        return self.serialize_to_dict(result)

    def remote_isinstance(self, test_object, class_or_tuple):
        self.logger.debug("remote_isinstance({}, {})".format(
            test_object, class_or_tuple))

        check_class_tuple = None
        # if we're not checking against a tuple, force it into one
        if not _is_bridged_object(class_or_tuple):
            # local - probably a tuple already
            if not isinstance(class_or_tuple, tuple):
                # it's not :X
                raise Exception(
                    "Can't use remote_isinstance on a non-bridged class: {}".format(class_or_tuple))
            else:
                check_class_tuple = class_or_tuple
        else:
            # single bridged, just wrap in a tuple
            check_class_tuple = (class_or_tuple,)

        command_dict = {CMD: ISINSTANCE, ARGS: self.serialize_to_dict(
            {OBJ: test_object, TUPLE: check_class_tuple})}
        return self.deserialize_from_dict(self.send_cmd(command_dict))

    def local_isinstance(self, args_dict):
        args = self.deserialize_from_dict(args_dict)
        test_object = args[OBJ]
        check_class_tuple = args[TUPLE]

        self.logger.debug("local_isinstance({},{})".format(
            test_object, check_class_tuple))

        # make sure every element is a local object on this side
        if _is_bridged_object(test_object):
            raise Exception(
                "Can't use local_isinstance on a bridged object: {}".format(test_object))

        for clazz in check_class_tuple:
            if _is_bridged_object(clazz):
                raise Exception(
                    "Can't use local_isinstance on a bridged class: {}".format(clazz))

        result = isinstance(test_object, check_class_tuple)

        return self.serialize_to_dict(result)

    def handle_command(self, message_dict):

        response_dict = {VERSION: COMMS_VERSION_2,
                         ID: message_dict[ID],
                         TYPE: RESULT,
                         RESULT: {}}

        command_dict = message_dict[CMD]

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
        elif command_dict[CMD] == TYPE:
            response_dict[RESULT] = self.local_get_type(command_dict[ARGS])
        elif command_dict[CMD] == CREATE_TYPE:
            response_dict[RESULT] = self.local_create_type(command_dict[ARGS])
        elif command_dict[CMD] == GET_ALL:
            response_dict[RESULT] = self.local_get_all(command_dict[ARGS])
        elif command_dict[CMD] == ISINSTANCE:
            response_dict[RESULT] = self.local_isinstance(command_dict[ARGS])

        self.logger.debug("Responding with {}".format(response_dict))
        return json.dumps(response_dict).encode("utf-8")


class BridgeServer(threading.Thread):
    """ Python2Python RPC bridge server 

        Like a thread, so call run() to run directly, or start() to run on a background thread
    """

    def __init__(self, server_host=DEFAULT_HOST, server_port=0, loglevel=None, response_timeout=DEFAULT_RESPONSE_TIMEOUT):
        """ Set up the bridge.

            server_host/port: host/port to listen on to serve requests. If not specified, defaults to 127.0.0.1:0 (random port - use get_server_info() to find out where it's serving)
            loglevel - what messages to log
            response_timeout - how long to wait for a response before throwing an exception, in seconds
        """
        super(BridgeServer, self).__init__()

        # init the server
        self.server = ThreadingTCPServer(
            (server_host, server_port), BridgeCommandHandler)
        # the server needs to be able to get back to the bridge to handle commands, but we don't want that reference keeping the bridge alive
        self.server.bridge = weakref.proxy(self)
        self.server.timeout = 1
        self.daemon = True
        self.is_serving = False

        logging.basicConfig()
        self.logger = logging.getLogger(__name__)
        if loglevel is None:  # we don't want any logging - ignore everything
            loglevel = logging.CRITICAL+1

        self.logger.setLevel(loglevel)
        self.response_timeout = response_timeout

    def get_server_info(self):
        """ return where the server is serving on """
        return self.server.socket.getsockname()

    def run(self):
        self.logger.info("serving!")
        self.is_serving = True
        self.server.serve_forever()
        self.logger.info("stopped serving")

    def __del__(self):
        self.shutdown()

    def shutdown(self):
        self.logger.info("Shutting down bridge")
        if self.is_serving:
            self.is_serving = False
            self.server.server_close()


class BridgeClient(object):
    """ Python2Python RPC bridge client """

    def __init__(self, connect_to_host=DEFAULT_HOST, connect_to_port=DEFAULT_SERVER_PORT, loglevel=None, response_timeout=DEFAULT_RESPONSE_TIMEOUT):
        """ Set up the bridge client
            connect_to_host/port - host/port to connect to run commands. 
            loglevel - what messages to log
            response_timeout - how long to wait for a response before throwing an error, in seconds
        """
        logging.basicConfig()
        self.logger = logging.getLogger(__name__)
        if loglevel is None:  # we don't want any logging - ignore everything
            loglevel = logging.CRITICAL+1

        self.logger.setLevel(loglevel)

        self.client = BridgeConn(
            self, sock=None, connect_to_host=connect_to_host, connect_to_port=connect_to_port, response_timeout=response_timeout)

    def remote_import(self, module_name):
        return self.client.remote_import(module_name)

    # TODO shutdown


def _is_bridged_object(object):
    """ Utility function to detect if an object is bridged or not. 

        Not recommended for use outside this class, because it breaks the goal that you shouldn't
        need to know if something is bridged or not
    """
    return hasattr(object, "_bridge_type")


def bridged_isinstance(test_object, class_or_tuple):
    """ Utility function to wrap isinstance to handle bridged objects. Behaves as isinstance, but if all the objects/classes
        are bridged, will direct the call over the bridge.

        Currently, don't have a good way of handling a mix of bridge/non-bridge, so will just return false
    """
    # make sure we have the real isinstance, just in case we've overridden it (e.g., with ghidra_bridge namespace)
    builtin_isinstance = None
    try:
        from builtins import isinstance as builtin_isinstance  # python3
    except:
        # try falling back to python2 syntax
        from __builtin__ import isinstance as builtin_isinstance

    result = False

    # force class_or_tuple to be a tuple - just easier that way
    if _is_bridged_object(class_or_tuple):
        # bridged object, so not a tuple
        class_or_tuple = (class_or_tuple,)
    if not builtin_isinstance(class_or_tuple, tuple):
        # local clazz, not a tuple
        class_or_tuple = (class_or_tuple,)

    # now is the test_object bridged or not?
    if _is_bridged_object(test_object):
        # yes - we need to handle.
        # remove any non-bridged classes in the tuple
        new_tuple = tuple(
            clazz for clazz in class_or_tuple if _is_bridged_object(clazz))

        if new_tuple:  # make sure there's still some things left to check - otherwise, just return false without shooting it over the bridge
            result = test_object._bridge_isinstance(new_tuple)
    else:
        # test_object isn't bridged - remove any bridged classes in the tuple and palm it off to isinstance
        new_tuple = tuple(
            clazz for clazz in class_or_tuple if not _is_bridged_object(clazz))

        result = builtin_isinstance(test_object, new_tuple)

    return result


class BridgedObject(object):
    """ An object you can only interact with on the opposite side of a bridge """
    _bridge_conn = None
    _bridge_handle = None
    _bridge_type = None
    _bridge_attrs = None
    # overrides allow you to make changes just in the local bridge object, not against the remote object (e.g., to avoid conflicts with interactive fixups to the remote __main__)
    _bridge_overrides = None

    def __init__(self, bridge_conn, obj_dict):
        self._bridge_conn = bridge_conn
        self._bridge_handle = obj_dict[HANDLE]
        self._bridge_type = obj_dict[TYPE]
        self._bridge_attrs = obj_dict[ATTRS]
        self._bridge_repr = obj_dict[REPR]
        self._bridge_overrides = dict()

    def __getattribute__(self, attr):
        if attr.startswith(BRIDGE_PREFIX) or attr == "__class__":
            result = object.__getattribute__(self, attr)
        elif attr == "__mro_entries__":  # ignore mro entries - only being called if we're creating a class based off a bridged object
            raise AttributeError()
        else:
            result = self._bridged_get(attr)
        return result

    def __setattr__(self, attr, value):
        if attr.startswith(BRIDGE_PREFIX):
            object.__setattr__(self, attr, value)
        else:
            self._bridged_set(attr, value)

    def _bridged_get(self, name):
        if name in self._bridge_overrides:
            return self._bridge_overrides[name]

        return self._bridge_conn.remote_get(self._bridge_handle, name)

    def _bridged_get_all(self):
        """ As an optimisation, get all of the attributes at once and store them as overrides.

            Should only use this for objects that are unlikely to have their attributes change values (e.g., imported modules),
            otherwise you won't be able to get the updated values without clearing the override
        """
        attrs_dict = self._bridge_conn.remote_get_all(self._bridge_handle)

        # the result is a dictionary of attributes and their bridged objects. set them as overrides in the bridged object
        for name, value in attrs_dict.items():
            self._bridge_set_override(name, value)

    def _bridged_set(self, name, value):
        if name in self._bridge_overrides:
            self._bridge_overrides[name] = value
        else:
            self._bridge_conn.remote_set(self._bridge_handle, name, value)

    def _bridged_get_type(self):
        """ Get a bridged object representing the type of this object """
        return self._bridge_conn.remote_get_type(self._bridge_handle)

    def _bridge_set_override(self, name, value):
        self._bridge_overrides[name] = value

    def _bridge_clear_override(self, name):
        del self._bridge_overrides[name]

    def _bridge_isinstance(self, bridged_class_or_tuple):
        """ check whether this object is an instance of the bridged class (or tuple of bridged classes) """
        # enforce that the bridged_class_or_tuple elements are actually bridged
        if not _is_bridged_object(bridged_class_or_tuple):
            # might be a tuple
            if isinstance(bridged_class_or_tuple, tuple):
                # check all the elements of the tuple
                for clazz in bridged_class_or_tuple:
                    if not _is_bridged_object(clazz):
                        raise Exception(
                            "Can't use _bridge_isinstance with non-bridged class {}".format(clazz))
            else:
                # nope :x
                raise Exception(
                    "Can't use _bridge_isinstance with non-bridged class {}".format(bridged_class_or_tuple))

        # cool, arguments are valid
        return self._bridge_conn.remote_isinstance(self, bridged_class_or_tuple)

    def __del__(self):
        if self._bridge_conn is not None:  # only need to del if this was properly init'd
            self._bridge_conn.remote_del(self._bridge_handle)

    def __str__(self):
        # need to call str against the type, with the instance as the argument (otherwise it doesn't handle java packages/classes correctly)
        return self._bridged_get_type()._bridged_get("__str__")(self)

    def __repr__(self):
        return "<{}('{}', type={}, handle={})>".format(type(self).__name__, self._bridge_repr, self._bridge_type, self._bridge_handle)

    def __dir__(self):
        return dir(super(type(self))) + self._bridge_attrs


class BridgedCallable(BridgedObject):
    # TODO can we further make BridgedClass a subclass of BridgedCallable? How can we detect? Allow us to pull this class/type hack further away from normal calls
    def __new__(cls, bridge_conn, obj_dict, class_init=None):
        """ BridgedCallables can also be classes, which means they might be used as base classes for other classes. If this happens,
            you'll essentially get BridgedCallable.__new__ being called with 4 arguments to create the new class 
            (instead of 3, for an instance of BridgedCallable). 

            We handle this by creating the class remotely, and returning the BridgedCallable to that remote class. Note that the class methods
            (including __init__) will be bridged on the remote end, back to us.

            TODO: note sure what might happen if you define __new__ in a class that has a BridgedCallable as the base class
        """
        if class_init is None:
            # instance __new__
            return super(BridgedCallable, cls).__new__(cls)
        else:
            # want to create a class that's based off the remote class represented by a BridgedCallable (in the bases)
            # [Assumption: BridgedCallable base always first? Not sure what would happen if you had multiple inheritance]
            # ignore cls, it's just BridgedCallable
            # name is the name we want to call the class
            name = bridge_conn
            # bases are what the class inherits from. Assuming the first one is the BridgedCallable
            bases = obj_dict
            # dct is the class dictionary
            dct = class_init
            assert isinstance(bases[0], BridgedCallable)
            # create the class remotely, and return the BridgedCallable back to it
            return bases[0]._bridge_conn.remote_create_type(name, bases, dct)

    def __init__(self, bridge_conn, obj_dict, class_init=None):
        """ As with __new__, __init__ may be called as part of a class creation, not just an instance of BridgedCallable. We just ignore that case """
        if class_init is None:
            super(BridgedCallable, self).__init__(bridge_conn, obj_dict)

    def __call__(self, *args, **kwargs):
        return self._bridge_conn.remote_call(self._bridge_handle, *args, **kwargs)

    def __get__(self, instance, owner):
        """ Implement descriptor get so that we can bind the BridgedCallable to an object if it's defined as part of a class 
            Use functools.partial to return a wrapper to the BridgedCallable with the instance object as the first arg
        """
        return functools.partial(self, instance)

    def __repr__(self):
        return "<BridgedCallable({}, handle={})>".format(self._bridge_type, self._bridge_handle)


class BridgedIterable(BridgedObject):
    def __iter__(self):
        return self._bridged_get("__iter__")()


class BridgedIterator(BridgedObject):
    def __next__(self):
        # py2 vs 3 - next vs __next__
        try:
            return self._bridged_get("__next__" if "__next__" in self._bridge_attrs else "next")()
        except BridgeException as e:
            # we expect the StopIteration exception - check to see if that's what we got, and if so, raise locally
            if e.args[1]._bridge_type == "StopIteration":
                raise StopIteration
            # otherwise, something went bad - reraise
            raise

    next = __next__  # handle being run in a py2 environment



class BridgedIterableIterator(BridgedIterator, BridgedIterable):
    """ Common enough that iterables return themselves from __iter__ """
    pass
