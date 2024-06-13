# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from functools import wraps
import google.protobuf.text_format
from google.rpc import status_pb2, code_pb2
from abc import abstractmethod
from datetime import datetime
from queue import Queue
import threading
import queue
import logging

import grpc
from p4.tmp import p4config_pb2
from p4.v1 import p4runtime_pb2, p4runtime_pb2_grpc
import traceback

MSG_LOG_MAX_LEN = 1024


class P4RuntimeErrorFormatException(Exception):
    def __init__(self, message):
        super().__init__(message)


# Used to iterate over the p4.Error messages in a gRPC error Status object
class P4RuntimeErrorIterator:
    def __init__(self, grpc_error):
        assert(grpc_error.code() == grpc.StatusCode.UNKNOWN)
        self.grpc_error = grpc_error

        error = None
        # The gRPC Python package does not have a convenient way to access the
        # binary details for the error: they are treated as trailing metadata.
        for meta in self.grpc_error.trailing_metadata():
            if meta[0] == "grpc-status-details-bin":
                error = status_pb2.Status()
                error.ParseFromString(meta[1])
                break
        if error is None:
            raise P4RuntimeErrorFormatException("No binary details field")

        if len(error.details) == 0:
            raise P4RuntimeErrorFormatException(
                "Binary details field has empty Any details repeated field")
        self.errors = error.details
        self.idx = 0

    def __iter__(self):
        return self

    def __next__(self):
        while self.idx < len(self.errors):
            p4_error = p4runtime_pb2.Error()
            one_error_any = self.errors[self.idx]
            if not one_error_any.Unpack(p4_error):
                raise P4RuntimeErrorFormatException(
                    "Cannot convert Any message to p4.Error")
            if p4_error.canonical_code == code_pb2.OK:
                continue
            v = self.idx, p4_error
            self.idx += 1
            return v
        raise StopIteration


# P4Runtime uses a 3-level message in case of an error during the processing of
# a write batch. This means that if we do not wrap the grpc.RpcError inside a
# custom exception, we can end-up with a non-helpful exception message in case
# of failure as only the first level will be printed. In this custom exception
# class, we extract the nested error message (one for each operation included in
# the batch) in order to print error code + user-facing message.  See P4 Runtime
# documentation for more details on error-reporting.
class P4RuntimeWriteException(Exception):
    def __init__(self, grpc_error):
        assert(grpc_error.code() == grpc.StatusCode.UNKNOWN)
        super().__init__()
        self.errors = []
        try:
            error_iterator = P4RuntimeErrorIterator(grpc_error)
            for error_tuple in error_iterator:
                self.errors.append(error_tuple)
        except P4RuntimeErrorFormatException:
            raise  # just propagate exception for now

    def __str__(self):
        message = "Error(s) during Write:\n"
        for idx, p4_error in self.errors:
            code_name = code_pb2._CODE.values_by_number[
                p4_error.canonical_code].name
            message += "\t* At index {}: {}, '{}'\n".format(
                idx, code_name, p4_error.message)
        return message


class P4RuntimeException(Exception):
    def __init__(self, grpc_error):
        super().__init__()
        self.grpc_error = grpc_error

    def __str__(self):
        message = "P4Runtime RPC error ({}): {}".format(
            self.grpc_error.code().name, self.grpc_error.details())
        return message


def parse_p4runtime_write_error(f):
    @wraps(f)
    def handle(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except grpc.RpcError as e:
            if e.code() != grpc.StatusCode.UNKNOWN:
                raise e
            raise P4RuntimeWriteException(e) from None
    return handle


def parse_p4runtime_error(f):
    @wraps(f)
    def handle(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except grpc.RpcError as e:
            raise P4RuntimeException(e) from None
    return handle
# List of all active connections
connections = []

def ShutdownAllSwitchConnections():
    for c in connections:
        c.shutdown()

class SwitchConnection(object):

    def __init__(self, name=None, address='127.0.0.1:50051', device_id=0,
                 proto_dump_file=None):
        self.name = name
        self.address = address
        self.device_id = device_id
        self.p4info = None
        self.channel = grpc.insecure_channel(self.address)
        if proto_dump_file is not None:
            interceptor = GrpcRequestLogger(proto_dump_file)
            self.channel = grpc.intercept_channel(self.channel, interceptor)
        self.client_stub = p4runtime_pb2_grpc.P4RuntimeStub(self.channel)
        #self.requests_stream = IterableQueue()
        self.requests_stream = Queue() # IterableQueue()

        def stream_req_iterator():
            while True:
                p = self.requests_stream.get()
                if p is None:
                    break
                yield p

        #self.stream_msg_resp = self.client_stub.StreamChannel(iter(self.requests_stream))
        self.stream_msg_resp = self.client_stub.StreamChannel(stream_req_iterator())
        self.proto_dump_file = proto_dump_file
        connections.append(self)
        self.stream_in_q ={"packet" : Queue(), "digest": Queue(), "arbitration": Queue() , "unknown": Queue()}

        def stream_recv_wrapper(stream):
            @parse_p4runtime_error
            def stream_recv():
                for p in stream:
            #        print(p)
                    if p.HasField("packet"):
                        self.stream_in_q["packet"].put(p)
                    elif p.HasField("digest"):
                        self.stream_in_q["digest"].put(p)
                    elif p.HasField("arbitration"):
                        self.stream_in_q["arbitration"].put(p)
                    else:
                        self.stream_in_q["unknown"].put(p)
            try:
                stream_recv()
            except P4RuntimeException as e:
                print("ERROR!")
                logging.critical("StreamChannel error, closing stream")
                logging.critical(e)
                for k in self.stream_in_q:
                    self.stream_in_q[k].put(None)

        self.stream_recv_thread=threading.Thread(target=stream_recv_wrapper, args=(self.stream_msg_resp,))
        self.stream_recv_thread.start()

    def get_stream_packet(self, type_, timeout=1):
        if type_ not in self.stream_in_q:
            print("Unknown stream type '{}'".format(type_))
            return None
        try:
            msg=self.stream_in_q[type_].get(timeout=timeout)
            return msg
        except queue.Empty:
            return None

    @abstractmethod
    def buildDeviceConfig(self, **kwargs):
        return p4config_pb2.P4DeviceConfig()

    def shutdown(self):
        self.requests_stream.close()
        self.stream_msg_resp.cancel()

    def BuildDigestEntry(self, digest_id):
        digest_entry = p4runtime_pb2.DigestEntry()
        # using name
        digest_entry.digest_id = digest_id
        # using id directly
        #digest_entry.digest_id = int(digest_id)
        # FIXME: set config
        digest_entry.config.max_timeout_ns = 10
        digest_entry.config.max_list_size = 1
        digest_entry.config.ack_timeout_ns = 10
        return digest_entry
    
    def SendDigestEntry(self, digest_entry, elecid=1, dry_run=False):
        # send a digest entry INSERT message to init the streaming process
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = elecid
        update = request.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        update.entity.digest_entry.CopyFrom(digest_entry)

        if dry_run:
            print ("P4Runtime Enable digest %s on switch %s" % (
                digest_entry.digest_id, request))
        else:
            self.client_stub.Write(request)

    def StreamDigestMessages(self, digest_id, elecid=1, dry_run=False):
        # now read the digests
        request = p4runtime_pb2.StreamMessageRequest()
        request.arbitration.device_id = self.device_id
        request.arbitration.election_id.high = 0
        request.arbitration.election_id.low = elecid
        if dry_run:
            print ("P4Runtime Read stream digest message: ", request)
        else:
            self.requests_stream.put(request)
            #for item in self.stream_msg_resp:
             #   return item
            #rep = self.get_stream_packet("arbitration", timeout=2)
            #rep = self.get_stream_packet("digest", timeout=2)
           # if rep is None:
            #    print("Failed to establish sessoin with the server")
             #   #print(item)
              #  if item.WhichOneof('update') == 'digest':
               #     yield item.digest

    def MasterArbitrationUpdate(self, elecid=1, dry_run=False , **kwargs):
        request = p4runtime_pb2.StreamMessageRequest()
        request.arbitration.device_id = self.device_id
        request.arbitration.role.id = elecid -1
        request.arbitration.election_id.high = 0
        request.arbitration.election_id.low = elecid

        if dry_run:
            print("P4Runtime MasterArbitrationUpdate: ", request)
        else:
            self.requests_stream.put(request)

            rep = self.get_stream_packet("arbitration", timeout=20)
            if rep is None:
                print("Failed to establish sessoin with the server")
            #for item in self.stream_msg_resp:
             #   return item # just one

    def SetForwardingPipelineConfig(self, p4info, dry_run=False, **kwargs):
        device_config = self.buildDeviceConfig(**kwargs)
        request = p4runtime_pb2.SetForwardingPipelineConfigRequest()
        request.election_id.low = 1
        request.device_id = self.device_id
        config = request.config

        config.p4info.CopyFrom(p4info)
        config.p4_device_config = device_config.SerializeToString()

        request.action = p4runtime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_COMMIT
        if dry_run:
            print("P4Runtime SetForwardingPipelineConfig:", request)
        else:
            self.client_stub.SetForwardingPipelineConfig(request)

    def get_p4info(self):
        req = p4runtime_pb2.GetForwardingPipelineConfigRequest()
        req.device_id = self.device_id
        req.response_type = p4runtime_pb2.GetForwardingPipelineConfigRequest.P4INFO_AND_COOKIE
        rep = self.client_stub.GetForwardingPipelineConfig(req)
        return rep.config.p4info

    def WriteTableEntry(self, table_entry, dry_run=False):
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        update = request.updates.add()
        if table_entry.is_default_action:
            update.type = p4runtime_pb2.Update.MODIFY
        else:
            update.type = p4runtime_pb2.Update.INSERT
        update.entity.table_entry.CopyFrom(table_entry)
        if dry_run:
            print("P4Runtime Write:", request)
        else:
            self.client_stub.Write(request)

    def ReadTableEntries(self, table_id=None, dry_run=False):
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity = request.entities.add()
        table_entry = entity.table_entry
        if table_id is not None:
            table_entry.table_id = table_id
        else:
            table_entry.table_id = 0
        if dry_run:
            print("P4Runtime Read:", request)
        else:
            for response in self.client_stub.Read(request):
                yield response

    def ReadCounters(self, counter_id=None, index=None, dry_run=False):
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity = request.entities.add()
        counter_entry = entity.counter_entry
        if counter_id is not None:
            counter_entry.counter_id = counter_id
        else:
            counter_entry.counter_id = 0
        if index is not None:
            counter_entry.index.index = index
        if dry_run:
            print("P4Runtime Read:", request)
        else:
            for response in self.client_stub.Read(request):
                yield response

    def WritePREEntry(self, pre_entry, dry_run=False):
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        update = request.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        update.entity.packet_replication_engine_entry.CopyFrom(pre_entry)
        if dry_run:
            print("P4Runtime Write:", request)
        else:
            self.client_stub.Write(request)

class GrpcRequestLogger(grpc.UnaryUnaryClientInterceptor,
                        grpc.UnaryStreamClientInterceptor):
    """Implementation of a gRPC interceptor that logs request to a file"""

    def __init__(self, log_file):
        self.log_file = log_file
        with open(self.log_file, 'w') as f:
            # Clear content if it exists.
            f.write("")

    def log_message(self, method_name, body):
        with open(self.log_file, 'a') as f:
            ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            msg = str(body)
            f.write("\n[%s] %s\n---\n" % (ts, method_name))
            if len(msg) < MSG_LOG_MAX_LEN:
                f.write(str(body))
            else:
                f.write("Message too long (%d bytes)! Skipping log...\n" % len(msg))
            f.write('---\n')

    def intercept_unary_unary(self, continuation, client_call_details, request):
        self.log_message(client_call_details.method, request)
        return continuation(client_call_details, request)

    def intercept_unary_stream(self, continuation, client_call_details, request):
        self.log_message(client_call_details.method, request)
        return continuation(client_call_details, request)

class IterableQueue(Queue):
    _sentinel = object()

    def __iter__(self):
        return iter(self.get, self._sentinel)

    def close(self):
        self.put(self._sentinel)
