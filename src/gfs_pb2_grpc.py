# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc
import warnings

import gfs_pb2 as gfs__pb2

GRPC_GENERATED_VERSION = '1.71.0'
GRPC_VERSION = grpc.__version__
_version_not_supported = False


try:
    from grpc._utilities import first_version_is_lower
    _version_not_supported = first_version_is_lower(GRPC_VERSION, GRPC_GENERATED_VERSION)
except ImportError:
    _version_not_supported = True

if _version_not_supported:
    raise RuntimeError(
        f'The grpc package installed is at version {GRPC_VERSION},'
        + f' but the generated code in gfs_pb2_grpc.py depends on'
        + f' grpcio>={GRPC_GENERATED_VERSION}.'
        + f' Please upgrade your grpc module to grpcio>={GRPC_GENERATED_VERSION}'
        + f' or downgrade your generated code using grpcio-tools<={GRPC_VERSION}.'
    )


class MasterServerToClientStub(object):
    """Missing associated documentation comment in .proto file."""

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.ListFiles = channel.unary_unary(
                '/gfs.MasterServerToClient/ListFiles',
                request_serializer=gfs__pb2.String.SerializeToString,
                response_deserializer=gfs__pb2.String.FromString,
                _registered_method=True)
        self.CreateFile = channel.unary_unary(
                '/gfs.MasterServerToClient/CreateFile',
                request_serializer=gfs__pb2.String.SerializeToString,
                response_deserializer=gfs__pb2.String.FromString,
                _registered_method=True)
        self.AppendFile = channel.unary_unary(
                '/gfs.MasterServerToClient/AppendFile',
                request_serializer=gfs__pb2.String.SerializeToString,
                response_deserializer=gfs__pb2.String.FromString,
                _registered_method=True)
        self.CreateChunk = channel.unary_unary(
                '/gfs.MasterServerToClient/CreateChunk',
                request_serializer=gfs__pb2.String.SerializeToString,
                response_deserializer=gfs__pb2.String.FromString,
                _registered_method=True)
        self.ReadFile = channel.unary_unary(
                '/gfs.MasterServerToClient/ReadFile',
                request_serializer=gfs__pb2.String.SerializeToString,
                response_deserializer=gfs__pb2.String.FromString,
                _registered_method=True)
        self.DeleteFile = channel.unary_unary(
                '/gfs.MasterServerToClient/DeleteFile',
                request_serializer=gfs__pb2.String.SerializeToString,
                response_deserializer=gfs__pb2.String.FromString,
                _registered_method=True)
        self.UndeleteFile = channel.unary_unary(
                '/gfs.MasterServerToClient/UndeleteFile',
                request_serializer=gfs__pb2.String.SerializeToString,
                response_deserializer=gfs__pb2.String.FromString,
                _registered_method=True)


class MasterServerToClientServicer(object):
    """Missing associated documentation comment in .proto file."""

    def ListFiles(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def CreateFile(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def AppendFile(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def CreateChunk(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def ReadFile(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def DeleteFile(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def UndeleteFile(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_MasterServerToClientServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'ListFiles': grpc.unary_unary_rpc_method_handler(
                    servicer.ListFiles,
                    request_deserializer=gfs__pb2.String.FromString,
                    response_serializer=gfs__pb2.String.SerializeToString,
            ),
            'CreateFile': grpc.unary_unary_rpc_method_handler(
                    servicer.CreateFile,
                    request_deserializer=gfs__pb2.String.FromString,
                    response_serializer=gfs__pb2.String.SerializeToString,
            ),
            'AppendFile': grpc.unary_unary_rpc_method_handler(
                    servicer.AppendFile,
                    request_deserializer=gfs__pb2.String.FromString,
                    response_serializer=gfs__pb2.String.SerializeToString,
            ),
            'CreateChunk': grpc.unary_unary_rpc_method_handler(
                    servicer.CreateChunk,
                    request_deserializer=gfs__pb2.String.FromString,
                    response_serializer=gfs__pb2.String.SerializeToString,
            ),
            'ReadFile': grpc.unary_unary_rpc_method_handler(
                    servicer.ReadFile,
                    request_deserializer=gfs__pb2.String.FromString,
                    response_serializer=gfs__pb2.String.SerializeToString,
            ),
            'DeleteFile': grpc.unary_unary_rpc_method_handler(
                    servicer.DeleteFile,
                    request_deserializer=gfs__pb2.String.FromString,
                    response_serializer=gfs__pb2.String.SerializeToString,
            ),
            'UndeleteFile': grpc.unary_unary_rpc_method_handler(
                    servicer.UndeleteFile,
                    request_deserializer=gfs__pb2.String.FromString,
                    response_serializer=gfs__pb2.String.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'gfs.MasterServerToClient', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))
    server.add_registered_method_handlers('gfs.MasterServerToClient', rpc_method_handlers)


 # This class is part of an EXPERIMENTAL API.
class MasterServerToClient(object):
    """Missing associated documentation comment in .proto file."""

    @staticmethod
    def ListFiles(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/gfs.MasterServerToClient/ListFiles',
            gfs__pb2.String.SerializeToString,
            gfs__pb2.String.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def CreateFile(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/gfs.MasterServerToClient/CreateFile',
            gfs__pb2.String.SerializeToString,
            gfs__pb2.String.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def AppendFile(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/gfs.MasterServerToClient/AppendFile',
            gfs__pb2.String.SerializeToString,
            gfs__pb2.String.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def CreateChunk(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/gfs.MasterServerToClient/CreateChunk',
            gfs__pb2.String.SerializeToString,
            gfs__pb2.String.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def ReadFile(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/gfs.MasterServerToClient/ReadFile',
            gfs__pb2.String.SerializeToString,
            gfs__pb2.String.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def DeleteFile(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/gfs.MasterServerToClient/DeleteFile',
            gfs__pb2.String.SerializeToString,
            gfs__pb2.String.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def UndeleteFile(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/gfs.MasterServerToClient/UndeleteFile',
            gfs__pb2.String.SerializeToString,
            gfs__pb2.String.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)


class ChunkServerToClientStub(object):
    """Missing associated documentation comment in .proto file."""

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.Create = channel.unary_unary(
                '/gfs.ChunkServerToClient/Create',
                request_serializer=gfs__pb2.String.SerializeToString,
                response_deserializer=gfs__pb2.String.FromString,
                _registered_method=True)
        self.GetChunkSpace = channel.unary_unary(
                '/gfs.ChunkServerToClient/GetChunkSpace',
                request_serializer=gfs__pb2.String.SerializeToString,
                response_deserializer=gfs__pb2.String.FromString,
                _registered_method=True)
        self.Append = channel.unary_unary(
                '/gfs.ChunkServerToClient/Append',
                request_serializer=gfs__pb2.String.SerializeToString,
                response_deserializer=gfs__pb2.String.FromString,
                _registered_method=True)
        self.Read = channel.unary_unary(
                '/gfs.ChunkServerToClient/Read',
                request_serializer=gfs__pb2.String.SerializeToString,
                response_deserializer=gfs__pb2.String.FromString,
                _registered_method=True)


class ChunkServerToClientServicer(object):
    """Missing associated documentation comment in .proto file."""

    def Create(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GetChunkSpace(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def Append(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def Read(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_ChunkServerToClientServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'Create': grpc.unary_unary_rpc_method_handler(
                    servicer.Create,
                    request_deserializer=gfs__pb2.String.FromString,
                    response_serializer=gfs__pb2.String.SerializeToString,
            ),
            'GetChunkSpace': grpc.unary_unary_rpc_method_handler(
                    servicer.GetChunkSpace,
                    request_deserializer=gfs__pb2.String.FromString,
                    response_serializer=gfs__pb2.String.SerializeToString,
            ),
            'Append': grpc.unary_unary_rpc_method_handler(
                    servicer.Append,
                    request_deserializer=gfs__pb2.String.FromString,
                    response_serializer=gfs__pb2.String.SerializeToString,
            ),
            'Read': grpc.unary_unary_rpc_method_handler(
                    servicer.Read,
                    request_deserializer=gfs__pb2.String.FromString,
                    response_serializer=gfs__pb2.String.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'gfs.ChunkServerToClient', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))
    server.add_registered_method_handlers('gfs.ChunkServerToClient', rpc_method_handlers)


 # This class is part of an EXPERIMENTAL API.
class ChunkServerToClient(object):
    """Missing associated documentation comment in .proto file."""

    @staticmethod
    def Create(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/gfs.ChunkServerToClient/Create',
            gfs__pb2.String.SerializeToString,
            gfs__pb2.String.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def GetChunkSpace(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/gfs.ChunkServerToClient/GetChunkSpace',
            gfs__pb2.String.SerializeToString,
            gfs__pb2.String.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def Append(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/gfs.ChunkServerToClient/Append',
            gfs__pb2.String.SerializeToString,
            gfs__pb2.String.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def Read(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/gfs.ChunkServerToClient/Read',
            gfs__pb2.String.SerializeToString,
            gfs__pb2.String.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)
