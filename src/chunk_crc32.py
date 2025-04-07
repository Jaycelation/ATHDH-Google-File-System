import os
import sys
from concurrent import futures
import time
from multiprocessing import Pool, Process
import binascii
import struct

import grpc
import gfs_pb2_grpc
import gfs_pb2


from common import Config as cfg
from common import Status

class ChunkServerCRC32(object):
    def __init__(self, port, root):
        self.port = port
        self.root = root
        if not os.path.isdir(root):
            os.mkdir(root)
        self.checksums = {}  # Dictionary to store chunk checksums
        self.block_size = 64 * 1024  # 64KB block size
        print(f"[ChunkServer {self.port}] Initialized with root directory: {root}")

    def calculate_crc32(self, data):
        """Calculate CRC32 checksum for data"""
        crc = 0xFFFFFFFF  # Initial value
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xEDB88320  # Polynomial
                else:
                    crc >>= 1
        return crc ^ 0xFFFFFFFF  # Final inversion

    def calculate_checksum(self, chunk_handle):
        """Calculate CRC32 checksum for each 64KB block in the chunk"""
        try:
            file_path = os.path.join(self.root, chunk_handle)
            with open(file_path, 'rb') as f:
                content = f.read()
                # Calculate checksum for each 64KB block
                block_checksums = []
                for i in range(0, len(content), self.block_size):
                    block = content[i:i + self.block_size]
                    checksum = self.calculate_crc32(block)
                    block_checksums.append(checksum)
                    print(f"[ChunkServer {self.port}] Block {i//self.block_size} checksum: {hex(checksum)}")
                
                # Store checksums in metadata file
                metadata_path = os.path.join(self.root, f"{chunk_handle}.meta")
                with open(metadata_path, 'wb') as meta_file:
                    for checksum in block_checksums:
                        meta_file.write(struct.pack('>I', checksum))
                
                self.checksums[chunk_handle] = block_checksums
                return block_checksums
        except Exception as e:
            print(f"[ChunkServer {self.port}] Error calculating checksum for {chunk_handle}: {str(e)}")
            return None

    def verify_checksum(self, chunk_handle):
        """Verify CRC32 checksum for each block in the chunk"""
        if chunk_handle not in self.checksums:
            print(f"[ChunkServer {self.port}] No stored checksum found for chunk {chunk_handle}")
            return False

        try:
            file_path = os.path.join(self.root, chunk_handle)
            metadata_path = os.path.join(self.root, f"{chunk_handle}.meta")
            
            # Read stored checksums from metadata
            with open(metadata_path, 'rb') as meta_file:
                stored_checksums = []
                while True:
                    data = meta_file.read(4)
                    if not data:
                        break
                    stored_checksums.append(struct.unpack('>I', data)[0])

            # Read and verify each block
            with open(file_path, 'rb') as f:
                content = f.read()
                for i in range(0, len(content), self.block_size):
                    block = content[i:i + self.block_size]
                    current_checksum = self.calculate_crc32(block)
                    block_index = i // self.block_size
                    
                    print(f"[ChunkServer {self.port}] Verifying block {block_index}")
                    print(f"  - Stored checksum: {hex(stored_checksums[block_index])}")
                    print(f"  - Current checksum: {hex(current_checksum)}")
                    
                    if current_checksum != stored_checksums[block_index]:
                        print(f"[ChunkServer {self.port}] Checksum mismatch in block {block_index}")
                        return False
                
            return True
        except Exception as e:
            print(f"[ChunkServer {self.port}] Error verifying checksum for {chunk_handle}: {str(e)}")
            return False

    def create(self, chunk_handle):
        try:
            file_path = os.path.join(self.root, chunk_handle)
            with open(file_path, 'wb') as f:
                f.write(b'')  # Create empty file
            print(f"[ChunkServer {self.port}] Created new chunk file: {chunk_handle}")
            # Calculate initial checksum
            self.calculate_checksum(chunk_handle)
        except Exception as e:
            print(f"[ChunkServer {self.port}] Error creating chunk {chunk_handle}: {str(e)}")
            return Status(-1, "ERROR :" + str(e))
        else:
            return Status(0, "SUCCESS: chunk created")

    def get_chunk_space(self, chunk_handle):
        try:
            chunk_space = cfg.chunk_size - os.stat(os.path.join(self.root, chunk_handle)).st_size
            chunk_space = str(chunk_space)
            print(f"[ChunkServer {self.port}] Available space in chunk {chunk_handle}: {chunk_space} bytes")
        except Exception as e:
            print(f"[ChunkServer {self.port}] Error getting space for chunk {chunk_handle}: {str(e)}")
            return None, Status(-1, "ERROR: " + str(e))
        else:
            return chunk_space, Status(0, "")

    def append(self, chunk_handle, data):
        try:
            file_path = os.path.join(self.root, chunk_handle)
            print(f"[ChunkServer {self.port}] Appending {len(data)} bytes to chunk {chunk_handle}")
            with open(file_path, "ab") as f:
                f.write(data.encode('utf-8'))
            # Update checksum after append
            new_checksums = self.calculate_checksum(chunk_handle)
            print(f"[ChunkServer {self.port}] New checksums after append: {[hex(c) for c in new_checksums]}")
        except Exception as e:
            print(f"[ChunkServer {self.port}] Error appending to chunk {chunk_handle}: {str(e)}")
            return Status(-1, "ERROR: " + str(e))
        else:
            return Status(0, "SUCCESS: data appended")

    def read(self, chunk_handle, start_offset, numbytes):
        start_offset = int(start_offset)
        numbytes = int(numbytes)
        try:
            # Verify checksum before reading
            print(f"[ChunkServer {self.port}] Reading chunk {chunk_handle}")
            if not self.verify_checksum(chunk_handle):
                print(f"[ChunkServer {self.port}] Checksum verification failed for chunk {chunk_handle}")
                return Status(-1, "ERROR: Checksum verification failed")
                
            with open(os.path.join(self.root, chunk_handle), "rb") as f:
                f.seek(start_offset)
                ret = f.read(numbytes)
                print(f"[ChunkServer {self.port}] Read {len(ret)} bytes from offset {start_offset}")
        except Exception as e:
            print(f"[ChunkServer {self.port}] Error reading chunk {chunk_handle}: {str(e)}")
            return Status(-1, "ERROR: " + str(e))
        else:
            return Status(0, ret.decode('utf-8'))

class ChunkServerToClientServicer(gfs_pb2_grpc.ChunkServerToClientServicer):
    def __init__(self, ckser):
        self.ckser = ckser
        self.port = self.ckser.port

    def Create(self, request, context):
        chunk_handle = request.st
        print("{} CreateChunk {}".format(self.port, chunk_handle))
        status = self.ckser.create(chunk_handle)
        return gfs_pb2.String(st=status.e)

    def GetChunkSpace(self, request, context):
        chunk_handle = request.st
        print("{} GetChunkSpace {}".format(self.port, chunk_handle))
        chunk_space, status = self.ckser.get_chunk_space(chunk_handle)
        if status.v != 0:
            return gfs_pb2.String(st=status.e)
        else:
            return gfs_pb2.String(st=chunk_space)

    def Append(self, request, context):
        chunk_handle, data = request.st.split("|")
        print("{} Append {} {}".format(self.port, chunk_handle, data))
        status = self.ckser.append(chunk_handle, data)
        return gfs_pb2.String(st=status.e)

    def Read(self, request, context):
        chunk_handle, start_offset, numbytes = request.st.split("|")
        print("{} Read {} {}".format(chunk_handle, start_offset, numbytes))
        status = self.ckser.read(chunk_handle, start_offset, numbytes)
        return gfs_pb2.String(st=status.e)

def start(port):
    print("Starting Chunk server on {}".format(port))
    ckser = ChunkServerCRC32(port=port, root=os.path.join(cfg.chunkserver_root, port))

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=3))
    gfs_pb2_grpc.add_ChunkServerToClientServicer_to_server(ChunkServerToClientServicer(ckser), server)
    server.add_insecure_port("[::]:{}".format(port))
    server.start()
    try:
        while True:
            time.sleep(200000)
    except KeyboardInterrupt:
        server.stop(0)

if __name__ == "__main__":
    for loc in cfg.chunkserver_locs:
        p = Process(target=start, args=(loc,))
        p.start()
    p.join() 
