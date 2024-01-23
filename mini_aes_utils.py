
def string_to_bytes(st):
    return (''.join('{0:08b}'.format(ord(x), 'b') for x in st))

def bytes_to_blocks(bytes):
    block = []
    for i in range(0,len(bytes),16):
        data=[]
        for j in range(0,16,4):
            data.append(bytes[i+j:i+j+4])
        block.append(data)
    return block

def bytes_to_string(bytes):
    st = ''
    for i in range(0,len(bytes),8):
        st += chr(int(bytes[i:i+8],2))
    return st