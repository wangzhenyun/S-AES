# S盒和逆S盒
S_BOX = [
    [9, 4, 10, 11],
    [13, 1, 8, 5],
    [6, 2, 0, 3],
    [12, 14, 15, 7]
]

INV_S_BOX = [
    [10, 5, 9, 11],
    [1, 7, 8, 15],
    [6, 0, 2, 3],
    [12, 4, 13, 14]
]


# 行移位
def shift_rows(data):
    shifted_data = []
    for i in range(4):
        shifted_data.append(data[i*4:(i+1)*4][i:] + data[i*4:(i+1)*4][:i])
    return shifted_data


# 列混淆
def mix_columns(data):
    mixed_data = []
    for i in range(4):
        column = data[i::4]
        mixed_column = [
            (2 * column[0] + 3 * column[1] + column[2] + column[3]) % 16,
            (column[0] + 2 * column[1] + 3 * column[2] + column[3]) % 16,
            (column[0] + column[1] + 2 * column[2] + 3 * column[3]) % 16,
            (3 * column[0] + column[1] + column[2] + 2 * column[3]) % 16
        ]
        mixed_data.extend(mixed_column)
    return mixed_data


# 密钥扩展
def expand_key(key):
    expanded_key = key.copy()
    for i in range(4, 12):
        if i % 4 == 0:
            word = [expanded_key[(i-4)*4+j] for j in range(4)]
            word = word[1:] + [word[0]]
            for j in range(4):
                s_box_value = S_BOX[word[j] // 4][word[j] % 4]
                expanded_key.extend([expanded_key[(i-1)*4+j] ^ s_box_value])
        else:
            for j in range(4):
                expanded_key.extend([expanded_key[(i-1)*4+j] ^ expanded_key[(i-4)*4+j]])
    return expanded_key


# 加密
def encrypt(data, key):
    expanded_key = expand_key(key)
    state = data.copy()
    for i in range(9):
        # 字节替换
        for j in range(16):
            state[j] = S_BOX[state[j] // 4][state[j] % 4]
        # 行移位
        state = shift_rows(state)
        # 列混淆
        state = mix_columns(state)
        # 轮密钥加
        for j in range(16):
            state[j] ^= expanded_key[i*16+j]
    # 字节替换
    for j in range(16):
        state[j] = S_BOX[state[j] // 4][state[j] % 4]
    # 行移位
    state = shift_rows(state)
    # 轮密钥加
    for j in range(16):
        state[j] ^= expanded_key[9*16+j]
    return state


# 解密
def decrypt(ciphertext, key):
    expanded_key = expand_key(key)
    state = ciphertext.copy()
    # 轮密钥加
    for j in range(16):
        state[j] ^= expanded_key[9*16+j]
    # 逆行移位
    state = shift_rows(state[::-1])[::-1]
    # 逆字节替换
    for j in range(16):
        state[j] = INV_S_BOX[state[j] // 4][state[j] % 4]
    for i in range(8, -1, -1):
        # 逆列混淆
        state = mix_columns(state[::-1])[::-1]
        # 逆行移位
        state = shift_rows(state[::-1])[::-1]
        # 逆字节替换
        for j in range(16):
            state[j] = INV_S_BOX[state[j] // 4][state[j] % 4]
        # 轮密钥加
        for j in range(16):
            state[j] ^= expanded_key[i*16+j]
    return state


# ASCII编码字符串转16bit数据
def ascii_to_data(ascii_string):
    data = []
    for c in ascii_string:
        data.extend([ord(c) // 16, ord(c) % 16])
    return data


# 16bit数据转ASCII编码字符串
def data_to_ascii(data):
    ascii_string = ""
    for i in range(0, len(data), 2):
        ascii_string += chr(data[i] * 16 + data[i+1])
    return ascii_string

