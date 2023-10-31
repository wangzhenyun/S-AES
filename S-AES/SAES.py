S = [[0x9, 0x4, 0xA, 0xB],
     [0xD, 0x1, 0x8, 0x5],
     [0x6, 0x2, 0x0, 0x3],
     [0xC, 0xE, 0xF, 0x7]]


def xor_bits(a, b):
    result = ""
    for i in range(len(a)):
        result += str(int(a[i]) ^ int(b[i]))
    return result


def RotNib(w):
    left_half = w[:4]
    right_half = w[4:]
    result = right_half + left_half
    return result


def SubNib(w):
    left_half = w[:4]
    right_half = w[4:]
    s_left_half = sbox_substitution(left_half, S)
    s_right_half = sbox_substitution(right_half, S)
    result = s_left_half + s_right_half
    return result


def sbox_substitution(input_text, S):
    row = int(input_text[0] + input_text[1], 2)
    col = int(input_text[2] + input_text[3], 2)
    return format(S[row][col], '04b')  # 以二进制格式返回


def get_key_extension(w):
    RCON1 = '10000000'  # 轮常数
    RCON2 = '00110000'
    key_w = []
    w0 = w[:8]
    w1 = w[8:]
    key_w.append(w0 + w1)
    w2 = xor_bits(xor_bits(w0, RCON1), SubNib(RotNib(w1)))
    w3 = xor_bits(w2, w1)
    key_w.append(w2 + w3)
    w4 = xor_bits(xor_bits(w2, RCON2), SubNib(RotNib(w3)))
    w5 = xor_bits(w4, w3)
    key_w.append(w4 + w5)
    return key_w


S = [[0x9, 0x4, 0xA, 0xB],
     [0xD, 0x1, 0x8, 0x5],
     [0x6, 0x2, 0x0, 0x3],
     [0xC, 0xE, 0xF, 0x7]]
M = [[0x1, 0x4],
     [0x4, 0x1]]

S_inv = [[0xA, 0x5, 0x9, 0xB],
         [0x1, 0x7, 0x8, 0xF],
         [0x6, 0x0, 0x2, 0x3],
         [0xC, 0x4, 0xD, 0xE]]
M_inv = [[0x9, 0x2],
         [0x2, 0x9]]


def sbox_substitution(input_text, S):
    row = int(input_text[0] + input_text[1], 2)
    col = int(input_text[2] + input_text[3], 2)
    return format(S[row][col], '04b')


def halfbyte_substitution(P, S):
    halfByte00 = P[:4]
    halfByte10 = P[4:8]
    halfByte01 = P[8:12]
    halfByte11 = P[12:]
    s_halfByte00 = sbox_substitution(halfByte00, S)
    s_halfByte10 = sbox_substitution(halfByte10, S)
    s_halfByte01 = sbox_substitution(halfByte01, S)
    s_halfByte11 = sbox_substitution(halfByte11, S)
    result = s_halfByte00 + s_halfByte10 + s_halfByte01 + s_halfByte11
    return result


def shift_row(P):
    halfByte00 = P[:4]
    halfByte10 = P[4:8]
    halfByte01 = P[8:12]
    halfByte11 = P[12:]
    result = halfByte00 + halfByte11 + halfByte01 + halfByte10
    return result


def confusion_column(P, M):
    halfByte00 = P[:4]
    halfByte10 = P[4:8]
    halfByte01 = P[8:12]
    halfByte11 = P[12:]
    c_halfByte00 = xor_bits((gf2_4_multiply_binary(format(M[0][0], '04b'), halfByte00)).zfill(4),
                            (gf2_4_multiply_binary(format(M[0][1], '04b'), halfByte10)).zfill(4))
    c_halfByte10 = xor_bits((gf2_4_multiply_binary(format(M[1][0], '04b'), halfByte00)).zfill(4),
                            (gf2_4_multiply_binary(format(M[1][1], '04b'), halfByte10)).zfill(4))
    c_halfByte01 = xor_bits((gf2_4_multiply_binary(format(M[0][0], '04b'), halfByte01)).zfill(4),
                            (gf2_4_multiply_binary(format(M[0][1], '04b'), halfByte11)).zfill(4))
    c_halfByte11 = xor_bits((gf2_4_multiply_binary(format(M[1][0], '04b'), halfByte01)).zfill(4),
                            (gf2_4_multiply_binary(format(M[1][1], '04b'), halfByte11)).zfill(4))
    result = c_halfByte00 + c_halfByte10 + c_halfByte01 + c_halfByte11
    return result


def gf2_4_multiply_binary(a, b):
    # 将二进制字符串转换为整数
    a = int(a, 2)
    b = int(b, 2)

    # 在GF(2^4)中执行乘法
    result = 0
    for i in range(4):
        if (b & 1) == 1:
            result ^= a
        high_bit_set = (a & 8) == 8
        a <<= 1
        if high_bit_set:
            a ^= 0b10011  # GF(2^4)的模
        b >>= 1
    return bin(result)[2:]


def encrypting_binary(plaintext_binary, key):
    keys = get_key_extension(key)
    Ak0 = xor_bits(plaintext_binary, keys[0])
    NS = halfbyte_substitution(Ak0, S)
    SR = shift_row(NS)
    MC = confusion_column(SR, M)
    Ak1 = xor_bits(MC, keys[1])
    NS = halfbyte_substitution(Ak1, S)
    SR = shift_row(NS)
    Ak2 = xor_bits(SR, keys[2])
    return Ak2


def decrypting_binary(ciphertext_binary, key):
    keys = get_key_extension(key)
    Ak2 = xor_bits(ciphertext_binary, keys[2])
    ISR = shift_row(Ak2)
    INS = halfbyte_substitution(ISR, S_inv)
    Ak1 = xor_bits(INS, keys[1])
    IMC = confusion_column(Ak1, M_inv)
    ISR = shift_row(IMC)
    INS = halfbyte_substitution(ISR, S_inv)
    Ak0 = xor_bits(INS, keys[0])
    return Ak0


def decrypting_binaryStr(ciphertext_str, key):
    length = len(ciphertext_str)
    if length % 16 != 0:
        return
    plaintext_binarystring = ""
    for i in range(0, length, 16):
        group = ciphertext_str[i:i + 16]
        plain_group = decrypting_binary(group, key)
        plaintext_binarystring = plaintext_binarystring + plain_group
    return plaintext_binarystring


def decrypting_hexadecimal(ciphertext_hexadecimal, key_hexadecimal):
    length = len(ciphertext_hexadecimal)
    if length % 4 != 0:
        return
    plaintext_hexadeciaml = ""
    key = (bin(int(key_hexadecimal, 16))[2:]).zfill(16)
    for i in range(0, length, 4):
        group = ciphertext_hexadecimal[i:i + 4]
        ciphertext_binary = (bin(int(group, 16))[2:]).zfill(16)
        plaintext_binary = decrypting_binary(ciphertext_binary, key)
        plaintext_hexadeciaml1 = hex(int(plaintext_binary, 2))[2:].zfill(4)
        plaintext_hexadeciaml = plaintext_hexadeciaml + plaintext_hexadeciaml1
    return plaintext_hexadeciaml


def decrypting_ascii(ciphertext_ascii, key):
    length = len(ciphertext_ascii)
    if length % 2 != 0:
        return
    plaintext_ascii = ""
    for i in range(0, length, 2):
        group = ciphertext_ascii[i:i + 2]
        ciphertext_binary = ''.join([bin(ord(char))[2:].zfill(8) for char in group])
        plaintext_binary1 = decrypting_binary(ciphertext_binary, key)
        byte1 = plaintext_binary1[0:8]
        byte2 = plaintext_binary1[8:16]
        plaintext_ascii1 = chr(int(byte1, 2)) + chr(int(byte2, 2))
        plaintext_ascii = plaintext_ascii + plaintext_ascii1
    return plaintext_ascii


def decrypting_double(ciphertext_double, key):
    key1 = key[:16]
    key2 = key[16:]
    plaintext_double = decrypting_binary(decrypting_binary(ciphertext_double, key2), key1)
    return plaintext_double


def decrypting_three(ciphertext_three, key):
    key1 = key[:16]
    key2 = key[16:32]
    key3 = key[32:]
    plaintext = decrypting_binary(encrypting_binary(decrypting_binary(ciphertext_three, key3), key2), key1)
    return plaintext


def encrypting_binaryStr(plaintext_str, key):
    length = len(plaintext_str)
    if length % 16 != 0:
        return
    ciphertext_binarystring = ""
    for i in range(0, length, 16):
        group = plaintext_str[i:i + 16]
        plain_group = encrypting_binary(group, key)
        ciphertext_binarystring += plain_group
    return ciphertext_binarystring


def encrypting_hexadecimal(plaintext_hexadecimal, key_hexadecimal):
    length = len(plaintext_hexadecimal)
    if length % 4 != 0:
        return
    ciphertext_hexadeciaml = ""
    key = (bin(int(key_hexadecimal, 16))[2:]).zfill(16)
    for i in range(0, length, 4):
        group = plaintext_hexadecimal[i:i + 4]
        ciphertext_binary = (bin(int(group, 16))[2:]).zfill(16)
        ciphertext_binary = encrypting_binary(ciphertext_binary, key)
        ciphertext_hexadeciaml1 = hex(int(ciphertext_binary, 2))[2:].zfill(4)
        ciphertext_hexadeciaml += ciphertext_hexadeciaml1
    return ciphertext_hexadeciaml


def encrypting_ascii(plaintext_ascii, key):
    length = len(plaintext_ascii)
    if length % 2 != 0:
        return
    ciphertext_ascii = ""
    for i in range(0, length, 2):
        group = plaintext_ascii[i:i + 2]
        plaintext_binary = ''.join([bin(ord(char))[2:].zfill(8) for char in group])
        ciphertext_binary1 = encrypting_binary(plaintext_binary, key)
        byte1 = ciphertext_binary1[0:8]
        byte2 = ciphertext_binary1[8:16]
        ciphertext_ascii1 = chr(int(byte1, 2)) + chr(int(byte2, 2))
        ciphertext_ascii += ciphertext_ascii1
    return ciphertext_ascii


def encrypting_double(plaintext_double, key):
    key1 = key[:16]
    key2 = key[16:]
    ciphertext_double = encrypting_binary(encrypting_binary(plaintext_double, key1), key2)
    return ciphertext_double


def encrypting_three(plaintext_three, key):
    key1 = key[:16]
    key2 = key[16:32]
    key3 = key[32:]
    ciphertext = encrypting_binary(decrypting_binary(encrypting_binary(plaintext_three, key1), key2), key3)
    return ciphertext


import random


def IV_generate(seed):
    random.seed(seed)
    iv = bytes([random.randint(0, 255) for _ in range(2)])
    iv_binary = ''.join(format(byte, '08b') for byte in iv)
    return iv_binary


def CBC_encryption(plaintext_binary, key, seed, padding):
    IV = IV_generate(seed)
    result = str()
    plain_group = str()
    if len(plaintext_binary)%16 != 0:
        group_number = len(plaintext_binary)//16 + 1
        padding = group_number * 16 - len(plaintext_binary)
        plaintext_binary += '0' * padding
    for i in range(0, len(plaintext_binary), 16):
        group = plaintext_binary[i:i + 16]
        if i == 0:
            curr = xor_bits(group, IV)      # 第一轮和IV做异或, 再加密
        else:
            curr = xor_bits(group, plain_group)     # 之后先和上一轮加密的结果做异或, 再加密
        plain_group = encrypting_binary(curr, key)
        result += plain_group
    return result, padding


def CBC_decryption(ciphertext_binary, key, seed, padding):
    IV = IV_generate(seed)
    result = str()
    cipher_group = str()
    for i in range(0,len(ciphertext_binary),16):
        group = ciphertext_binary[i: i+16]
        curr = decrypting_binary(group, key)
        if i == 0:
            cipher_group = xor_bits(IV, curr)
            result += cipher_group
        else:
            cipher_group = xor_bits(ciphertext_binary[i-16:i], curr)
            result += cipher_group
    if padding == 0:
        return result
    else:
        return result[:-padding]


import copy
# 第一组加密解密，得到一个列表


def encrypt_decrypt_all(P, C):
    my_list = []  # 记录所有加密结果
    key1_list = []
    key2_list = []
    for key in range(2 ** 16):
        binary_key1 = format(key, '016b')  # 将密钥转换为二进制字符串
        my_list.append(encrypting_binary(P, binary_key1))
    for key in range(2 ** 16):
        binary_key2 = format(key, '016b')
        decrypted_text = decrypting_binary(C, binary_key2)
        if decrypted_text in my_list:
            index = my_list.index(decrypted_text)
            binary_key1 = format(index, '016b')
            key1_list.append(binary_key1)
            key2_list.append(binary_key2)
    return key1_list, key2_list


# 其他组解密
def try_decrypt(key1_list, key2_list, p_list, c_list):
    key1 = []
    key2 = []
    for i in range(len(c_list)):
        key1.clear()
        key2.clear()
        for j in range(len(key1_list)):
            decrypt_P = decrypting_double(c_list[i], key1_list[j] + key2_list[j])
            if decrypt_P == p_list[i]:
                key1.append(key1_list[j])
                key2.append(key2_list[j])
        key1_list = copy.copy(key1)
        key2_list = copy.copy(key2)
    return key1, key2


def meet_in(P, C):
    key1_list, key2_list = encrypt_decrypt_all(P[0], C[0])
    P_copy = copy.copy(P)
    C_copy = copy.copy(C)
    P_copy.pop(0)
    C_copy.pop(0)
    result_key=[]
    key1_list11,key2_list11=try_decrypt(key1_list, key2_list, P_copy, C_copy)
    for i in range(len(key1_list11)):
        result_key.append(key1_list11[i]+key2_list11[i])
    return result_key


def main():
    n=input('已有使用相同明密文对数量：')
    P_list=[]
    C_list=[]
    i=0
    while i<3:
        p=input(f'第{i+1}个明文：')
        c=input(f'第{i+1}个密文：')
        P_list.append(p)
        C_list.append(c)
        i=i+1
    print(meet_in(P_list,C_list))


if __name__ == "__main__":
    main()
