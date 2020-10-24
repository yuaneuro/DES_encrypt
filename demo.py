import re
from DES_BOX import *


# 将明文转化为二进制
def str2bin(message):
    res = ''
    for i in message:
        tmp = bin(ord(i))[2:]  # 将每个字符转化成二进制
        tmp = str('0' * (8 - len(tmp))) + tmp  # 补齐8位
        res += tmp
    if len(res) % 64 != 0:
        count = 64 - len(res) % 64  # 不够64位补充0
    else:
        count = 0
    res += '0' * count
    return res


# 将密钥转化为二进制
def key2bin(key):
    res = ''
    for i in key:
        tmp = bin(ord(i))[2:]  # 将每个字符转化成二进制
        tmp = str('0' * (8 - len(tmp))) + tmp  # 补齐8位
        res += tmp
    if len(res) < 64:
        count = 64 - len(res) % 64  # 不够64位补充0
        res += '0' * count
    else:
        res = res[:64]
    return res


# IP盒处理
def ip_change(str_bin):
    res = ''
    for i in IP_table:
        res += str_bin[i - 1]
    return res


# 生成子密钥
def gen_key(bin_key):
    key_list = []
    key1 = change_key1(bin_key)  # 秘钥的PC-1置换
    key_C0 = key1[0:28]
    key_D0 = key1[28:]
    for i in SHIFT:  # shift左移位数
        key_c = key_C0[i:] + key_C0[:i]  # 左移操作
        key_d = key_D0[i:] + key_D0[:i]
        key_output = change_key2(key_c + key_d)  # 秘钥的PC-2置换
        key_list.append(key_output)
    return key_list


# 秘钥的PC-1置换
def change_key1(my_key):
    res = ""
    for i in PC_1:  # PC_1盒上的元素表示位置    只循环64次
        res += my_key[i - 1]  # 将密钥按照PC_1的位置顺序排列，
    return res


# 秘钥的PC-2置换
def change_key2(my_key):
    res = ""
    for i in PC_2:
        res += my_key[i - 1]
    return res


# E盒置换
def e_change(str_left):
    res = ""
    for i in E:
        res += str_left[i - 1]
    return res


def xor_change(str1, str2):
    res = ""
    for i in range(0, len(str1)):
        xor_res = int(str1[i], 10) ^ int(str2[i], 10)  # 进行xor操作
        if xor_res == 1:
            res += '1'
        if xor_res == 0:
            res += '0'
    return res


def s_change(my_str):
    res = ""
    c = 0
    for i in range(0, len(my_str), 6):  # 步长为6   表示分6为一组
        now_str = my_str[i:i + 6]  # 第i个分组
        row = int(now_str[0] + now_str[5], 2)  # 第r行
        col = int(now_str[1:5], 2)  # 第c列
        # 第几个s盒的第row*16+col个位置的元素
        num = bin(S[c][row * 16 + col])[2:]  # 利用了bin输出有可能不是4位str类型的值，所以才有下面的循环并且加上字符0
        for gz in range(0, 4 - len(num)):  # 补全4位
            num = '0' + num
        res += num
        c += 1
    return res


def p_change(bin_str):
    res = ""
    for i in P:
        res += bin_str[i - 1]
    return res


def f(str_left, key):
    e_change_output = e_change(str_left)  # E扩展置换
    xor_output = xor_change(e_change_output, key)  # 将48位结果与子密钥Ki进行异或（xor）
    s_change_output = s_change(xor_output)
    res = p_change(s_change_output)
    return res


# IP逆盒处理
def ip_re_change(bin_str):
    res = ""
    for i in IP_re_table:
        res += bin_str[i - 1]
    return res


# 二进制转字符串
def bin2str(bin_str):
    res = ""
    tmp = re.findall(r'.{8}', bin_str)  # 每8位表示一个字符
    for i in tmp:
        res += chr(int(i, 2))
    return res


def encrypt():
    bin_str = str2bin(input('请输入明文：'))
    bin_key = key2bin(input('请输入密钥：'))
    tmp = re.findall(r'.{64}', bin_str)
    result = ''
    for i in tmp:
        str_bin = ip_change(i)  # IP置换
        key_lst = gen_key(bin_key)  # 生成16个子密钥
        str_left = str_bin[:32]
        str_right = str_bin[32:]
        for j in range(15):  # 先循环15次 因为最后一次不需要不用换位
            f_res = f(str_right, key_lst[j])
            str_left = xor_change(f_res, str_left)
            str_left, str_right = str_right, str_left

        f_res = f(str_right, key_lst[15])  # 第16次
        str_left = xor_change(str_left, f_res)
        fin_str = ip_re_change(str_left + str_right)  # ip的逆
        result += fin_str
    last = bin2str(result)
    print('密文为:', last)


def decrypt():  # 解密和加密的步骤差不多，但要注意解密时密钥是倒过来的 ，第一个的时候左右不交换
    bin_str = str2bin(input('请输入密文：'))
    bin_key = key2bin(input('请输入密钥：'))
    tmp = re.findall(r'.{64}', bin_str)
    result = ''
    for i in tmp:
        str_bin = ip_change(i)  # IP置换
        key_lst = gen_key(bin_key)  # 生成16个子密钥
        str_left = str_bin[:32]
        str_right = str_bin[32:]
        for _j in range(1, 16):
            j = 16 - _j  # 解密的时候秘钥反过来的
            f_res = f(str_right, key_lst[j])
            str_left = xor_change(f_res, str_left)
            str_left, str_right = str_right, str_left
        f_res = f(str_right, key_lst[0])
        str_left = xor_change(str_left, f_res)
        fin_str = ip_re_change(str_left + str_right)  # ip的逆
        result += fin_str
    last = bin2str(result)
    print('明文为:', last)


if __name__ == '__main__':
    print("1.使用DES加密")
    print("2.使用DES解密")
    mode = input()
    if mode == '1':
        encrypt()
    elif mode == '2':
        decrypt()
    else:
        print('error')
