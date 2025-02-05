# -*- coding: utf-8 -*-
# @Date     : 2024-07-08
# @File     : utils.py
# @function : 工具类，主要为了替换API中的特殊字符
import re


def replace_api_patterns(api):
    # 判断api是否以'$'或'#'开头
    if api.startswith('$') or api.startswith('#'):
        # 使用正则表达式替换'$'或'#'后面的{}为\d+
        api = re.sub(r'[\$\#]\{.*?\}', r'\\d+', api)
    else:
        # 使用正则表达式替换{}为\d+
        # api = re.sub(r'\{.*?\}', r'\\d+', api)
        api = re.sub(r'\{[^}]*\}', r'\\d+', api)
    return api


def URL_encode(api):
    # return api.replace("/", "%2F") # 使用replace函数进行编码，只替换/
    # return quote(api, safe='')  # 使用quote函数进行编码，支持所有字符

    # 减少依赖问题，自己创建编码函数
    # 此处由于正则匹配优于URL编码，因此先将\d+ 替换一下
    protected_pattern = '__PROTECTED__'
    #api = re.sub(r'\\d+', protected_pattern, api)
    api = api.replace('\d+', protected_pattern)

    encoded = ""
    for char in api:
        if char.isalnum() or char in ('-', '_', '.', '~', '{', '}'):
            encoded += char
        elif char == ' ':
            encoded += '+'
        else:
            # 其他字符需要编码
            hex_val = format(ord(char), 'x')
            encoded += '%' + hex_val.upper()

    # 恢复之前保护的模式
    encoded = encoded.replace(protected_pattern, r'\d+')
    return encoded