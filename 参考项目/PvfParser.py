# -*- encoding: utf-8 -*-
"""
--------------------------------------------------------
@File: PvfParser.py
@Project: dnf 
@Time: 2024/11/10   22:33
@Author: shelhen
@Email: shelhen@163.com
@Software: PyCharm 
--------------------------------------------------------
"""
import struct
from struct import unpack
from zhconv import convert
import json
from pathlib import Path
from typing import Optional
from copy import deepcopy
from config import json_dict_converter, settings

try:
    import multiprocessing
except:
    pass


is_gen_keyword = False
KeywordMap = settings['keywordmaps']
FiletypeMap = settings['filetype']
Keywords = json_dict_converter(KeywordMap["keywords"])
KeywordsDict = json_dict_converter(KeywordMap["keywords_dict"])
subKeywordsDict = {}


def decrypt(input_bytes: bytes, crc):
    """
    对原始字节流进行 预处理
    """
    key = 0x81A79011
    xor = crc ^ key
    int_num = len(input_bytes) // 4
    key_all = xor.to_bytes(4, 'little') * int_num
    value_xor = int.from_bytes(key_all, 'little') ^ int.from_bytes(input_bytes, 'little')
    mask_1 = 0b00000000_00000000_00000000_00111111
    mask_2 = 0b11111111_11111111_11111111_11000000
    mask_1_all = int.from_bytes(mask_1.to_bytes(4, 'little') * int_num, 'little')
    mask_2_all = int.from_bytes(mask_2.to_bytes(4, 'little') * int_num, 'little')
    value_1 = value_xor & mask_1_all
    value_2 = value_xor & mask_2_all
    _value = value_1 << 26 | value_2 >> 6
    return _value.to_bytes(4 * int_num, 'little')


class PVFHeader(object):
    """PVF头部类"""

    def __init__(self, path, readFullFile=False):
        self.path = path
        self.fp = open(self.path, 'rb')
        self.index = 0  # 用于读取HeaderTree的指针
        self.uuid_len = struct.unpack('i', self.fp.read(4))[0]
        self.uuid = self.fp.read(self.uuid_len)
        self.version = struct.unpack('i', self.fp.read(4))[0]
        self.dirTreeLength = struct.unpack('i', self.fp.read(4))[0]  # 长度
        self.dirTreeCrc32 = struct.unpack('I', self.fp.read(4))[0]
        self.numFilesInDirTree: int = struct.unpack('I', self.fp.read(4))[0]
        self.filePackIndexShift = self.fp.tell() + self.dirTreeLength
        self.headerLength = self.fp.tell()
        # 读内部文件树头
        self.headerTreeBytes = self.fp.read(self.dirTreeLength)
        self.unpackedHeaderTreeDecrypted = decrypt(self.headerTreeBytes, self.dirTreeCrc32)
        if readFullFile:
            self.filePackBytes = self.fp.read()
            self.fp.seek(0)
            self.fullFile = self.fp.read()
        else:
            self.fullFile = None

    def to_bytes(self, CRC: int, file_num=0, tree_length=0, uuid=b'\x00' * 36):
        file_num = self.numFilesInDirTree if file_num == 0 else file_num
        tree_length = self.dirTreeLength if tree_length == 0 else tree_length
        res = bytearray()
        res += len(uuid).to_bytes(4, 'little')
        res += uuid
        res += self.version.to_bytes(4, 'little')
        res += tree_length.to_bytes(4, 'little')
        res += CRC.to_bytes(4, 'little')  # dirTreeCrc32.to_bytes(4,'little')
        res += file_num.to_bytes(4, 'little')
        return res

    def get_header_tree_bytes(self, byte_num=4):
        res = self.unpackedHeaderTreeDecrypted[self.index:self.index + byte_num]
        self.index += byte_num
        return res

    def read_bytes(self, start, length):
        if self.fullFile is not None:
            return self.fullFile[start:start + length]
        else:
            if self.fp is None:
                self.fp = open(self.path, 'rb')
            self.fp.seek(start)
            return self.fp.read(length)

    def __repr__(self):
        return 'PVF [{0}]\nVer:{1}\nTreeLength:{2}\nCRC:{3}\n{4} files'.format(
            self.uuid.decode(), self.version, self.dirTreeLength, self.dirTreeCrc32, self.numFilesInDirTree
        )

    def __del__(self):
        self.fp.close()

    __str__ = __repr__


class BinStringTable(object):
    """stringtable.bin文件类"""

    def __init__(self, table_bytes: bytes, encode='big5') -> None:

        self.length = struct.unpack('I', table_bytes[:4])[0]  # 字符串数量
        self.StringTableIndex = table_bytes[4:]  # 4+self.length*4*2
        self.stringTableChunk = table_bytes[4 + self.length * 4 * 2:]
        self.converted = False
        self.encode = encode
        self.convertChunk = []
        if self.encode == 'big5':
            self.trad2sim()

    def __getitem__(self, n):
        """指第n和n+1个int，不是第n组int"""
        if self.converted:
            return self.convertChunk[n]
        else:
            _index = struct.unpack('<II', self.StringTableIndex[n * 4:n * 4 + 8])
            _value = convert(self.StringTableIndex[_index[0]:_index[1]].decode(self.encode, 'ignore'), 'zh-cn')
        return _value

    def trad2sim(self):
        """繁体转化为简体"""
        self.convertChunk = []
        for n in range(self.length * 2):
            _index = struct.unpack('<II', self.StringTableIndex[n * 4:n * 4 + 8])
            _value = self.StringTableIndex[_index[0]:_index[1]].decode(self.encode, 'ignore')
            self.convertChunk.append(convert(_value, 'zh-cn'))
        self.converted = True


class StrTable(object):
    """处理*.str文件"""

    def __init__(self, cont):
        self.text = convert(cont, 'zh-cn')
        lines = filter(lambda x: '>' in x, self.text.split('\n'))
        self.strDict = {line.split('>', 1)[0]: line.split('>', 1)[1] for line in lines}

    def __getitem__(self, key):
        res = self.strDict.get(key)
        return 'None' if res is None else res.replace('\r', '')

    def __repr__(self):
        return 'Str object. <{str(self.strDict.items())[:100]}...>'

    __str__ = __repr__


class LstTable(object):
    """处理*.lst文件对象"""

    def __init__(self, content_bytes, tiny_pvf, bin_string_table, encode='big5', base_dir='', is2sim=True):
        self.code = content_bytes[:2]
        self.tiny_pvf = tiny_pvf
        self.bst: BinStringTable = bin_string_table
        self.baseDir = base_dir
        self.encode = encode

        self.str_dict = {}
        # 存储索引对应的str对象
        self.tablemap = {}
        i = 2
        while i + 10 <= len(content_bytes):
            a, aa, b, bb = struct.unpack('<bIbI', content_bytes[i:i + 10])
            if a == 2:
                _index1 = aa
            elif a == 7:
                _index2 = aa
            if b == 2:
                _index1 = bb
            elif b == 7:
                _index2 = bb
            string = self.bst[_index2]
            self.tablemap[_index1] = string
            i += 10

    def __getitem__(self, n):
        return self.tablemap[n]

    def get(self, key):
        _value = self.str_dict.get(key)
        if _value is not None:
            return _value
        _key = self.tablemap[key].lower()
        content = self.tiny_pvf.fileContentDict.get(_key, self.tiny_pvf.read_File_In_Decrypted_Bin(_key))
        return StrTable(content.decode(self.encode, 'ignore'))

    def __repr__(self):
        return 'Lst object. <{}...>'.format(str(self.tablemap)[:100])

    __str__ = __repr__


class TinyPVF(object):
    """快速查询的pvf节点类"""

    def __init__(self, header: PVFHeader, encode='big5') -> None:
        self.structuremap = {}  # 按结构存储PVF文件树
        self.treemap = {}  # 按 path: leaf存储文件树
        self.contentmap = {}  # 按路径或者物品id作为key存储文件内容
        self.header = header
        self.encode = encode
        self.lst = None
        self.bst = None

    def load_leafs(self, directories=None, header: PVFHeader = None, is_structured=False):
        """
        按pvfHeader读取叶子，当structured为true时，同时会生成结构化的字典
        """
        if directories is None:
            directories = []
        header = self.header if header is None else header
        self.header.index = 0
        # 迭代PVF结构头
        for i in range(header.numFilesInDirTree):
            fn_bytes = header.get_header_tree_bytes(4)
            fp_len_bytes = header.get_header_tree_bytes(4)
            fp_len = struct.unpack('I', fp_len_bytes)[0]
            fp_bytes = header.get_header_tree_bytes(fp_len)
            file_len_bytes = header.get_header_tree_bytes(4)
            crc32_bytes = header.get_header_tree_bytes(4)
            offset_bytes = header.get_header_tree_bytes(4)
            leaf = {
                'index': header.index,
                'fn_bytes': fn_bytes,
                'fn': unpack('I', fn_bytes)[0],
                'fp_len_bytes': fp_len_bytes,
                'fp_len': fp_len,
                'fp_bytes': fp_bytes,
                'fp': fp_bytes.decode(errors='replace').lower(),  # 全部转换为小写
                'file_len_bytes': file_len_bytes,
                'file_len': (unpack('I', file_len_bytes)[0] + 3) & 0xFFFFFFFC,
                'crc32_bytes': crc32_bytes,
                'crc32': unpack('I', crc32_bytes)[0],
                'offset': unpack('I', offset_bytes)[0],
                'content': b'',
            }
            if leaf['fp'][0] == '/':
                print(leaf['filePath'])
                leaf['fp'] = leaf['fp'][1:]
            '''
            if len(dirs)>0 or len(paths)>0:
                leafpaths = leaf['filePath'].split('/')
                if len(leafpaths)>1 and leafpaths[0] not in dirs and leaf['filePath'] not in paths:
                    continue
            '''
            self.treemap[leaf['fp']] = leaf  # 存到路径：文件字典
            if is_structured:
                directories = leaf['fp'].split('/')[1:-1]
                _tmap = self.structuremap
                # 字典扩展：若self.structuremap包含这些键，则不变，若存在不包含的键盘，添加键并设置值为{}
                for directory in directories:
                    if directory not in _tmap.keys():
                        _tmap[directory] = {}
                    _tmap = _tmap[directory]
                _tmap[leaf['fp']] = leaf

        if self.bst is None:
            self.bst = BinStringTable(self.parse_bytestream(FiletypeMap['bst']), self.encode)
            self.lst = LstTable(self.parse_bytestream(FiletypeMap['lst']), self, self.bst, self.encode)
        return self.treemap

    def parse_bytestream(self, filepath, header=None):
        """根据传入路径初步解析字节流"""
        filepath = filepath.lower().replace('\\', '/')
        filepath = filepath[1:] if filepath[0] == '/' else filepath
        leaf = self.treemap.get(filepath)
        if leaf is None:
            directories = filepath.split('/')[0]
            self.load_leafs(directories, header)
            leaf = self.treemap.get(filepath)
        header = self.header if header is None else header
        if self.contentmap.get(filepath) is not None:
            return self.contentmap.get(filepath)

        try:
            result = decrypt(header.read_bytes(header.filePackIndexShift + leaf['offset'], leaf['file_len']),
                             leaf['crc32'])
        except Exception as e:
            print("Error with {0}, {1}".format(e, filepath, leaf))
            result = b''
        return result

    def load_lst(self, filepath, encode=None):
        encode = encode if encode else self.encode
        content = self.parse_bytestream(filepath)
        if '/' in filepath:
            directory, filename = filepath.rsplit('/', 1)
        else:
            directory, filename = '', filepath
        return LstTable(content, self, self.bst, encode, directory)

    def load_bin2list(self, cont=b'', filepath=None, bst: BinStringTable = None, lst: LstTable = None, quote=''):

        bst = self.bst if bst is None else bst
        lst = self.lst if lst is None else lst
        if filepath is not None:
            filepath = filepath.replace('//', '/') if '//' in filepath else filepath
            cont = self.parse_bytestream(filepath)
        return self.decrypt_bin2flist(cont, bst, lst, quote)

    @staticmethod
    def decrypt_bin2flist(cont, bst: BinStringTable, lst: LstTable, quote='', is_trad2sim=False) -> list:
        """二进制文本（如stk文件）解密，解密结果为 字段类型和关键字 组成的List"""
        if cont is None:
            return [[], []]
        unit_len = (len(cont) - 2) // 5
        shift = 2
        spats = '<'
        unit_types = []

        for i in range(unit_len):
            unit_type = cont[i * 5 + shift]
            unit_types.append(unit_type)
            _spa = 'Bf' if unit_type == 4 else 'Bi'
            spats += _spa
        units = struct.unpack(spats, cont[2:2 + 5 * unit_len])
        unit_types = units[::2]
        unit_values = units[1::2]
        units = []
        def trad2sim(x):
            if not isinstance(x, str):
                return x
            try:
                x = convert(x, 'zh-cn')
            except:
                return x
        # 不用字典的原因：unit_type可能重复
        for i in range(unit_len):
            unit_type = unit_types[i]
            if unit_type in (2, 3, 4):
                unit_value = trad2sim(unit_values[i]) if is_trad2sim else unit_values[i]
                units.append((unit_type, unit_value))
            elif unit_type in (5, 6, 8):
                unit_value = trad2sim(bst[unit_values[i]]) if is_trad2sim else bst[unit_values[i]]
                units.append((unit_type, unit_value))
            elif unit_type in (7,):
                unit_value = quote + bst[unit_values[i]] + quote
                units.append((unit_type, trad2sim(unit_value) if is_trad2sim else unit_value))
            elif unit_type in (9,):
                unit_value = lst.get(unit_values[i])[bst[unit_values[i + 1]]]
                units.append((unit_type,trad2sim(unit_value) if is_trad2sim else unit_value))
            else:
                continue
        return units

    @staticmethod
    def serialize_list(units):
        """
        将list序列化为更具备结构的list->段落转为dict存储到list,可能需要重新调试。
        """
        end_segments1,end_segments2 = [], []
        i = len(units) - 1
        end_mark = None

        while i >= 0:
            unit = units[i]
            if end_mark is None and unit[0]==5 and unit[1][:2]=='[/' and unit[1][-1] == ']':
                end_segments1.append(i)
                end_mark = '[' + unit[1][2:]
            elif unit[0] == 5 and unit[1] == end_mark:
                end_segments2.append(i)
                end_mark = None
            i -= 1
        assert len(end_segments1) != len(end_segments2), 'Error'
        segments = []
        i = 0
        while i < len(units):
            unit = units[i]
            if unit[0] != 5:
                segments.append(unit)
                i += 1
                continue
            sub_segment_key = unit[1]
            if i in end_segments1:
                # 寻找结束符，然后递归调用
                end_index = end_segments2[end_segments1.index(i)]
                sub_segments = deepcopy(units[i+1:end_index])
                segments.append({sub_segment_key: TinyPVF.serialize_list(sub_segments) + [True]})
                i = end_index + 1
            else:
                # 持续 segKey,value循环直到此段落结束
                sub_segments = []
                i += 1
                while i < len(units) and units[i][0]!=5:
                    sub_segments.append(unit)
                    i += 1
                segments.append({sub_segment_key: list(dict(sub_segments).values())})
        return segments

    @staticmethod
    def get_seg(structs: list, key='')->list:
        for item in structs:
            if isinstance(item, dict):
                seg = item.get(key)
                if seg is not None:
                    return seg
        return None

    @staticmethod
    def dict2text(segments: dict, prefix='', prefix_add='    ', max_seg_num=50, depth=4) -> str:
        """递归对字段转换为带缩进的文本"""
        count = 0
        paragraph = ''
        if depth <= 0:
            return prefix + str(segments)
        for key, value in segments.items():
            count += 1
            paragraph += prefix + key + '\n'
            if isinstance(value, dict):
                # 递归获取
                paragraph += TinyPVF.dict2text(value, prefix+prefix_add, depth=depth-1)
            else:
                temp = ''
                if len(value) > max_seg_num:
                    value = value[:max_seg_num] + ['...', ]
                for _v in value:
                    temp += f"{_v} "
                    temp = temp.replace('\n', f"\n{prefix}{prefix_add}").replace(r'%%', r'%')
                paragraph += f"{prefix}{prefix_add}{temp}\n"
            if count > max_seg_num:
                break
        return paragraph


class PvfApi(object):
    """封装用于操作TinyPFV实例的一系列接口"""
    def __init__(self):
        pass



if __name__ == '__main__':
    pfv_file = 'Script.pvf'
    pvfHeader = PVFHeader(pfv_file)
    path = 'stackable/stackable.lst'





