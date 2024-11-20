# -*- encoding: utf-8 -*-
"""
--------------------------------------------------------
@File: PvfParser.py
@Project: dnf-pfv-manager 
@Time: 2024/11/13   10:11
@Author: shelhen
@Email: shelhen@163.com
@Software: PyCharm 
--------------------------------------------------------
# @Brief:用于读取和加载PVF的类
"""
import json
import struct
from copy import deepcopy
from zhconv import convert
from pkgkits.utils import rarity_map, trade_map, equip_map, job_map, equipment_map, supply_map

"""
# 参考：
PVF解密算法：https://github.com/similing4/pvf/blob/master/chunk.md
NPK解密算法：https://github.com/KiraMaple/DNFExtractor

PVF存储结构：
header 头部，不加密，存储有文件树的密钥
fileTree 文件树，使用头部的密钥进行加密，解密后是对应文件的大小、偏移、文件路径、密钥
data 文件数据，各自使用对应的密钥进行加密

dnf的pvf文件：
stringtable.bin 存储有所有的文本字段，其他文件只存储文本的字段索引。代码使用StringTable类处理
n_string.lst 存储有一些str文件的路径
*.str 表示一些stringTable的等价文本替换，例如 growtype_name_0 等同于 格斗家。代码使用Str类处理
*.lst id列表，例如 stackable.lst，存着物品id和对应的物品文件（.stk）之间的映射列表。代码使用Lst类处理
*.stk 物品文件，解密后按字节读取，替换为stringtable对应文本。部分stk需要使用str文本进行二次替换（字段为0x09和0x0a）。代码使用
"""


class TinyPVF(object):

    def __init__(self, pvf_path, encoding='big5'):
        """读取pvf文件，初步缓存和解析需要的内容。"""
        self.pvf_path = pvf_path
        self.encoding = encoding
        self.fp = open(self.pvf_path, 'rb')
        uuid_len = struct.unpack('i', self.fp.read(4))[0]
        self.uuid = self.fp.read(uuid_len)
        self.version = struct.unpack('i', self.fp.read(4))[0]
        self.dir_nodes_len = struct.unpack('i', self.fp.read(4))[0]  # 长度
        self.dir_nodes_crc32 = struct.unpack('I', self.fp.read(4))[0]
        self.file_nodes_len = struct.unpack('I', self.fp.read(4))[0]

        self.pack_offset = self.fp.tell() + self.dir_nodes_len
        self.header_len = self.fp.tell()
        self.headers = self.init_headers()
        self.bst = self.load_bst()
        self.lst = self.load_lst()

    def read_bytes(self, start, length):
        """截取指定位置指定长度读取"""
        if self.fp is None:
            self.fp = open(self.pvf_path, 'rb')
        self.fp.seek(start)
        return self.fp.read(length)

    def init_headers(self):
        """
        结构化 header 为字典对象。
        """
        header_bytes = self.fp.read(self.dir_nodes_len)
        unpacked_header_nodes = self.decrypt(header_bytes, self.dir_nodes_crc32)
        treemap = dict()

        def get_header_bytes(offset=4):
            """根据给定的索引和偏移获取头树的属性。"""
            nonlocal _index
            cont = unpacked_header_nodes[_index: _index + offset]
            _index += offset
            return cont

        _index = 0
        # 初始化PVF结构头节点
        for i in range(self.file_nodes_len):
            fn_bytes = get_header_bytes(4)
            fp_len_bytes = get_header_bytes(4)
            fp_len = struct.unpack('I', fp_len_bytes)[0]
            fp_bytes = get_header_bytes(fp_len)
            file_len_bytes = get_header_bytes(4)
            crc32_bytes = get_header_bytes(4)
            offset_bytes = get_header_bytes(4)
            _leaf = {
                'index': _index,
                # 'fn_bytes': fn_bytes,
                'fn': struct.unpack('I', fn_bytes)[0],
                # 'fp_len_bytes': fp_len_bytes,
                'fp_len': fp_len,
                # 'fp_bytes': fp_bytes,
                'fp': fp_bytes.decode(errors='replace').lower(),  # 全部转换为小写
                # 'file_len_bytes': file_len_bytes,
                'file_len': (struct.unpack('I', file_len_bytes)[0] + 3) & 0xFFFFFFFC,
                # 'crc32_bytes': crc32_bytes,
                'crc32': struct.unpack('I', crc32_bytes)[0],
                'offset': struct.unpack('I', offset_bytes)[0],
                # 'content': b'',
            }
            treemap[_leaf['fp']] = _leaf  # 存到路径：文件字典
        return treemap

    def parse_bytestream(self, filepath):
        """根据传入路径初步解析字节流"""
        filepath = filepath.lower().replace('\\', '/').lstrip("/")
        _leaf = self.headers.get(filepath)
        try:
            bytestream = self.read_bytes(self.pack_offset + _leaf['offset'], _leaf['file_len'])
            cont = self.decrypt(bytestream, _leaf['crc32'])
        except Exception as e:
            print(f"Error :{e}, {filepath}, {_leaf}")
            return b""
        return cont

    def load_bst(self, bst_path: str = 'stringtable.bin', encoding=None) -> list:
        """解析stringtable.bin文件类，将其解析为 list[str]"""
        encoding = self.encoding if encoding is None else encoding
        bytestream = self.parse_bytestream(bst_path)
        # 前4位是 该组数据包含的字符串数/2
        bsts_len = struct.unpack('I', bytestream[:4])[0] * 2
        bytestream = bytestream[4:]
        _bsts = []
        for _i in range(bsts_len):
            _shape = struct.unpack('<II', bytestream[_i * 4: _i * 4 + 8])
            _chunk = bytestream[_shape[0]: _shape[1]].decode(encoding, 'ignore')
            _bsts.append(convert(_chunk, 'zh-cn'))
        return _bsts

    def load_stt(self, stt_path: str, encoding=None) -> dict:
        """用于解析处理*.str文件"""
        encoding = self.encoding if encoding is None else encoding
        bytestream = self.parse_bytestream(stt_path)
        text = convert(bytestream.decode(encoding, 'ignore'), 'zh-cn')
        lines = filter(lambda x: '>' in x, text.split('\n'))
        tmap = dict()
        for line in lines:
            _key, _value = line.split('>', 1)
            tmap[_key] = _value if _value else "None"
        return tmap

    def load_lst(self, lst_path: str = 'n_string.lst', encoding=None) -> dict:
        """"用于解析处理*.lst文件对象 {}"""
        encoding = self.encoding if encoding is None else encoding
        bytestream = self.parse_bytestream(lst_path)
        dirname = lst_path.rsplit('/', 1)[0] if '/' in lst_path else ''
        tablemap = {}
        i = 2
        while i + 10 <= len(bytestream):
            a, ia, b, ib = struct.unpack('<bIbI', bytestream[i:i + 10])
            _ind = ia if a == 2 else ib
            tablemap[_ind] = f"{dirname}/{deepcopy(self.bst[ia if a == 7 else ib].lower())}"
            i += 10
        return tablemap

    def decrypt_bin2slist(self, _lst_path: str, quote=None):
        """用于解析非lst二进制文本（如stk文件）解密入口，解密结果为 字段类型和关键字 组成的List"""
        quote = '' if quote is None else quote
        bytestream = self.parse_bytestream(_lst_path)
        if bytestream is None:
            return [[], []]
        # 文件解析
        unit_len = (len(bytestream) - 2) // 5
        _shift = 2
        _spats = '<'
        unit_types = []
        for i in range(unit_len):
            unit_type = bytestream[i * 5 + _shift]
            unit_types.append(unit_type)
            _spa = 'Bf' if unit_type == 4 else 'Bi'
            _spats += _spa
        units = struct.unpack(_spats, bytestream[2:2 + 5 * unit_len])

        unit_types = units[::2]
        unit_values = units[1::2]
        units = []

        def trad2sim(x):
            if not isinstance(x, str):
                return x
            try:
                x = convert(x, 'zh-cn')
            except Exception as e:
                print(f"Trans Error :{e}, {x}")
            return x

        # 不用字典的原因：unit_type可能重复
        for i in range(unit_len):
            unit_type = unit_types[i]
            if unit_type in (2, 3, 4):
                unit_value = trad2sim(unit_values[i])
                units.append((unit_type, unit_value))
            elif unit_type in (5, 6, 8):
                unit_value = trad2sim(self.bst[unit_values[i]])
                units.append((unit_type, unit_value))
            elif unit_type in (7,):
                unit_value = quote + self.bst[unit_values[i]] + quote
                units.append((unit_type, trad2sim(unit_value)))
            elif unit_type in (9,):
                unit_value = self.lst.get(unit_values[i])[self.bst[unit_values[i + 1]]]
                units.append((unit_type, trad2sim(unit_value)))
            else:
                continue
        return units

    @staticmethod
    def build_tree(struct_list: list):
        _tree = {}  # 用于存储最终的树结构
        _stack = []  # 用于存储当前节点的层级路径
        for entry in struct_list:
            if entry[0] == 5:
                # 处理特殊情况
                if '/' in entry[1]:
                    continue
                if _tree.get(entry[1]) is not None:
                    i = 1
                    while _tree.get(f"{entry[1]}-{i}") is not None:
                        i += 1
                    _adjust_key = f"{entry[1]}-{i}"
                else:
                    _adjust_key = entry[1]
                current_node = {"key": entry[0], "value": entry[1], "children": []}
                _tree[_adjust_key] = current_node
                _stack = [current_node]
            else:
                # 对于非根节点 —— 检查 该节点 是否处于 当前节点树的 任一 层级路径中
                position = 0
                is_exist = False
                # 搜索当前树所有的key，是否与本key相等
                for _ix, child in enumerate(_stack[::-1]):
                    if child["key"] == entry[0]:
                        # 存在True，提前结束遍，减小计算量
                        position = _ix
                        is_exist = True
                        break
                # 1.存在： 依次当前节点 出栈 直到 父节点
                if is_exist:
                    for i in range(position+1):
                        _stack.pop()

                # 2.无论是否存在：创建新的子节点，并链接父节点
                child_node = {"key": entry[0], "value": entry[1], "children": []}
                _stack[-1]["children"].append(child_node)
                _stack.append(child_node)
        return _tree

    @staticmethod
    def slist2dict5(units: list, parent_key=None):
        """
        将结构化列表递归还原为字典，同时解析出段落规则，该函数的规则是以5为属性名，其余值都是属性值
        """
        seg_map = {}
        segments = []
        segment_key = None

        for unit in units:
            if unit[0] == 5:
                if '/' in unit[1]:
                    continue
                if seg_map.get(segment_key) is not None:
                    # 曾经存过这个数据，避免覆盖
                    i = 1
                    while seg_map.get(f"{segment_key}-{i}") is not None:
                        i += 1
                    segment_key = f"{segment_key}-{i}"
                # 保存旧数据
                seg_map[segment_key] = segments
                # 更新键 并 初始化segments
                segment_key = unit[1]
                segments = []
            else:
                segments.append(unit[1])
        return seg_map


    @staticmethod
    def decrypt(stream: bytes, crc):
        """
        对原始字节流进行 预处理
        """
        xor = crc ^ 0x81A79011
        int_num = len(stream) // 4
        key_all = xor.to_bytes(4, 'little') * int_num
        value_xor = int.from_bytes(key_all, 'little') ^ int.from_bytes(stream, 'little')
        _a = 0b00000000_00000000_00000000_00111111
        _b = 0b11111111_11111111_11111111_11000000
        tma = int.from_bytes(_a.to_bytes(4, 'little') * int_num, 'little')
        tmb = int.from_bytes(_b.to_bytes(4, 'little') * int_num, 'little')
        v1 = value_xor & tma
        v2 = value_xor & tmb
        tv = v1 << 26 | v2 >> 6
        return tv.to_bytes(4 * int_num, 'little')

    def __repr__(self):
        return "PVF [{0}]\nVer:{1}\nTreeLength:{2}\n{3} files".format(
            self.uuid.decode(), self.version, self.dir_nodes_len, self.file_nodes_len
        )

    def __del__(self):
        self.fp.close()

    __str__ = __repr__


class PVFApi(object):
    """基于pvf封装的一系列接口，一旦成功实例化，会创建一系列缓存，可用于快速读取需要的数据。"""

    def __init__(self, pvf_path, encoding="big5"):
        self.path = pvf_path
        self.pvf = None
        self.headers =None

    def load_pvf(self):
        self.pvf = TinyPVF(pvf_path=pfv_file)
        self.pvf.headers = self.pvf.init_headers()
        self.headers = None

    def get_magic_steal(self, file_path):
        # ='etc/randomoption/randomizedoptionoverall2.etc'
        magic_seal_map = {}
        file_path = 'etc/randomoption/randomizedoptionoverall2.etc'
        structs = self.pvf.decrypt_bin2slist(file_path)
        magic_seal_tree = self.pvf.build_tree(structs)
        for item in magic_seal_tree['[postfix]']["children"]:
            if not item["children"]:
                continue
            magic_seal_map[item["value"]] = [child['value'] for child in item['children']]
        return magic_seal_map

    def get_jobs(self, file_path='character/character.lst'):
        # characters = pvf.load_lst(file_path)
        job_type_map = {}
        job_map = {}
        characters = {
            0: 'character/swordman/swordman.chr',
            1: 'character/fighter/fighter.chr',
            2: 'character/gunner/gunner.chr',
            3: 'character/mage/mage.chr',
            4: 'character/priest/priest.chr',
            5: 'character/gunner/atgunner.chr',
            6: 'character/thief/thief.chr',
            7: 'character/fighter/atfighter.chr',
            8: 'character/mage/atmage.chr',
            9: 'character/swordman/demonicswordman.chr',
            10: 'character/swordman/atswordman.chr'
        }
        for key, path in characters.items():
            units = self.pvf.decrypt_bin2slist(path)
            job_tree = self.pvf.build_tree(units)
            job_map[key] = job_tree.get('[job]')['children'][0]['value']
            job_type_map[key] = {i: child['value'] for i, child in enumerate(job_tree['[growtype name]']['children'])}
        return job_map, job_type_map

    def get_exp(self, file_path=r'character/exptable.tbl'):
        units = self.pvf.decrypt_bin2slist(file_path)
        exps = [unit[1] for unit in units if isinstance(unit[1], int)]
        return exps

    def get_equipments(self, file_path='equipment/equipment.lst'):
        equipment_detail_map = {}
        equipments = self.pvf.load_lst(file_path)
        for _id, path in equipments.items():
            units = self.pvf.decrypt_bin2slist(path)
            equipment_detail_map[_id] = self.pvf.build_tree(units)
        return equipment_detail_map


    def get_supplies(self, file_path='stackable/stackable.lst'):
        """获取与解析物品信息"""
        supply_map = {}
        supply_detail_map = {}
        supplies = self.pvf.load_lst(file_path)
        for _id, _path in supplies.items():
            units = self.pvf.decrypt_bin2slist(_path)
            supply_detail_map[_id] = self.pvf.build_tree(units)
            names = [str(name["value"]) for name in supply_detail_map[_id].get('[name]')["children"]]
            if names is not None:
                supply_map[_id] = ''.join(names)
            else:
                supply_map[_id] = '[无名称]'
        return supply_map, supply_detail_map

    def get_instances(self, file_path='dungeon/dungeon.lst'):
        """解析副本介绍等信息"""
        instance_map = {}
        instances = self.pvf.load_lst(file_path)
        for _id, _path in instances.items():
            units = self.pvf.decrypt_bin2slist(_path)
            instance_map[_id] = self.pvf.build_tree(units)
        return instance_map

    def get_avatar_roulette(self, file_path='etc/avatar_roulette/avatarfixedhiddenoptionlist.etc'):
        """解析时装潜力"""
        units = self.pvf.decrypt_bin2slist(file_path)
        # avatar_roulette_map = pvf.build_tree(units)
        uppers = []
        rares = []
        upper, rare = False, False
        for unit in units:
            value = unit[1]
            if value == '[upper]':
                upper = True
                continue
            if value == '[/upper]':
                upper = False
                continue
            if value == '[rare]':
                rare = True
                continue
            if value == '[/rare]':
                rare = False
                continue
            if '[' in str(value) and upper:
                uppers.append(value[1:-1])
            if '[' in str(value) and rare:
                rares.append(value[1:-1])
        return uppers, rares

    def get_tasks(self, file_path = 'n_quest/quest.lst'):
        task_map = {}
        tasks = self.pvf.load_lst(file_path)
        for _id, _path in tasks.items():
            units = self.pvf.decrypt_bin2slist(_path)
            task_map[_id] = self.pvf.build_tree(units)
        return task_map

    def get_skills(self, file_path = 'n_quest/skills.lst'):
        skill_map = {}
        skills = self.pvf.load_lst(file_path)
        for _id, lsp_path in skills.items():
            job_name = lsp_path.replace('skill', '').strip('/').split('.')[0]
            temp_skill_map = {}
            temp_skills = self.pvf.load_lst(lsp_path)
            for skid, skpath in temp_skills.items():
                units = self.pvf.decrypt_bin2slist(skpath)
                temp_skill_map[skid] = {"detail": self.pvf.build_tree(units), "path": skpath}
            skill_map[_id] = {"job_name": job_name, "path": lsp_path, "skills": temp_skill_map}
        return skill_map

    def get_skill_shop_tree(self, file_path='clientonly/skillshoptreespindex.co'):
        skill_map = {}
        units = self.pvf.decrypt_bin2slist(file_path)
        name = None
        for unit in units:
            if unit[0] == 5:
                continue
            if "[" in unit[1] and "]" in unit[1]:
                name = unit[1]
            else:
                skill_map[name] = f"clientonly/{unit[1]}".lower()
        return skill_map

    def parse_equipments(self, equipment_detail_map):
        clean = lambda x: ''.join([i.strip() for i in x.split('\n')]).replace("%%", "%")
        cget = lambda x, y, d=-1: y.get(x, {"children": [{"value": d}]})["children"][0]["value"]
        equips = []
        for key, value in equipment_detail_map.items():
            eid = key
            name = cget("[name]", value)
            grade = cget("[grade]", value, 0)
            rarity = rarity_map[cget("[rarity]", value, -1)]
            trade = trade_map[cget("[attach type]", value, '[trade]')]
            job_usable = [child["value"] for child in value.get("[usable job]", {"children": []})["children"]]
            job_usable = ['[all]'] if len(job_usable) == 0 else job_usable
            require_job = ','.join([job_map[job] for job in job_usable])
            equip_type = cget("[equipment type]", value, '[artifact]').strip('[').strip(']').strip()
            equipment_type = equip_map[equip_type]
            if equipment_type in ['武器', "头肩", "腰带", "上衣", '下装', "鞋"]:
                subtype = cget("[sub type]", value, -1)
                # 计算-细分类别【type1, type2, type3】
                if equipment_type == "武器":
                    equipment_type_map = equipment_map["武器"]
                    if "鬼剑士" in require_job:
                        _equipment_type = "鬼剑士"
                    elif "魔法师" in require_job:
                        _equipment_type = "魔法师"
                    elif "格斗家" in require_job:
                        _equipment_type = "格斗家"
                    elif "神枪手" in require_job:
                        _equipment_type = "神枪手"
                    else:
                        _equipment_type = require_job
                    type2 = equipment_type_map[_equipment_type].get(subtype, "全部")
                else:
                    equipment_type_map = equipment_map["防具"]
                    type2 = equipment_type_map.get(subtype, "全部")
            elif equipment_type in ['项链', '手镯', '戒指']:
                type2 = equipment_type
                equipment_type = "首饰"
            elif equipment_type in ['辅助装备', '魔法石', '称号']:
                type2 = equipment_type
                equipment_type = "特殊装备"
            elif equipment_type in ["未知", "绿色", "蓝色", "红色"]:
                type2 = equipment_type
                equipment_type = "宠物装备"
            else:
                type2 = equipment_type
                equipment_type = "时装"
            desc = clean(cget("[explain]", value, ''))
            equips.append(dict(
                eid=eid,
                name=name,
                grade=grade,
                rarity=rarity,
                trade=trade,
                require_job=require_job,
                type1=equipment_type,
                type2=type2,
                desc=desc
            ))
        return equips


    def parse_supplies(self, supply_detail_map):

        clean = lambda x: ''.join([i.strip() for i in x.split('\n')]).replace("%%", "%")
        cget = lambda x, y, d=-1: y.get(x, {"children": [{"value": d}]})["children"][0]["value"]
        stackables= []
        for sid, value in supply_detail_map.items():
            if value == {}:
                continue
            name = cget("[name]", value, 'null')
            grade = cget("[grade]", value, 1)
            rarity = rarity_map[cget("[rarity]", value, -1)]
            job_usable = [child["value"] for child in value.get("[usable job]", {"children": []})["children"]]
            job_usable = ['[all]'] if len(job_usable) == 0 else job_usable
            require_job = ','.join([job_map[job.lower()] for job in job_usable])
            stackable_type = cget("[stackable type]", value).strip('[').strip(']').strip()
            stackable_type = supply_map.get(stackable_type, [-1, '其他'])[1]
            attach_type = trade_map[cget("[attach type]", value, "[trade]")]
            explain = clean(cget("[explain]", value, "")).strip()
            stackables.append(dict(
                sid=sid,
                name=name,
                grade=grade,
                rarity=rarity,
                require_job=require_job,
                stackable_type=stackable_type,
                attach_type=attach_type,
                explain=explain
            ))


def save_tojson(path, obj):
    with open(path, 'w', encoding='utf8') as f:
        json.dump(obj, f, indent=4, ensure_ascii=False)


def loadjson(path):
    with open(path, 'r', encoding='utf8') as f:
        obj = json.load(f)
    return obj


if __name__ == '__main__':
    pfv_file = './Script.pvf'
    encode = 'big5'






