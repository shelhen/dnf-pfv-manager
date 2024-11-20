import pandas as pd
from pkgkits.PvfParser import TinyPVF
from pkgkits.utils import rarity_map, trade_map, equip_map, job_map, equipment_map, supply_map

pfv_file = './Script.pvf'
encode = 'big5'

pvf = TinyPVF(pvf_path=pfv_file)
# pvf


def get_equipments(file_path='equipment/equipment.lst'):
    equipment_detail_map = {}
    equipments = pvf.load_lst(file_path)
    for _id, path in equipments.items():
        units = pvf.decrypt_bin2slist(path)
        equipment_detail_map[_id] = pvf.build_tree(units)
    return equipment_detail_map


def parse_equipments(equipment_detail_map):
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


equipment_detail_map = get_equipments()
equips = parse_equipments(equipment_detail_map)
pd.DataFrame(equips).to_excel('./equipment_detail_map.xlsx', index=False)