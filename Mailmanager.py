# -*- encoding: utf-8 -*-
"""
--------------------------------------------------------
@File: Mailmanager.py
@Project: dnf-pfv-manager 
@Time: 2024/11/15   12:59
@Author: shelhen
@Email: shelhen@163.com
@Software: PyCharm 
--------------------------------------------------------
# @Brief:
"""
from datetime import datetime




def send_message(cNo, sender='测试发件人',message='测试邮件')->int:
    reg_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sql = f'insert into letter (charac_no,send_charac_no,send_charac_name,letter_text,reg_date,stat) ' + \
          f"values ({cNo},0,%s,%s,'{reg_time}',1);"
    execute_and_commit('taiwan_cain_2nd',sql,(sender.encode('utf-8'),message.encode('utf-8')),'latin1')
    sql = f"select letter_id from letter where reg_date='{reg_time}'"
    letterID = execute_and_fech('taiwan_cain_2nd',sql)
    return letterID[-1][0]

def send_postal(cNo,letterID=0,sender='测试发件人',message='测试邮件',itemID=1000,increaseType=0,increaseValue=0,forgeLev=0,seal=0,totalnum=1,enhanceValue=0,gold=0,avata_flag=0,creature_flag=0,endurance=0):
    def send():
        nonlocal num
        occ_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if avata_flag==1:
            sql = f"insert into taiwan_cain_2nd.user_items (charac_no,it_id,expire_date,obtain_from,reg_date,stat) values ({cNo},{itemID},'9999-12-31 23:59:59',1,'{occ_time}',2)"
            execute_and_commit('taiwan_cain_2nd',sql)
            sql = f"select ui_id from user_items where charac_no={cNo} and it_id={itemID} and reg_date='{occ_time}';"
            ui_id = execute_and_fech('taiwan_cain_2nd',sql)[0][0]
            num = ui_id
        elif creature_flag==1:
            sql = f"insert into taiwan_cain_2nd.creature_items (charac_no,it_id,expire_date,reg_date,stat,item_lock_key,creature_type) values ({cNo},{itemID},'9999-12-31 23:59:59','{occ_time}',1,1,1)"
            execute_and_commit('taiwan_cain_2nd',sql)
            sql = f"select ui_id from creature_items where charac_no={cNo} and it_id={itemID} and reg_date='{occ_time}';"
            ui_id = execute_and_fech('taiwan_cain_2nd',sql)[0][0]
            num = ui_id
        sql = 'insert into postal (occ_time,send_charac_name,receive_charac_no,amplify_option,amplify_value,seperate_upgrade,seal_flag,item_id,add_info,upgrade,gold,letter_id,avata_flag,creature_flag,endurance,unlimit_flag) '+ \
              f"values ('{occ_time}',%s,{cNo},{increaseType},{increaseValue},{forgeLev},{seal},{itemID},{num},{enhanceValue},{gold},{letterID},{avata_flag},{creature_flag},{endurance},1)"
        execute_and_commit('taiwan_cain_2nd',sql,(sender.encode(),),'latin1')
    if letterID==0:
        letterID = send_message(cNo,sender='测试发件人',message='测试邮件')
    stkLimit = cacheM.get_Item_Info_In_Dict(itemID).get('[stack limit]')
    if stkLimit is not None:
        stkLimit = stkLimit[0]
    else:
        stkLimit = 1e19
    numSend = 0
    subNum = 0  #邮件内附件数量

    while numSend<totalnum or totalnum<=0:
        if subNum>9:
            letterID = send_message(cNo,sender,message)
            subNum = 0
        num_tmp = min(stkLimit,totalnum-numSend)
        num = num_tmp
        send()
        gold = 0
        subNum += 1
        numSend += num_tmp
        if totalnum<=0:
            break