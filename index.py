# -*- coding: utf8 -*-
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

import logging
import re
import json
import requests
from email.mime.text import MIMEText
from email.header import Header
import smtplib
import datetime
import rsa
import base64
from requests import Session


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# Third-party SMTP service for sending alert emails. 第三方 SMTP 服务，用于发送告警邮件
mail_host = "smtp.qq.com"       # SMTP server, such as QQ mailbox, need to open SMTP service in the account. SMTP服务器,如QQ邮箱，需要在账户里开启SMTP服务
mail_user = "邮箱"  # Username 用户名
mail_pass = "密码"  # Password, SMTP service password. 口令，SMTP服务密码
mail_port = 465  # SMTP service port. SMTP服务端口

# The notification list of alert emails. 告警邮件通知列表
email_notify_list = {
    "通知目标邮箱",
}


def sendEmail(fromAddr, toAddr, subject, content):
    sender = fromAddr
    receivers = [toAddr]
    message = MIMEText(content, 'plain', 'utf-8')
    message['From'] = Header(fromAddr, 'utf-8')
    message['To'] = Header(toAddr, 'utf-8')
    message['Subject'] = Header(subject, 'utf-8')
    try:
        smtpObj = smtplib.SMTP_SSL(mail_host, mail_port)
        smtpObj.login(mail_user, mail_pass)
        smtpObj.sendmail(sender, receivers, message.as_string())
        print("send email success")
        return True
    except smtplib.SMTPException as e:
        print(e)
        print("Error: send email fail")
        return False

def daka():
    session = Session()

    data = {
        'oauth_uname': '易班用户',
        'oauth_upwd': '易班密码',
        'client_id': '抓包得',
        'redirect_uri': '目标应用url',
        'state': '抓包登陆',
        'scope': '1,2,3,4,',
        'display': 'html',
    }

    headers = {
        'Accept': '*/*',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Origin': 'https://oauth.yiban.cn',
        'Pragma': 'no-cache',
        'Referer': f"https://oauth.yiban.cn/code/html?client_id={data['client_id']}&redirect_uri={data['redirect_url']}&state={data['state']}",
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Mobile Safari/537.36',
        'X-Requested-With': 'XMLHttpRequest',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="102", "Google Chrome";v="102"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
    }

    r = session.get(f"https://oauth.yiban.cn/code/html?client_id={data['client_id']}&redirect_uri={data['redirect_url']}&state={data['state']}", headers=headers)
    sub = r'<input type="test" id="key" value="([\s\S]*?)" style="display:none">'
    public_key = re.findall(sub, r.text)[0]
    public_key = rsa.PublicKey.load_pkcs1_openssl_pem(public_key.encode('utf-8'))
    data["oauth_upwd"] = base64.b64encode(rsa.encrypt(data["oauth_upwd"].encode(), public_key)).decode()

    session.post('https://oauth.yiban.cn/code/usersure', headers=headers, data=data)
    response = session.get(data["redirect_uri"], headers=headers)
    access_token = response.url.split("access_token=")[1]

    login_url = '抓包得' + access_token
    login_headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Host': '学校易班域名',
        'Pragma': 'no-cache',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 11; RMX2121 Build/RP1A.200720.011)',
     }

    school_home_url = "学校易班平台url"

    try:
        token = json.loads(session.get(login_url, headers=login_headers).content)['token']
    except Exception as e:
        raise e

    login_headers["Accept"] = "application/json, text/plain, */*:"
    login_headers['token'] = token
    login_headers["Content-Type"] = "application/json;charset=UTF-8"
    login_headers['Referer'] = school_home_url
    login_headers["Origin"] = school_home_url

    daka_url = school_home_url + "/api/diag/click"
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    a_p = datetime.datetime.now().strftime("%p")
    data = {
        "yb_uid": int, # id
        "temperature": int, # 体温
        "address": "XX,XX,XX", # 地址
        "position": None,
        "date": datetime.date.today().strftime("%Y-%m-%d"),
        "is_illness": 0,
        "create_time": current_time,
        "update_time": current_time,
        "delete_time": None,
        "time": a_p.upper(),
        "is_go_out": "否",
        "go_out_address": "",
        "is_14_ncp": "否",
        "is_touch_patient": "否",
        "is_return_school": "",
        "return_datetime": "0000-00-00 00:00:00",
        "return_vehicle": "",
        "health": "健康",
        "is_cough": ".",
        "is_go_doctor": "",
        "hospital": "",
        "result": "",
        "is_isolated": "",
        "isolated_place": "",
        "jt_health": "健康",
        "jt_remark": "",
        "remark_qt": "",
        "time_type": a_p.lower(),
        "stu_type": "2"
    }

    r = session.post(daka_url, headers=login_headers, data=json.dumps(data))
    result = json.loads(r.content.decode())
    session.close()
    if result.get("code", None) != 201:
        raise Exception("打卡失败", result["msg"])
    else:
        print(result)
        

def handler(event, context):
    try:
        daka()
    except Exception as e:
        for toAddr in email_notify_list:
            sendEmail(mail_user, toAddr, "易班没打卡", str(e))
        return


if __name__ == '__main__':
    handler("", "")
