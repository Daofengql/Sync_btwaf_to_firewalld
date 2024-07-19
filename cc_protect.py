import aiohttp
import asyncio
import os
import json
from time import time
from loguru import logger
from datetime import datetime
from hashlib import md5
from urllib.parse import quote


BASE_URL = ""
BT_PANNLE = ""
BT_KEY = ""



#



class bt_firewalld:
    def __init__(self,baseurl,key) -> None:
        self.baseurl = baseurl
        self.key = key
        self.session = aiohttp.ClientSession

    async def GetMd5(self,s):  # 参考了Demo.py
        m = md5()
        m.update(s.encode("utf-8"))
        return m.hexdigest()

    async def GetKeyData(self):  # 签名算法
        now_time = time()
        p_data = {
            "request_token": await self.GetMd5(str(now_time) + "" + await self.GetMd5(self.key)),
            "request_time": now_time
        }
        return p_data


    async def GetFinalData(self,data):
        pdata = await self.GetKeyData()
        for key in pdata:
                data[key] = pdata[key]
        return data


    async def DelIPrules(self,details):
        url = self.baseurl + "/plugin?action=a&name=firewall&s=remove_ip_rules"
        async def delf(details,url):
            async with self.session() as session:
                for det in details:
                    data = await self.GetFinalData({
                        "id":det["id"],
                        "types":det['types'],
                        "address":det["address"]
                    })
                    async with session.post(url,data=data) as resp2:
                        pass

        asyncio.create_task(delf(details,url))
        return True

    async def AddIPrules(self,rules):
         async with self.session(timeout=aiohttp.ClientTimeout(20000)) as session:
            url = self.baseurl + "/files?action=upload"
            size = len(rules.encode('utf-8'))

            data = await self.GetFinalData({
                        "f_path":"/www/server/panel/plugin/firewall",
                        "f_name":"extip.json",
                        "f_size":str(size),
                        "f_start":"0",
                    })


            # 创建FormData对象
            form_data = aiohttp.FormData()

            # 遍历字典，添加字段到FormData对象中
            for key, value in data.items():
                form_data.add_field(key, str(value))

            form_data.add_field('blob',rules.encode('utf-8'), filename='ip,json')

            async with session.post(url,data=form_data) as resp:
                pass

            url = self.baseurl + "/plugin?action=a&name=firewall&s=import_rules"
            data = await self.GetFinalData({
                        "rule_name":"ip_rule",
                        "file_name":"extip.json"
                    })
            async with session.post(url,data=data) as resp:
                pass

        
    async def GetIPrules(self):  # 获取系统基础统计
        async with self.session(timeout=aiohttp.ClientTimeout(20000)) as session:
            url = self.baseurl + "/plugin?action=a&name=firewall&s=export_rules"
            data = await self.GetFinalData({
                "rule_name":"ip_rule"
            })

            async with session.post(url,data=data) as resp:
                if resp.status == 200:
                    dat = await resp.json()
                else :
                    logger.error("获取系统防火墙IP规则失败")
                    return 
            
            data = await self.GetFinalData({
                "path":dat['msg']
            })
            async with session.post( self.baseurl + f"/files?action=GetFileBody",data=data) as resp2:
                if resp2.status == 200:
                    dat = await resp2.json()
                    return json.loads(dat['data'])
                else :
                    logger.error("获取系统防火墙IP规则失败")
                    return 



async def httpRequestGet(url):
    async with aiohttp.ClientSession() as session:
        try:
            header = {
                "User-Agent": "Auto CC Protect Service"
            }
            async with session.get(url,headers = header) as result:
                return True,await result.text()
        except:
            return False,None

#主进程
async def main():
    btSign = bt_firewalld(baseurl=BT_PANNLE,key=BT_KEY)
    while True:
        
        status,block_ip = await httpRequestGet(BASE_URL + "/block_ip")
        if status == False:
            logger.error(f"获取当前防火墙黑名单IP失败，请检查获取地址是否配置错误")
        else:
            block_ip = json.loads(block_ip)
            firewalldip = await btSign.GetIPrules()

            tempblack = []

            if not block_ip['ips']:
                for rule in firewalldip:
                    if rule["brief"] == "自动脚本安全防御自动添加" :
                        tempblack.append(rule)
                logger.info(f"获取到当前防火墙黑名单IP成功，当前没有黑名单IP，系统安全")
                await btSign.DelIPrules(tempblack)
            else:
                
                logger.warning(f"获取到当前防火墙黑名单IP成功，总数{len(block_ip['ips'])}")
                # 获取当前时间
                current_time = datetime.now()
                formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
                
                #处理系统防火墙中已经不处于拉黑状态的ip，压入队列准备删除
                for rule in firewalldip:
                    if rule["brief"] == "自动脚本安全防御自动添加" and rule["address"] not in block_ip['ips']:
                        tempblack.append(rule)

                await btSign.DelIPrules(tempblack)
            
                logger.info(f"开始计算新增IP")
                #开始处理添加的ip
                tempblack2 = []
                for rule in firewalldip:
                    if rule["brief"] == "自动脚本安全防御自动添加":
                        tempblack2.append(rule["address"])
                #获取不在其中的ip
                tempblack2 = list(set(block_ip['ips']) - set(tempblack2))

                if tempblack2:
                    blacks = []
                    #开始处理添加ip
                    
                    for ip in tempblack2:
                        blacks.append(
                            {"id": 1, "types": "drop", "address": f"{ip}", "brief": "自动脚本安全防御自动添加", "addtime": f"{formatted_time}", "sid": 0, "domain": ""}
                        )
                    logger.info(f"获取新增IP {len(blacks)} 个")
                    blacks = json.dumps(blacks, ensure_ascii=False)
                    logger.info(f"开始阻断新增IP")
                    await btSign.AddIPrules(blacks)
                    logger.info(f"添加完成")

                else:
                    logger.info(f"没有新增IP")





        await asyncio.sleep(20)

    




# 运行主函数
asyncio.run(main())
