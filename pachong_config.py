#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : YourName
# @Time   : 2023-10-12
# @File   : vulnerability_crawler.py
# -----------------------------------------------
#融合OSCS1024漏洞库、安天、Tenable平台的漏洞信息爬取脚本
# -----------------------------------------------

import json
import requests
from datetime import datetime
import hashlib
import os
import logging
import traceback
from logging.handlers import TimedRotatingFileHandler
from abc import ABCMeta, abstractmethod
from lxml import etree  # 导入lxml.etree模块
import re  # 导入re模块
import time
import pickle
from functools import lru_cache
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 确保目录存在
PRJ_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(PRJ_DIR, 'log')
CACHE_DIR = os.path.join(PRJ_DIR, 'cache')

# 创建目录
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)

# 日志配置
RUN_LOG = os.path.join(LOG_DIR, 'run.log')
ERR_LOG = os.path.join(LOG_DIR, 'err.log')

# 缓存配置
CACHE_EXPIRE = 3600  # 缓存过期时间（秒）

def init_log(runlog=RUN_LOG, errlog=ERR_LOG):
    """
    初始化日志配置
    """
    # 全局配置
    logger = logging.getLogger()
    logger.setLevel("INFO")  # 改为INFO级别，减少日志量
    BASIC_FORMAT = "%(asctime)s [%(levelname)s] : %(message)s"
    DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
    formatter = logging.Formatter(BASIC_FORMAT, DATE_FORMAT)

    # 输出到控制台的 handler
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    ch.setLevel("INFO")
    logger.addHandler(ch)

    # 输出到运行日志文件的 handler
    fh = TimedRotatingFileHandler(
        filename=runlog,
        when="MIDNIGHT",
        interval=1,
        backupCount=7,
        encoding='utf-8',
        delay=True  # 延迟创建文件
    )
    fh.setFormatter(formatter)
    fh.setLevel("INFO")
    logger.addHandler(fh)

    # 输出到异常日志文件的 handler
    exfh = TimedRotatingFileHandler(
        filename=errlog,
        when="MIDNIGHT",
        interval=1,
        backupCount=7,
        encoding='utf-8',
        delay=True  # 延迟创建文件
    )
    exfh.setLevel("ERROR")
    exfh.setFormatter(formatter)
    logger.addHandler(exfh)

    # 禁用第三方日志
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    # 确保日志目录存在
    os.makedirs(os.path.dirname(runlog), exist_ok=True)
    os.makedirs(os.path.dirname(errlog), exist_ok=True)

    # 创建日志文件
    try:
        if not os.path.exists(runlog):
            open(runlog, 'a').close()
        if not os.path.exists(errlog):
            open(errlog, 'a').close()
    except Exception as e:
        print(f"创建日志文件失败: {str(e)}")

# 初始化日志
init_log()

def log_debug(msg):
    """
    打印调试信息
    :param msg: 日志信息
    :return: None
    """
    try:
        logging.debug(msg)
    except Exception as e:
        print(f"写入调试日志失败: {str(e)}")

def log_info(msg):
    """
    打印正常信息
    :param msg: 日志信息
    :return: None
    """
    try:
        logging.info(msg)
    except Exception as e:
        print(f"写入信息日志失败: {str(e)}")

def log_warn(msg):
    """
    打印警告信息
    :param msg: 日志信息
    :return: None
    """
    try:
        logging.warning(msg)
    except Exception as e:
        print(f"写入警告日志失败: {str(e)}")

def log_error(msg):
    """
    打印异常信息和异常堆栈
    :param msg: 日志信息
    :return: None
    """
    try:
        logging.error(msg)
        logging.error(traceback.format_exc())
    except Exception as e:
        print(f"写入错误日志失败: {str(e)}")
        print(f"原始错误信息: {msg}")
        print(traceback.format_exc())

class CacheManager:
    """
    缓存管理器
    """
    def __init__(self, cache_dir=CACHE_DIR, expire_time=CACHE_EXPIRE):
        self.cache_dir = cache_dir
        self.expire_time = expire_time

    def get_cache_path(self, key):
        return os.path.join(self.cache_dir, f"{key}.cache")

    def get(self, key):
        cache_path = self.get_cache_path(key)
        if not os.path.exists(cache_path):
            return None
        
        try:
            with open(cache_path, 'rb') as f:
                data = pickle.load(f)
                if time.time() - data['timestamp'] > self.expire_time:
                    return None
                return data['content']
        except Exception as e:
            log_error(f"读取缓存失败: {str(e)}")
            return None

    def set(self, key, content):
        cache_path = self.get_cache_path(key)
        try:
            with open(cache_path, 'wb') as f:
                pickle.dump({
                    'timestamp': time.time(),
                    'content': content
                }, f)
        except Exception as e:
            log_error(f"写入缓存失败: {str(e)}")

# 创建全局缓存管理器实例
cache_manager = CacheManager()

class VulnerabilityInfo:
    """
    漏洞信息类
    """

    def __init__(self):
        self.title = ''
        self.time = ''
        self.ids = []
        self.source = ''
        self.detail_url = ''
        self.md5 = ''

    def is_valid(self):
        return bool(self.title)

    def MD5(self):
        if not self.md5:
            data = '%s%s%s' % (self.title, self.time, self.detail_url)
            self.md5 = hashlib.md5(data.encode(encoding='UTF-8')).hexdigest()
        return self.md5

    def to_msg(self):
        return '\n'.join([
            "\n==============================================",
            "[ 标题 ] %s" % self.title,
            "[ 时间 ] %s" % self.time,
            "[ 编号 ] %s" % ', '.join(self.ids),
            "[ 来源 ] %s" % self.source,
            "[ 详情 ] %s" % self.detail_url
        ])

class CVEInfo:
    """
    漏洞信息类
    """

    def __init__(self):
        self.title = ''
        self.time = ''
        self.cve = ''
        self.src = ''
        self.url = ''
        self.id = ''
        self.info = ''
        self.md5 = ''

    def is_valid(self):
        return bool(self.title)

    def MD5(self):
        if not self.md5:
            data = '%s%s%s' % (self.id, self.title, self.url)
            self.md5 = hashlib.md5(data.encode(encoding='UTF-8')).hexdigest()
        return self.md5

    def to_msg(self):
        return '\n'.join([
            "\n==============================================",
            "[ 标题  ] %s" % self.title,
            "[ 时间  ] %s" % self.time,
            "[ 编号  ] %s" % self.cve,
            "[ 来源  ] %s" % self.src,
            "[ 详情  ] %s" % self.url
        ])

class BaseCrawler:
    """
    爬虫基类
    """
    __metaclass__ = ABCMeta  # 定义为抽象类

    def __init__(self, timeout=60, charset='utf-8'):
        self.timeout = timeout or 60
        self.charset = charset or 'utf-8'
        self.session = self._create_session()

    def _create_session(self):
        """
        创建并配置请求会话
        """
        session = requests.Session()
        
        # 配置重试策略
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # 设置请求头
        session.headers.update({
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        })
        
        return session

    @abstractmethod
    def NAME_CH(self):
        return '未知'

    @abstractmethod
    def NAME_EN(self):
        return 'unknown'

    def get_cached_data(self, key):
        """
        获取缓存数据
        """
        return cache_manager.get(key)

    def set_cached_data(self, key, data):
        """
        设置缓存数据
        """
        cache_manager.set(key, data)

    def vulnerabilities(self):
        log_info('正在获取 [%s] 漏洞信息...' % self.NAME_CH())
        
        try:
            # 尝试从缓存获取
            cache_key = f"{self.NAME_EN()}_vulns"
            cached_data = self.get_cached_data(cache_key)
            if cached_data:
                log_info(f"从缓存获取到 [{self.NAME_CH()}] 漏洞信息")
                return cached_data

            # 如果缓存未命中，则爬取
            new_vulnerabilities = self.get_vulnerabilities()
            target_date = datetime.now().strftime('%Y-%m-%d')
            filtered_vulnerabilities = self.filter_by_date(new_vulnerabilities, target_date)
            
            # 缓存结果
            self.set_cached_data(cache_key, filtered_vulnerabilities)
            
            return filtered_vulnerabilities
            
        except Exception as e:
            log_error(f"获取 [{self.NAME_CH()}] 漏洞信息异常: {str(e)}")
            return []

    def cves(self):
        log_info('正在获取 [%s] 威胁情报...' % self.NAME_CH())
        
        try:
            # 尝试从缓存获取
            cache_key = f"{self.NAME_EN()}_cves"
            cached_data = self.get_cached_data(cache_key)
            if cached_data:
                log_info(f"从缓存获取到 [{self.NAME_CH()}] 威胁情报")
                return cached_data

            # 如果缓存未命中，则爬取
            new_cves = self.get_cves()
            
            # 缓存结果
            self.set_cached_data(cache_key, new_cves)
            
            return new_cves
            
        except Exception as e:
            log_error(f"获取 [{self.NAME_CH()}] 威胁情报异常: {str(e)}")
            return []

    @abstractmethod
    def get_vulnerabilities(self):
        return []

    @abstractmethod
    def get_cves(self):
        return []

    def filter_by_date(self, vulnerabilities, target_date):
        """
        根据日期过滤漏洞信息
        """
        filtered = []
        for vuln in vulnerabilities:
            if vuln.time.startswith(target_date):
                filtered.append(vuln)
        return filtered

class OSCS1024Crawler(BaseCrawler):
    """
    OSCS1024漏洞库爬虫类
    """

    def __init__(self):
        super(OSCS1024Crawler, self).__init__()
        # OSCS1024漏洞库API地址
        self.api_url = 'https://www.oscs1024.com/oscs/v1/intelligence/list'

    def NAME_CH(self):
        return 'OSCS1024漏洞库'

    def NAME_EN(self):
        return 'OSCS1024'

    def vulnerabilities(self):
        """
        获取OSCS1024漏洞库的漏洞信息
        :return: 漏洞信息列表
        """
        try:
            log_info(f"[{self.NAME_CH()}] 开始获取漏洞信息")
            
            # 尝试从缓存获取数据
            cache_key = f"oscs1024_vulnerabilities"
            cached_data = cache_manager.get(cache_key)
            if cached_data:
                log_info(f"[{self.NAME_CH()}] 使用缓存数据")
                return cached_data
            
            # 构造请求参数
            params = {
                'page': 1,
                'per_page': 50,  # 获取最新的50条记录
                'type': 'intelligence',
                'sort': 'newest'
            }
            
            # 发送请求
            response = self.session.get(self.api_url, params=params)
            response.raise_for_status()  # 检查HTTP错误
            data = response.json()
            
            # 解析数据
            vulnerabilities = []
            if data.get('code') == 200 and 'data' in data and 'intelligence' in data['data']:
                for item in data['data']['intelligence']:
                    vuln = VulnerabilityInfo()
                    vuln.title = item.get('title', '')
                    vuln.time = item.get('publish_time', '')
                    vuln.ids = [cve.get('cve_id', '') for cve in item.get('cve', [])]
                    vuln.source = self.NAME_CH()
                    vuln.detail_url = f"https://www.oscs1024.com/hd/intelligence/{item.get('id', '')}"
                    
                    if vuln.is_valid():
                        vulnerabilities.append(vuln)
            
            # 缓存结果
            cache_manager.set(cache_key, vulnerabilities)
            
            log_info(f"[{self.NAME_CH()}] 获取到 {len(vulnerabilities)} 条漏洞信息")
            return vulnerabilities
        except Exception as e:
            log_error(f"[{self.NAME_CH()}] 获取漏洞信息失败: {str(e)}")
            return []

class AntiYCloud(BaseCrawler):
    """
    安天(antiycloud)爬虫类
    """

    def __init__(self):
        super(AntiYCloud, self).__init__()
        # 安天(antiycloud)API地址
        self.api_url = 'https://www.antiycloud.com/api/v3/alert/list'

    def NAME_CH(self):
        return '安天(antiycloud)'

    def NAME_EN(self):
        return 'AntiYCloud'

    def cves(self):
        """
        获取安天(antiycloud)的漏洞信息
        :return: 漏洞信息列表
        """
        try:
            log_info(f"[{self.NAME_CH()}] 开始获取漏洞信息")
            
            # 尝试从缓存获取数据
            cache_key = f"antiycloud_cves"
            cached_data = cache_manager.get(cache_key)
            if cached_data:
                log_info(f"[{self.NAME_CH()}] 使用缓存数据")
                return cached_data
            
            # 构造请求参数
            params = {
                'page': 1,
                'size': 50,  # 获取最新的50条记录
                'type': 'cve'
            }
            
            # 发送请求
            response = self.session.get(self.api_url, params=params)
            response.raise_for_status()  # 检查HTTP错误
            data = response.json()
            
            # 解析数据
            cve_list = []
            if data.get('code') == 200 and 'data' in data and 'list' in data['data']:
                for item in data['data']['list']:
                    cve = CVEInfo()
                    cve.title = item.get('title', '')
                    cve.time = item.get('publish_time', '')
                    cve.cve = item.get('cve_id', '')
                    cve.src = self.NAME_CH()
                    cve.url = f"https://www.antiycloud.com/alert/detail?id={item.get('id', '')}"
                    cve.id = item.get('cve_id', '')
                    cve.info = item.get('description', '')
                    
                    if cve.is_valid():
                        cve_list.append(cve)
            
            # 缓存结果
            cache_manager.set(cache_key, cve_list)
            
            log_info(f"[{self.NAME_CH()}] 获取到 {len(cve_list)} 条漏洞信息")
            return cve_list
        except Exception as e:
            log_error(f"[{self.NAME_CH()}] 获取漏洞信息失败: {str(e)}")
            return []

class Tenable(BaseCrawler):
    """
    Tenable (Nessus)爬虫类
    """

    def __init__(self):
        super(Tenable, self).__init__()
        # Tenable (Nessus)API地址
        self.api_url = 'https://www.tenable.com/plugins/api/v2/plugins/search'

    def NAME_CH(self):
        return 'Tenable (Nessus)'

    def NAME_EN(self):
        return 'Tenable'

    def cves(self):
        """
        获取Tenable (Nessus)的漏洞信息
        :return: 漏洞信息列表
        """
        try:
            log_info(f"[{self.NAME_CH()}] 开始获取漏洞信息")
            
            # 尝试从缓存获取数据
            cache_key = f"tenable_cves"
            cached_data = cache_manager.get(cache_key)
            if cached_data:
                log_info(f"[{self.NAME_CH()}] 使用缓存数据")
                return cached_data
            
            # 构造请求参数
            params = {
                'page': 1,
                'size': 50,  # 获取最新的50条记录
                'sort': 'newest'
            }
            
            # 发送请求
            response = self.session.get(self.api_url, params=params)
            response.raise_for_status()  # 检查HTTP错误
            data = response.json()
            
            # 解析数据
            cve_list = []
            if 'plugins' in data:
                for item in data['plugins']:
                    cve = CVEInfo()
                    cve.title = item.get('name', '')
                    cve.time = item.get('added', '')
                    cve.src = self.NAME_CH()
                    cve.url = f"https://www.tenable.com/plugins/nessus/{item.get('id', '')}"
                    cve.id = str(item.get('id', ''))
                    cve.info = item.get('description', '')
                    
                    if cve.is_valid():
                        cve_list.append(cve)
            
            # 缓存结果
            cache_manager.set(cache_key, cve_list)
            
            log_info(f"[{self.NAME_CH()}] 获取到 {len(cve_list)} 条漏洞信息")
            return cve_list
        except Exception as e:
            log_error(f"[{self.NAME_CH()}] 获取漏洞信息失败: {str(e)}")
            return []

class MicrosoftSecurityCrawler(BaseCrawler):
    """
    微软安全响应中心爬虫类
    """

    def __init__(self):
        super(MicrosoftSecurityCrawler, self).__init__()
        # 微软安全响应中心API地址
        self.api_url = 'https://api.msrc.microsoft.com/cvrf/v2.0/updates'

    def NAME_CH(self):
        return '微软安全响应中心'

    def NAME_EN(self):
        return 'MSRC'

    def get_cves(self):
        """
        获取微软安全响应中心的漏洞信息
        :return: 漏洞信息列表
        """
        try:
            log_info(f"[{self.NAME_CH()}] 开始获取漏洞信息")
            
            # 尝试从缓存获取数据
            cache_key = f"msrc_cves"
            cached_data = cache_manager.get(cache_key)
            if cached_data:
                log_info(f"[{self.NAME_CH()}] 使用缓存数据")
                return cached_data
            
            # 发送请求
            response = self.session.get(self.api_url)
            response.raise_for_status()  # 检查HTTP错误
            data = response.json()
            
            # 解析数据
            cve_list = []
            if 'value' in data:
                # 只获取最新的50条记录
                for item in data['value'][:50]:
                    # 获取详细信息
                    detail_url = f"https://api.msrc.microsoft.com/cvrf/v2.0/document/{item.get('ID', '')}"
                    detail_response = self.session.get(detail_url)
                    if detail_response.status_code == 200:
                        detail_data = detail_response.json()
                        
                        # 提取漏洞信息
                        if 'Vulnerability' in detail_data:
                            for vuln in detail_data['Vulnerability']:
                                cve = CVEInfo()
                                cve.title = vuln.get('Title', {}).get('Value', '')
                                cve.time = item.get('CurrentReleaseDate', '')
                                cve.cve = vuln.get('CVE', '')
                                cve.src = self.NAME_CH()
                                cve.url = f"https://msrc.microsoft.com/update-guide/vulnerability/{vuln.get('CVE', '')}"
                                cve.id = vuln.get('CVE', '')
                                cve.info = vuln.get('Description', {}).get('Value', '')
                                
                                if cve.is_valid():
                                    cve_list.append(cve)
            
            # 缓存结果
            cache_manager.set(cache_key, cve_list)
            
            log_info(f"[{self.NAME_CH()}] 获取到 {len(cve_list)} 条漏洞信息")
            return cve_list
        except Exception as e:
            log_error(f"[{self.NAME_CH()}] 获取漏洞信息失败: {str(e)}")
            return []

class OKCVECrawler(BaseCrawler):
    """
    CVE漏洞库爬虫类
    """

    def __init__(self):
        super(OKCVECrawler, self).__init__()
        # CVE漏洞库API地址
        self.json_url = 'https://raw.githubusercontent.com/CVEProject/cvelistV5/refs/heads/main/cves/deltaLog.json'

    def NAME_CH(self):
        return 'CVE漏洞库'

    def NAME_EN(self):
        return 'OKCVE'

    def get_vulnerabilities(self):
        return []  # 使用get_cves方法获取漏洞信息

    def get_cves(self):
        """
        从CVE漏洞库获取最新CVE信息
        :return: 漏洞信息列表
        """
        try:
            log_info(f"[{self.NAME_CH()}] 开始获取最新CVE信息")
            
            # 获取当前日期，用于过滤
            current_date = datetime.now().strftime('%Y-%m-%d')
            log_info(f"[{self.NAME_CH()}] 当前日期: {current_date}, 只获取当天的CVE信息")
            
            # 尝试从缓存获取数据
            cache_key = f"okcve_cves"
            cached_data = cache_manager.get(cache_key)
            if cached_data:
                log_info(f"[{self.NAME_CH()}] 使用缓存数据")
                return cached_data
            
            # 从URL获取JSON数据
            response = self.session.get(self.json_url)
            if response.status_code != 200:
                log_error(f"[{self.NAME_CH()}] 获取JSON数据失败，状态码: {response.status_code}")
                return []
                
            data = response.json()
            
            cve_list = []
            
            # 处理数据 - 特别关注updated数组，并只获取当天的数据
            for entry in data:
                # 处理新增的CVE
                if 'new' in entry and isinstance(entry['new'], list):
                    for cve in entry['new']:
                        # 检查日期是否为当天
                        date_updated = cve.get('dateUpdated', '')
                        cve_id = cve.get('cveId', '')
                        
                        # 只处理当天的且未处理过的CVE
                        if date_updated.startswith(current_date) and cve_id not in processed_cve_ids:
                            cve_info = self.to_cve(cve, entry.get('fetchTime', ''))
                            if cve_info.is_valid():
                                cve_list.append(cve_info)
                                processed_cve_ids.add(cve_id)  # 记录已处理的CVE ID
                
                # 处理更新的CVE - 确保这部分代码正确执行
                if 'updated' in entry and isinstance(entry['updated'], list):
                    for cve in entry['updated']:
                        # 检查日期是否为当天
                        date_updated = cve.get('dateUpdated', '')
                        cve_id = cve.get('cveId', '')
                        
                        # 只处理当天的且未处理过的CVE
                        if date_updated.startswith(current_date) and cve_id not in processed_cve_ids:
                            cve_info = self.to_cve(cve, entry.get('fetchTime', ''))
                            if cve_info.is_valid():
                                cve_list.append(cve_info)
                                processed_cve_ids.add(cve_id)  # 记录已处理的CVE ID
            
            # 缓存结果
            cache_manager.set(cache_key, cve_list)
            
            log_info(f"[{self.NAME_CH()}] 获取到 {len(cve_list)} 条当天的CVE信息")
            return cve_list
        except Exception as e:
            log_error(f"[{self.NAME_CH()}] 获取CVE信息失败: {str(e)}")
            traceback.print_exc()  # 打印详细错误信息
            return []

    def to_cve(self, cve_data, fetch_time):
        """
        转换CVE数据为CVEInfo对象
        :param cve_data: CVE数据
        :param fetch_time: 抓取时间
        :return: CVEInfo对象
        """
        try:
            info = CVEInfo()
            cve_id = cve_data.get('cveId', '')
            info.title = cve_id + ' 漏洞'
            
            # 使用dateUpdated作为时间，确保格式正确
            date_updated = cve_data.get('dateUpdated', fetch_time)
            info.time = date_updated
            
            info.cve = cve_id
            info.src = self.NAME_CH()
            info.url = cve_data.get('cveOrgLink', '')
            info.id = cve_id
            info.info = f"详情请访问: {cve_data.get('githubLink', '')}"
            
            # 调试信息
            log_debug(f"处理CVE: {cve_id}, 更新时间: {date_updated}")
            
            return info
        except Exception as e:
            log_error(f"处理CVE数据时出错: {str(e)}")
            return CVEInfo()  # 返回空对象

    def export_to_txt(self, cves, filename='CVE漏洞库.txt'):
        """
        导出CVE信息到TXT文件
        :param cves: CVE信息列表
        :param filename: 文件名
        :return: 文件路径
        """
        filepath = os.path.join(CACHE_DIR, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            for cve in cves:
                f.write(cve.to_msg())
                f.write("\n==============================================\n\n")
        log_info(f"[{self.NAME_CH()}] 已导出 {len(cves)} 条CVE信息到 {filepath}")
        return filepath

if __name__ == '__main__':
    # 初始化爬虫对象
    oscs1024 = OSCS1024Crawler()
    antiycloud = AntiYCloud()
    tenable = Tenable()

    # 获取漏洞信息
    oscs1024_vulnerabilities = oscs1024.vulnerabilities()
    antiycloud_cves = antiycloud.cves()
    tenable_cves = tenable.cves()

    # 导出漏洞信息到文件
    if oscs1024_vulnerabilities:
        oscs1024.export_to_txt(oscs1024_vulnerabilities)
        log_info('漏洞信息已导出到OSCS1024漏洞库.txt文件')

    if antiycloud_cves:
        antiycloud.export_to_txt(antiycloud_cves)
        log_info('威胁情报信息已导出到安天(antiycloud).txt文件')

    if tenable_cves:
        tenable.export_to_txt(tenable_cves)
        log_info('威胁情报信息已导出到Tenable (Nessus).txt文件')