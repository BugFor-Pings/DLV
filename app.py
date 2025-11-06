#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 威胁情报平台主程序

import os
import sqlite3
from flask import Flask, render_template, redirect, url_for, request, send_file
from datetime import datetime
import json
import threading
import time
import traceback
from lxml import etree
from contextlib import contextmanager
import queue
import concurrent.futures
import zipfile
import shutil

# 导入爬虫模块
from pachong_config import OSCS1024Crawler, AntiYCloud, Tenable, MicrosoftSecurityCrawler, OKCVECrawler, init_log
# 导入日志函数
from pachong_config import log_info, log_error, log_warn, log_debug

# 初始化日志
init_log()

# 初始化Flask应用
app = Flask(__name__)

# 数据库配置
DATABASE = 'vulnerabilities.db'
REPORT_DIR = 'report'
ZIP_FILE = 'report.zip'

# 数据库连接池
db_pool = queue.Queue(maxsize=5)

# 爬取任务锁，防止并发爬取
crawl_lock = threading.Lock()
# 记录最后一次爬取时间
last_crawl_time = None
# 最小爬取间隔(秒)
MIN_CRAWL_INTERVAL = 60

# 确保目录存在
def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

# 创建数据库连接
def create_db_connection():
    db = sqlite3.connect(DATABASE, check_same_thread=False)  # 允许跨线程使用
    db.row_factory = sqlite3.Row
    return db

# 初始化连接池
def init_db_pool():
    for _ in range(5):
        db_pool.put(create_db_connection())

# 获取数据库连接
@contextmanager
def get_db():
    db = None
    try:
        db = db_pool.get()
        yield db
    finally:
        if db:
            db_pool.put(db)

# 初始化数据库
def init_db():
    with app.app_context():
        with get_db() as db:
            with open('schema.sql', 'r', encoding='utf-8') as f:
                db.executescript(f.read())
            db.commit()

# 保存漏洞信息到数据库
def save_vulnerability(title, time, ids, source, detail_url, md5):
    try:
        with get_db() as db:
            cursor = db.cursor()
            
            # 首先检查MD5是否已存在
            cursor.execute('SELECT * FROM vulnerabilities WHERE md5 = ?', (md5,))
            if cursor.fetchone() is not None:
                return False
            
            # 对于CVE漏洞库，额外检查CVE ID是否已存在
            if source == 'CVE漏洞库' and ids:
                cursor.execute('SELECT * FROM vulnerabilities WHERE ids = ? AND source = ?', (ids, source))
                if cursor.fetchone() is not None:
                    log_info(f"CVE ID {ids} 已存在，跳过保存")
                    return False
            
            # 插入新记录
            cursor.execute(
                'INSERT INTO vulnerabilities (title, time, ids, source, detail_url, md5, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                (title, time, ids, source, detail_url, md5, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            )
            db.commit()
            return True
    except Exception as e:
        log_error(f"保存漏洞信息失败: {str(e)}")
        return False

# 确保报告目录存在
def ensure_report_dir():
    try:
        ensure_dir(REPORT_DIR)
        log_info("已确保报告目录存在")
    except Exception as e:
        log_error(f"创建报告目录失败: {str(e)}")

# 创建ZIP文件
def create_zip_file():
    try:
        zip_path = os.path.join(REPORT_DIR, ZIP_FILE)
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(REPORT_DIR):
                for file in files:
                    if file != ZIP_FILE:  # 排除zip文件本身
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, REPORT_DIR)
                        zipf.write(file_path, arcname)
        return True
    except Exception as e:
        log_error(f"创建ZIP文件失败: {str(e)}")
        return False

# 下载报告路由
@app.route('/download_report')
def download_report():
    try:
        zip_path = os.path.join(REPORT_DIR, ZIP_FILE)
        if os.path.exists(zip_path):
            # 直接下载文件，不设置任何跳转标志
            return send_file(
                zip_path,
                as_attachment=True,
                download_name=ZIP_FILE,
                mimetype='application/zip'
            )
        else:
            # 返回友好的HTML页面，告知用户报告正在准备中
            return render_template('report_preparing.html')
    except Exception as e:
        log_error(f"下载报告失败: {str(e)}")
        return "下载失败", 500

# 爬取并保存漏洞信息
def crawl_and_save():
    global last_crawl_time
    
    # 检查是否可以执行爬取
    current_time = time.time()
    if last_crawl_time and current_time - last_crawl_time < MIN_CRAWL_INTERVAL:
        log_info(f"距离上次爬取时间不足{MIN_CRAWL_INTERVAL}秒，跳过本次爬取")
        return
    
    # 尝试获取锁，如果锁被占用则跳过本次爬取
    if not crawl_lock.acquire(blocking=False):
        log_info("另一个爬取任务正在进行，跳过本次爬取")
        return
    
    try:
        last_crawl_time = current_time
        log_info("开始爬取漏洞信息...")
        
        max_retries = 5
        retry_delay = 60  # 重试延迟时间（秒）
        
        for attempt in range(max_retries):
            try:
                # 使用线程池控制并发
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    # OSCS1024
                    oscs = OSCS1024Crawler()
                    oscs_future = executor.submit(oscs.vulnerabilities)
                    
                    # 安天
                    antiy = AntiYCloud()
                    antiy_future = executor.submit(antiy.cves)
                    
                    # Tenable
                    tenable = Tenable()
                    tenable_future = executor.submit(tenable.cves)
                    
                    # Microsoft安全响应中心
                    msrc = MicrosoftSecurityCrawler()
                    msrc_future = executor.submit(msrc.get_cves)
                    
                    # CVE漏洞库
                    okcve = OKCVECrawler()
                    okcve_future = executor.submit(okcve.get_cves)
                    
                    # 等待所有爬虫完成
                    oscs_vulns = oscs_future.result()
                    antiy_vulns = antiy_future.result()
                    tenable_vulns = tenable_future.result()
                    msrc_vulns = msrc_future.result()
                    okcve_vulns = okcve_future.result()
                    
                    # 显示爬取结果统计
                    log_info(f"从 [OSCS1024漏洞库] 获取到 {len(oscs_vulns)} 条漏洞信息")
                    log_info(f"从 [安天(antiycloud)] 获取到 {len(antiy_vulns)} 条威胁情报")
                    log_info(f"从 [Tenable (Nessus)] 获取到 {len(tenable_vulns)} 条威胁情报")
                    log_info(f"从 [微软安全响应中心] 获取到 {len(msrc_vulns)} 条漏洞信息")
                    log_info(f"从 [CVE漏洞库] 获取到 {len(okcve_vulns)} 条威胁情报")
                    
                    # 保存结果到数据库
                    # 创建新保存漏洞的列表，用于后续导出报告
                    new_oscs_vulns = []
                    saved_count = 0
                    for vuln in oscs_vulns:
                        if save_vulnerability(
                            vuln.title,
                            vuln.time,
                            ', '.join(vuln.ids),
                            vuln.source,
                            vuln.detail_url,
                            vuln.MD5()
                        ):
                            saved_count += 1
                            new_oscs_vulns.append(vuln)  # 添加到新保存列表
                    log_info(f"成功保存 {saved_count} 条 [OSCS1024漏洞库] 数据")
                    
                    new_antiy_vulns = []
                    saved_count = 0
                    for vuln in antiy_vulns:
                        if save_vulnerability(
                            vuln.title,
                            vuln.time,
                            vuln.cve,
                            vuln.src,
                            vuln.url,
                            vuln.MD5()
                        ):
                            saved_count += 1
                            new_antiy_vulns.append(vuln)  # 添加到新保存列表
                    log_info(f"成功保存 {saved_count} 条 [安天(antiycloud)] 数据")
                    
                    new_tenable_vulns = []
                    saved_count = 0
                    for vuln in tenable_vulns:
                        if save_vulnerability(
                            vuln.title,
                            vuln.time,
                            vuln.id,
                            vuln.src,
                            vuln.url,
                            vuln.MD5()
                        ):
                            saved_count += 1
                            new_tenable_vulns.append(vuln)  # 添加到新保存列表
                    log_info(f"成功保存 {saved_count} 条 [Tenable (Nessus)] 数据")
                    
                    new_msrc_vulns = []
                    saved_count = 0
                    for vuln in msrc_vulns:
                        if save_vulnerability(
                            vuln.title,
                            vuln.time,
                            vuln.cve,
                            vuln.src,
                            vuln.url,
                            vuln.MD5()
                        ):
                            saved_count += 1
                            new_msrc_vulns.append(vuln)  # 添加到新保存列表
                    log_info(f"成功保存 {saved_count} 条 [微软安全响应中心] 数据")
                    
                    new_okcve_vulns = []
                    saved_count = 0
                    for vuln in okcve_vulns:
                        if save_vulnerability(
                            vuln.title,
                            vuln.time,
                            vuln.cve,
                            vuln.src,
                            vuln.url,
                            vuln.MD5()
                        ):
                            saved_count += 1
                            new_okcve_vulns.append(vuln)  # 添加到新保存列表
                    log_info(f"成功保存 {saved_count} 条 [CVE漏洞库] 数据")
                    
                    # 导出报告 - 仅导出新保存的漏洞信息
                    has_new_data = False  # 跟踪是否有新数据
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    
                    # OSCS1024报告
                    if new_oscs_vulns:
                        has_new_data = True
                        report_path = os.path.join(REPORT_DIR, 'OSCS1024漏洞库.txt')
                        # 使用追加模式写入文件
                        with open(report_path, 'a', encoding='utf-8') as file:
                            # 添加批次信息和时间戳
                            file.write(f"\n\n===== 爬取时间：{timestamp} =====\n")
                            for vuln in new_oscs_vulns:
                                file.write(vuln.to_msg())
                                file.write('\n')
                        log_info(f"已追加 {len(new_oscs_vulns)} 条新 [OSCS1024漏洞库] 报告")
                    
                    # 安天报告
                    if new_antiy_vulns:
                        has_new_data = True
                        report_path = os.path.join(REPORT_DIR, '安天(antiycloud).txt')
                        # 使用追加模式写入文件
                        with open(report_path, 'a', encoding='utf-8') as file:
                            # 添加批次信息和时间戳
                            file.write(f"\n\n===== 爬取时间：{timestamp} =====\n")
                            for vuln in new_antiy_vulns:
                                file.write(vuln.to_msg())
                                file.write('\n')
                        log_info(f"已追加 {len(new_antiy_vulns)} 条新 [安天(antiycloud)] 报告")
                    
                    # Tenable报告
                    if new_tenable_vulns:
                        has_new_data = True
                        report_path = os.path.join(REPORT_DIR, 'Tenable(Nessus).txt')
                        # 使用追加模式写入文件
                        with open(report_path, 'a', encoding='utf-8') as file:
                            # 添加批次信息和时间戳
                            file.write(f"\n\n===== 爬取时间：{timestamp} =====\n")
                            for vuln in new_tenable_vulns:
                                file.write(vuln.to_msg())
                                file.write('\n')
                        log_info(f"已追加 {len(new_tenable_vulns)} 条新 [Tenable (Nessus)] 报告")
                    
                    # 微软安全响应中心报告
                    if new_msrc_vulns:
                        has_new_data = True
                        report_path = os.path.join(REPORT_DIR, '微软安全响应中心.txt')
                        # 使用追加模式写入文件
                        with open(report_path, 'a', encoding='utf-8') as file:
                            # 添加批次信息和时间戳
                            file.write(f"\n\n===== 爬取时间：{timestamp} =====\n")
                            for vuln in new_msrc_vulns:
                                file.write(vuln.to_msg())
                                file.write('\n')
                        log_info(f"已追加 {len(new_msrc_vulns)} 条新 [微软安全响应中心] 报告")
                    
                    # CVE漏洞库报告
                    if new_okcve_vulns:
                        has_new_data = True
                        report_path = os.path.join(REPORT_DIR, 'CVE漏洞库.txt')
                        # 使用追加模式写入文件
                        with open(report_path, 'a', encoding='utf-8') as file:
                            # 添加批次信息和时间戳
                            file.write(f"\n\n===== 爬取时间：{timestamp} =====\n")
                            for vuln in new_okcve_vulns:
                                file.write(vuln.to_msg())
                                file.write('\n')
                        log_info(f"已追加 {len(new_okcve_vulns)} 条新 [CVE漏洞库] 报告")
                    
                    # 只有在有新数据时才创建新的ZIP文件
                    if has_new_data:
                        if create_zip_file():
                            log_info("已创建报告压缩包")
                    else:
                        log_info("本次爬取未发现新漏洞，未更新报告文件")
                    
                    # 如果成功，跳出重试循环
                    break
                    
            except Exception as e:
                log_error(f"爬取失败 (尝试 {attempt + 1}/{max_retries}): {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                else:
                    log_error("达到最大重试次数，放弃爬取")
    finally:
        # 释放锁
        crawl_lock.release()

# 定时任务：动态间隔爬取
def scheduled_task():
    base_interval = 180  # 基础间隔时间（秒）
    max_interval = 3600  # 最大间隔时间（秒）
    current_interval = base_interval
    
    # 确保报告目录存在
    ensure_report_dir()
    
    # 等待30秒后开始第一次爬取
    time.sleep(30)
    
    while True:
        try:
            # 爬取漏洞信息
            crawl_and_save()
            
            # 根据爬取结果动态调整间隔
            current_interval = min(current_interval * 1.5, max_interval)
            time.sleep(current_interval)
        except Exception as e:
            log_error(f"定时任务异常: {str(e)}")
            # 发生异常时增加间隔时间
            current_interval = min(current_interval * 2, max_interval)
            time.sleep(current_interval)

# 全局上下文处理
@app.context_processor
def inject_globals():
    return {
        'current_year': datetime.now().year
    }

# 路由：首页
@app.route('/')
def index():
    with get_db() as db:
        cursor = db.cursor()
        
        # 获取分页参数
        page = request.args.get('page', 1, type=int)
        per_page = 20
        offset = (page - 1) * per_page
        
        # 获取总数
        cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
        total = cursor.fetchone()[0]
        
        # 获取漏洞列表
        cursor.execute('SELECT * FROM vulnerabilities ORDER BY time DESC LIMIT ? OFFSET ?', 
                       (per_page, offset))
        vulnerabilities = cursor.fetchall()
        
        # 计算总页数
        total_pages = (total + per_page - 1) // per_page
        
        return render_template('index.html', 
                               vulnerabilities=vulnerabilities,
                               page=page,
                               total_pages=total_pages)

# 路由：按来源筛选
@app.route('/source/<source>')
def filter_by_source(source):
    with get_db() as db:
        cursor = db.cursor()
        
        # 获取分页参数
        page = request.args.get('page', 1, type=int)
        per_page = 20
        offset = (page - 1) * per_page
        
        # 获取总数
        cursor.execute('SELECT COUNT(*) FROM vulnerabilities WHERE source = ?', (source,))
        total = cursor.fetchone()[0]
        
        # 获取漏洞列表
        cursor.execute('SELECT * FROM vulnerabilities WHERE source = ? ORDER BY time DESC LIMIT ? OFFSET ?', 
                       (source, per_page, offset))
        vulnerabilities = cursor.fetchall()
        
        # 计算总页数
        total_pages = (total + per_page - 1) // per_page
        
        return render_template('index.html', 
                               vulnerabilities=vulnerabilities,
                               page=page,
                               total_pages=total_pages,
                               current_source=source)

# 路由：搜索
@app.route('/search')
def search():
    query = request.args.get('q', '')
    if not query:
        return redirect(url_for('index'))
    
    with get_db() as db:
        cursor = db.cursor()
        
        # 获取分页参数
        page = request.args.get('page', 1, type=int)
        per_page = 20
        offset = (page - 1) * per_page
        
        # 获取总数
        cursor.execute('SELECT COUNT(*) FROM vulnerabilities WHERE title LIKE ? OR ids LIKE ?', 
                       (f'%{query}%', f'%{query}%'))
        total = cursor.fetchone()[0]
        
        # 获取漏洞列表
        cursor.execute('SELECT * FROM vulnerabilities WHERE title LIKE ? OR ids LIKE ? ORDER BY time DESC LIMIT ? OFFSET ?', 
                       (f'%{query}%', f'%{query}%', per_page, offset))
        vulnerabilities = cursor.fetchall()
        
        # 计算总页数
        total_pages = (total + per_page - 1) // per_page
        
        return render_template('index.html', 
                               vulnerabilities=vulnerabilities,
                               page=page,
                               total_pages=total_pages,
                               query=query)

# 添加检测可用端口的函数
def find_available_ports(start_port=8000, end_port=9000):
    """检测指定范围内的可用端口"""
    import socket
    available_ports = []
    
    for port in range(start_port, end_port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)  # 设置超时时间
        try:
            result = sock.connect_ex(('127.0.0.1', port))
            if result != 0:  # 端口未被占用
                available_ports.append(port)
            sock.close()
            # 只获取前30个可用端口
            if len(available_ports) >= 30:
                break
        except:
            sock.close()
    
    return available_ports

# 添加保存选择的端口到文件的函数
def save_port_to_file(port):
    """保存选择的端口到文件，以便重启时使用"""
    with open('selected_port.txt', 'w') as f:
        f.write(str(port))

# 添加从文件读取端口的函数
def load_port_from_file():
    """从文件读取之前选择的端口"""
    try:
        with open('selected_port.txt', 'r') as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return None

# 添加检查端口是否可用的函数
def is_port_available(port):
    """检查指定端口是否可用"""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.1)  # 设置超时时间
    try:
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        return result != 0  # 如果结果不为0，表示端口可用
    except:
        sock.close()
        return False

# 添加一个路由来清除缓存
@app.route('/clear_cache')
def clear_cache():
    try:
        # 清除缓存目录中的所有文件
        cache_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cache')
        for file in os.listdir(cache_dir):
            file_path = os.path.join(cache_dir, file)
            if os.path.isfile(file_path):
                os.remove(file_path)
        
        return "缓存已清除，请返回首页查看最新数据"
    except Exception as e:
        return f"清除缓存时出错: {str(e)}"

# 主程序
if __name__ == '__main__':
    # 确保目录存在
    ensure_dir(os.path.dirname(os.path.abspath(DATABASE)))
    ensure_report_dir()
    
    # 初始化数据库
    if not os.path.exists(DATABASE):
        init_db()
    
    # 初始化数据库连接池
    init_db_pool()
    
    # 尝试从文件读取之前选择的端口
    port = load_port_from_file()
    
    # 检查之前选择的端口是否可用
    if port is not None and not is_port_available(port):
        print(f"警告：之前选择的端口 {port} 已被占用，需要重新选择端口")
        port = None  # 重置端口，进入重新选择流程
    
    # 如果没有之前选择的端口或端口被占用，则进行端口检测和选择
    if port is None:
        # 检测可用端口
        available_ports = find_available_ports(8000, 9000)
        
        if not available_ports:
            print("警告：未找到可用端口，将使用默认端口 8080")
            port = 8080
            # 检查默认端口是否可用
            if not is_port_available(port):
                print(f"错误：默认端口 {port} 也被占用，无法启动服务")
                import sys
                sys.exit(1)
        else:
            print("\n可用端口列表:")
            for i, p in enumerate(available_ports):
                print(f"{i+1}. {p}")
            
            # 用户选择端口
            while True:
                try:
                    choice = input("\n请选择要使用的端口编号1-30之间 (输入q退出): ")
                    if choice.lower() == 'q':
                        print("程序已退出")
                        import sys
                        sys.exit(0)
                    
                    choice = int(choice)
                    if 1 <= choice <= len(available_ports):
                        port = available_ports[choice-1]
                        # 保存选择的端口到文件
                        save_port_to_file(port)
                        break
                    else:
                        print(f"请输入1-{len(available_ports)}之间的数字")
                except ValueError:
                    print("请输入有效的数字")
    else:
        print(f"使用之前选择的端口: {port}")
    
    print(f"\n威胁情报平台启动中，端口: {port}...")
    print(f"请访问 http://localhost:{port} 或 http://127.0.0.1:{port}")
    
    # 先启动Flask应用，再启动定时任务
    # 创建定时任务线程但不立即启动
    scheduler = threading.Thread(target=scheduled_task)
    scheduler.daemon = True
    
    # 添加环境变量，防止Flask重新加载时重新选择端口
    os.environ['FLASK_RUN_PORT'] = str(port)
    
    # 启动定时任务
    scheduler.start()
    
    # 启动Flask应用
    app.run(debug=True, host='0.0.0.0', port=port, use_reloader=False)