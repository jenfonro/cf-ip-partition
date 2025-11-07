import ipaddress
import json
import logging
import os
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

import maxminddb

DEFAULT_DB_PATH = "ipinfo_lite.mmdb"
DEFAULT_TEST_IP = "8.8.8.8"

_db_path = DEFAULT_DB_PATH
_test_ip = DEFAULT_TEST_IP
_logger = logging.getLogger("ip_lookup")
_logger.addHandler(logging.NullHandler())


def set_db_config(db_path: Optional[str] = None, test_ip: Optional[str] = None) -> None:
    global _db_path, _test_ip
    if db_path:
        _db_path = db_path
    if test_ip:
        _test_ip = test_ip


def set_logger(external_logger: logging.Logger) -> None:
    global _logger
    _logger = external_logger


class DBManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(DBManager, cls).__new__(cls)
                cls._instance.reader = None
                cls._instance.loaded = False
                cls._instance.operation_lock = threading.RLock()
        return cls._instance

    def load_database(self) -> bool:
        with self.operation_lock:
            if self.loaded:
                _logger.info("数据库已加载，无需重复操作")
                return True

            if not os.path.exists(_db_path):
                _logger.error(f"数据库文件不存在：{os.path.abspath(_db_path)}")
                return False
            if not os.access(_db_path, os.R_OK):
                _logger.error(f"无权限读取数据库：{_db_path}（执行 chmod +r {_db_path} 赋予权限）")
                return False

            try:
                self.reader = maxminddb.open_database(_db_path)
                test_result = self.reader.get(_test_ip)
                if not test_result:
                    _logger.error(f"数据库无效，测试IP {_test_ip} 查询无结果")
                    self.reader.close()
                    self.reader = None
                    return False

                self.loaded = True
                _logger.info(f"数据库加载成功（路径：{os.path.abspath(_db_path)}）")
                return True
            except maxminddb.errors.InvalidDatabaseError:
                _logger.error("数据库文件损坏或格式错误")
                self.reader = None
                return False
            except Exception as e:
                _logger.error(f"数据库加载失败：{str(e)}")
                self.reader = None
                return False

    def close_database(self) -> None:
        with self.operation_lock:
            if self.loaded and self.reader:
                try:
                    self.reader.close()
                    _logger.info("数据库连接已关闭")
                except Exception as e:
                    _logger.warning(f"关闭数据库警告：{str(e)}")
                finally:
                    self.loaded = False
                    self.reader = None

    def query_ip(self, ip: str) -> Dict[str, Any]:
        with self.operation_lock:
            if not self.loaded or not self.reader:
                _logger.warning(f"查询IP {ip} 时数据库未加载，尝试紧急恢复")
                if not self.load_database():
                    raise RuntimeError("数据库未加载且紧急恢复失败")

            try:
                ip_clean = ip.strip()
                ipaddress.ip_address(ip_clean)
            except ValueError as e:
                raise ValueError(f"无效IP格式：{ip}（{str(e)}）")

            try:
                raw_data = self.reader.get(ip_clean)
                _logger.debug(f"IP {ip} 原始查询结果：{json.dumps(raw_data, ensure_ascii=False)}")
                return raw_data if raw_data else {}
            except Exception as e:
                raise RuntimeError(f"查询执行失败：{str(e)}")


class IPInfoParser:
    _continent_code_map = {
        "North America": "NA",
        "South America": "SA",
        "Asia": "AS",
        "Europe": "EU",
        "Africa": "AF",
        "Oceania": "OC",
        "Antarctica": "AN",
    }

    _country_map = {
        "United States": {"code": "US", "name_zh": "美国"},
        "China": {"code": "CN", "name_zh": "中国"},
        "Japan": {"code": "JP", "name_zh": "日本"},
        "South Korea": {"code": "KR", "name_zh": "韩国"},
        "United Kingdom": {"code": "GB", "name_zh": "英国"},
        "Germany": {"code": "DE", "name_zh": "德国"},
        "France": {"code": "FR", "name_zh": "法国"},
        "Canada": {"code": "CA", "name_zh": "加拿大"},
        "Australia": {"code": "AU", "name_zh": "澳大利亚"},
        "Singapore": {"code": "SG", "name_zh": "新加坡"},
        "Hong Kong": {"code": "HK", "name_zh": "中国香港"},
        "Taiwan": {"code": "TW", "name_zh": "中国台湾"},
        "Macao": {"code": "MO", "name_zh": "中国澳门"},
        "India": {"code": "IN", "name_zh": "印度"},
        "Russia": {"code": "RU", "name_zh": "俄罗斯"},
        "Brazil": {"code": "BR", "name_zh": "巴西"},
        "Italy": {"code": "IT", "name_zh": "意大利"},
        "Spain": {"code": "ES", "name_zh": "西班牙"},
        "Mexico": {"code": "MX", "name_zh": "墨西哥"},
        "Netherlands": {"code": "NL", "name_zh": "荷兰"},
        "Switzerland": {"code": "CH", "name_zh": "瑞士"},
        "Sweden": {"code": "SE", "name_zh": "瑞典"},
        "Norway": {"code": "NO", "name_zh": "挪威"},
        "Denmark": {"code": "DK", "name_zh": "丹麦"},
        "Finland": {"code": "FI", "name_zh": "芬兰"},
        "Belgium": {"code": "BE", "name_zh": "比利时"},
        "Austria": {"code": "AT", "name_zh": "奥地利"},
        "Greece": {"code": "GR", "name_zh": "希腊"},
        "Portugal": {"code": "PT", "name_zh": "葡萄牙"},
        "Ireland": {"code": "IE", "name_zh": "爱尔兰"},
        "Poland": {"code": "PL", "name_zh": "波兰"},
        "Ukraine": {"code": "UA", "name_zh": "乌克兰"},
        "South Africa": {"code": "ZA", "name_zh": "南非"},
        "Egypt": {"code": "EG", "name_zh": "埃及"},
        "Nigeria": {"code": "NG", "name_zh": "尼日利亚"},
        "Argentina": {"code": "AR", "name_zh": "阿根廷"},
        "Chile": {"code": "CL", "name_zh": "智利"},
        "Colombia": {"code": "CO", "name_zh": "哥伦比亚"},
        "Turkey": {"code": "TR", "name_zh": "土耳其"},
        "Saudi Arabia": {"code": "SA", "name_zh": "沙特阿拉伯"},
        "United Arab Emirates": {"code": "AE", "name_zh": "阿联酋"},
        "Israel": {"code": "IL", "name_zh": "以色列"},
        "Thailand": {"code": "TH", "name_zh": "泰国"},
        "Malaysia": {"code": "MY", "name_zh": "马来西亚"},
        "Indonesia": {"code": "ID", "name_zh": "印度尼西亚"},
        "Vietnam": {"code": "VN", "name_zh": "越南"},
        "Philippines": {"code": "PH", "name_zh": "菲律宾"},
    }

    _city_zh_map = {
        "New York": "纽约",
        "Los Angeles": "洛杉矶",
        "Chicago": "芝加哥",
        "Houston": "休斯顿",
        "Phoenix": "凤凰城",
        "Philadelphia": "费城",
        "San Antonio": "圣安东尼奥",
        "San Diego": "圣地亚哥",
        "Dallas": "达拉斯",
        "San Jose": "圣何塞",
        "Austin": "奥斯汀",
        "Jacksonville": "杰克逊维尔",
        "Fort Worth": "沃斯堡",
        "Columbus": "哥伦布",
        "Charlotte": "夏洛特",
        "San Francisco": "旧金山",
        "Indianapolis": "印第安纳波利斯",
        "Seattle": "西雅图",
        "Denver": "丹佛",
        "Washington": "华盛顿",
        "Boston": "波士顿",
        "Beijing": "北京",
        "Shanghai": "上海",
        "Guangzhou": "广州",
        "Shenzhen": "深圳",
        "Hangzhou": "杭州",
        "Chengdu": "成都",
        "Chongqing": "重庆",
        "Nanjing": "南京",
        "Wuhan": "武汉",
        "Xi'an": "西安",
        "Suzhou": "苏州",
        "Tianjin": "天津",
        "Shenyang": "沈阳",
        "Qingdao": "青岛",
        "Tokyo": "东京",
        "Osaka": "大阪",
        "Seoul": "首尔",
        "London": "伦敦",
        "Paris": "巴黎",
        "Berlin": "柏林",
        "Moscow": "莫斯科",
        "Sydney": "悉尼",
        "Singapore": "新加坡市",
        "Hong Kong": "香港",
        "Taipei": "台北",
    }

    @classmethod
    def parse(cls, ip: str, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        result = {
            "ip": ip.strip(),
            "continent_code": "未知",
            "country": "未知",
            "country_zh": "未知",
            "country_code": "XX",
            "city": "未知",
            "city_zh": "未知",
            "registered_country_code": "XX",
            "asn": 0,
            "organization": "未知",
            "timestamp": int(time.time() * 1000),
            "request_id": str(uuid.uuid4()),
        }

        if not raw_data:
            _logger.warning(f"IP {ip} 无原始查询数据，返回默认值")
            return result

        continent_name = raw_data.get("continent", "").strip()
        if continent_name:
            result["continent_code"] = cls._continent_code_map.get(continent_name, continent_name)

        country_name = raw_data.get("country_name", "").strip() or raw_data.get("country", "").strip()
        if country_name:
            if country_name in cls._country_map:
                result["country"] = country_name
                result["country_code"] = cls._country_map[country_name]["code"]
                result["country_zh"] = cls._country_map[country_name]["name_zh"]
            else:
                result["country"] = country_name
                result["country_code"] = "XX"
                result["country_zh"] = "未知（未配置映射）"

        city_name = raw_data.get("city", "").strip()
        if city_name:
            result["city"] = city_name
            result["city_zh"] = cls._city_zh_map.get(city_name, city_name)

        result["registered_country_code"] = result["country_code"]

        asn_raw = raw_data.get("asn", "").strip()
        if asn_raw.startswith("AS"):
            asn_parts = asn_raw.split(maxsplit=1)
            if len(asn_parts) >= 1 and asn_parts[0][2:].isdigit():
                result["asn"] = int(asn_parts[0][2:])
            result["organization"] = asn_parts[1] if len(asn_parts) >= 2 else asn_raw
        else:
            result["organization"] = asn_raw

        return result


def get_single_ip_info(ip: str) -> Dict[str, Any]:
    db_manager = DBManager()
    try:
        raw_data = db_manager.query_ip(ip)
        parsed_data = IPInfoParser.parse(ip, raw_data)
        _logger.info(f"IP {ip} 查询成功（国家：{parsed_data['country_zh']}，城市：{parsed_data['city_zh']}）")
        return parsed_data
    except RuntimeError as e:
        error_msg = f"数据库错误：{str(e)}"
        _logger.error(f"IP {ip} 查询失败：{error_msg}")
        return {
            "ip": ip.strip(),
            "error": error_msg,
            "timestamp": int(time.time() * 1000),
            "request_id": str(uuid.uuid4()),
        }
    except ValueError as e:
        error_msg = f"无效IP：{str(e)}"
        _logger.warning(f"IP {ip} 查询失败：{error_msg}")
        return {
            "ip": ip.strip(),
            "error": error_msg,
            "timestamp": int(time.time() * 1000),
            "request_id": str(uuid.uuid4()),
        }
    except Exception as e:
        error_msg = f"未知错误：{str(e)}"
        _logger.error(f"IP {ip} 查询失败：{error_msg}")
        return {
            "ip": ip.strip(),
            "error": "查询处理失败，请稍后重试",
            "timestamp": int(time.time() * 1000),
            "request_id": str(uuid.uuid4()),
        }


def parse_ip_input(ip_input: str) -> List[str]:
    if not ip_input or not ip_input.strip():
        return []
    return list(set([ip.strip() for ip in ip_input.split(",") if ip.strip()]))


def get_ip_info_unified(ip_input: str) -> Dict[str, Any]:
    ip_list = parse_ip_input(ip_input)
    if len(ip_list) == 1:
        return get_single_ip_info(ip_list[0])
    elif len(ip_list) > 1:
        batch_result = {
            "batch_request_id": str(uuid.uuid4()),
            "timestamp": int(time.time() * 1000),
            "total": len(ip_list),
            "success": 0,
            "failed": 0,
            "results": [],
        }
        for ip in ip_list:
            result = get_single_ip_info(ip)
            if "error" in result:
                batch_result["failed"] += 1
                status = "failed"
            else:
                batch_result["success"] += 1
                status = "success"
            batch_result["results"].append({"ip": ip, "status": status, "data": result})
        return batch_result
    else:
        raise ValueError("未提供有效IP（单个IP直接传，多个IP用逗号分隔）")


__all__ = [
    "DBManager",
    "IPInfoParser",
    "get_single_ip_info",
    "get_ip_info_unified",
    "parse_ip_input",
    "set_db_config",
    "set_logger",
]
