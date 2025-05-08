#!/usr/bin/env python3
"""
Cookie Getter for Facebook Auto Share
Converts Facebook login credentials to JSON cookie format compatible with Auto Share
"""

import os
import sys
import uuid
import random
import json
from datetime import datetime
# UTC is only available in Python 3.11+, so use timezone.utc for compatibility
import datetime as dt

try:
    import httpx
except ModuleNotFoundError:
    print("Required modules not found. Installing...")
    os.system('python -m pip install httpx')
    import httpx

def get_cookie_json(user, passw):
    """
    Get Facebook cookies in JSON format from login credentials
    
    Args:
        user (str): Facebook username or email
        passw (str): Facebook password
        
    Returns:
        dict: Result with status and data (cookies or error message)
    """
    accessToken = '350685531728|62f8ce9f74b12f84c123cc23437a4a32'
    data = {
        'adid': str(uuid.uuid4()),
        'format': 'json',
        'device_id': str(uuid.uuid4()),
        'cpl': 'true',
        'family_device_id': str(uuid.uuid4()),
        'credentials_type': 'device_based_login_password',
        'error_detail_type': 'button_with_disabled',
        'source': 'device_based_login',
        'email': user,
        'password': passw,
        'access_token': accessToken,
        'generate_session_cookies': '1',
        'meta_inf_fbmeta': '',
        'advertiser_id': str(uuid.uuid4()),
        'currently_logged_in_userid': '0',
        'locale': 'en_US',
        'client_country_code': 'US',
        'method': 'auth.login',
        'fb_api_req_friendly_name': 'authenticate',
        'fb_api_caller_class': 'com.facebook.account.login.protocol.Fb4aAuthHandler',
        'api_key': '62f8ce9f74b12f84c123cc23437a4a32'
    }
    headers = {
        'User-Agent': "[FBAN/FB4A;FBAV/196.0.0.29.99;FBPN/com.facebook.katana;FBLC/en_US]",
        'Content-Type': 'application/x-www-form-urlencoded',
        'Host': 'graph.facebook.com',
        'X-FB-Net-HNI': str(random.randint(10000, 99999)),
        'X-FB-SIM-HNI': str(random.randint(10000, 99999)),
        'X-FB-Connection-Type': 'MOBILE.LTE',
        'X-Tigon-Is-Retry': 'False',
        'x-fb-session-id': 'nid=abc;pid=Main;',
        'x-fb-device-group': str(random.randint(1000, 9999)),
        'X-FB-Friendly-Name': 'ViewerReactionsMutation',
        'X-FB-Request-Analytics-Tags': 'graphservice',
        'X-FB-HTTP-Engine': 'Liger',
        'X-FB-Client-IP': 'True',
        'X-FB-Connection-Bandwidth': str(random.randint(20000000, 30000000)),
        'X-FB-Server-Cluster': 'True',
        'x-fb-connection-token': '62f8ce9f74b12f84c123cc23437a4a32'
    }

    try:
        response = httpx.post("https://b-graph.facebook.com/auth/login", headers=headers, data=data, follow_redirects=False)
        pos = response.json()

        if "session_key" in pos:
            # Use timezone.utc instead of UTC for Python <3.11 compatibility
            now_iso = datetime.now(dt.timezone.utc).isoformat()
            cookies_list = []

            for cookie in pos['session_cookies']:
                cookies_list.append({
                    "key": cookie['name'],
                    "value": cookie['value'],
                    "domain": "facebook.com",
                    "path": "/",
                    "hostOnly": False,
                    "creation": now_iso,
                    "lastAccessed": now_iso
                })

            # Add sb cookie if not present
            if not any(cookie['key'] == 'sb' for cookie in cookies_list):
                cookies_list.insert(0, {
                    "key": "sb",
                    "value": ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=24)),
                    "domain": "facebook.com",
                    "path": "/",
                    "hostOnly": False,
                    "creation": now_iso,
                    "lastAccessed": now_iso
                })

            return {
                "success": True,
                "data": cookies_list
            }
        else:
            error_message = "Login failed"
            if "error" in pos:
                if "error_msg" in pos:
                    error_message = pos["error_msg"]
                elif "message" in pos["error"]:
                    error_message = pos["error"]["message"]
            
            return {
                "success": False,
                "error": error_message,
                "response": pos
            }
    except Exception as e:
        return {
            "success": False,
            "error": f"Request error: {str(e)}"
        }
