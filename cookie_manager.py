#!/usr/bin/env python3
"""
Cookie Manager for handling Facebook cookies
"""

import re
import json
import requests

class CookieManager:
    """Class to manage Facebook cookies"""

    def json_to_string(self, cookie_json):
        """
        Convert JSON cookie format to string format
        
        Args:
            cookie_json (list): List of cookie dictionaries in the format:
            [
                {
                    "key": "sb",
                    "value": "6aORovgdGGBD0mzBki15oCZO",
                    "domain": "facebook.com",
                    "path": "/",
                    "hostOnly": false,
                    "creation": "2025-05-08T09:33:01.020638+00:00",
                    "lastAccessed": "2025-05-08T09:33:01.020638+00:00"
                },
                ...
            ]
            
        Returns:
            str: Cookie string in format "key1=value1; key2=value2; ..."
        """
        cookie_parts = []
        
        for cookie in cookie_json:
            if "key" in cookie and "value" in cookie:
                cookie_parts.append(f"{cookie['key']}={cookie['value']}")
        
        return "; ".join(cookie_parts)

    def validate_cookie(self, cookie_string):
        """
        Validate if the cookie string contains required Facebook tokens
        
        Args:
            cookie_string (str): The cookie string to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        if not cookie_string:
            return False
            
        # Check if cookie contains c_user which is required for Facebook authentication
        if 'c_user=' not in cookie_string:
            return False
            
        # Additional validation could be done here, such as checking for xs, sb tokens
        required_tokens = ['c_user', 'xs']
        for token in required_tokens:
            pattern = f"{token}=([^;]+)"
            if not re.search(pattern, cookie_string):
                return False
                
        return True
        
    def check_cookie_live(self, cookie_string):
        """
        Check if the cookie is still valid by making a test request to Facebook
        
        Args:
            cookie_string (str): The cookie string to check
            
        Returns:
            bool: True if cookie is valid, False otherwise
        """
        try:
            headers = {
                'Cookie': cookie_string,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36'
            }
            
            # Make a request to Facebook's homepage to check if cookie is valid
            response = requests.get('https://www.facebook.com/me', headers=headers, allow_redirects=False)
            
            # If we get a 302 redirect to login page, the cookie is invalid
            if response.status_code == 302 and 'login' in response.headers.get('Location', ''):
                return False
                
            # If we get a 200 response, the cookie is likely valid
            return response.status_code == 200
            
        except Exception:
            return False
