#!/usr/bin/env python3
"""
Facebook Sharer module for handling Facebook API interactions
"""

import re
import time
import asyncio
import aiohttp

class FacebookSharer:
    """Class to handle Facebook sharing functionality"""
    
    def __init__(self, cookie, ui):
        self.cookie = cookie
        self.ui = ui
        self.headers = {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
            'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': "Windows",
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'none',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'cookie': cookie
        }
    
    async def get_access_token(self, session):
        """Extract Facebook access token from the business content management page"""
        try:
            self.ui.show_status("Fetching access token...")
            
            async with session.get('https://business.facebook.com/content_management', 
                                   headers=self.headers) as response:
                data = await response.text()
                access_token_match = re.search('EAAG(.*?)","', data)
                
                if not access_token_match:
                    self.ui.show_error("Failed to extract access token")
                    return None
                
                access_token = 'EAAG' + access_token_match.group(1)
                self.ui.show_success("Access token obtained successfully")
                return access_token
                
        except Exception as e:
            self.ui.show_error(f"Error getting access token: {str(e)}")
            return None
    
    async def share_post(self, post_url, share_count, delay):
        """Share a Facebook post multiple times with progress updates"""
        async with aiohttp.ClientSession() as session:
            access_token = await self.get_access_token(session)
            
            if not access_token:
                self.ui.show_error("Failed to obtain access token. Cookie may be invalid.")
                return False
            
            # Extract the post ID from the URL
            if '/' in post_url:
                post_id = post_url.rstrip('/').split('/')[-1]
                if '?' in post_id:
                    post_id = post_id.split('?')[0]
            else:
                post_id = post_url
            
            # Facebook Graph API endpoint for sharing
            share_headers = {
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
                "sec-ch-ua": '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": "Windows",
                "sec-fetch-dest": "document",
                "sec-fetch-mode": "navigate",
                "sec-fetch-site": "none",
                "sec-fetch-user": "?1",
                "upgrade-insecure-requests": "1",
                "cookie": self.cookie,
                "accept-encoding": "gzip, deflate",
                "host": "b-graph.facebook.com"
            }
            
            success_count = 0
            
            # Setup progress tracking
            self.ui.init_progress_bar(share_count)
            
            for i in range(1, share_count + 1):
                # Display current progress
                self.ui.update_sharing_status(i-1, share_count, post_id)
                
                try:
                    # Facebook sharing API endpoint
                    share_url = f'https://b-graph.facebook.com/me/feed?link={post_url}&published=0&access_token={access_token}'
                    
                    async with session.post(share_url, headers=share_headers) as response:
                        data = await response.json()
                        
                        if 'id' in data:
                            success_count += 1
                            self.ui.update_sharing_status(i, share_count, post_id, success=True)
                        else:
                            self.ui.update_sharing_status(i, share_count, post_id, success=False)
                            error_msg = data.get('error', {}).get('message', 'Unknown error')
                            self.ui.show_error(f"Share {i} failed: {error_msg}")
                    
                    # Add delay between shares if delay is greater than 0
                    if i < share_count and delay > 0:
                        self.ui.show_delay_animation(delay)
                        await asyncio.sleep(delay)
                
                except Exception as e:
                    self.ui.show_error(f"Error during share {i}: {str(e)}")
                    self.ui.update_sharing_status(i, share_count, post_id, success=False)
            
            # Final summary
            self.ui.show_summary(success_count, share_count)
            return success_count > 0
