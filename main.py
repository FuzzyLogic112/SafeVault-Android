import flet as ft
import hashlib
import json
import random
import string
import datetime
import os
import base64
import sys

# ==========================================
# 核心逻辑层 (保持不变)
# ==========================================

class AppUtils:
    @staticmethod
    def get_data_file_path():
        # 在安卓上，Flet 会自动处理路径，直接用文件名即可
        return "data.json"

class SimpleCrypt:
    # ... (加密算法保持完全一致) ...
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

    @staticmethod
    def encrypt_string(plaintext: str, key: bytes) -> str:
        try:
            if not plaintext: return ""
            iv = os.urandom(16)
            keystream_seed = key + iv
            keystream = hashlib.sha256(keystream_seed).digest()
            text_bytes = plaintext.encode('utf-8')
            while len(keystream) < len(text_bytes):
                keystream += hashlib.sha256(keystream).digest()
            encrypted_bytes = bytearray()
            for i in range(len(text_bytes)):
                encrypted_bytes.append(text_bytes[i] ^ keystream[i])
            return base64.b64encode(iv + encrypted_bytes).decode('utf-8')
        except Exception:
            return ""

    @staticmethod
    def decrypt_string(ciphertext_b64: str, key: bytes) -> str:
        try:
            if not ciphertext_b64: return ""
            data = base64.b64decode(ciphertext_b64)
            if len(data) < 17: return ""
            iv = data[:16]
            encrypted_bytes = data[16:]
            keystream_seed = key + iv
            keystream = hashlib.sha256(keystream_seed).digest()
            while len(keystream) < len(encrypted_bytes):
                keystream += hashlib.sha256(keystream).digest()
            decrypted_bytes = bytearray()
            for i in range(len(encrypted_bytes)):
                decrypted_bytes.append(encrypted_bytes[i] ^ keystream[i])
            return decrypted_bytes.decode('utf-8')
        except Exception:
            return "Error"

class PasswordManagerLogic:
    # ... (业务逻辑层保持完全一致) ...
    def __init__(self):
        self.file_path = AppUtils.get_data_file_path()
        self.session_key = None 
        self.raw_data = self._load_raw_data()
        self.decrypted_cache = [] 

    def _load_raw_data(self):
        if not os.path.exists(self.file_path):
            return {"salt": None, "verify_hash": None, "records": []}
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {"salt": None, "verify_hash": None, "records": []}

    def save_data(self):
        try:
            with open(self.file_path, 'w', encoding='utf-8') as f:
                json.dump(self.raw_data, f, ensure_ascii=False, indent=4)
        except Exception as e:
            print(f"Error saving: {e}")

    def is_first_run(self):
        return self.raw_data.get("salt") is None

    def check_password_strength(self, password):
        if len(password) < 8: return False, "长度需>8位"
        if not any(c.isupper() for c in password): return False, "缺大写字母"
        if not any(c.islower() for c in password): return False, "缺小写字母"
        if not any(c.isdigit() for c in password): return False, "缺数字"
        if not any(c in string.punctuation for c in password): return False, "缺符号"
        return True, "合格"

    def register_master_password(self, password):
        salt = os.urandom(16)
        key = SimpleCrypt.derive_key(password, salt)
        verify_token = SimpleCrypt.encrypt_string("CHECK_VALID", key)
        self.raw_data["salt"] = base64.b64encode(salt).decode()
        self.raw_data["verify_hash"] = verify_token
        self.raw_data["records"] = []
        self.session_key = key
        self.save_data()

    def login(self, password):
        try:
            salt_b64 = self.raw_data.get("salt")
            verify_token = self.raw_data.get("verify_hash")
            if not salt_b64 or not verify_token: return False
            salt = base64.b64decode(salt_b64)
            derived_key = SimpleCrypt.derive_key(password, salt)
            if SimpleCrypt.decrypt_string(verify_token, derived_key) == "CHECK_VALID":
                self.session_key = derived_key
                self.refresh_decrypted_cache()
                return True
            return False
        except Exception:
            return False

    def add_record(self, username, password, remark=""):
        if not self.session_key: return
        enc_user = SimpleCrypt.encrypt_string(username, self.session_key)
        enc_pass = SimpleCrypt.encrypt_string(password, self.session_key)
        enc_remark = SimpleCrypt.encrypt_string(remark, self.session_key)
        
        record = {
            "id": self._generate_id(),
            "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "u_enc": enc_user, "p_enc": enc_pass, "r_enc": enc_remark
        }
        self.raw_data["records"].insert(0, record)
        self.save_data()
        self.refresh_decrypted_cache()

    def delete_record(self, record_id):
        self.raw_data["records"] = [r for r in self.raw_data["records"] if r.get("id") != record_id]
        self.save_data()
        self.refresh_decrypted_cache()

    def _generate_id(self):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=8))

    def refresh_decrypted_cache(self):
        self.decrypted_cache = []
        if not self.session_key: return
        for r in self.raw_data["records"]:
            try:
                self.decrypted_cache.append({
                    "id": r.get("id", ""),
                    "created_at": r["created_at"],
                    "username": SimpleCrypt.decrypt_string(r["u_enc"], self.session_key),
                    "password": SimpleCrypt.decrypt_string(r["p_enc"], self.session_key),
                    "remark": SimpleCrypt.decrypt_string(r["r_enc"], self.session_key),
                })
            except:
                continue
    
    def search_records(self, query):
        if not query: return self.decrypted_cache
        query = query.lower()
        return [r for r in self.decrypted_cache if query in r["remark"].lower() or query in r["username"].lower()]

    @staticmethod
    def generate_random_username():
        return ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(8, 12)))

    @staticmethod
    def generate_strong_password():
        length = 16
        pool = [string.ascii_uppercase, string.ascii_lowercase, string.digits, "!@#$%^&*()_+-=[]{}|;:,.<>?"]
        chars = [random.choice(p) for p in pool]
        chars += random.choices(''.join(pool), k=length - 4)
        random.shuffle(chars)
        return ''.join(chars)

# ==========================================
# UI 层 (修复布局问题)
# ==========================================
def main(page: ft.Page):
    page.title = "SafeVault"
    page.theme_mode = ft.ThemeMode.LIGHT
    page.padding = 20
    
    logic = PasswordManagerLogic()
    
    # === 页面切换辅助函数 ===
    def switch_to_login():
        page.clean()
        page.add(build_login_view())
    
    def switch_to_setup():
        page.clean()
        page.add(build_setup_view())

    def switch_to_main():
        page.clean()
        page.add(build_main_view())

    # === 1. 初始化页面 (修复居中) ===
    def build_setup_view():
        pwd_field = ft.TextField(label="设置主密码", password=True, can_reveal_password=True)
        
        def on_setup(e):
            valid, msg = logic.check_password_strength(pwd_field.value)
            if not valid:
                page.snack_bar = ft.SnackBar(ft.Text(f"强度不足: {msg}"))
                page.snack_bar.open = True
                page.update()
                return
            logic.register_master_password(pwd_field.value)
            switch_to_main()

        # 【修复点】增加 expand=True 和明确的对齐方式
        return ft.Column(
            [
                ft.Icon(name=ft.icons.SECURITY, size=60, color=ft.colors.BLUE_GREY),
                ft.Text("初始化金库", size=30, weight="bold"),
                ft.Text("请设置一个强密码，一旦丢失无法找回！", color="red"),
                ft.Container(height=20),
                pwd_field,
                ft.ElevatedButton("初始化", on_click=on_setup, width=400, height=50),
            ],
            alignment=ft.MainAxisAlignment.CENTER, # 垂直居中
            horizontal_alignment=ft.CrossAxisAlignment.CENTER, # 水平居中
            spacing=20,
            expand=True # 撑满全屏
        )

    # === 2. 登录页面 (修复居中) ===
    def build_login_view():
        pwd_field = ft.TextField(label="输入主密码", password=True, can_reveal_password=True)
        
        def on_login(e):
            if logic.login(pwd_field.value):
                switch_to_main()
            else:
                pwd_field.error_text = "密码错误"
                pwd_field.update()

        # 【修复点】增加 expand=True 和明确的对齐方式
        return ft.Column(
            [
                ft.Icon(name=ft.icons.LOCK_OPEN, size=60, color=ft.colors.BLUE),
                ft.Text("解密金库", size=30, weight="bold"),
                ft.Container(height=20),
                pwd_field,
                ft.ElevatedButton("解锁", on_click=on_login, width=400, height=50),
            ],
            alignment=ft.MainAxisAlignment.CENTER, # 垂直居中
            horizontal_alignment=ft.CrossAxisAlignment.CENTER, # 水平居中
            spacing=20,
            expand=True # 撑满全屏
        )

    # === 3. 主页面 (修复白屏) ===
    def build_main_view():
        # --- 录入 Tab ---
        t_remark = ft.TextField(label="备注 (如: 淘宝)")
        t_user = ft.TextField(label="账号/用户名")
        t_pass = ft.TextField(label="密码")
        
        def gen_random(e):
            t_user.value = logic.generate_random_username()
            t_pass.value = logic.generate_strong_password()
            page.update()

        def save_record(e):
            if not t_user.value or not t_pass.value:
                page.snack_bar = ft.SnackBar(ft.Text("账号密码不能为空"))
                page.snack_bar.open = True
                page.update()
                return
            logic.add_record(t_user.value, t_pass.value, t_remark.value)
            t_user.value = ""
            t_pass.value = ""
            t_remark.value = ""
            page.snack_bar = ft.SnackBar(ft.Text("保存成功！请去列表查看"))
            page.snack_bar.open = True
            refresh_list()
            page.update()

        # 【修复点】增加 expand=True
        tab_add = ft.Column([
            ft.Container(height=10),
            t_remark,
            t_user,
            t_pass,
            ft.Row([
                ft.ElevatedButton("🎲 随机生成", on_click=gen_random, expand=True),
                ft.ElevatedButton("💾 保存", on_click=save_record, expand=True),
            ]),
        ], scroll="auto", expand=True)

        # --- 列表 Tab ---
        # 【修复点】增加 expand=True
        lv = ft.ListView(expand=True, spacing=10, padding=10)

        def copy_text(text):
            page.set_clipboard(text)
            page.snack_bar = ft.SnackBar(ft.Text("已复制到剪贴板"))
            page.snack_bar.open = True
            page.update()

        def delete_item(rid):
            logic.delete_record(rid)
            refresh_list()

        def refresh_list(query=""):
            lv.controls.clear()
            records = logic.search_records(query)
            
            for r in records:
                try:
                    # 每一个记录卡片
                    rid = r['id']
                    r_user = r['username']
                    r_pass = r['password']
                    r_remark = r['remark'] or "未命名"
                    
                    card = ft.Card(
                        content=ft.Container(
                            content=ft.Column([
                                ft.ListTile(
                                    leading=ft.Icon(ft.icons.KEY_VPM_SHARP, color=ft.colors.BLUE_GREY),
                                    title=ft.Text(r_remark, weight="bold"),
                                    subtitle=ft.Text(f"账号: {r_user}\n密码: ••••••"),
                                ),
                                ft.Row([
                                    ft.TextButton("复制账号", on_click=lambda e, x=r_user: copy_text(x)),
                                    ft.TextButton("复制密码", on_click=lambda e, x=r_pass: copy_text(x)),
                                    ft.IconButton(ft.icons.DELETE_OUTLINE, icon_color="red", 
                                                on_click=lambda e, x=rid: delete_item(x))
                                ], alignment="end")
                            ]),
                            padding=10
                        )
                    )
                    lv.controls.append(card)
                except Exception as e:
                    # 【修复点】增加错误捕获，防止单条数据错误导致白屏
                    print(f"Error building card: {e}")
                    lv.controls.append(ft.Card(content=ft.Container(content=ft.Text(f"数据加载错误: {r.get('id')}", color="red"), padding=10)))

            page.update()

        t_search = ft.TextField(label="🔍 搜索...", prefix_icon=ft.icons.SEARCH, on_change=lambda e: refresh_list(e.control.value))

        # 【修复点】增加 expand=True
        tab_list = ft.Column([
            t_search,
            lv
        ], expand=True)

        refresh_list()

        # 【修复点】Tabs 控件本身已经有 expand=True，但它的子控件(上面的 tab_add, tab_list)也必须有 expand=True 才能撑开
        tabs = ft.Tabs(
            selected_index=0,
            animation_duration=300,
            tabs=[
                ft.Tab(text="录入", icon=ft.icons.ADD_CIRCLE_OUTLINE, content=tab_add),
                ft.Tab(text="密码库", icon=ft.icons.LIST_ALT_ROUNDED, content=tab_list),
            ],
            expand=True,
        )

        return tabs

    # === 程序入口判断 ===
    if logic.is_first_run():
        switch_to_setup()
    else:
        switch_to_login()

ft.app(target=main)