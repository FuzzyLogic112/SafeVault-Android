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
# 核心逻辑层 (可以直接复用之前的代码，仅修改路径获取)
# ==========================================

class AppUtils:
    @staticmethod
    def get_data_file_path():
        # 安卓/Flet环境下，我们存放在当前应用文档目录
        # 这里简化处理，直接用 os.getcwd() 或者 Flet 提供的存储
        # 实际 APK 运行时，会自动映射到应用私有目录
        return "data.json"

class SimpleCrypt:
    # ... (加密算法保持完全一致，直接复制之前的) ...
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
        if len(password) < 8: return False, "长度需>8位" # 手机上提示短一点
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
# UI 层 (使用 Flet 重写，适配移动端)
# ==========================================
def main(page: ft.Page):
    page.title = "SafeVault Mobile"
    page.theme_mode = ft.ThemeMode.LIGHT
    page.padding = 20
    # 适配手机竖屏
    page.window_width = 390 
    page.window_height = 844
    
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

    # === 1. 初始化页面 ===
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

        return ft.Column([
            ft.Text("🛡️ 初始化金库", size=30, weight="bold"),
            ft.Text("请设置一个强密码，一旦丢失无法找回！", color="red"),
            ft.Container(height=20),
            pwd_field,
            ft.ElevatedButton("初始化", on_click=on_setup, width=400, height=50),
        ], alignment="center", spacing=20)

    # === 2. 登录页面 ===
    def build_login_view():
        pwd_field = ft.TextField(label="输入主密码", password=True, can_reveal_password=True)
        
        def on_login(e):
            if logic.login(pwd_field.value):
                switch_to_main()
            else:
                pwd_field.error_text = "密码错误"
                pwd_field.update()

        return ft.Column([
            ft.Icon(name=ft.icons.LOCK, size=60, color=ft.colors.BLUE),
            ft.Text("解密金库", size=30, weight="bold"),
            ft.Container(height=20),
            pwd_field,
            ft.ElevatedButton("解锁", on_click=on_login, width=400, height=50),
        ], alignment="center", spacing=20, expand=True) # expand=True 让内容垂直居中

    # === 3. 主页面 (包含 录入/列表 两个Tab) ===
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
            # 清空并提示
            t_user.value = ""
            t_pass.value = ""
            t_remark.value = ""
            page.snack_bar = ft.SnackBar(ft.Text("保存成功！请去列表查看"))
            page.snack_bar.open = True
            refresh_list() # 刷新列表
            page.update()

        tab_add = ft.Column([
            ft.Container(height=10),
            t_remark,
            t_user,
            t_pass,
            ft.Row([
                ft.ElevatedButton("🎲 随机生成", on_click=gen_random, expand=True),
                ft.ElevatedButton("💾 保存", on_click=save_record, expand=True),
            ]),
        ], scroll="auto")

        # --- 列表 Tab ---
        lv = ft.ListView(expand=True, spacing=10)

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
                # 每一个记录卡片
                rid = r['id']
                r_user = r['username']
                r_pass = r['password']
                
                card = ft.Card(
                    content=ft.Container(
                        content=ft.Column([
                            ft.ListTile(
                                leading=ft.Icon(ft.icons.KEY),
                                title=ft.Text(r['remark'] or "未命名"),
                                subtitle=ft.Text(f"账号: {r_user}\n密码: ••••••"),
                            ),
                            ft.Row([
                                ft.TextButton("复制账号", on_click=lambda e, x=r_user: copy_text(x)),
                                ft.TextButton("复制密码", on_click=lambda e, x=r_pass: copy_text(x)),
                                ft.IconButton(ft.icons.DELETE, icon_color="red", 
                                            on_click=lambda e, x=rid: delete_item(x))
                            ], alignment="end")
                        ]),
                        padding=10
                    )
                )
                lv.controls.append(card)
            page.update()

        # 搜索框
        t_search = ft.TextField(label="🔍 搜索...", on_change=lambda e: refresh_list(e.control.value))

        tab_list = ft.Column([
            t_search,
            lv
        ], expand=True)

        # 初始化列表
        refresh_list()

        # 使用 Tabs 布局
        tabs = ft.Tabs(
            selected_index=0,
            animation_duration=300,
            tabs=[
                ft.Tab(text="录入", icon=ft.icons.ADD, content=tab_add),
                ft.Tab(text="密码库", icon=ft.icons.LIST, content=tab_list),
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