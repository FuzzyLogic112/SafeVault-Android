import flet as ft
import hashlib
import random
import string
import datetime
import os
import base64

# ==========================================
# 1. 核心逻辑层 (加密与数据管理)
# ==========================================

class SimpleCrypt:
    """
    加密工具类：保持不变，提供基础的 AES/XOR 混淆或加密功能
    """
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
    def __init__(self, page: ft.Page):
        self.page = page  # 需要持有 page 对象来使用 client_storage
        self.storage_key = "safevault.data"
        self.session_key = None 
        self.raw_data = self._load_raw_data()
        self.decrypted_cache = [] 

    def _load_raw_data(self):
        """
        [关键修改] 从 page.client_storage 读取数据，适配 Android
        """
        try:
            if self.page.client_storage.contains_key(self.storage_key):
                return self.page.client_storage.get(self.storage_key)
            else:
                return {"salt": None, "verify_hash": None, "records": []}
        except Exception as e:
            print(f"Read Error: {e}")
            return {"salt": None, "verify_hash": None, "records": []}

    def save_data(self):
        """
        [关键修改] 保存到 page.client_storage
        """
        try:
            self.page.client_storage.set(self.storage_key, self.raw_data)
        except Exception as e:
            print(f"Error saving: {e}")

    def is_first_run(self):
        return self.raw_data.get("salt") is None

    def check_password_strength(self, password):
        if len(password) < 6: return False, "长度需>6位" # 稍微放宽一点限制，方便手机输入
        if not any(c.isdigit() for c in password): return False, "缺数字"
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
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

    @staticmethod
    def generate_strong_password():
        length = 12
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(random.choices(chars, k=length))

# ==========================================
# 2. UI 层 (适配 Android 布局)
# ==========================================

def main(page: ft.Page):
    page.title = "SafeVault"
    page.theme_mode = ft.ThemeMode.LIGHT
    
    # [关键修复] Android 上必须设置 padding=0 并自行管理 SafeArea
    page.padding = 0
    page.scroll = None  # 禁止页面本身滚动，由内部控件接管
    
    # 传递 page 给 logic 以使用 client_storage
    logic = PasswordManagerLogic(page)

    def switch_to_main():
        """切换到主界面的辅助函数"""
        page.clean()
        # 使用 SafeArea 包裹，防止状态栏遮挡
        page.add(ft.SafeArea(build_main_view(), expand=True))
        page.update()

    # --- 界面构建器 ---

    # 1. 初始化界面
    def build_setup_view():
        pwd_field = ft.TextField(label="设置主密码", password=True, can_reveal_password=True, width=300)
        
        def on_setup(e):
            valid, msg = logic.check_password_strength(pwd_field.value)
            if not valid:
                page.snack_bar = ft.SnackBar(ft.Text(f"强度不足: {msg}"))
                page.snack_bar.open = True
                page.update()
                return
            logic.register_master_password(pwd_field.value)
            switch_to_main()

        content = ft.Column(
            [
                ft.Icon(name=ft.icons.SECURITY, size=80, color=ft.colors.BLUE_GREY),
                ft.Text("初始化金库", size=28, weight="bold"),
                ft.Text("设置唯一密码，丢失无法找回", color="red", size=12),
                ft.Container(height=20),
                pwd_field,
                ft.Container(height=10),
                ft.ElevatedButton("初始化并进入", on_click=on_setup, width=300, height=45),
            ],
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=10,
        )
        
        # 使用 Container 包裹并居中，而不是依赖 page 的 alignment
        return ft.Container(content=content, alignment=ft.alignment.center, expand=True)

    # 2. 登录界面
    def build_login_view():
        pwd_field = ft.TextField(label="输入主密码", password=True, can_reveal_password=True, width=300)
        
        def on_login(e):
            if logic.login(pwd_field.value):
                switch_to_main()
            else:
                pwd_field.error_text = "密码错误"
                pwd_field.update()

        content = ft.Column(
            [
                ft.Icon(name=ft.icons.LOCK_OPEN, size=80, color=ft.colors.BLUE),
                ft.Text("解密金库", size=28, weight="bold"),
                ft.Container(height=20),
                pwd_field,
                ft.Container(height=10),
                ft.ElevatedButton("立即解锁", on_click=on_login, width=300, height=45),
            ],
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=10,
        )
        return ft.Container(content=content, alignment=ft.alignment.center, expand=True)

    # 3. 主界面
    def build_main_view():
        # --- 录入 Tab ---
        t_remark = ft.TextField(label="备注 (如: 淘宝)")
        t_user = ft.TextField(label="账号")
        t_pass = ft.TextField(label="密码")
        
        def gen_random(e):
            t_user.value = logic.generate_random_username()
            t_pass.value = logic.generate_strong_password()
            t_user.update()
            t_pass.update()

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
            page.snack_bar = ft.SnackBar(ft.Text("保存成功"))
            page.snack_bar.open = True
            refresh_list() # 刷新列表
            page.update()

        tab_add_content = ft.Column([
            ft.Container(height=20),
            t_remark,
            t_user,
            t_pass,
            ft.Container(height=20),
            ft.Row([
                ft.ElevatedButton("🎲 随机", on_click=gen_random, expand=True),
                ft.ElevatedButton("💾 保存", on_click=save_record, expand=True),
            ]),
        ], scroll=ft.ScrollMode.AUTO, expand=True) # Column 内部滚动

        tab_add = ft.Container(content=tab_add_content, padding=20, expand=True)

        # --- 列表 Tab ---
        lv = ft.ListView(expand=True, spacing=10, padding=10)

        def copy_text(text):
            page.set_clipboard(text)
            page.snack_bar = ft.SnackBar(ft.Text("已复制"))
            page.snack_bar.open = True
            page.update()

        def delete_item(rid):
            logic.delete_record(rid)
            refresh_list(t_search.value if t_search.value else "")

        def refresh_list(query=""):
            lv.controls.clear()
            records = logic.search_records(query)
            if not records:
                lv.controls.append(ft.Text("暂无数据", text_align=ft.TextAlign.CENTER, color="grey"))
            
            for r in records:
                rid = r['id']
                r_user = r['username']
                r_pass = r['password']
                r_remark = r['remark'] or "未命名"
                
                card = ft.Card(
                    content=ft.Container(
                        content=ft.Column([
                            ft.ListTile(
                                leading=ft.Icon(ft.icons.KEY),
                                title=ft.Text(r_remark, weight="bold"),
                                subtitle=ft.Text(f"账号: {r_user}"),
                            ),
                            ft.Row([
                                ft.TextButton("复制密码", on_click=lambda e, x=r_pass: copy_text(x)),
                                ft.IconButton(ft.icons.DELETE, icon_color="red", 
                                            on_click=lambda e, x=rid: delete_item(x))
                            ], alignment=ft.MainAxisAlignment.END)
                        ]),
                        padding=5
                    )
                )
                lv.controls.append(card)
            lv.update()

        t_search = ft.TextField(label="搜索...", prefix_icon=ft.icons.SEARCH, 
                              on_change=lambda e: refresh_list(e.control.value))

        tab_list = ft.Column([
            ft.Container(content=t_search, padding=ft.padding.only(left=10, right=10, top=10)),
            lv
        ], expand=True)

        # 初始加载列表
        # 注意：这里不能直接调用 refresh_list() update UI，因为 UI 还没添加到 page
        # 我们利用 did_mount 或者在返回后由调用者刷新，或者在这里预填充 controls
        records = logic.search_records("")
        if not records:
            lv.controls.append(ft.Text("暂无数据", text_align=ft.TextAlign.CENTER))
        else:
            # 复用上面的逻辑（为了代码简洁，这里简单重写循环，实际建议封装）
            for r in records:
                rid = r['id']
                r_user = r['username']
                r_pass = r['password']
                r_remark = r['remark'] or "未命名"
                card = ft.Card(
                    content=ft.Container(
                        content=ft.Column([
                            ft.ListTile(leading=ft.Icon(ft.icons.KEY),title=ft.Text(r_remark, weight="bold"),subtitle=ft.Text(f"账号: {r_user}")),
                            ft.Row([ft.TextButton("复制密码", on_click=lambda e, x=r_pass: copy_text(x)),ft.IconButton(ft.icons.DELETE, icon_color="red", on_click=lambda e, x=rid: delete_item(x))], alignment=ft.MainAxisAlignment.END)
                        ]), padding=5
                    )
                )
                lv.controls.append(card)

        return ft.Tabs(
            selected_index=0,
            animation_duration=300,
            tabs=[
                ft.Tab(text="录入", icon=ft.icons.ADD, content=tab_add),
                ft.Tab(text="密码库", icon=ft.icons.LIST, content=tab_list),
            ],
            expand=True,
        )

    # 4. 路由逻辑 (入口)
    # 使用 SafeArea 确保 Android 顶部状态栏不遮挡内容
    if logic.is_first_run():
        page.add(ft.SafeArea(build_setup_view(), expand=True))
    else:
        page.add(ft.SafeArea(build_login_view(), expand=True))

ft.app(target=main)