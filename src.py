import ctypes
import threading
import subprocess
import time
import os
import platform
import requests
import psutil
import base64
import winsound
import tempfile
import winreg
import msvcrt
import shutil
import sys
import random
import string
from ctypes import wintypes
from keyauth.api import Keyauth
from colorama import init, Fore
from rich.progress import Progress, BarColumn, TimeRemainingColumn, TextColumn
from rich.console import Console, Group
from rich.text import Text
from rich.table import Table
from rich.live import Live
from rich.align import Align

init(autoreset=True)
console = Console()
FAKE_DRIVER_PATH = '.\\vgk.sys'
ORIGINAL_DRIVER_PATH = 'C:\\Program Files\\Riot Vanguard\\vgk.sys'

# Global suspended threads list for DNS cache suspension
suspended_threads = []

# ==================== UI & LICENSE ====================

class LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.c_ulong), ("HighPart", ctypes.c_long)]

def set_cmd_font_to_courier_new():
    try:
        key_path = r"Console"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
            winreg.SetValueEx(key, "FaceName", 0, winreg.REG_SZ, "Courier New")
            winreg.SetValueEx(key, "FontFamily", 0, winreg.REG_DWORD, 0x30)
            winreg.SetValueEx(key, "FontSize", 0, winreg.REG_DWORD, 0x00100000)  # 16x size
            winreg.SetValueEx(key, "FontWeight", 0, winreg.REG_DWORD, 400)  # Normal weight
            print("CMD font set to Courier New. Please restart the terminal.")
    except Exception as e:
        print(f"Failed to set CMD font: {e}")
        
def print_centered_animated(text, delay=0.0002):
    terminal_width = shutil.get_terminal_size().columns
    centered_text = text.center(terminal_width)
    for char in centered_text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def centered_input(prompt):
    width = shutil.get_terminal_size().columns
    return input(Fore.WHITE + prompt.center(width) + Fore.RESET)

def resize_and_center_cmd(columns=120, lines=35):
    os.system(f'mode con: cols={columns} lines={lines}')

def set_random_title(length=12):
    title = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    os.system(f'title {title}')
    return title

def show_banner():
    resize_and_center_cmd()
    set_random_title()
    os.system('cls')
    banner = """
 ▄       ▄  ▄▄▄▄▄▄▄▄▄     ▄▄▄▄     
▐░▌     ▐░▌▐░░░░░░░░░▌  ▄█░░░░▌    
 ▐░▌   ▐░▌▐░█░█▀▀▀▀▀█░▌▐░░▌▐░░▌    
  ▐░▌ ▐░▌ ▐░▌▐░▌    ▐░▌ ▀▀ ▐░░▌    
   ▐░▐░▌  ▐░▌ ▐░▌   ▐░▌    ▐░░▌    
    ▐░▌   ▐░▌  ▐░▌  ▐░▌    ▐░░▌    
   ▐░▌░▌  ▐░▌   ▐░▌ ▐░▌    ▐░░▌    
  ▐░▌ ▐░▌ ▐░▌    ▐░▌▐░▌    ▐░░▌    
 ▐░▌   ▐░▌▐░█▄▄▄▄▄█░█░▌▄▄▄▄█░░█▄▄▄ 
▐░▌     ▐░▌▐░░░░░░░░░▌▐░░░░░░░░░░░▌
 ▀       ▀  ▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀ 
                                                   
    """
    width = shutil.get_terminal_size().columns
    for line in banner.splitlines():
        print(Fore.RED + line.center(width) + Fore.RESET)
    log("Bypass : discord.gg/x01", "success")
    log("Last Updated : 18.07.2025 | Undetected - Safe", "success")
    log("", "step")

    

def log(msg, type='info'):
    width = shutil.get_terminal_size().columns
    color = {
        'info': Fore.CYAN,
        'success': Fore.GREEN,
        'warn': Fore.YELLOW,
        'error': Fore.RED,
        'step': Fore.BLUE
    }.get(type, Fore.WHITE)
    print(color + msg.center(width) + Fore.RESET)

def get_keyauth_config_from_url(url):
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
    except requests.exceptions.RequestException:
        return None
    config = {}
    for line in response.text.strip().splitlines():
        if '=' in line:
            key, value = line.strip().split('=', 1)
            config[key.strip()] = value.strip()
    return config

def initialize_keyauth():
    pastebin_raw_url = "https://pastebin.com/raw/hHDCkuXM"
    config = get_keyauth_config_from_url(pastebin_raw_url)
    if config is None:
        return None
    return Keyauth(
        name=config['name'],
        owner_id=config['owner_id'],
        version=config['version'],
        secret=config['secret'],
        file_hash=config['file_hash']
    )

def verify_license():
    os.system('cls')
    show_banner()
    try:
        keyauthapp = initialize_keyauth()
    except Exception:
        print_centered_animated('[ERROR] Please check your internet connection or try again later.')
        return 0

    try:
        license_key = centered_input('Enter your license key: ')
    except Exception:
        print_centered_animated('[ERROR] License key input failed.')
        return 0

    try:
        keyauthapp.license(license_key)
        print_centered_animated(' Successful!')
        os.system('cls')
        return 1
    except Exception:
        print_centered_animated(' Invalid License')
        return 0
    
def create_fake_driver():
    try:
        with open(FAKE_DRIVER_PATH, 'w') as f:
            f.write(' Fake Driver!')
    except PermissionError:
        sys.exit(1)

def replace_driver():
    try:
        if os.path.exists(ORIGINAL_DRIVER_PATH):
            shutil.copy(ORIGINAL_DRIVER_PATH, ORIGINAL_DRIVER_PATH + '.bak')
        shutil.move(FAKE_DRIVER_PATH, ORIGINAL_DRIVER_PATH)
    except Exception:
        pass

    

# ==================== PRIVILEGE ====================
advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002
class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]
class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]
class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]
OpenProcessToken = advapi32.OpenProcessToken
OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
OpenProcessToken.restype = wintypes.BOOL
LookupPrivilegeValueW = advapi32.LookupPrivilegeValueW
LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)]
LookupPrivilegeValueW.restype = wintypes.BOOL
AdjustTokenPrivileges = advapi32.AdjustTokenPrivileges
AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES), wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID]
AdjustTokenPrivileges.restype = wintypes.BOOL
GetCurrentProcess = ctypes.windll.kernel32.GetCurrentProcess
GetCurrentProcess.restype = wintypes.HANDLE

def adjust_privileges():
    privileges = [
        "SeDebugPrivilege",
        "SeLoadDriverPrivilege",
        "SeShutdownPrivilege",
        "SeTakeOwnershipPrivilege",
        "SeSecurityPrivilege",
        "SeIncreaseQuotaPrivilege"
    ]
    hToken = wintypes.HANDLE()
    if not OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(hToken)):
        log("Failed to open process token.", "error")
        return False
    for priv in privileges:
        luid = LUID()
        if not LookupPrivilegeValueW(None, priv, ctypes.byref(luid)):
            continue
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        AdjustTokenPrivileges(hToken, False, ctypes.byref(tp), 0, None, None)
    return True

# ==================== DRIVER LOAD ====================
def load_driver_from_base64(driver_b64: str):
    try:
        temp_path = os.path.join(tempfile.gettempdir(), "koreanthebeast.sys")
        with open(temp_path, "wb") as f:
            f.write(base64.b64decode(driver_b64))
        service_name = "valorhack"
        subprocess.run(["sc", "create", service_name, "binPath=", temp_path, "type=", "kernel", "start=", "demand"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["sc", "start", service_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log("Driver loaded and started.", "success")
        os.remove(temp_path)
    except Exception as e:
        log(f"Driver loading error: {str(e)}", "error")

# ==================== VALORANT MONITORING ====================
def find_process(name):
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] and proc.info['name'].lower() == name.lower():
            return proc
    return None

def terminate_vgtray():
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] and proc.info['name'].lower() == "vgtray.exe":
            try:
                proc.kill()
                log("vgtray.exe terminated.", "info")
                return True
            except Exception:
                pass
    return False

def backup_vgk_sys():
    vgk_path = r"C:\\Program Files\\Riot Vanguard\\vgk.sys"
    backup_path = vgk_path + ".bak"
    try:
        if os.path.exists(vgk_path):
            subprocess.run(['takeown', '/f', vgk_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['icacls', vgk_path, '/grant', 'Administrators:F'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['icacls', vgk_path, '/grant', 'SYSTEM:F'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            shutil.copy2(vgk_path, backup_path)
            log("Vanguard file backed up.", "success")
            return True
        else:
            log("vgk.sys not found.", "warn")
            return False
    except Exception as e:
        log(f"Backup failed: {str(e)}", "error")
        return False

def get_service_pid(service_name):
    try:
        cmd = ['powershell', '-Command',
               f"(Get-WmiObject -Class Win32_Service | Where-Object {{$_.Name -eq '{service_name}'}}).ProcessId"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        pid_str = result.stdout.strip()

        if result.returncode == 0 and pid_str.isdigit():
            return int(pid_str)
    except Exception:
        pass
    return None

def suspend_dns_cache():
    global suspended_threads
    suspended_threads.clear()
    pid = get_service_pid("Dnscache")
    if not pid:
        log("  alınamadı.", "error")
        return False

    try:
        process = psutil.Process(pid)
        threads = process.threads()

        for t in threads:
            tid = t.id
            # THREAD_SUSPEND_RESUME = 0x0002 (standard value)
            h_thread = ctypes.windll.kernel32.OpenThread(0x0002, False, tid)
            if h_thread:
                res = ctypes.windll.kernel32.SuspendThread(h_thread)
                if res != -1:
                    suspended_threads.append(tid)
                ctypes.windll.kernel32.CloseHandle(h_thread)
        log("VGK Changed.", "success")
        return True
    except Exception as e:
        log(f"Sailed", "error")
        return False

def resume_suspended_threads():
    global suspended_threads
    for tid in suspended_threads:
        try:
            h_thread = ctypes.windll.kernel32.OpenThread(0x0002, False, tid)
            if h_thread:
                ctypes.windll.kernel32.ResumeThread(h_thread)
                ctypes.windll.kernel32.CloseHandle(h_thread)
        except Exception as e:
            log(f" failed", "error")
    suspended_threads.clear()
    log(".", "info")

def watch_valorant():
    valorant_detected = False
    dns_suspended = False

    while True:
        time.sleep(1)
        valorant = find_process("VALORANT.exe")

        if valorant and not valorant_detected:
            valorant_detected = True
            terminate_vgtray()
            backup_vgk_sys()
            log("Valorant detected. Preparing bypass...", "step")

            countdown_15_seconds()

            if not dns_suspended:
                if suspend_dns_cache():
                    dns_suspended = True
                    log("Bypass active!", "success")

            countdown_40_minutes()

        elif not valorant and valorant_detected:
            valorant_detected = False
            log("Valorant closed.", "warn")
            if dns_suspended:
                resume_suspended_threads()
                dns_suspended = False


def countdown_15_seconds():
    seconds = 75
    progress = Progress(
        TextColumn("[red]Injecting in..."),
        BarColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=True
    )
    task = progress.add_task("", total=seconds)

    with Live(console=console, refresh_per_second=10) as live:
        while not progress.finished:
            progress.advance(task)
            live.update(Align.center(progress))
            time.sleep(1)
    console.print(Align.center("[bold yellow]INJECT THE CHEAT[/bold yellow]", vertical="middle"))


def countdown_40_minutes():
    seconds = 14 * 60
    progress = Progress(
        TextColumn("[cyan]Press F3 after the time.."),
        BarColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=True
    )
    task = progress.add_task("", total=seconds)

    with Live(console=console, refresh_per_second=10) as live:
        while not progress.finished:
            progress.advance(task)
            live.update(Align.center(progress))
            time.sleep(1)
    os.system('powershell [console]::beep(800,300)')
    os.system('powershell [console]::beep(800,300)')
    os.system('powershell [console]::beep(800,300)')
    console.print(Align.center("[bold yellow]PRESS F3 ![/bold yellow]", vertical="middle"))

        
def terminate_processes_by_names(names):
    for proc in psutil.process_iter(['name']):
        try:
            pname = proc.info['name']
            if pname and pname.lower() in (n.lower() for n in names):
                proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

process_names = ["vgc.exe", "vgtray.exe", "VALORANT.exe", "VALORANT-Win64-Shipping.exe"]

def change_service_description(service_name, new_description):
    cmd = [
        "powershell",
        "-Command",
        f'Set-Service -Name "{service_name}" -Description "{new_description}"'
    ]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(f"Hata: {e.stderr.decode().strip()}")

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def start_watcher_thread():
    watcher_thread = threading.Thread(target=watch_valorant, daemon=True)
    watcher_thread.start()
    return watcher_thread


# ==================== MAIN ====================
def main():
    set_cmd_font_to_courier_new()
    if not is_admin():
        print("Yönetici izni gerekiyor. Tekrar başlatılıyor...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)
    
    if verify_license() != 1:
        sys.exit(0)

    show_banner()
    terminate_processes_by_names(process_names)
    change_service_description("vgc", "Aeltrx BYPASS")
    adjust_privileges()
    

    driver_b64 = "c0JZUEFTU3MgRmFrZSBEcml2ZXIh"  # Fake driver base64
    if driver_b64.strip():
        load_driver_from_base64(driver_b64)
    
    create_fake_driver()
    replace_driver()



    print_centered_animated(" Press f3 every match end.\n")
    print_centered_animated(" open Valorant when ready\n")

    while True:
        if msvcrt.kbhit():
            key = msvcrt.getch()
            if key == b'\x3d':  # F3 key (note: sometimes F3 = b'\x3d' or b'\x73', test if needed)
                log("Resetting program...", "info")
                terminate_processes_by_names(process_names)
                resume_suspended_threads()  # Suspend kaldırılıyor
                time.sleep(3)
                return

def run():
    watcher_thread = start_watcher_thread()  # Thread sadece bir kez başlatılıyor
    while True:
        main()

if __name__ == '__main__':
    run()
