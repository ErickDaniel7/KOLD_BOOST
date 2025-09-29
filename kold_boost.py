# -*- coding: utf-8 -*-
# KOLD BOOST - Windows Performance Toolkit (ULTIMATE SINGLE FILE)
# Interface dark com abas + tweaks seguros/avançados/arriscados
# Requisitos: Python 3.9+ no Windows. Execute como ADMIN.
# AVISO: Use por sua conta e risco. Crie ponto de restauração.

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import subprocess
import threading
from datetime import datetime
import ctypes
import time
import os
import sys
import winsound
import shutil
import tempfile
import traceback
import json

APP_NAME = "KOLD BOOST ⚡"
APP_VERSION = "v2.0-ultimate"
AUTHOR = "Você :)"

# Pasta de logs
LOG_DIR = os.path.join(os.path.expanduser("~"), "KOLD_BOOST_LOGS")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, f"log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

# ==========================
# Configurações globais
# ==========================
class Config:
    dry_run = False          # Simulação (não executa de fato)
    confirm_each = False     # Pergunta antes de cada comando
    show_cmd_output = False  # Mostra stdout/stderr no log
    backup_reg = True        # Exportar .reg antes de mexer
    theme = "dark"           # "dark" ou "light"

# ==========================
# Helpers de sistema / admin
# ==========================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def beep_ok():
    try: winsound.MessageBeep(winsound.MB_ICONASTERISK)
    except Exception: pass

def beep_warn():
    try: winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
    except Exception: pass

def beep_err():
    try: winsound.MessageBeep(winsound.MB_ICONHAND)
    except Exception: pass

def timestamp():
    return datetime.now().strftime("[%H:%M:%S] ")

# ==========================
# Logging
# ==========================
def log_to_file(text: str):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(timestamp() + text.rstrip() + "\n")
    except Exception:
        pass

def log(widget, text, color="white", typing_effect=False):
    log_to_file(text)
    if widget is None:
        return
    widget.configure(state='normal')
    line = f"{timestamp()}{text}\n"
    if typing_effect:
        for ch in line:
            widget.insert(tk.END, ch)
            widget.tag_add(color, f"{widget.index('end')} -1c", tk.END)
            widget.update()
            time.sleep(0.0012)
    else:
        widget.insert(tk.END, line)
        widget.tag_add(color, f"{widget.index('end')} -1c linestart", tk.END)
    widget.see(tk.END)
    widget.configure(state='disabled')

def clear_log(widget):
    if widget is None:
        return
    widget.configure(state='normal')
    widget.delete(1.0, tk.END)
    widget.configure(state='disabled')

def copy_log_to_clipboard(widget):
    try:
        content = widget.get("1.0", tk.END)
        root.clipboard_clear()
        root.clipboard_append(content)
        beep_ok()
        messagebox.showinfo("Log", "Log copiado para a área de transferência.")
    except Exception:
        messagebox.showerror("Erro", "Não foi possível copiar o log.")

def export_log_as_txt(widget):
    try:
        content = widget.get("1.0", tk.END)
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Arquivo de texto", "*.txt")],
            title="Salvar log como"
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        beep_ok()
        messagebox.showinfo("Log", f"Log salvo em:\n{path}")
    except Exception as e:
        messagebox.showerror("Erro", f"Falha ao salvar log: {e}")

# ==========================
# Execução de comandos
# ==========================
def run_command(cmd, log_widget=None, progress=None, expect_ok_codes=(0,), desc=None):
    """Executa um comando de shell. Obedece Dry-run, Confirmar cada e Show stdout."""
    if desc:
        log(log_widget, desc, "yellow")
    log(log_widget, f"Executando: {cmd}", "yellow")

    if Config.confirm_each:
        if not messagebox.askyesno("Confirmar comando", f"Executar?\n\n{cmd}"):
            log(log_widget, "Ignorado pelo usuário.", "red")
            if progress: progress.step(1)
            return False

    if Config.dry_run:
        log(log_widget, "Simulação (dry-run).", "green")
        if progress: progress.step(1)
        return True

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, errors="replace")
        rc = result.returncode
        out = (result.stdout or "").strip()
        err = (result.stderr or "").strip()
        if Config.show_cmd_output and out:
            log(log_widget, f"STDOUT: {out}", "white")
        if Config.show_cmd_output and err:
            log(log_widget, f"STDERR: {err}", "red")

        if rc in expect_ok_codes:
            log(log_widget, "Ok.", "green")
            ok = True
        else:
            log(log_widget, f"Falhou (código {rc}).", "red")
            if not Config.show_cmd_output:
                if out:
                    log(log_widget, f"STDOUT: {out}", "white")
                if err:
                    log(log_widget, f"STDERR: {err}", "red")
            ok = False
    except Exception as e:
        log(log_widget, f"Erro: {e}", "red")
        ok = False

    if progress:
        progress.step(1)
    return ok

# ==========================
# Backup de chaves de registro (.reg)
# ==========================
def export_reg_key(reg_path, dest_dir, log_widget=None):
    """Exporta uma chave do registro usando reg.exe /E"""
    if not Config.backup_reg:
        return
    try:
        os.makedirs(dest_dir, exist_ok=True)
        safe_filename = reg_path.replace("\\", "_").replace("/", "_").replace(":", "").replace("\"", "")
        export_path = os.path.join(dest_dir, f"{safe_filename}.reg")
        cmd = f'reg export "{reg_path}" "{export_path}" /y'
        run_command(cmd, log_widget, desc=f"[Backup] Exportando {reg_path} para .reg")
    except Exception as e:
        log(log_widget, f"[Backup] Erro ao exportar {reg_path}: {e}", "red")

# ==========================
# Ponto de restauração
# ==========================
def create_restore_point(log_widget=None, progress=None):
    """Cria ponto de restauração via PowerShell (requer Proteção do Sistema ativa)"""
    log(log_widget, "[Sistema] Criando ponto de restauração...", "yellow")
    cmd = (
        'powershell -NoProfile -ExecutionPolicy Bypass '
        '-Command "Checkpoint-Computer -Description \\"KOLD_BOOST\\" -RestorePointType \\"MODIFY_SETTINGS\\""'
    )
    ok = run_command(cmd, log_widget, progress=progress)
    if ok:
        log(log_widget, "Ponto de restauração criado.", "green")
    else:
        log(log_widget, "Não foi possível criar ponto de restauração (Proteção do Sistema pode estar desativada).", "red")

# ==========================
# Utilidades de shell / sistema
# ==========================
def open_cmd_admin():
    try:
        subprocess.Popen('powershell -NoProfile -Command "Start-Process cmd -Verb RunAs"', shell=True)
    except Exception:
        pass

def open_regedit():
    try:
        subprocess.Popen('regedit', shell=True)
    except Exception:
        pass

def open_log_folder():
    try:
        if os.name == "nt":
            os.startfile(LOG_DIR)
    except Exception:
        pass

# ==========================
# BLOCO: SISTEMA (seguros)
# ==========================
def sistema_tweaks(log_widget, progress=None):
    """Tweaks de GameDVR, notificações, serviços comuns"""
    log(log_widget, "[Sistema] Aplicando tweaks avançados...", "yellow")
    export_reg_key(r'HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR', LOG_DIR, log_widget)
    export_reg_key(r'HKCU\System\GameConfigStore', LOG_DIR, log_widget)
    export_reg_key(r'HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications', LOG_DIR, log_widget)
    export_reg_key(r'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer', LOG_DIR, log_widget)

    cmds = [
        r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f',
        r'reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f',
        r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v ToastEnabled /t REG_DWORD /d 0 /f',
        r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCenter /t REG_DWORD /d 1 /f',

        "sc config DiagTrack start= disabled",
        "sc config WSearch start= disabled",
        "sc config SysMain start= disabled",
        "sc config XblAuthManager start= disabled",
        "sc config XblGameSave start= disabled",
        "sc config XboxGipSvc start= disabled",
        "sc config MapsBroker start= disabled",
        "sc config RetailDemo start= disabled",
        "sc config PeopleSvc start= disabled",
        "sc config PhoneSvc start= disabled",
    ]
    for c in cmds:
        run_command(c, log_widget, progress=progress)
    log(log_widget, "[Sistema] Concluído!\n", "green")
    messagebox.showinfo("Sistema", "Tweaks do sistema aplicados!")

def tarefas_telemetria(log_widget, progress=None):
    """Desativar tarefas agendadas de telemetria"""
    log(log_widget, "[Sistema] Desativando tarefas de telemetria/feedback...", "yellow")
    tasks = [
        r'\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
        r'\Microsoft\Windows\Application Experience\ProgramDataUpdater',
        r'\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
        r'\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip',
        r'\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector',
        r'\Microsoft\Windows\Feedback\Siuf\DmClient',
        r'\Microsoft\Windows\Feedback\Siuf\DmClientOnScenario',
    ]
    for t in tasks:
        cmd = f'schtasks /Change /TN "{t}" /DISABLE'
        run_command(cmd, log_widget, progress=progress)
    log(log_widget, "[Sistema] Tarefas desativadas.\n", "green")

def apps_background(log_widget, progress=None):
    """Desativa apps em 2º plano"""
    log(log_widget, "[Sistema] Desativando aplicativos em segundo plano...", "yellow")
    export_reg_key(r'HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications', LOG_DIR, log_widget)
    cmd = r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f'
    run_command(cmd, log_widget, progress=progress)
    log(log_widget, "[Sistema] Apps em segundo plano desativados.\n", "green")

# ==========================
# CPU & ENERGIA
# ==========================
def cpu_power(log_widget, progress=None):
    log(log_widget, "[CPU & Energia] Máximo desempenho...", "yellow")
    cmds = [
        'powercfg -setactive SCHEME_MAX',
        'bcdedit /set useplatformclock true',
        'bcdedit /set disabledynamictick yes',
        'bcdedit /set tscsyncpolicy Enhanced',
        'bcdedit /set nx OptOut'
    ]
    for c in cmds:
        run_command(c, log_widget, progress=progress)

    cmds2 = [
        'powercfg -setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 100',
        'powercfg -setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100',
        'powercfg -setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 100',
        'powercfg -setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100',
        'powercfg -setactive SCHEME_CURRENT'
    ]
    for c in cmds2:
        run_command(c, log_widget, progress=progress)

    log(log_widget, "[CPU & Energia] Concluído!\n", "green")
    messagebox.showinfo("CPU & Energia", "Ajustes aplicados!")

def desativar_servicos_basicos(log_widget, progress=None):
    log(log_widget, "[Serviços] Desativando serviços pouco usados...", "yellow")
    cmds = [
        "sc config Spooler start= disabled",
        "sc config Fax start= disabled",
        "sc config RemoteRegistry start= disabled",
        "sc config WMPNetworkSvc start= disabled"
    ]
    for c in cmds:
        run_command(c, log_widget, progress=progress)
    log(log_widget, "[Serviços] Concluído!\n", "green")

# ==========================
# GPU
# ==========================
def gpu_tweaks(log_widget, progress=None):
    log(log_widget, "[GPU] Otimizações (TdrDelay/HwSch/ShaderCache)...", "yellow")
    export_reg_key(r'HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers', LOG_DIR, log_widget)
    export_reg_key(r'HKCU\Software\Microsoft\DirectX\ShaderCache', LOG_DIR, log_widget)
    export_reg_key(r'HKLM\SOFTWARE\Microsoft\DirectX\Diagnostics', LOG_DIR, log_widget)
    cmds = [
        r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v TdrDelay /t REG_DWORD /d 10 /f',
        r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v HwSchMode /t REG_DWORD /d 1 /f',
        r'reg add "HKCU\Software\Microsoft\DirectX\ShaderCache" /v Enabled /t REG_DWORD /d 0 /f',
        r'reg add "HKLM\SOFTWARE\Microsoft\DirectX\Diagnostics" /v DisableHardwareAcceleration /t REG_DWORD /d 0 /f'
    ]
    for c in cmds:
        run_command(c, log_widget, progress=progress)
    log(log_widget, "[GPU] Concluído!\n", "green")
    messagebox.showinfo("GPU", "Tweaks de GPU aplicados!")

def game_mode_on(log_widget, progress=None):
    log(log_widget, "[GPU] Ativando Game Mode...", "yellow")
    export_reg_key(r'HKCU\Software\Microsoft\GameBar', LOG_DIR, log_widget)
    cmds = [
        r'reg add "HKCU\Software\Microsoft\GameBar" /v AutoGameModeEnabled /t REG_DWORD /d 1 /f',
        r'reg add "HKCU\Software\Microsoft\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 1 /f'
    ]
    for c in cmds:
        run_command(c, log_widget, progress=progress)
    log(log_widget, "[GPU] Game Mode ativado.\n", "green")

# ==========================
# REDE
# ==========================
def rede_tweaks(log_widget, progress=None):
    log(log_widget, "[Rede] TCP/Delivery/Serviços...", "yellow")
    export_reg_key(r'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization', LOG_DIR, log_widget)
    export_reg_key(r'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache', LOG_DIR, log_widget)
    export_reg_key(r'HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc', LOG_DIR, log_widget)
    cmds = [
        "netsh int tcp set global autotuninglevel=disabled",
        "netsh int tcp set global rss=enabled",
        "netsh int tcp set global netdma=enabled",
        r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f',
        r'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache" /v Start /t REG_DWORD /d 2 /f',
        r'reg add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc" /v Start /t REG_DWORD /d 2 /f'
    ]
    for c in cmds:
        run_command(c, log_widget, progress=progress)
    log(log_widget, "[Rede] Concluído!\n", "green")
    messagebox.showinfo("Rede", "Tweaks de rede aplicados!")

def flush_dns(log_widget, progress=None):
    log(log_widget, "[Rede] Limpando cache DNS...", "yellow")
    run_command("ipconfig /flushdns", log_widget, progress=progress)
    log(log_widget, "[Rede] Cache DNS limpo.\n", "green")
    messagebox.showinfo("Rede", "Cache DNS limpo com sucesso!")

def reset_winsock(log_widget, progress=None):
    log(log_widget, "[Rede] Reset Winsock/TCPIP...", "yellow")
    cmds = ["netsh winsock reset", "netsh int ip reset"]
    for c in cmds:
        run_command(c, log_widget, progress=progress)
    log(log_widget, "[Rede] Reset concluído (pode exigir reinício).\n", "green")

# ==========================
# VISUAL / INPUT
# ==========================
def input_lag(log_widget, progress=None):
    log(log_widget, "[Input] Mouse/teclado/prioridades...", "yellow")
    export_reg_key(r'HKCU\Control Panel\Mouse', LOG_DIR, log_widget)
    export_reg_key(r'HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl', LOG_DIR, log_widget)
    cmds = [
        r'reg add "HKCU\Control Panel\Mouse" /v MouseSpeed /t REG_SZ /d 0 /f',
        r'reg add "HKCU\Control Panel\Mouse" /v MouseThreshold1 /t REG_SZ /d 0 /f',
        r'reg add "HKCU\Control Panel\Mouse" /v MouseThreshold2 /t REG_SZ /d 0 /f',
        r'reg add "HKCU\Control Panel\Mouse" /v MouseEnhancePointerPrecision /t REG_SZ /d 0 /f',
        r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 26 /f'
    ]
    for c in cmds:
        run_command(c, log_widget, progress=progress)
    log(log_widget, "[Input] Concluído!\n", "green")
    messagebox.showinfo("Input Lag", "Otimizações de input aplicadas!")

def audio_inputlag(log_widget, progress=None):
    log(log_widget, "[Áudio] Reduzindo delay...", "yellow")
    export_reg_key(r'HKCU\Software\Microsoft\Multimedia\Audio', LOG_DIR, log_widget)
    cmds = [
        r'reg add "HKCU\Software\Microsoft\Multimedia\Audio" /v ExclusiveMode /t REG_DWORD /d 1 /f',
        r'reg add "HKCU\Software\Microsoft\Multimedia\Audio" /v DisableEffects /t REG_DWORD /d 1 /f'
    ]
    for c in cmds:
        run_command(c, log_widget, progress=progress)
    log(log_widget, "[Áudio] Concluído!\n", "green")
    messagebox.showinfo("Áudio", "Ajustes de áudio aplicados!")

def desativar_animacoes(log_widget, progress=None):
    log(log_widget, "[Visual] Desativando animações...", "yellow")
    export_reg_key(r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects', LOG_DIR, log_widget)
    cmd = r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f'
    run_command(cmd, log_widget, progress=progress)
    log(log_widget, "[Visual] Animações desativadas.\n", "green")
    messagebox.showinfo("Visual", "Animações visuais desativadas!")

# ==========================
# MANUTENÇÃO
# ==========================
def limpeza_temp(log_widget, progress=None):
    log(log_widget, "[Limpeza] Temporários e logs...", "yellow")
    cmds = [
        r'del /q /f "%TEMP%\*"',
        r'del /q /f "C:\Windows\Prefetch\*"',
        r'del /q /f "C:\Windows\Temp\*"',
        r'del /q /f "C:\Windows\Logs\*"',
        r'cleanmgr /sagerun:1'
    ]
    for c in cmds:
        run_command(c, log_widget, progress=progress)
    log(log_widget, "[Limpeza] Concluído!\n", "green")
    messagebox.showinfo("Limpeza", "Arquivos temporários removidos!")

def otimizar_disco(log_widget, progress=None):
    log(log_widget, "[Disco] Otimizando C:", "yellow")
    cmd = "defrag C: /O /U /V"
    run_command(cmd, log_widget, progress=progress)
    log(log_widget, "[Disco] Concluído!\n", "green")
    messagebox.showinfo("Disco", "Otimização de disco concluída!")

def limpar_cache_microsoft_store(log_widget, progress=None):
    log(log_widget, "[Manutenção] Limpando cache da Microsoft Store...", "yellow")
    cmd = "wsreset.exe"
    run_command(cmd, log_widget, progress=progress)
    log(log_widget, "[Manutenção] Cache da Store limpo.\n", "green")

def limpar_cache_fontes(log_widget, progress=None):
    log(log_widget, "[Manutenção] Limpando cache de fontes...", "yellow")
    cmd = r'del /q /f "%windir%\ServiceProfiles\LocalService\AppData\Local\FontCache\*"'
    run_command(cmd, log_widget, progress=progress)
    log(log_widget, "[Manutenção] Cache de fontes limpo.\n", "green")

# ==========================
# SEGURANÇA (seguros)
# ==========================
def firewall_reset(log_widget, progress=None):
    log(log_widget, "[Segurança] Resetando firewall (padrão)...", "yellow")
    cmd = "netsh advfirewall reset"
    run_command(cmd, log_widget, progress=progress)
    log(log_widget, "[Segurança] Firewall resetado.\n", "green")

def defender_quick_scan(log_widget, progress=None):
    log(log_widget, "[Segurança] Defender Quick Scan...", "yellow")
    cmd = r'powershell -NoProfile -Command "Start-MpScan -ScanType QuickScan"'
    run_command(cmd, log_widget, progress=progress)
    log(log_widget, "[Segurança] Verificação solicitada.\n", "green")

# ==========================
# AVANÇADOS (mexem em regedit/serviços/pacotes)
# ==========================
def desativar_cortana(log_widget, progress=None):
    log(log_widget, "[Avançado] Desativando Cortana...", "yellow")
    export_reg_key(r'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search', LOG_DIR, log_widget)
    cmds = [
        r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f',
        r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f'
    ]
    for c in cmds:
        run_command(c, log_widget, progress=progress)
    log(log_widget, "[Avançado] Cortana desativada.\n", "green")

def desinstalar_onedrive(log_widget, progress=None):
    log(log_widget, "[Avançado] Desativando/Desinstalando OneDrive...", "yellow")
    cmds = [
        r'taskkill /f /im OneDrive.exe',
        r'%SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall',
        r'%SystemRoot%\System32\OneDriveSetup.exe /uninstall',
        r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f',
        r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v DisableFileSync /t REG_DWORD /d 1 /f'
    ]
    for c in cmds:
        run_command(c, log_widget, progress=progress)
    log(log_widget, "[Avançado] OneDrive removido/desativado.\n", "green")

def resetar_spooler_impressao(log_widget, progress=None):
    log(log_widget, "[Avançado] Resetando Spooler de Impressão...", "yellow")
    cmds = [
        "net stop spooler",
        r'del /q /f "%systemroot%\System32\spool\PRINTERS\*"',
        "net start spooler"
    ]
    for c in cmds:
        run_command(c, log_widget, progress=progress)
    log(log_widget, "[Avançado] Spooler resetado.\n", "green")

def smb1_desativar(log_widget, progress=None):
    log(log_widget, "[Avançado] Desativando SMBv1...", "yellow")
    cmds = [
        r'dism /online /norestart /disable-feature /featurename:SMB1Protocol',
        r'reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f'
    ]
    for c in cmds:
        run_command(c, log_widget, progress=progress)
    log(log_widget, "[Avançado] SMBv1 desativado.\n", "green")

def limpar_cache_navegadores(log_widget, progress=None):
    log(log_widget, "[Manutenção] Limpando cache de navegadores (Chrome/Edge/Firefox)...", "yellow")
    base = os.path.expanduser("~")
    # Chrome
    chrome_paths = [
        os.path.join(base, r"AppData\Local\Google\Chrome\User Data\Default\Cache"),
        os.path.join(base, r"AppData\Local\Google\Chrome\User Data\Default\Code Cache"),
        os.path.join(base, r"AppData\Local\Google\Chrome\User Data\Default\GPUCache"),
    ]
    # Edge
    edge_paths = [
        os.path.join(base, r"AppData\Local\Microsoft\Edge\User Data\Default\Cache"),
        os.path.join(base, r"AppData\Local\Microsoft\Edge\User Data\Default\Code Cache"),
        os.path.join(base, r"AppData\Local\Microsoft\Edge\User Data\Default\GPUCache"),
    ]
    # Firefox (limpar cache padrão)
    firefox_cache = os.path.join(base, r"AppData\Local\Mozilla\Firefox\Profiles")
    paths = chrome_paths + edge_paths

    for p in paths:
        if os.path.exists(p):
            try:
                for item in os.listdir(p):
                    fp = os.path.join(p, item)
                    if os.path.isfile(fp):
                        try:
                            if not Config.dry_run:
                                os.remove(fp)
                        except Exception:
                            pass
                    else:
                        try:
                            if not Config.dry_run:
                                shutil.rmtree(fp, ignore_errors=True)
                        except Exception:
                            pass
                log(log_widget, f"[Navegadores] Limpo: {p}", "green")
            except Exception as e:
                log(log_widget, f"[Navegadores] Erro em {p}: {e}", "red")
        else:
            log(log_widget, f"[Navegadores] Pasta não encontrada: {p}", "yellow")

    # Firefox caches em subpastas
    if os.path.exists(firefox_cache):
        try:
            for prof in os.listdir(firefox_cache):
                cache_dir = os.path.join(firefox_cache, prof, "cache2")
                if os.path.exists(cache_dir):
                    try:
                        if not Config.dry_run:
                            shutil.rmtree(cache_dir, ignore_errors=True)
                        log(log_widget, f"[Firefox] cache2 limpo: {cache_dir}", "green")
                    except Exception as e:
                        log(log_widget, f"[Firefox] Erro: {e}", "red")
        except Exception as e:
            log(log_widget, f"[Firefox] Erro no profiles dir: {e}", "red")

    if progress: progress.step(1)
    messagebox.showinfo("Navegadores", "Cache limpo (onde aplicável).")

# ==========================
# WINDOWS UPDATE / DEFENDER (ARRISCADOS)
# ==========================
def windows_update_pausar_long(log_widget, progress=None):
    log(log_widget, "[Update] Pausando Windows Update (longo prazo)...", "yellow")
    export_reg_key(r'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings', LOG_DIR, log_widget)
    cmds = [
        r'reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v PauseFeatureUpdatesStartTime /t REG_SZ /d "2020-01-01T00:00:00Z" /f',
        r'reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v PauseFeatureUpdatesEndTime /t REG_SZ /d "2099-01-01T00:00:00Z" /f',
        r'reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v PauseQualityUpdatesStartTime /t REG_SZ /d "2020-01-01T00:00:00Z" /f',
        r'reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v PauseQualityUpdatesEndTime /t REG_SZ /d "2099-01-01T00:00:00Z" /f'
    ]
    for c in cmds:
        run_command(c, log_widget, progress=progress)
    log(log_widget, "[Update] Pausa aplicada.\n", "green")

def windows_update_desligar_total(log_widget, progress=None):
    """Bloqueio agressivo do Windows Update."""
    log(log_widget, "[Update] DESLIGANDO Windows Update (agressivo)...", "yellow")
    export_reg_key(r'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU', LOG_DIR, log_widget)
    cmds = [
        r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f',
        "sc stop wuauserv",
        "sc config wuauserv start= disabled",
        "sc stop bits",
        "sc config bits start= disabled",
        "sc stop dosvc",
        "sc config dosvc start= disabled",
        "sc stop WaaSMedicSvc",
        "sc config WaaSMedicSvc start= disabled"
    ]
    for c in cmds:
        run_command(c, log_widget, progress=progress)
    log(log_widget, "[Update] Bloqueio pesado aplicado. (Pode quebrar updates/loja)", "green")

def windows_update_reverter(log_widget, progress=None):
    """Restaura Windows Update para automático (tenta desfazer o hard block)."""
    log(log_widget, "[Update] Reativando Windows Update (revertendo)...", "yellow")
    cmds = [
        r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f',
        "sc config wuauserv start= demand",
        "sc start wuauserv",
        "sc config bits start= demand",
        "sc start bits",
        "sc config dosvc start= demand",
        "sc start dosvc",
        "sc config WaaSMedicSvc start= demand",
        "sc start WaaSMedicSvc"
    ]
    for c in cmds:
        run_command(c, log_widget, progress=progress)
    log(log_widget, "[Update] Reativado (pode exigir reinício).", "green")

def defender_desligar_tempo_real(log_widget, progress=None):
    """Desativa proteção em tempo real do Defender via políticas. Arriscado."""
    log(log_widget, "[Defender] DESATIVANDO tempo real (arriscado)...", "yellow")
    export_reg_key(r'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender', LOG_DIR, log_widget)
    export_reg_key(r'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection', LOG_DIR, log_widget)
    cmds = [
        r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f',
        r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f',
        r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f',
        r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f',
        r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f',
        r'net stop WinDefend'
    ]
    for c in cmds:
        run_command(c, log_widget, progress=progress)
    log(log_widget, "[Defender] Tempo real desativado. (Risco de segurança)", "green")

def defender_reativar_tempo_real(log_widget, progress=None):
    log(log_widget, "[Defender] Reativando tempo real...", "yellow")
    cmds = [
        r'reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /f',
        r'reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /f',
        r'reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /f',
        r'reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnAccessProtection /f',
        r'reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableScanOnRealtimeEnable /f',
        r'net start WinDefend'
    ]
    for c in cmds:
        run_command(c, log_widget, progress=progress)
    log(log_widget, "[Defender] Reativado (pode exigir reinício).", "green")

# ==========================
# UAC mínimo (arriscado)
# ==========================
def uac_minimo(log_widget, progress=None):
    log(log_widget, "[Segurança] UAC no mínimo (arriscado)...", "yellow")
    export_reg_key(r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', LOG_DIR, log_widget)
    cmds = [
        r'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f',
        r'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 0 /f'
    ]
    for c in cmds:
        run_command(c, log_widget, progress=progress)
    log(log_widget, "[Segurança] UAC ajustado ao mínimo. (Risco)", "green")

def uac_padroes(log_widget, progress=None):
    log(log_widget, "[Segurança] UAC para padrão...", "yellow")
    cmds = [
        r'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 5 /f',
        r'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f'
    ]
    for c in cmds:
        run_command(c, log_widget, progress=progress)
    log(log_widget, "[Segurança] UAC restaurado (pode exigir logoff).", "green")

# ==========================
# BOOST TOTAL
# ==========================
def boost_total(log_widget, progress=None):
    resp = messagebox.askyesno("Boost Total", 
        "Você está prestes a aplicar TODOS os ajustes (inclui itens avançados/arriscados se clicar depois).\n"
        "Recomendado: criar Ponto de Restauração antes.\n\n"
        "Deseja continuar?")
    if not resp:
        log(log_widget, "[Boost Total] Cancelado.", "red")
        return

    steps = [
        ("Criando ponto de restauração", create_restore_point),
        ("Tweaks de Sistema", sistema_tweaks),
        ("Desativar tarefas de telemetria", tarefas_telemetria),
        ("Desativar apps em 2º plano", apps_background),
        ("CPU & Energia", cpu_power),
        ("Tweaks de GPU", gpu_tweaks),
        ("Ativar Game Mode", game_mode_on),
        ("Otimizações de Rede", rede_tweaks),
        ("Flush DNS", flush_dns),
        ("Reset Winsock/TCPIP", reset_winsock),
        ("Input Lag", input_lag),
        ("Áudio (delay menor)", audio_inputlag),
        ("Desativar animações", desativar_animacoes),
        ("Limpeza temp/logs", limpeza_temp),
        ("Otimizar disco", otimizar_disco),
        ("Cache Microsoft Store", limpar_cache_microsoft_store),
        ("Cache de fontes", limpar_cache_fontes),
        ("Cortana OFF", desativar_cortana),
        ("OneDrive OFF", desinstalar_onedrive),
        ("Spooler reset", resetar_spooler_impressao),
        ("SMBv1 OFF", smb1_desativar),
        ("Cache navegadores", limpar_cache_navegadores),
        ("Firewall reset", firewall_reset),
        ("Defender Quick Scan", defender_quick_scan),
    ]

    total = len(steps)
    pb = ttk.Progressbar(root, length=900, maximum=total, mode='determinate')
    pb.pack(pady=5)
    try:
        for (desc, fn) in steps:
            log(log_widget, f"[Boost Total] {desc}...", "yellow")
            try:
                fn(log_widget, progress=pb)
            except Exception as e:
                log(log_widget, f"Erro em '{desc}': {e}", "red")
                traceback.print_exc()
        log(log_widget, "[Boost Total] Concluído!\n", "green")
        beep_ok()
        messagebox.showinfo("Boost Total", "A execução padrão foi concluída.\nItens ARRISCADOS estão na aba própria.")
    finally:
        pb.destroy()

# ==========================
# Tema (Dark/Light) e UI
# ==========================
def apply_dark_theme(root):
    style = ttk.Style(root)
    style.theme_use("clam")

    bg_main = "#121212"
    bg_card = "#1b1b1b"
    bg_tab = "#1e1e1e"
    bg_tab_sel = "#2e2e2e"
    fg_text = "#ffffff"
    accent = "#00ff88"
    accent_dim = "#00cc70"
    danger = "#ff5555"
    warn = "#ffcc00"

    root.configure(bg=bg_main)
    style.configure("TNotebook", background=bg_main, borderwidth=0)
    style.configure("TNotebook.Tab", background=bg_tab, foreground=fg_text, padding=[18, 9], borderwidth=0)
    style.map("TNotebook.Tab",
              background=[("selected", bg_tab_sel), ("active", bg_tab_sel)],
              foreground=[("selected", accent), ("active", accent)])

    style.configure("Dark.TFrame", background=bg_main)
    style.configure("Card.TFrame", background=bg_card, relief="flat")

    style.configure("Accent.TButton",
                    font=("Segoe UI", 12, "bold"),
                    padding=12,
                    relief="flat",
                    background=bg_tab,
                    foreground=fg_text,
                    borderwidth=0)
    style.map("Accent.TButton",
              background=[("active", accent), ("pressed", accent_dim)],
              foreground=[("active", "#000000"), ("pressed", "#000000")])

    style.configure("Danger.TButton",
                    font=("Segoe UI", 12, "bold"),
                    padding=12,
                    relief="flat",
                    background="#2a1010",
                    foreground="#ffdddd",
                    borderwidth=0)
    style.map("Danger.TButton",
              background=[("active", danger), ("pressed", "#cc4444")],
              foreground=[("active", "#000000"), ("pressed", "#000000")])

    style.configure("Warn.TButton",
                    font=("Segoe UI", 12, "bold"),
                    padding=12,
                    relief="flat",
                    background="#2a2a10",
                    foreground="#fff0c2",
                    borderwidth=0)
    style.map("Warn.TButton",
              background=[("active", warn), ("pressed", "#ccaa00")],
              foreground=[("active", "#000000"), ("pressed", "#000000")])

    style.configure("TProgressbar", troughcolor=bg_tab, background=accent,
                    bordercolor=bg_tab, lightcolor=accent, darkcolor=accent)

    style.configure("Vertical.TScrollbar",
                    background=bg_tab,
                    troughcolor=bg_tab,
                    arrowcolor=fg_text,
                    bordercolor=bg_tab,
                    lightcolor=bg_tab,
                    darkcolor=bg_tab)

    return {
        "bg_main": bg_main,
        "bg_card": bg_card,
        "fg_text": fg_text,
        "accent": accent,
        "danger": danger,
        "warn": warn
    }

def apply_light_theme(root):
    style = ttk.Style(root)
    style.theme_use("clam")

    bg_main = "#f1f1f1"
    bg_card = "#ffffff"
    bg_tab = "#e9e9e9"
    bg_tab_sel = "#dcdcdc"
    fg_text = "#000000"
    accent = "#00875a"
    danger = "#b00020"
    warn = "#b58900"

    root.configure(bg=bg_main)
    style.configure("TNotebook", background=bg_main, borderwidth=0)
    style.configure("TNotebook.Tab", background=bg_tab, foreground=fg_text, padding=[18, 9], borderwidth=0)
    style.map("TNotebook.Tab",
              background=[("selected", bg_tab_sel), ("active", bg_tab_sel)],
              foreground=[("selected", accent), ("active", accent)])

    style.configure("Dark.TFrame", background=bg_main)
    style.configure("Card.TFrame", background=bg_card, relief="flat")

    style.configure("Accent.TButton",
                    font=("Segoe UI", 12, "bold"),
                    padding=12,
                    relief="flat",
                    background=bg_tab,
                    foreground=fg_text,
                    borderwidth=0)
    style.map("Accent.TButton",
              background=[("active", accent), ("pressed", "#006644")],
              foreground=[("active", "#ffffff"), ("pressed", "#ffffff")])

    style.configure("Danger.TButton",
                    font=("Segoe UI", 12, "bold"),
                    padding=12,
                    relief="flat",
                    background="#ffecec",
                    foreground="#8a0000",
                    borderwidth=0)
    style.map("Danger.TButton",
              background=[("active", "#ff6666"), ("pressed", "#cc4444")],
              foreground=[("active", "#000000"), ("pressed", "#000000")])

    style.configure("Warn.TButton",
                    font=("Segoe UI", 12, "bold"),
                    padding=12,
                    relief="flat",
                    background="#fff7e0",
                    foreground="#7a5a00",
                    borderwidth=0)
    style.map("Warn.TButton",
              background=[("active", warn), ("pressed", "#8a6a00")],
              foreground=[("active", "#ffffff"), ("pressed", "#ffffff")])

    style.configure("TProgressbar", troughcolor=bg_tab, background=accent,
                    bordercolor=bg_tab, lightcolor=accent, darkcolor=accent)

    style.configure("Vertical.TScrollbar",
                    background=bg_tab,
                    troughcolor=bg_tab,
                    arrowcolor=fg_text,
                    bordercolor=bg_tab,
                    lightcolor=bg_tab,
                    darkcolor=bg_tab)

    return {
        "bg_main": bg_main,
        "bg_card": bg_card,
        "fg_text": fg_text,
        "accent": accent,
        "danger": danger,
        "warn": warn
    }

def toggle_theme(log_widget):
    Config.theme = "light" if Config.theme == "dark" else "dark"
    rebuild_ui(log_widget)  # Reconstrói a UI para aplicar o tema

# ==========================
# Hotkeys e toggles
# ==========================
def add_hotkeys(root, log_widget):
    root.bind_all("<Control-l>", lambda e: clear_log(log_widget))
    root.bind_all("<Control-L>", lambda e: clear_log(log_widget))
    root.bind_all("<Control-q>", lambda e: root.destroy())
    root.bind_all("<Control-Q>", lambda e: root.destroy())
    root.bind_all("<F1>", lambda e: show_about())

def show_about():
    messagebox.showinfo("Sobre", f"{APP_NAME} {APP_VERSION}\nAutor: {AUTHOR}\n\n"
                                 "Ferramenta de otimização para Windows.\n"
                                 "Use com cautela e por sua conta e risco.\n"
                                 "Recomendo criar Ponto de Restauração.")

def toggle_dry_run(var_state, log_widget):
    Config.dry_run = bool(var_state.get())
    state = "ON (simulação)" if Config.dry_run else "OFF"
    log(log_widget, f"[Config] Dry-run: {state}", "yellow")

def toggle_confirm_each(var_state, log_widget):
    Config.confirm_each = bool(var_state.get())
    state = "ON (confirmar cada comando)" if Config.confirm_each else "OFF"
    log(log_widget, f"[Config] Confirmar cada: {state}", "yellow")

def toggle_show_cmd_output(var_state, log_widget):
    Config.show_cmd_output = bool(var_state.get())
    state = "ON (mostrar stdout)" if Config.show_cmd_output else "OFF"
    log(log_widget, f"[Config] STDOUT no log: {state}", "yellow")

def toggle_backup_reg(var_state, log_widget):
    Config.backup_reg = bool(var_state.get())
    state = "ON (exportar .reg)" if Config.backup_reg else "OFF"
    log(log_widget, f"[Config] Backup de registro: {state}", "yellow")

# ==========================
# Layout de botões helper
# ==========================
def make_button(parent, text, cmd, style="Accent.TButton"):
    b = ttk.Button(parent, text=text, style=style, command=cmd)
    return b

def pack_buttons_grid(frame, buttons, cols=3):
    row, col = 0, 0
    for btn in buttons:
        btn.grid(row=row, column=col, padx=12, pady=12, sticky="nsew")
        col += 1
        if col >= cols:
            col = 0
            row += 1
    for c in range(cols):
        frame.grid_columnconfigure(c, weight=1)

# ==========================
# Barras de menu
# ==========================
def build_menubar(root, log_widget):
    menubar = tk.Menu(root)

    # Arquivo
    m_file = tk.Menu(menubar, tearoff=0)
    m_file.add_command(label="Exportar Log...", command=lambda: export_log_as_txt(log_widget))
    m_file.add_command(label="Abrir Pasta de Logs", command=open_log_folder)
    m_file.add_separator()
    m_file.add_command(label="Sair (Ctrl+Q)", command=root.destroy)
    menubar.add_cascade(label="Arquivo", menu=m_file)

    # Ferramentas
    m_tools = tk.Menu(menubar, tearoff=0)
    m_tools.add_command(label="Criar Ponto de Restauração", command=lambda: threading.Thread(target=create_restore_point, args=(log_widget,)).start())
    m_tools.add_command(label="Abrir CMD como Admin", command=open_cmd_admin)
    m_tools.add_command(label="Abrir Regedit", command=open_regedit)
    m_tools.add_separator()
    m_tools.add_command(label="Tema: Alternar Dark/Light", command=lambda: toggle_theme(log_widget))
    menubar.add_cascade(label="Ferramentas", menu=m_tools)

    # Ajuda
    m_help = tk.Menu(menubar, tearoff=0)
    m_help.add_command(label="Sobre (F1)", command=show_about)
    m_help.add_command(label="Guia Rápido", command=lambda: messagebox.showinfo("Guia",
        "1) Rode como ADMIN.\n2) Faça Ponto de Restauração.\n3) Use Dry-run para simular.\n4) Aplique tweaks por abas.\n5) Itens ARRISCADOS na aba própria.\n6) Reinicie se necessário."))
    menubar.add_cascade(label="Ajuda", menu=m_help)

    root.config(menu=menubar)

# ==========================
# Construção/Rebuild de UI
# ==========================
def rebuild_ui(prev_log_widget=None):
    global root
    try:
        old_geo = root.geometry()
    except Exception:
        old_geo = "1280x900"
    root.destroy()

    # Recria janela
    root = tk.Tk()
    root.title(f"{APP_NAME} {APP_VERSION}")
    root.geometry(old_geo)

    if Config.theme == "dark":
        theme = apply_dark_theme(root)
    else:
        theme = apply_light_theme(root)

    # Barra de menu
    # Será construída depois do log para passar referência do widget
    # Criamos log primeiro:
    log_frame = ttk.Frame(root, style="Card.TFrame")
    log_frame.pack(fill="both", expand=False, padx=12, pady=(12, 0))

    log_label = tk.Label(log_frame, text="LOG", fg=theme["accent"], bg=theme["bg_card"], font=("Segoe UI", 12, "bold"))
    log_label.pack(anchor="w", padx=12, pady=(10, 0))

    log_text = scrolledtext.ScrolledText(
        log_frame, width=160, height=16,
        bg="#0d0d0d" if Config.theme == "dark" else "#ffffff",
        fg="white" if Config.theme == "dark" else "#000000",
        insertbackground="white" if Config.theme == "dark" else "#000000",
        font=("Consolas", 10), borderwidth=0
    )
    log_text.tag_config("red", foreground=theme["danger"])
    log_text.tag_config("green", foreground="#55ff55" if Config.theme == "dark" else "#008000")
    log_text.tag_config("yellow", foreground=theme["warn"])
    log_text.tag_config("white", foreground=theme["fg_text"])
    log_text.pack(fill="both", expand=True, padx=12, pady=12)

    # Menubar agora com referência ao log
    build_menubar(root, log_text)

    # Barra de toggles/ações rápidas
    bar = ttk.Frame(root, style="Dark.TFrame")
    bar.pack(fill="x", padx=12, pady=8)

    var_dry = tk.BooleanVar(value=Config.dry_run)
    var_cfe = tk.BooleanVar(value=Config.confirm_each)
    var_out = tk.BooleanVar(value=Config.show_cmd_output)
    var_bkp = tk.BooleanVar(value=Config.backup_reg)

    cb_dry = ttk.Checkbutton(bar, text="Dry-run (simular)", style="Accent.TButton",
                              command=lambda: toggle_dry_run(var_dry, log_text), variable=var_dry)
    cb_cfe = ttk.Checkbutton(bar, text="Confirmar cada", style="Accent.TButton",
                              command=lambda: toggle_confirm_each(var_cfe, log_text), variable=var_cfe)
    cb_out = ttk.Checkbutton(bar, text="Mostrar stdout", style="Accent.TButton",
                              command=lambda: toggle_show_cmd_output(var_out, log_text), variable=var_out)
    cb_bkp = ttk.Checkbutton(bar, text="Backup .reg", style="Accent.TButton",
                              command=lambda: toggle_backup_reg(var_bkp, log_text), variable=var_bkp)

    btn_copy = make_button(bar, "Copiar Log", lambda: copy_log_to_clipboard(log_text))
    btn_open_log = make_button(bar, "Abrir Pasta de Logs", open_log_folder)
    btn_about = make_button(bar, "Sobre (F1)", show_about)

    for w in [cb_dry, cb_cfe, cb_out, cb_bkp, btn_copy, btn_open_log, btn_about]:
        w.pack(side="left", padx=6, pady=4)

    # Notebook
    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    # --------- SISTEMA ---------
    tab_sistema = ttk.Frame(notebook, style="Dark.TFrame"); notebook.add(tab_sistema, text="Sistema")
    frm_sis = ttk.Frame(tab_sistema, style="Card.TFrame"); frm_sis.pack(fill="both", expand=True, padx=8, pady=8)
    pack_buttons_grid(frm_sis, [
        make_button(frm_sis, "Criar Ponto de Restauração", lambda: threading.Thread(target=create_restore_point, args=(log_text,)).start()),
        make_button(frm_sis, "Tweaks de Sistema", lambda: threading.Thread(target=sistema_tweaks, args=(log_text,)).start()),
        make_button(frm_sis, "Tarefas de Telemetria (OFF)", lambda: threading.Thread(target=tarefas_telemetria, args=(log_text,)).start()),
        make_button(frm_sis, "Apps em 2º Plano (OFF)", lambda: threading.Thread(target=apps_background, args=(log_text,)).start()),
    ], cols=3)

    # --------- CPU & ENERGIA ---------
    tab_cpu = ttk.Frame(notebook, style="Dark.TFrame"); notebook.add(tab_cpu, text="CPU & Energia")
    frm_cpu = ttk.Frame(tab_cpu, style="Card.TFrame"); frm_cpu.pack(fill="both", expand=True, padx=8, pady=8)
    pack_buttons_grid(frm_cpu, [
        make_button(frm_cpu, "CPU & Energia (Máx)", lambda: threading.Thread(target=cpu_power, args=(log_text,)).start()),
        make_button(frm_cpu, "Serviços Básicos (OFF)", lambda: threading.Thread(target=desativar_servicos_basicos, args=(log_text,)).start()),
    ], cols=3)

    # --------- GPU ---------
    tab_gpu = ttk.Frame(notebook, style="Dark.TFrame"); notebook.add(tab_gpu, text="GPU")
    frm_gpu = ttk.Frame(tab_gpu, style="Card.TFrame"); frm_gpu.pack(fill="both", expand=True, padx=8, pady=8)
    pack_buttons_grid(frm_gpu, [
        make_button(frm_gpu, "Ativar Game Mode", lambda: threading.Thread(target=game_mode_on, args=(log_text,)).start()),
        make_button(frm_gpu, "Tweaks de GPU", lambda: threading.Thread(target=gpu_tweaks, args=(log_text,)).start()),
    ], cols=3)

    # --------- REDE ---------
    tab_net = ttk.Frame(notebook, style="Dark.TFrame"); notebook.add(tab_net, text="Rede")
    frm_net = ttk.Frame(tab_net, style="Card.TFrame"); frm_net.pack(fill="both", expand=True, padx=8, pady=8)
    pack_buttons_grid(frm_net, [
        make_button(frm_net, "Otimizações TCP/Delivery", lambda: threading.Thread(target=rede_tweaks, args=(log_text,)).start()),
        make_button(frm_net, "Flush DNS", lambda: threading.Thread(target=flush_dns, args=(log_text,)).start()),
        make_button(frm_net, "Reset Winsock/TCPIP", lambda: threading.Thread(target=reset_winsock, args=(log_text,)).start()),
    ], cols=3)

    # --------- VISUAL & INPUT ---------
    tab_visual = ttk.Frame(notebook, style="Dark.TFrame"); notebook.add(tab_visual, text="Visual & Input")
    frm_vis = ttk.Frame(tab_visual, style="Card.TFrame"); frm_vis.pack(fill="both", expand=True, padx=8, pady=8)
    pack_buttons_grid(frm_vis, [
        make_button(frm_vis, "Input Lag (Mouse/Teclado)", lambda: threading.Thread(target=input_lag, args=(log_text,)).start()),
        make_button(frm_vis, "Áudio: Delay menor", lambda: threading.Thread(target=audio_inputlag, args=(log_text,)).start()),
        make_button(frm_vis, "Desativar Animações", lambda: threading.Thread(target=desativar_animacoes, args=(log_text,)).start()),
    ], cols=3)

    # --------- MANUTENÇÃO ---------
    tab_maint = ttk.Frame(notebook, style="Dark.TFrame"); notebook.add(tab_maint, text="Manutenção")
    frm_maint = ttk.Frame(tab_maint, style="Card.TFrame"); frm_maint.pack(fill="both", expand=True, padx=8, pady=8)
    pack_buttons_grid(frm_maint, [
        make_button(frm_maint, "Limpeza Temp/Logs", lambda: threading.Thread(target=limpeza_temp, args=(log_text,)).start()),
        make_button(frm_maint, "Otimizar Disco (C:)", lambda: threading.Thread(target=otimizar_disco, args=(log_text,)).start()),
        make_button(frm_maint, "Cache Microsoft Store", lambda: threading.Thread(target=limpar_cache_microsoft_store, args=(log_text,)).start()),
        make_button(frm_maint, "Cache de Fontes", lambda: threading.Thread(target=limpar_cache_fontes, args=(log_text,)).start()),
        make_button(frm_maint, "Cache Navegadores", lambda: threading.Thread(target=limpar_cache_navegadores, args=(log_text,)).start()),
        make_button(frm_maint, "Spooler (reset)", lambda: threading.Thread(target=resetar_spooler_impressao, args=(log_text,)).start()),
    ], cols=3)

    # --------- AVANÇADO ---------
    tab_adv = ttk.Frame(notebook, style="Dark.TFrame"); notebook.add(tab_adv, text="Avançado")
    frm_adv = ttk.Frame(tab_adv, style="Card.TFrame"); frm_adv.pack(fill="both", expand=True, padx=8, pady=8)
    pack_buttons_grid(frm_adv, [
        make_button(frm_adv, "Cortana OFF", lambda: threading.Thread(target=desativar_cortana, args=(log_text,)).start()),
        make_button(frm_adv, "OneDrive OFF", lambda: threading.Thread(target=desinstalar_onedrive, args=(log_text,)).start()),
        make_button(frm_adv, "SMBv1 OFF", lambda: threading.Thread(target=smb1_desativar, args=(log_text,)).start()),
    ], cols=3)

    # --------- ARRISCADOS (vermelho) ---------
    tab_risk = ttk.Frame(notebook, style="Dark.TFrame"); notebook.add(tab_risk, text="ARRISCADOS")
    frm_risk = ttk.Frame(tab_risk, style="Card.TFrame"); frm_risk.pack(fill="both", expand=True, padx=8, pady=8)
    risk_buttons = [
        ttk.Button(frm_risk, text="UAC Mínimo (RISCO)", style="Danger.TButton",
                   command=lambda: threading.Thread(target=uac_minimo, args=(log_text,)).start()),
        ttk.Button(frm_risk, text="UAC Padrão (Desfazer)", style="Warn.TButton",
                   command=lambda: threading.Thread(target=uac_padroes, args=(log_text,)).start()),
        ttk.Button(frm_risk, text="Defender OFF (Tempo Real)", style="Danger.TButton",
                   command=lambda: threading.Thread(target=defender_desligar_tempo_real, args=(log_text,)).start()),
        ttk.Button(frm_risk, text="Defender ON (Reativar)", style="Warn.TButton",
                   command=lambda: threading.Thread(target=defender_reativar_tempo_real, args=(log_text,)).start()),
        ttk.Button(frm_risk, text="Windows Update OFF (Hard)", style="Danger.TButton",
                   command=lambda: threading.Thread(target=windows_update_desligar_total, args=(log_text,)).start()),
        ttk.Button(frm_risk, text="Windows Update ON (Desfazer)", style="Warn.TButton",
                   command=lambda: threading.Thread(target=windows_update_reverter, args=(log_text,)).start()),
    ]
    pack_buttons_grid(frm_risk, risk_buttons, cols=2)

    # --------- GERAL ---------
    tab_all = ttk.Frame(notebook, style="Dark.TFrame"); notebook.add(tab_all, text="Geral")
    frm_all = ttk.Frame(tab_all, style="Card.TFrame"); frm_all.pack(fill="both", expand=True, padx=8, pady=8)
    pack_buttons_grid(frm_all, [
        make_button(frm_all, "BOOST TOTAL (padrão)", lambda: threading.Thread(target=boost_total, args=(log_text,)).start()),
        make_button(frm_all, "Limpar LOG (Ctrl+L)", lambda: clear_log(log_text)),
        make_button(frm_all, "Alternar Tema (Menu/Ferramentas)", lambda: toggle_theme(log_text)),
        make_button(frm_all, "Sair (Ctrl+Q)", lambda: root.destroy()),
    ], cols=3)

    # Mensagens
    log(log_text, f"Bem-vindo ao {APP_NAME} {APP_VERSION}", "yellow", typing_effect=True)
    log(log_text, "Rode como ADMIN. Crie um Ponto de Restauração antes de tweaks agressivos.", "yellow")
    log(log_text, f"Logs em: {LOG_FILE}", "white")

    add_hotkeys(root, log_text)

# ==========================
# MAIN
# ==========================
def main():
    global root
    if not is_admin():
        messagebox.showerror("Erro", "Execute o programa como ADMINISTRADOR!")
        sys.exit(1)

    # Janela base
    root = tk.Tk()
    root.title(f"{APP_NAME} {APP_VERSION}")
    root.geometry("1280x900")

    # Tema inicial
    apply_dark_theme(root) if Config.theme == "dark" else apply_light_theme(root)

    # Reconstrói com tudo montado
    rebuild_ui(None)

    root.mainloop()

# ================
# ENTRY POINT
# ================
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        beep_err()
        try:
            messagebox.showerror("Erro fatal", str(e))
        except Exception:
            print("Erro fatal:", e)
        raise
