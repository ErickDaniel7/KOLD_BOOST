import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import threading
from datetime import datetime
import ctypes
import time
import os
import winsound
import psutil
import wmi

# ===================================================
# Funções auxiliares
# ===================================================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def beep():
    winsound.MessageBeep()

def log(widget, text, color="white", typing_effect=False):
    timestamp = datetime.now().strftime("[%H:%M:%S] ")
    widget.configure(state='normal')
    if typing_effect:
        for char in timestamp + text + "\n":
            widget.insert(tk.END, char)
            widget.tag_add(color, f"{widget.index('end')} -1c", tk.END)
            widget.update()
            time.sleep(0.005)
    else:
        widget.insert(tk.END, timestamp + text + "\n")
        widget.tag_add(color, f"{widget.index('end')} -1c linestart", tk.END)
    widget.see(tk.END)
    widget.configure(state='disabled')

def run_command(cmd, log_widget=None, progress=None):
    try:
        if log_widget:
            log(log_widget, f"Executando: {cmd}", "yellow")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, errors='replace')
        output = result.stdout.strip()
        if log_widget:
            if result.returncode == 0:
                log(log_widget, "Ok.", "green")
            else:
                log(log_widget, f"Erro: {output}", "red")
        if progress:
            progress.step(1)
    except Exception as e:
        if log_widget:
            log(log_widget, f"Erro: {str(e)}", "red")

def clear_log(widget):
    widget.configure(state='normal')
    widget.delete(1.0, tk.END)
    widget.configure(state='disabled')

# ===================================================
# Funções de Tweaks
# ===================================================
def sistema(log_widget, progress=None):
    log(log_widget, "[Sistema] Aplicando tweaks avançados...", "yellow")
    cmds = [
        'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f',
        'reg add "HKCU\\System\\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f',
        'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\PushNotifications" /v ToastEnabled /t REG_DWORD /d 0 /f',
        'reg add "HKCU\\Software\\Policies\\Microsoft\\Windows\\Explorer" /v DisableNotificationCenter /t REG_DWORD /d 1 /f',
        'sc config DiagTrack start= disabled',
        'sc config WSearch start= disabled',
        'sc config SysMain start= disabled',
        'sc config XblAuthManager start= disabled',
        'sc config XblGameSave start= disabled',
        'sc config XboxGipSvc start= disabled',
        'sc config MapsBroker start= disabled',
        'sc config RetailDemo start= disabled',
        'sc config PeopleSvc start= disabled',
        'sc config PhoneSvc start= disabled'
    ]
    for cmd in cmds:
        run_command(cmd, log_widget, progress)
    log(log_widget, "[Sistema] Tweaks concluídos!\n", "green")
    messagebox.showinfo("Sistema", "Tweaks do sistema aplicados!")

def cpu(log_widget, progress=None):
    log(log_widget, "[CPU & Energia] Aplicando otimizações para máximo desempenho...", "yellow")
    cmds = [
        'powercfg -setactive SCHEME_MAX',
        'bcdedit /set useplatformclock true',
        'bcdedit /set disabledynamictick yes',
        'bcdedit /set tscsyncpolicy Enhanced',
        'bcdedit /set nx OptOut'
    ]
    for cmd in cmds:
        run_command(cmd, log_widget, progress)
    log(log_widget, "[CPU & Energia] Concluído!\n", "green")
    messagebox.showinfo("CPU & Energia", "Ajustes de CPU e energia aplicados!")

def gpu(log_widget, progress=None):
    log(log_widget, "[GPU] Aplicando otimizações KOLD BOOST...", "yellow")
    cmds = [
        'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers" /v TdrDelay /t REG_DWORD /d 10 /f',
        'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers" /v HwSchMode /t REG_DWORD /d 1 /f',
        'reg add "HKCU\\Software\\Microsoft\\DirectX\\ShaderCache" /v Enabled /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Microsoft\\DirectX\\Diagnostics" /v DisableHardwareAcceleration /t REG_DWORD /d 0 /f'
    ]
    for cmd in cmds:
        run_command(cmd, log_widget, progress)
    log(log_widget, "[GPU] Concluído!\n", "green")
    messagebox.showinfo("GPU", "Tweaks de GPU aplicados!")

def input_opt(log_widget, progress=None):
    log(log_widget, "[Input Lag] Otimizando mouse e teclado...", "yellow")
    cmds = [
        'reg add "HKCU\\Control Panel\\Mouse" /v MouseSpeed /t REG_SZ /d 0 /f',
        'reg add "HKCU\\Control Panel\\Mouse" /v MouseThreshold1 /t REG_SZ /d 0 /f',
        'reg add "HKCU\\Control Panel\\Mouse" /v MouseThreshold2 /t REG_SZ /d 0 /f',
        'reg add "HKCU\\Control Panel\\Mouse" /v MouseEnhancePointerPrecision /t REG_SZ /d 0 /f',
        'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 26 /f'
    ]
    for cmd in cmds:
        run_command(cmd, log_widget, progress)
    log(log_widget, "[Input Lag] Concluído!\n", "green")
    messagebox.showinfo("Input Lag", "Otimizações de mouse e teclado aplicadas!")

def rede(log_widget, progress=None):
    log(log_widget, "[Rede] Aplicando tweaks KOLD BOOST...", "yellow")
    cmds = [
        "netsh int tcp set global autotuninglevel=disabled",
        "netsh int tcp set global rss=enabled",
        "netsh int tcp set global netdma=enabled",
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache" /v Start /t REG_DWORD /d 2 /f',
        'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NlaSvc" /v Start /t REG_DWORD /d 2 /f'
    ]
    for cmd in cmds:
        run_command(cmd, log_widget, progress)
    log(log_widget, "[Rede] Concluído!\n", "green")
    messagebox.showinfo("Rede", "Tweaks de rede aplicados!")

def limpeza(log_widget, progress=None):
    log(log_widget, "[Limpeza] Removendo arquivos temporários e realizando limpeza de disco...", "yellow")
    cmds = [
        'del /q /f %TEMP%\\*',
        'del /q /f C:\\Windows\\Prefetch\\*',
        'del /q /f C:\\Windows\\Temp\\*',
        'del /q /f C:\\Windows\\Logs\\*',
        'cleanmgr /sagerun:1'
    ]
    for cmd in cmds:
        run_command(cmd, log_widget, progress)
    log(log_widget, "[Limpeza] Concluído!\n", "green")
    messagebox.showinfo("Limpeza", "Arquivos temporários e limpeza de disco concluídos!")

def audio_inputlag(log_widget, progress=None):
    log(log_widget, "[Audio] Reduzindo input lag...", "yellow")
    cmds = [
        'reg add "HKCU\\Software\\Microsoft\\Multimedia\\Audio" /v ExclusiveMode /t REG_DWORD /d 1 /f',
        'reg add "HKCU\\Software\\Microsoft\\Multimedia\\Audio" /v DisableEffects /t REG_DWORD /d 1 /f'
    ]
    for cmd in cmds:
        run_command(cmd, log_widget, progress)
    log(log_widget, "[Audio] Concluído!\n", "green")
    messagebox.showinfo("Audio", "Input lag de áudio reduzido!")

# ===================================================
# Boost Total KOLD BOOST
# ===================================================
def boost_total(log_widget):
    resposta = messagebox.askyesno("Boost Total", 
        "Você está prestes a aplicar todos os tweaks do KOLD BOOST.\n\n"
        "Recomendamos criar um ponto de restauração do Windows antes de continuar.\n\n"
        "Deseja continuar?")
    if resposta:
        total_steps = 20
        progress = ttk.Progressbar(root, length=800, maximum=total_steps, mode='determinate')
        progress.pack(pady=5)
        log(log_widget, "[Boost Total] Iniciando ...", "yellow", typing_effect=True)
        sistema(log_widget, progress)
        cpu(log_widget, progress)
        gpu(log_widget, progress)
        input_opt(log_widget, progress)
        rede(log_widget, progress)
        limpeza(log_widget, progress)
        audio_inputlag(log_widget, progress)
        log(log_widget, "[Boost Total] Concluído!\n", "green", typing_effect=True)
        messagebox.showinfo("Boost Total", "Todos os tweaks foram aplicados com sucesso!")
        progress.destroy()
    else:
        log(log_widget, "[Boost Total] Cancelado pelo usuário.\n", "red", typing_effect=True)

# ===================================================
# Monitoramento em tempo real
# ===================================================
def monitoramento(status_labels):
    c = wmi.WMI(namespace="root\\wmi")
    while True:
        # CPU %
        cpu_percent = psutil.cpu_percent(interval=1)
        status_labels['cpu'].config(text=f"CPU: {cpu_percent}%")

        # RAM %
        ram = psutil.virtual_memory()
        status_labels['ram'].config(text=f"RAM: {ram.percent}%")

        # CPU Temp (via WMI)
        try:
            temps = c.MSAcpi_ThermalZoneTemperature()
            if temps:
                # temperatura em Celsius
                cpu_temp = sum([t.CurrentTemperature for t in temps]) / len(temps)
                cpu_temp = (cpu_temp / 10.0) - 273.15
                status_labels['cpu_temp'].config(text=f"CPU Temp: {cpu_temp:.1f}°C")
            else:
                status_labels['cpu_temp'].config(text="CPU Temp: N/A")
        except:
            status_labels['cpu_temp'].config(text="CPU Temp: N/A")

        # GPU Temp
        try:
            # Tenta NVIDIA
            result = subprocess.run("nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader,nounits",
                                    shell=True, capture_output=True, text=True)
            gpu_temp = result.stdout.strip()
            if gpu_temp:
                status_labels['gpu_temp'].config(text=f"GPU Temp: {gpu_temp}°C")
            else:
                # Tenta Intel/AMD via WMI
                c2 = wmi.WMI(namespace="root\\OpenHardwareMonitor")
                gpus = c2.Sensor()
                temp_found = False
                for sensor in gpus:
                    if sensor.SensorType == u'Temperature' and 'GPU' in sensor.Name:
                        status_labels['gpu_temp'].config(text=f"GPU Temp: {sensor.Value:.1f}°C")
                        temp_found = True
                        break
                if not temp_found:
                    status_labels['gpu_temp'].config(text="GPU Temp: N/A")
        except:
            status_labels['gpu_temp'].config(text="GPU Temp: N/A")

        # Ping confiável
        try:
            ping_result = subprocess.run("ping 8.8.8.8 -n 1", shell=True, capture_output=True, text=True)
            latency = "N/A"
            for line in ping_result.stdout.splitlines():
                if "tempo" in line.lower() or "time=" in line.lower():
                    latency = ''.join(filter(lambda x: x.isdigit() or x=='.', line.split('=')[-1]))
                    break
            status_labels['ping'].config(text=f"Ping: {latency} ms")
        except:
            status_labels['ping'].config(text="Ping: N/A")

        time.sleep(1.5)

# ===================================================
# Sair
# ===================================================
def sair():
    messagebox.showinfo("Obrigado!", "🙏 Obrigado por usar o KOLD BOOST!")
    root.destroy()

# ===================================================
# Interface
# ===================================================
def main():
    global root
    if not is_admin():
        messagebox.showerror("Erro", "Execute o programa como ADMINISTRADOR!")
        return

    root = tk.Tk()
    root.title("KOLD BOOST")
    root.geometry("1200x780")
    root.configure(bg="#1b1b1b")

    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("TButton", font=("Segoe UI", 12, "bold"), padding=10, relief="flat", background="#2e2e2e", foreground="white")
    style.map("TButton", background=[('active', '#4e4e4e')])

    # Log
    log_text = scrolledtext.ScrolledText(root, width=160, height=32, bg="#121212", fg="white", insertbackground="white", font=("Consolas", 10))
    log_text.tag_config("red", foreground="red")
    log_text.tag_config("green", foreground="lime")
    log_text.tag_config("yellow", foreground="yellow")
    log_text.pack(pady=10)

    # Boas-vindas detalhada
    log(log_text, "Bem-vindo ao KOLD BOOST!\n", "yellow", typing_effect=True)
    log(log_text, "Aplicando otimizações profundas para performance máxima em games.\n", "yellow", typing_effect=True)
    log(log_text, "Crie um ponto de restauração antes de aplicar qualquer otimização.\n", "yellow", typing_effect=True)
    log(log_text, "Todos os logs serão exibidos aqui.\n\n", "yellow", typing_effect=True)

    # Frame de Status
    frame_status = tk.Frame(root, bg="#1b1b1b")
    frame_status.pack(pady=10)
    status_labels = {
        'cpu': tk.Label(frame_status, text="CPU: N/A", fg="white", bg="#1b1b1b", font=("Consolas", 12)),
        'ram': tk.Label(frame_status, text="RAM: N/A", fg="white", bg="#1b1b1b", font=("Consolas", 12)),
        'cpu_temp': tk.Label(frame_status, text="CPU Temp: N/A", fg="white", bg="#1b1b1b", font=("Consolas", 12)),
        'gpu_temp': tk.Label(frame_status, text="GPU Temp: N/A", fg="white", bg="#1b1b1b", font=("Consolas", 12)),
        'ping': tk.Label(frame_status, text="Ping: N/A", fg="white", bg="#1b1b1b", font=("Consolas", 12))
    }
    col = 0
    for key in status_labels:
        status_labels[key].grid(row=0, column=col, padx=15)
        col += 1

    # Inicia monitoramento em thread separada
    threading.Thread(target=monitoramento, args=(status_labels,), daemon=True).start()

    # Botões
    frame_buttons = tk.Frame(root, bg="#1b1b1b")
    frame_buttons.pack(pady=10)

    buttons = [
        ("Boost Total", lambda: threading.Thread(target=boost_total, args=(log_text,)).start()),
        ("Otimização Sistema", lambda: threading.Thread(target=sistema, args=(log_text,)).start()),
        ("Otimização CPU & Energia", lambda: threading.Thread(target=cpu, args=(log_text,)).start()),
        ("Otimização GPU", lambda: threading.Thread(target=gpu, args=(log_text,)).start()),
        ("Input Lag teclado/mouse", lambda: threading.Thread(target=input_opt, args=(log_text,)).start()),
        ("Otimização Rede", lambda: threading.Thread(target=rede, args=(log_text,)).start()),
        ("Limpeza", lambda: threading.Thread(target=limpeza, args=(log_text,)).start()),
        ("Audio", lambda: threading.Thread(target=audio_inputlag, args=(log_text,)).start()),
        ("Clear Log", lambda: clear_log(log_text)),
        ("Sair", sair)
    ]

    row = 0
    col = 0
    for (text, cmd) in buttons:
        b = ttk.Button(frame_buttons, text=text, command=cmd)
        b.grid(row=row, column=col, padx=12, pady=12, sticky="nsew")
        col += 1
        if col > 3:
            col = 0
            row += 1

    root.mainloop()

# ===================================================
if __name__ == "__main__":
    main()
