
import subprocess
import time
import sys
import os
import signal
import threading
import urllib.request
import json
import select
import tty
import termios

GREEN = '\033[92m'
BLUE = '\033[94m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
CYAN = '\033[96m'

SERVER_PROCESS = None
LOG_FILE = "server.log"
SERVER_PORT = 5002

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    clear_screen()
    print(f"{BLUE}╔════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BLUE}║         Network Analyzer - CLI Manager                         ║{RESET}")
    print(f"{BLUE}╚════════════════════════════════════════════════════════════════╝{RESET}")
    print("")
    print(f"🌐 {CYAN}Web Dashboard:{RESET} http://127.0.0.1:{SERVER_PORT}/")
    print("")

def start_server(host="127.0.0.1", port=5002):
    global SERVER_PROCESS, SERVER_PORT
    SERVER_PORT = port
    
    print(f"{YELLOW}Starting server on {host}:{port}...{RESET}")
    
    # Open log file
    log_fd = open(LOG_FILE, "w")
    
    # Start process
    cmd = [sys.executable, "-m", "network_analyzer", "--web", "--host", host, "--port", str(port)]
    
    try:
        SERVER_PROCESS = subprocess.Popen(
            cmd,
            stdout=log_fd,
            stderr=subprocess.STDOUT,
            cwd=os.getcwd()
        )
        time.sleep(2) # Give it a moment to start
        
        # Check if it died immediately
        if SERVER_PROCESS.poll() is not None:
             print(f"{RED}Server failed to start. Check {LOG_FILE} for details.{RESET}")
             return False
             
        print(f"{GREEN}Server running in background (PID: {SERVER_PROCESS.pid}){RESET}")
        return True
    except Exception as e:
        print(f"{RED}Error starting server: {e}{RESET}")
        return False

def save_logs():
    print(f"{YELLOW}Auto-saving logs to JSON...{RESET}")
    try:
        url = f"http://127.0.0.1:{SERVER_PORT}/api/system/save_logs"
        req = urllib.request.Request(url, method='POST')
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            print(f"{GREEN}Logs saved to: {data.get('path', 'unknown')}{RESET}")
    except Exception as e:
        print(f"{RED}Could not trigger auto-save (Server might be down): {e}{RESET}")

def stop_server():
    global SERVER_PROCESS
    if SERVER_PROCESS:
        print(f"{YELLOW}Stopping server...{RESET}")
        SERVER_PROCESS.terminate()
        try:
            SERVER_PROCESS.wait(timeout=5)
        except subprocess.TimeoutExpired:
            SERVER_PROCESS.kill()
        SERVER_PROCESS = None
        print(f"{GREEN}Server stopped.{RESET}")

def is_key_pressed():
    return select.select([sys.stdin], [], [], 0) == ([sys.stdin], [], [])

def get_char():
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch

def view_logs_delayed():
    print(f"{YELLOW}Preparing logs...{RESET}")
    print(f"{CYAN}Press 'o' to open immediately, or wait 20 seconds.{RESET}\n")
    
    # Network animation frames
    frames = [
        "  [PC] ─────→ ◉ ─────→ [SERVER]",
        "  [PC] ──────→ ◉ ────→ [SERVER]",
        "  [PC] ───────→ ◉ ───→ [SERVER]",
        "  [PC] ────────→ ◉ ──→ [SERVER]",
        "  [PC] ─────────→ ◉ ─→ [SERVER]",
        "  [PC] ──────────→ ◉ → [SERVER]",
        "  [PC] ───────────→ ◉  [SERVER]",
        "  [PC] ────────────→ ◉ [SERVER]",
        "  [PC]  ◉ ←───────────  [SERVER]",
        "  [PC] ← ◉ ──────────── [SERVER]",
        "  [PC] ←─ ◉ ─────────── [SERVER]",
        "  [PC] ←── ◉ ────────── [SERVER]",
        "  [PC] ←─── ◉ ───────── [SERVER]",
        "  [PC] ←──── ◉ ──────── [SERVER]",
        "  [PC] ←───── ◉ ─────── [SERVER]",
        "  [PC] ←────── ◉ ────── [SERVER]",
    ]
    
    # 20 second delay with animation
    try:
        for i in range(20, 0, -1):
            frame = frames[(20 - i) % len(frames)]
            sys.stdout.write(f"\r{CYAN}{frame}{RESET}  {YELLOW}[{i}s]{RESET}  {GREEN}Press 'o' to skip{RESET}")
            sys.stdout.flush()
            if is_key_pressed():
                ch = get_char()
                if ch.lower() == 'o':
                    print(f"\n{GREEN}Skipped!{RESET}\n")
                    break
            time.sleep(1)
        else:
            print(f"\n{GREEN}Ready!{RESET}\n")
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Cancelled.{RESET}")
        return

    print(f"{YELLOW}Streaming logs (Press Ctrl+C to return to menu)...{RESET}")
    print(f"{BLUE}{'-'*60}{RESET}")
    try:
        # Use tail -f to follow the file
        subprocess.run(["tail", "-f", LOG_FILE])
    except KeyboardInterrupt:
        # Catch Ctrl+C and do NOT exit, just return
        print(f"\n{BLUE}{'-'*60}{RESET}")
        print(f"{YELLOW}Stopped viewing logs. Server is still running.{RESET}")
        time.sleep(1)
        pass

def show_menu():
    while True:
        print_banner()
        if SERVER_PROCESS and SERVER_PROCESS.poll() is None:
            print(f"Status: {GREEN}RUNNING{RESET}")
        else:
            print(f"Status: {RED}STOPPED{RESET}")
            
        print("")
        print(f"[1] Start Server (if stopped)")
        print(f"[2] View Live Logs")
        print(f"[3] Stop Server & Exit")
        print("")
        
        choice = input(f"{BLUE}Select an option > {RESET}")
        
        if choice == '1':
            if SERVER_PROCESS and SERVER_PROCESS.poll() is None:
                print("Server is already running.")
                time.sleep(1)
            else:
                start_server(port=SERVER_PORT)
                input("Press Enter to continue...")
        elif choice == '2':
            if os.path.exists(LOG_FILE):
                view_logs_delayed()
            else:
                print("No log file found.")
                time.sleep(1)
        elif choice == '3':
            stop_server()
            break
        else:
            print("Invalid option")
            time.sleep(0.5)

def main():
    # Handle clean exit on Ctrl+C at menu level
    # Note: SIGINT in view_logs_delayed is handled locally by try/except KeyboardInterrupt
    
    # Auto-start server on port 5002
    if start_server(port=5002):
        try:
            show_menu()
        except KeyboardInterrupt:
            # Fallback if Ctrl+C pressed in menu input
            print("\nExiting...")
        finally:
            stop_server()
    else:
        print("Failed to initialize.")

if __name__ == "__main__":
    main()
