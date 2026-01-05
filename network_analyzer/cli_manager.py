
import subprocess
import time
import sys
import os
import threading

IS_WINDOWS = os.name == 'nt'

if not IS_WINDOWS:
    import select
    import tty
    import termios

GREEN = '\033[92m'
BLUE = '\033[94m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
CYAN = '\033[96m'

if IS_WINDOWS:
    GREEN = BLUE = YELLOW = RED = RESET = CYAN = ''

SERVER_PROCESS = None
LOG_FILE = "server.log"
SERVER_PORT = 5002

def clear_screen():
    os.system('cls' if IS_WINDOWS else 'clear')

def print_banner():
    clear_screen()
    print(f"{BLUE}╔════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BLUE}║         Network Analyzer - CLI Manager                         ║{RESET}")
    print(f"{BLUE}╚════════════════════════════════════════════════════════════════╝{RESET}")
    print("")
    print(f"Web Dashboard: http://127.0.0.1:{SERVER_PORT}/")
    print("")

def start_server(host="127.0.0.1", port=5002):
    global SERVER_PROCESS, SERVER_PORT
    SERVER_PORT = port
    
    print(f"{YELLOW}Starting server on {host}:{port}...{RESET}")
    
    log_fd = open(LOG_FILE, "w")
    
    cmd = [sys.executable, "-m", "network_analyzer", "--web", "--host", host, "--port", str(port)]
    
    try:
        SERVER_PROCESS = subprocess.Popen(
            cmd,
            stdout=log_fd,
            stderr=subprocess.STDOUT,
            cwd=os.getcwd()
        )
        time.sleep(2)
        
        if SERVER_PROCESS.poll() is not None:
             print(f"{RED}Server failed to start. Check {LOG_FILE} for details.{RESET}")
             return False
             
        print(f"{GREEN}Server running in background (PID: {SERVER_PROCESS.pid}){RESET}")
        return True
    except Exception as e:
        print(f"{RED}Error starting server: {e}{RESET}")
        return False

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

def is_key_pressed_unix():
    return select.select([sys.stdin], [], [], 0) == ([sys.stdin], [], [])

def get_char_unix():
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
    
    if IS_WINDOWS:
        print(f"{CYAN}Press Enter to view logs, or wait 5 seconds.{RESET}")
        time.sleep(5)
    else:
        print(f"{CYAN}Press 'o' to open immediately, or wait 20 seconds.{RESET}")
        try:
            for i in range(20, 0, -1):
                sys.stdout.write(f"\rLoading logs in {i}s... [Press 'o' to skip]")
                sys.stdout.flush()
                if is_key_pressed_unix():
                    ch = get_char_unix()
                    if ch.lower() == 'o':
                        break
                time.sleep(1)
            print("\n")
        except KeyboardInterrupt:
            print(f"\n{YELLOW}Cancelled.{RESET}")
            return

    print(f"{YELLOW}Streaming logs (Press Ctrl+C to return to menu)...{RESET}")
    print(f"{BLUE}{'-'*60}{RESET}")
    try:
        if IS_WINDOWS:
            subprocess.run(["powershell", "-Command", f"Get-Content -Path {LOG_FILE} -Wait"])
        else:
            subprocess.run(["tail", "-f", LOG_FILE])
    except KeyboardInterrupt:
        print(f"\n{BLUE}{'-'*60}{RESET}")
        print(f"{YELLOW}Stopped viewing logs. Server is still running.{RESET}")
        time.sleep(1)

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
    if start_server(port=5002):
        try:
            show_menu()
        except KeyboardInterrupt:
            print("\nExiting...")
        finally:
            stop_server()
    else:
        print("Failed to initialize.")

if __name__ == "__main__":
    main()
