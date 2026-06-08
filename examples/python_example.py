import ctypes
import os
import sys
import time


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LIBRARY_NAMES = {
    "win32": "grclib.dll",
    "darwin": "grclib.dylib",
}
DLL_PATH = os.path.join(ROOT, "bin", LIBRARY_NAMES.get(sys.platform, "grclib.so"))


class RCServer(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char_p),
        ("ip", ctypes.c_char_p),
        ("port", ctypes.c_int),
        ("players", ctypes.c_int),
        ("language", ctypes.c_char_p),
        ("description", ctypes.c_char_p),
    ]


RC_OnConnected = ctypes.CFUNCTYPE(None, ctypes.c_void_p)
RC_OnDisconnected = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_void_p)
RC_OnMessage = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_void_p)
RC_OnPrivateMessage = ctypes.CFUNCTYPE(
    None, ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p
)
RC_OnServerData = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p)


def text(value):
    return value.decode("latin-1", errors="ignore") if value else ""


def main():
    if not os.path.exists(DLL_PATH):
        raise SystemExit("Build grclib first with CMake: cmake --build build --config Release")

    if len(sys.argv) < 6:
        raise SystemExit("usage: python python_example.py <list-host> <list-port> <account> <password> <server-index>")

    list_host = sys.argv[1].encode("latin-1")
    list_port = int(sys.argv[2])
    account = sys.argv[3].encode("latin-1")
    password = sys.argv[4].encode("latin-1")
    server_index = int(sys.argv[5])

    rc = ctypes.CDLL(DLL_PATH)
    rc.rc_connect.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p]
    rc.rc_connect.restype = ctypes.c_void_p
    rc.rc_get_servers.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(RCServer))]
    rc.rc_get_servers.restype = ctypes.c_int
    rc.rc_connect_to_server.argtypes = [ctypes.c_void_p, ctypes.c_int]
    rc.rc_connect_to_server.restype = ctypes.c_int
    rc.rc_is_authenticated.argtypes = [ctypes.c_void_p]
    rc.rc_is_authenticated.restype = ctypes.c_int
    rc.rc_process_events.argtypes = [ctypes.c_void_p]
    rc.rc_disconnect.argtypes = [ctypes.c_void_p]
    rc.rc_last_error.argtypes = [ctypes.c_void_p]
    rc.rc_last_error.restype = ctypes.c_char_p
    rc.rc_execute.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    rc.rc_execute.restype = ctypes.c_int
    rc.rc_send_private_message.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p]
    rc.rc_send_private_message.restype = ctypes.c_int

    def on_connected(user_data):
        print("authenticated")

    def on_disconnected(reason, user_data):
        print("disconnected:", text(reason))

    def on_rc_chat(message, user_data):
        print("[rc]", text(message))

    def on_pm(player_id, sender_account, sender_nick, message, user_data):
        sender = text(sender_nick) or text(sender_account) or "player {}".format(player_id)
        print("[pm] {}: {}".format(sender, text(message)))

    def on_server_data(data_type, content, user_data):
        print("[{}] {}".format(text(data_type), text(content)))

    callbacks = [
        RC_OnConnected(on_connected),
        RC_OnDisconnected(on_disconnected),
        RC_OnMessage(on_rc_chat),
        RC_OnPrivateMessage(on_pm),
        RC_OnServerData(on_server_data),
    ]

    rc.rc_on_connected.argtypes = [ctypes.c_void_p, RC_OnConnected, ctypes.c_void_p]
    rc.rc_on_disconnected.argtypes = [ctypes.c_void_p, RC_OnDisconnected, ctypes.c_void_p]
    rc.rc_on_message.argtypes = [ctypes.c_void_p, RC_OnMessage, ctypes.c_void_p]
    rc.rc_on_private_message.argtypes = [ctypes.c_void_p, RC_OnPrivateMessage, ctypes.c_void_p]
    rc.rc_on_server_data.argtypes = [ctypes.c_void_p, RC_OnServerData, ctypes.c_void_p]

    handle = rc.rc_connect(list_host, list_port, account, password)
    if not handle:
        raise SystemExit("rc_connect failed")

    try:
        servers = ctypes.POINTER(RCServer)()
        count = rc.rc_get_servers(handle, ctypes.byref(servers))
        print("servers:", count)
        for index in range(min(count, 10)):
            server = servers[index]
            print("[{}] {} ({} players)".format(index, text(server.name), server.players))

        rc.rc_on_connected(handle, callbacks[0], None)
        rc.rc_on_disconnected(handle, callbacks[1], None)
        rc.rc_on_message(handle, callbacks[2], None)
        rc.rc_on_private_message(handle, callbacks[3], None)
        rc.rc_on_server_data(handle, callbacks[4], None)

        if not rc.rc_connect_to_server(handle, server_index):
            raise RuntimeError(text(rc.rc_last_error(handle)))

        while not rc.rc_is_authenticated(handle):
            rc.rc_process_events(handle)
            time.sleep(0.05)

        rc.rc_execute(handle, b"/opencomments")
        end = time.time() + 10
        while time.time() < end:
            rc.rc_process_events(handle)
            time.sleep(0.05)
    finally:
        rc.rc_disconnect(handle)


if __name__ == "__main__":
    main()
