import socketio
#python -m pip install python-socketio, requests, websocket-client
import threading

class ChatroomClient:
    def __init__(self, url="192.168.1.16:3000", sender="Anonymous"):
        self.url = "http://"+url
        self.sender = sender
        self.sio = socketio.Client()
        self.messages = []
        self.connected = False
        
        # Register event handlers
        self.sio.on('connect', self.on_connect)
        self.sio.on('disconnect', self.on_disconnect)
        self.sio.on('message', self.on_message)
    
    def on_connect(self):
        self.connected = True
        print(f"Connected to chatroom as {self.sender}")
        print("Type your messages below (Ctrl+C to exit):")
    
    def on_disconnect(self):
        print("\nDisconnected from chatroom")
    
    def on_message(self, data):
        """Called when a message is received"""
        # Don't print your own messages twice
        if data['sender'] != self.sender:
            print(f"\r[{data['sender']}]: {data['text']}")
            print("> ", end="", flush=True)
        self.messages.append(data)
    
    def connect(self):
        """Connect to the Socket.IO server"""
        try:
            self.sio.connect(self.url)
            self.sio.emit("join", self.sender)
        except Exception as e:
            print(f"Connection failed: {e}")
    
    def send_message(self, text):
        """Send a message to the chatroom"""
        if self.connected:
            msg = {
                "sender": self.sender,
                "text": text
            }
            self.sio.emit('message', msg)
    
    def show_history(self):
        """Display all stored messages"""
        print("\n--- Chat History ---")
        for msg in self.messages:
            print(f"[{msg['sender']}]: {msg['text']}")
        print("--- End History ---\n")
    
    def disconnect(self):
        """Disconnect from the server"""
        if self.connected:
            self.sio.emit('exit')
            #self.sio.disconnect()
            self.connected = False


if __name__ == "__main__":
    sender = input("Enter your name: ").strip() or "Anonymous"
    ip = input("Ingresa la dirección IP del chatroom: ").strip()
    client = ChatroomClient(sender=sender, url=ip)
    client.connect()
    
    try:
        while True:
            text = input("> ")
            if text.strip():
                if text == "/history":
                    client.show_history()
                else:
                    client.send_message(text)
    except KeyboardInterrupt:
        client.disconnect()