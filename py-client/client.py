import socketio
#python -m pip install python-socketio, requests, websocket-client
from prompt_toolkit import PromptSession, print_formatted_text
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.formatted_text import FormattedText



class ChatroomClient:
    def __init__(self, url="192.168.1.16:3000", sender="Anonymous", color='fg:green'):
        self.url = "http://"+url
        self.sender = sender
        self.sio = socketio.Client()
        self.messages = []
        self.connected = False
        self.color = color
        
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
        """Al recibir un mensaje, printearlo con el color apropiado"""
        fragments = FormattedText([
            (data['color'], f'[{data['sender']}]: '),
            ('fg:white', f'{data['text']}')
        ])
        print_formatted_text(fragments)
        #self.messages.append(data)
    
    def connect(self):
        """Connect to the Socket.IO server"""
        try:
            self.sio.connect(self.url)
            self.sio.emit("connect", self.sender)
        except Exception as e:
            print(f"Connection failed: {e}")

    def disconnect(self):
        """Disconnect from the server"""
        if self.connected:
            self.sio.disconnect()
            self.connected = False
    
    def send_message(self, text):
        """Send a message to the chatroom"""
        if self.connected:
            msg = {
                "sender": self.sender,
                "text": text,
                "color": self.color
            }
            self.sio.emit('message', msg)
    
    def show_history(self):
        """Display all stored messages"""
        print("\n--- Chat History ---")
        for msg in self.messages:
            print(f"[{msg['sender']}]: {msg['text']}")
        print("--- End History ---\n")

#funcion auxiliar para definir el color del usuario 
def pick_color():
    colors = {
        "0": "green",
        "1": "cyan",
        "2": "purple",
        "3": "pink",
        "4": "yellow"
    }

    print(f"Elija un color. Sus opciones son:")
    options = []
    for i in range(len(colors)):
        color = colors[str(i)]
        options.append((f'fg:{color}', f'   ({i}) {color}\n'))
    fragments = FormattedText(options)
    print_formatted_text(fragments)
    opt = input("Ingrese el número: ")

    return f"fg:{colors.get(opt, "green")}"

if __name__ == "__main__":
    # Recibir nombre e ip
    sender = input("Enter your name: ").strip() or "Anonymous"
    ip = input("Ingresa la dirección IP del chatroom: ").strip()

    # Instanciar el cliente
    client = ChatroomClient(sender=sender, url=ip, color=pick_color())
    client.connect()
    
    # Usar prompt_toolkit para evitar que se pierda lo que lleva escrito el usuario al recibir mensajes del server
    session = PromptSession()
    try:
        with patch_stdout():
            while True:

                text = session.prompt("> ")

                if text.strip():
                    if text == "/history":
                        client.show_history()
                    else:
                        client.send_message(text)

    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        client.disconnect()
