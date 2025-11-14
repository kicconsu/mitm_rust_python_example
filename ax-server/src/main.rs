mod state_models;
use crate::state_models::*; 
//Importar los modelos usados para el estado del chat
//por ahora solo son ChatMsg y un ChatState q guarda un diccionario de id: nombre (users)

use axum::{
    routing::{Router, get},
    serve
}; // pa las rutas y esas cosas

use socketioxide::{
    extract::{Data, SocketRef, State}, //extractores para manejar los datos de los sockets
    SocketIo // TODO: que es una capa???????
};
use tracing::info; //logging y esas cosas
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async  fn main(){
    //cosa para las INFO y tal
    tracing::subscriber::set_global_default(FmtSubscriber::default()).unwrap();
    info!("Booting up...");

    let chat_state = ChatState::new();

    //TODO: busca q es una capa y como funciona lol porfavor
    let (sock_layer, io) = SocketIo::builder().with_state(chat_state).build_layer();

    //io.namespace define las funciones que se ejecutan en un path dependiendo de eventos.
    //cada evento es un nombre y una funcion handler
    io.ns("/", async |s: SocketRef| {
        //s.on("connect", on_connect);//por defecto
        s.on("message", on_new_msg);//por defecto
        s.on("join", emit_join); // registrar usuario y anunciar su llegada
        s.on("exit", emit_exit);
        //s.on_disconnect(on_disc); //por defecto
    });
    
    //una app de Axum se define como una serie de rutas. (por ahora es solo '/'),
    //y a esta app se le añade una capa de SocketIo para que sirva el chat
    let app = Router::new()
        .route("/", get(connection_handler))
        .with_state(io)
        .layer(sock_layer);

    //Para servir la app toca definir un TcpListener en una direccion,
    // 0.0.0.0 significa q escucha en cualquier direccion
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    serve(listener, app).await.unwrap();
}

// ---------------- HANDLERS DE EVENTOS ----------------
async fn on_connect(_sock: SocketRef) {
    info!("Socket llegando...");
}

async fn on_disc(_sock: SocketRef) {
    info!("Socket saliendo...")
}

async fn emit_join(sock: SocketRef, Data(name):Data<String>, State(chat_state):State<ChatState>) {
    //Se abre un bloque{} de codigo para usar el users_dict solo por el tiempo necesario
    {
        let mut users = chat_state.users.lock().unwrap();
        users.insert(sock.id.to_string(), name.clone());
        info!("usuarios: {:?}", &users);
    }
    
    info!("Client connected: {}::[{}]", sock.id, name);

    let msg= ChatMsg { 
        sender: "[SERVER]".to_string(),
        text: format!("{} se ha unido al chatroom.", name)
    };
    sock.broadcast()
    .emit("message", &msg)
    .await.ok();
}

async fn emit_exit(sock: SocketRef, State(chat_state):State<ChatState>){
    
    let username:String;

    {
        let mut users = chat_state.users.lock().unwrap();
        username = users.remove(sock.id.as_str()).unwrap();
    }

    info!("Client disconnected: {}::[{}]", sock.id, &username);

    let msg = ChatMsg {
        sender: "[SERVER]".to_string(),
        text: format!("{} ha salido del chat.", {username})
    };
    sock.broadcast()
        .emit("message", &msg)
        .await.ok();

}

async fn on_new_msg(sock: SocketRef, Data(msg):Data<ChatMsg>) {
    info!("MENSAJE: {}//[{}]: {}", sock.id, &msg.sender, &msg.text);
    sock.broadcast()
        .emit("message", &msg).await.ok();
}

async fn connection_handler() -> &'static str{
    "Será será será"
}
