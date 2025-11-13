use axum::{
    routing::{Router, get},
    serve
}; // pa las rutas y esas cosas
use socketioxide::{
    extract::{Data, SocketRef}, //extractores para manejar los datos de los sockets
    SocketIo // TODO: que es una capa???????
};
use tracing::info; //logging y esas cosas
use tracing_subscriber::FmtSubscriber;
use serde::{Deserialize, Serialize}; //manejo de JSON

#[derive(Serialize, Deserialize, Clone)]
struct ChatMsg {
    sender: String,
    text: String,
}

#[tokio::main]
async  fn main(){
    //cosa para las INFO y tal
    tracing::subscriber::set_global_default(FmtSubscriber::default()).unwrap();
    info!("Booting up...");

    //TODO: busca q es una capa y como funciona lol porfavor
    let (sock_layer, io) = SocketIo::new_layer();

    //io.namespace define las funciones que se ejecutan en un path dependiendo de eventos.
    //cada evento es un nombre y una funcion handler
    io.ns("/", async |s: SocketRef| {
        s.on("join", on_join);
        s.on("message", on_new_msg);
        s.on_disconnect(on_quit);
    });
    
    //una app de Axum se define como una serie de rutas. (por ahora es solo '/'),
    //y a esta app se le añade una capa de SocketIo para que sirva el chat
    let app = Router::new()
        .route("/", get(connection_handler))
        .layer(sock_layer);

    //Para servir la app toca definir un TcpListener en una direccion,
    // 0.0.0.0 significa q escucha en cualquier direccion
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    serve(listener, app).await.unwrap();
}

// ---------------- HANDLERS DE EVENTOS ----------------
async fn on_join(sock: SocketRef) {
    info!("Client connected: {}", sock.id);
}

async fn on_new_msg(sock: SocketRef, Data(msg):Data<ChatMsg>) {
    info!("MENSAJE: {}//[{}]: {}", sock.id, &msg.sender, &msg.text);
    sock.broadcast()
        .emit("message", &msg).await.ok();
}

async fn on_quit(sock: SocketRef) {
    info!("Client disconnected: {}", sock.id);
}

async fn connection_handler() -> &'static str{
    "Será será será"
}
