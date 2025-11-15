use std::{collections::HashMap, sync::{Arc, Mutex}};
use serde::{Deserialize, Serialize}; //manejo de JSON

//Struct para des-serializar los mensajes entrantes y serializar los salientes.
#[derive(Serialize, Deserialize, Clone)]
pub struct ChatMsg {
    pub sender: String,
    pub text: String,
    pub color:String,
}
impl ChatMsg{
    pub fn make_server_msg(text:String) -> ChatMsg {
        ChatMsg {
            sender: "[SERVER]".to_string(),
            text:text,
            color: "fg:white".to_string()
        }
    }
}

// Estado compartido para: saber qué usuario está en cada socket (for now)
#[derive(Clone, Debug)]
pub struct ChatState {
    pub users: Arc<Mutex<HashMap<String, String>>>, // sock.id -> username
    //la manera en la q se usan estas estructuras Arc<Mutex<...>> es q
    //inicias un bloque{} de codigo en el cual obtienes el lock() de la variable.
    //esto te permite modificarla unicamente en el hilo actual.
    //una vez se termina el bloque{}, el lock se libera, y otro hilo podrá obtenerlo.
}
impl ChatState {
    pub fn new() -> Self {
        Self {
            users: Arc::new(Mutex::new(HashMap::new()))
        }
    }
}