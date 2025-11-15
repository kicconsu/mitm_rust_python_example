## Setup

Instalar scapy como dependencia global, o con virtualenv: 

```bash
python3 -m venv arp-venv
source arp-venv/bin/activate

pip install scapy
```

---

## Configuración extra
### 1. OS

Se recomienda una maquina virtual de Linux, y configurar el adaptador de red en modo *Bridge*.
Esto permite a la VM actuar como un dispositivo independiente en la red, con direccionamiento propio.

### 2. Interfaz de red

```bash
ip a # Comúnmente: enp0s3, eth0, wlan0
```

### 3. IP forwarding

Para que el ataque no interrumpa la comunicacion victima-router: 
```bash
sudo sysctl -w net.ipv4.ip_forward=1

# Verificar
cat /proc/sys/net/ipv4/ip_forward
```

**Nota:** El script puede hacer esto automáticamente con la flag `--enable-forwarding`, pero ha de revertirse manualmente, con este metodo

---

##  Uso 

Por favor referirse a

```bash
sudo python3 spoofer.py -h
```
