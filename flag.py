import socket
import struct
import time

def decode_all_packets(data):
    """Décode tous les paquets CCSDS dans les données"""
    pos = 0
    packets = []
    
    while pos + 6 <= len(data):
        # Lire en-tête
        word1 = struct.unpack('>H', data[pos:pos+2])[0]
        apid = word1 & 0x07FF
        
        word2 = struct.unpack('>H', data[pos+2:pos+4])[0]
        seq_count = word2 & 0x3FFF
        
        pkt_length = struct.unpack('>H', data[pos+4:pos+6])[0]
        total_length = 6 + pkt_length + 1  # CCSDS: pkt_length = data_length - 1
        
        if pos + total_length > len(data):
            break  # Paquet incomplet
        
        pkt_data = data[pos+6:pos+total_length]
        
        packets.append({
            'apid': apid,
            'seq': seq_count,
            'length': pkt_length,
            'data': pkt_data,
            'raw_header': data[pos:pos+6]
        })
        
        pos += total_length
    
    return packets, pos  # Retourne aussi la position traitée

def try_decode_flags(data):
    """Essaie de décoder les données comme des flags 7-bit"""
    flags = []
    bit_buffer = 0
    bit_count = 0
    
    for byte in data:
        bit_buffer = (bit_buffer << 8) | byte
        bit_count += 8
        
        while bit_count >= 7:
            flag_value = (bit_buffer >> (bit_count - 7)) & 0x7F
            flags.append(flag_value)
            bit_count -= 7
            bit_buffer &= (1 << bit_count) - 1
    
    # Convertir en ASCII
    ascii_flags = ''.join(chr(f) if 32 <= f < 127 else '.' for f in flags)
    return flags, ascii_flags

def get_flag_interactive():
    """Interaction ciblée pour obtenir le flag"""
    host = "80.211.133.33"
    port = 8123
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect((host, port))
    
    print("Connexion établie. Envoi de commandes...\n")
    
    # 1. Envoyer FLAG pour avoir le paquet APID 102
    sock.send(b"FLAG\n")
    time.sleep(1)
    response = sock.recv(4096)
    
    print(f"Réponse à FLAG ({len(response)} octets):")
    
    # Afficher en hex
    for i in range(0, len(response), 16):
        hex_line = ' '.join(f'{b:02x}' for b in response[i:i+8])
        hex_line2 = ' '.join(f'{b:02x}' for b in response[i+8:i+16])
        ascii_line = ''.join(chr(b) if 32 <= b < 127 else '.' for b in response[i:i+16])
        print(f"{i:04x}: {hex_line:<23} {hex_line2:<23} {ascii_line}")
    
    # Décoder tous les paquets
    packets, pos = decode_all_packets(response)
    
    print(f"\n{len(packets)} paquet(s) détecté(s):")
    
    for i, pkt in enumerate(packets):
        print(f"\nPaquet {i}: APID={pkt['apid']}, Seq={pkt['seq']}, Données={len(pkt['data'])} octets")
        
        # Afficher les données en hex
        hex_data = ' '.join(f'{b:02x}' for b in pkt['data'][:20])
        if len(pkt['data']) > 20:
            hex_data += " ..."
        print(f"  Données: {hex_data}")
        
        # Si c'est un paquet FLAG (APID 102)
        if pkt['apid'] == 102:
            print("  → C'est un paquet FLAG !")
            
            # Essayer le décodage 7-bit
            flags, ascii_flags = try_decode_flags(pkt['data'])
            print(f"  Décodage 7-bit: {len(flags)} valeurs")
            print(f"  ASCII: {ascii_flags[:100]}")
            
            # Vérifier si contient FLAG{
            if "FLAG{" in ascii_flags:
                print(f"\n🎉 FLAG TROUVÉ: {ascii_flags}")
                # Extraire le flag complet
                start = ascii_flags.find("FLAG{")
                end = ascii_flags.find("}", start)
                if end > start:
                    flag = ascii_flags[start:end+1]
                    print(f"\n🔑 FLAG COMPLET: {flag}")
                    return flag
    
    # 2. Essayer d'autres commandes si pas trouvé
    commands = [
        ("GETFLAG\n", "GETFLAG"),
        ("SEND_FLAG\n", "SEND_FLAG"),
        ("DEBUG\n", "DEBUG"),
        ("DUMP\n", "DUMP"),
        ("ALL\n", "ALL"),

    ]
    
    for cmd, name in commands:
        print(f"\n--- Essai: {name} ---")
        sock.send(cmd.encode())
        time.sleep(1)
        resp = sock.recv(4096)
        
        if resp:
            packets, _ = decode_all_packets(resp)
            for pkt in packets:
                if pkt['apid'] == 102:
                    flags, ascii_flags = try_decode_flags(pkt['data'])
                    if "FLAG{" in ascii_flags:
                        start = ascii_flags.find("FLAG{")
                        end = ascii_flags.find("}", start)
                        flag = ascii_flags[start:end+1]
                        print(f"\n🎉 FLAG TROUVÉ avec {name}: {flag}")
                        sock.close()
                        return flag
    
    sock.close()
    print("\nAucun flag trouvé dans les réponses standard.")
    return None

# Deuxième approche: analyser les données brutes différemment
def brute_force_search():
    """Cherche le flag par analyse brutale"""
    host = "80.211.133.33"
    port = 8123
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    
    # Collecter toutes les réponses
    all_data = b""
    
    # Essayer plusieurs commandes
    test_cmds = [b"FLAG\n", b"GETFLAG\n", b"HELP\n", b"STATUS\n", b"\n"]
    
    for cmd in test_cmds:
        sock.send(cmd)
        time.sleep(1)
        resp = sock.recv(4096)
        all_data += resp
    
    sock.close()
    
    print(f"Données totales collectées: {len(all_data)} octets")
    
    # Chercher FLAG{ dans les données brutes
    for i in range(len(all_data) - 5):
        # Chercher "FLAG{" en ASCII
        if all_data[i:i+5] == b"FLAG{":
            end = i + 5
            while end < len(all_data) and all_data[end] != ord("}"):
                end += 1
            if end < len(all_data):
                flag = all_data[i:end+1].decode('ascii')
                print(f"\n🎉 FLAG TROUVÉ par recherche brute: {flag}")
                return flag
        
        # Chercher en hex inverse (petit-boutiste)
        if all_data[i:i+5] == b"{GALF":
            # C'est "FLAG{" inversé (little-endian?)
            potential = all_data[i:i+50]
            print(f"Pattern inversé trouvé à {i}: {potential}")
    
    # Essayer tous les offsets de 7-bit
    print("\nEssai de tous les décalages 7-bit...")
    for offset in range(7):
        bits = ""
        for byte in all_data[:100]:
            bits += format(byte, '08b')
        
        # Prendre à partir de l'offset
        bits = bits[offset:]
        
        # Convertir groupes de 7 bits en ASCII
        chars = ""
        for j in range(0, len(bits) - 6, 7):
            byte_val = int(bits[j:j+7], 2)
            if 32 <= byte_val < 127:
                chars += chr(byte_val)
            else:
                chars += "."
        
        if "FLAG{" in chars:
            start = chars.find("FLAG{")
            end = chars.find("}", start)
            if end > start:
                flag = chars[start:end+1]
                print(f"Flag avec offset {offset}: {flag}")
                return flag
    
    return None

# Exécution
if __name__ == "__main__":
    print("=" * 60)
    print("METHODE 1: Analyse structurée")
    print("=" * 60)
    flag = get_flag_interactive()
    
    if not flag:
        print("\n" + "=" * 60)
        print("METHODE 2: Recherche brute")
        print("=" * 60)
        flag = brute_force_search()
    
    if flag:
        print(f"\n✅ SUCCÈS: {flag}")
    else:
        print("\n❌ Aucun flag trouvé avec les méthodes actuelles.")
        print("Suggestions:")
        print("1. Le flag pourrait être dans un APID différent")
        print("2. Il faut peut-être envoyer une commande spécifique")
        print("3. Le décodage 7-bit pourrait avoir un ordre différent")
