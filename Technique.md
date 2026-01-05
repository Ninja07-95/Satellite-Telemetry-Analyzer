# Processus de Développement : Du XTCE au Code Exécutable

## 📋 Table des Matières

- [Analyse du Fichier XTCE](#1-analyse-du-fichier-xtce)
- [Compréhension du Standard CCSDS](#2-compréhension-du-standard-ccsds)
- [Implémentation du Décodage CCSDS](#3-implémentation-du-décodage-ccsds)
- [Algorithme de Décodage 7-bit](#4-algorithme-de-décodage-7-bit)
- [Stratégie d'Interaction avec le Serveur](#5-stratégie-dinteraction-avec-le-serveur)
- [Méthodes de Débogage et Validation](#6-méthodes-de-débogage-et-validation)
- [Résumé du Workflow](#-résumé-du-workflow)

---

## 1. Analyse du Fichier XTCE

### 1.1 Structure Globale

```xml
<xtce:SpaceSystem name="Challenge1">
  <xtce:TelemetryMetaData>
    <!-- 3 sections principales -->
    <xtce:ParameterTypeSet>   <!-- Types de données -->
    <xtce:ParameterSet>       <!-- Paramètres concrets -->
    <xtce:ContainerSet>       <!-- Structure des paquets -->
  </xtce:TelemetryMetaData>
</xtce:SpaceSystem>
```

### 1.2 Types de Données Identifiés

Type	Taille	Signé	Usage
7BitInteger	7 bits	Non	Paramètres FLAG (x120)
TempType	16 bits	Oui	Température batterie
VoltageType	16 bits	Non	Tension batterie
PWR_STATUS	1 bit	-	États ON/OFF

### 1.3 Structure des Paquets FLAG

```xml

<xtce:SequenceContainer name="Flag Packet">
  <xtce:BaseContainer containerRef="AbstractTM Packet Header">
    <xtce:RestrictionCriteria>
      <xtce:Comparison parameterRef="CCSDS_APID" value="102"/>
    </xtce:RestrictionCriteria>
  </xtce:BaseContainer>
  <xtce:EntryList>
    <!-- 120 entrées FLAG1 à FLAG120 -->
    <xtce:ParameterRefEntry parameterRef="FLAG1"/>
    <!-- ... -->
    <xtce:ParameterRefEntry parameterRef="FLAG120"/>
  </xtce:EntryList>
</xtce:SequenceContainer>
```

Observations clés :

    APID 102 = Paquet FLAG

    120 paramètres de 7 bits chacun

    Total bits : 120 × 7 = 840 bits

    En octets : 840 ÷ 8 = 105 octets

## 2. Compréhension du Standard CCSDS
### 2.1 Format d'En-tête CCSDS
```text

Octets 0-1 (16 bits): [ VVV T S AAAAAAAAAAA ]
  VVV (3 bits): Version (généralement 0)
  T   (1 bit): Type (0=télémétrie, 1=commande)
  S   (1 bit): Secondary Header Flag
  AAAAAAAAAAA (11 bits): APID (0-2047)

Octets 2-3 (16 bits): [ SS SSSSSSSSSSSSSS ]
  SS (2 bits): Sequence Flags
  SSSSSSSSSSSSSS (14 bits): Sequence Count

Octets 4-5 (16 bits): [ LLLLLLLLLLLLLLLL ]
  Longueur des données utilisateur - 1
```
### 2.2 Calcul des Tailles

```python

# Longueur totale = en-tête + données
total_length = 6 + (pkt_length + 1)

# Où :
# - 6 = taille de l'en-tête
# - pkt_length = valeur du champ longueur
# - +1 car CCSDS: length = data_octets - 1
```
## 3. Implémentation du Décodage CCSDS
###3.1 Fonction decode_all_packets()
```python

def decode_all_packets(data):
    pos = 0
    packets = []
    
    while pos + 6 <= len(data):
        # 1. Lire les 2 premiers octets pour APID
        word1 = struct.unpack('>H', data[pos:pos+2])[0]
        apid = word1 & 0x07FF  # Masque 11 bits: 0x07FF = 0000011111111111
        
        # 2. Lire compteur de séquence
        word2 = struct.unpack('>H', data[pos+2:pos+4])[0]
        seq_count = word2 & 0x3FFF  # Masque 14 bits: 0x3FFF = 0011111111111111
        
        # 3. Lire longueur
        pkt_length = struct.unpack('>H', data[pos+4:pos+6])[0]
        
        # 4. Calculer taille totale
        total_length = 6 + pkt_length + 1  # CCSDS spécificité
        
        # Vérifier intégrité
        if pos + total_length > len(data):
            break  # Paquet incomplet
        
        # 5. Extraire données
        pkt_data = data[pos+6:pos+total_length]
        
        # 6. Stocker
        packets.append({
            'apid': apid,
            'seq': seq_count,
            'length': pkt_length,
            'data': pkt_data,
            'raw_header': data[pos:pos+6]
        })
        
        # 7. Avancer dans le buffer
        pos += total_length
    
    return packets, pos
````
### 3.2 Points d'Attention

    Big-endian ('>H') : standard spatial

    Gestion des paquets incomplets : vérification pos + total_length > len(data)

    APID comme clé : filtre principal pour identifier le type de paquet

## 4. Algorithme de Décodage 7-bit
### 4.1 Problème à Résoudre
```text

Données entrantes : flux d'octets (8 bits)
Sortie souhaitée : valeurs de 7 bits
````
### 4.2 Représentation Graphique
````text

Octets:     [AAAAAAAA] [BBBBBBBB] [CCCCCCCC]
Bits:        AAAAAAAABBBBBBBBCCCCCCCC
Groupes 7b:  AAAAAAA ABBBBBBB BCCCCCCC
````
### 4.3 Implémentation
````python

def try_decode_flags(data):
    flags = []
    bit_buffer = 0    # Accumulateur de bits
    bit_count = 0     # Nombre de bits valides dans le buffer
    
    for byte in data:
        # 1. Ajouter 8 nouveaux bits au buffer
        bit_buffer = (bit_buffer << 8) | byte
        bit_count += 8
        
        # 2. Extraire autant de valeurs 7-bit que possible
        while bit_count >= 7:
            # a) Prendre les 7 bits les plus significatifs
            #    (bit_count-7) détermine la position
            flag_value = (bit_buffer >> (bit_count - 7)) & 0x7F
            
            # b) Ajouter à la liste
            flags.append(flag_value)
            
            # c) Retirer ces 7 bits du buffer
            bit_count -= 7
            
            # d) Masquer pour garder seulement les bits restants
            #    (1 << bit_count) - 1 crée un masque de 'bit_count' bits
            bit_buffer &= (1 << bit_count) - 1
    
    # 3. Convertir en ASCII pour affichage
    ascii_flags = ''.join(chr(f) if 32 <= f < 127 else '.' for f in flags)
    return flags, ascii_flags
````
### 4.4 Exemple Détaillé
````text

Données: [0x68, 0x39] = [01101000, 00111001]

Étape 0: bit_buffer = 0, bit_count = 0

Étape 1 (byte=0x68):
  bit_buffer = 01101000, bit_count = 8
  bit_count >= 7? OUI
    flag_value = (01101000 >> 1) & 0x7F = 00110100 = 0x34 = '4'
    bit_count = 1
    bit_buffer = 0 (01101000 & 00000001)

Étape 2 (byte=0x39):
  bit_buffer = 0 00111001 = 00111001, bit_count = 9
  bit_count >= 7? OUI
    flag_value = (00111001 >> 2) & 0x7F = 00001110 = 0x0E
    bit_count = 2
    bit_buffer = 01 (00111001 & 00000011)
````
## 5. Stratégie d'Interaction avec le Serveur
### 5.1 Architecture Client-Serveur
````text

┌─────────┐      TCP/IP      ┌─────────┐
│  Client │◄────────────────►│ Serveur │
│  Python │   port 8123      │  Sat.   │
└─────────┘                  └─────────┘
     │                            │
     ├─ Envoi: commande textuelle │
     │  (ex: "FLAG\n")            │
     │                            │
     │◄─ Réception: données binaires
     │   format CCSDS
````
### 5.2 Fonction get_flag_interactive()
````python

def get_flag_interactive():
    # 1. Connexion TCP basique
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect((host, port))
    
    # 2. Phase d'écoute initiale
    sock.send(b"FLAG\n")
    response = sock.recv(4096)
    
    # 3. Analyse structurelle
    packets, _ = decode_all_packets(response)
    
    # 4. Recherche ciblée du paquet FLAG (APID 102)
    for pkt in packets:
        if pkt['apid'] == 102:
            flags, ascii_flags = try_decode_flags(pkt['data'])
            if "FLAG{" in ascii_flags:
                # Extraction du flag
                start = ascii_flags.find("FLAG{")
                end = ascii_flags.find("}", start)
                return ascii_flags[start:end+1]
    
    # 5. Si non trouvé, essayer d'autres commandes
    commands = ["GETFLAG\n", "SEND_FLAG\n", "DEBUG\n", "DUMP\n", "ALL\n"]
    for cmd in commands:
        sock.send(cmd.encode())
        resp = sock.recv(4096)
        # ... même analyse ...
```
### 5.3 Découverte de la Commande ALL

Problème : La commande FLAG retournait APID 105, pas APID 102.

Hypothèse testée :

    FLAG → Flag spécifique (peut-être chiffré/modifié)

    ALL → Tous les paquets (inclut flag en clair)

Validation :
````python

# Essai séquentiel
for cmd in commands:
    print(f"Test: {cmd}")
    sock.send(cmd.encode())
    resp = sock.recv(1024)
    packets, _ = decode_all_packets(resp)
    
    # Vérifier si contient APID 102
    for pkt in packets:
        if pkt['apid'] == 102:
            print(f"✓ {cmd} retourne paquet FLAG")
````
## 6. Méthodes de Débogage et Validation
### 6.1 Affichage Hexadécimal
````python

def hex_dump(data, length=16):
    for i in range(0, len(data), length):
        # Hex
        hex_str = ' '.join(f'{b:02x}' for b in data[i:i+8])
        hex_str += '  ' + ' '.join(f'{b:02x}' for b in data[i+8:i+16])
        
        # ASCII
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' 
                           for b in data[i:i+16])
        
        print(f"{i:04x}: {hex_str:<48} {ascii_str}")
````
Sortie typique :
````text

0000: 00 66 d7 15 00 57 8d 32  0c 7f 74 e8 34 86 cf 36  .f...W.2..t.4..6
0010: c8 19 fe 80 00 00 00 00  00 00 00 00 00 00 00 00  ................
````
### 6.2 Validation des Tailles
````python

# Pour paquet FLAG (APID 102)
expected_data_length = 105  # 120 flags × 7 bits ÷ 8 bits/octet

if pkt['apid'] == 102:
    actual_length = len(pkt['data'])
    if actual_length == expected_data_length:
        print("✓ Taille correcte pour décodage 7-bit")
    else:
        print(f"⚠ Taille anormale: {actual_length} vs {expected_data_length}")
````
### 6.3 Tests Unitaires
````python

# Test décodage 7-bit simple
def test_7bit_decoding():
    # Données: 'A' (0x41) et 'B' (0x42)
    # En 7-bit stocké: 0x41 = 1000001, 0x42 = 1000010
    test_data = bytes([0x41, 0x42])
    flags, ascii = try_decode_flags(test_data)
    
    # Vérifier
    assert flags[0] == 0x41  # 'A'
    assert ascii[0] == 'A'
    print("Test 7-bit: OK")
````

🎯 Résumé du Workflow
````text

XTCE File → Analyse Structure → Compréhension Format → Implémentation Code
     ↓            ↓                  ↓                     ↓
120×7 bits    APID=102           En-tête 6 octets    decode_all_packets()
     ↓            ↓                  ↓                     ↓
105 octets    FLAG Packet        Big-endian           try_decode_flags()
     ↓            ↓                  ↓                     ↓
Buffer bits   Serveur TCP        Connexion            get_flag_interactive()
     ↓            ↓                  ↓                     ↓
Décodage      Commande ALL       Réception             Extraction Flag
     ↓            ↓                  ↓                     ↓
ASCII Text    Paquet 102         Données binaires     FLAG{SP4C3fl@g}
````
