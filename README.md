# TP-Link EC220-G5 Encrypted API Control Tool (Method 2)

A fast, lightweight CLI and library to programmatically monitor and configure **TP-Link EC220-G5** routers using the reverse-engineered `tpEncrypt` HTTP protocol without launching a web browser.

---

## Configuration

Credentials and router configuration are loaded dynamically via environment variables (`.env`).

### Setup `.env`
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Edit `.env` with your router details:
```env
ROUTER_IP=10.0.0.1
ROUTER_PASSWORD=your_router_password_here
```

> [!NOTE]
> `.env` is automatically ignored in `.gitignore` to prevent credential leakage.
> Neither router passwords nor network configurations are hardcoded into scripts or documentation.

---

## Technical Overview (Reverse-Engineered `tpEncrypt` Architecture)

The TP-Link EC220-G5 web interface uses a proprietary multi-layer cryptographic protocol over standard HTTP POST endpoints:

1. **Seed & Dictionary Handshake**:
   - `POST /?code=2&asyn=1`
   - Returns error code `00007` (401 Unauthorized), which transmits a 32-character seed and an index-mapped 256-character dictionary table.
2. **Two-Stage Password Encryption**:
   - Stage 1: The password is pre-encrypted with `$.su.encrypt(password)` using an internal 15-character key.
   - Stage 2: The pre-encrypted string is XOR-ciphered against the 32-character server seed and indexed into the dictionary table to produce the active session `token`.
3. **RSA-1024 Handshake**:
   - `POST /?code=16&asyn=0` with payload `"get"`
   - Returns the router's RSA public exponent `ee` (65537), modulus `nn` (1024-bit), and sequence integer `seq`.
4. **AES-128-CBC Session Key Synchronization**:
   - Client generates a 16-byte random AES key and 16-byte IV (`k=<key>&i=<iv>`).
   - The key string is encrypted using the router's RSA public key and uploaded via `POST /?code=16&asyn=0&id=<token>` with payload `set <rsa_encrypted_aes_key>`.
5. **Encrypted Block RPC (`MERProxy`)**:
   - **Read Block**: `POST /?code=2&asyn=1&id=<token>` with payload `sign=<signature>\r\ndata=<aes_encrypted_block_id>`
   - **Write Block**: `POST /?code=1&asyn=0&id=<token>` with payload `sign=<signature>\r\ndata=<aes_encrypted_block_data>`
   - Responses are returned encrypted in AES-128-CBC and decrypted on the client.

### Key Data Block IDs:
- **Block 0 (`0|1,0,0`)**: Device information (Model, Hardware version, Firmware build, Serial number)
- **Block 1 (`1|1,0,0`)**: System configuration & WAN MAC clone settings (`wanMacType`: 0=Default, 1=PC Clone, 2=Custom)
- **Block 4 (`4|1,0,0`)**: LAN configuration (IP, subnet mask)
- **Block 13 (`13|1,0,0`)**: Connected client devices table
- **Block 22 (`22|1,0,0`)**: Link mode & connection type
- **Block 23 (`23|1,0,0`)**: Live WAN connection status, packet counts, uptime, and DNS servers
- **Block 24 (`24|1,0,0`)**: WAN Static IP configuration (IP, subnet mask, gateway, DNS servers, MTU)
- **Block 32 & 33**: Wireless basic settings (`33|1,1,0` for 2.4 GHz, `33|2,1,0` for 5 GHz)

---

## Quick Start (CLI)

Both Node.js and Python CLI entrypoints are available. Run commands from this folder:

### 1. View Router Status
```bash
node tplink.js status
# or
python tplink.py status
```

### 2. View WAN Configuration
```bash
node tplink.js wan
```

### 3. Update WAN Static IP Settings
Supports full or partial updates (omitted fields automatically retain their current router values):
```bash
# Update only the default gateway:
node tplink.js set-wan --gateway 192.0.2.1

# Update only DNS servers:
node tplink.js set-wan --dns1 1.0.0.1 --dns2 1.1.1.1

# Full WAN static configuration update:
node tplink.js set-wan --ip 192.0.2.10 --mask 255.255.255.0 --gateway 192.0.2.1 --dns1 1.0.0.1 --dns2 1.1.1.1
```

### 4. Manage WAN MAC Address (Cloning)
```bash
# View current WAN MAC and clone mode:
node tplink.js mac

# Change/clone a custom WAN MAC address:
node tplink.js set-mac 00:11:22:33:44:55
# or
python tplink.py set-mac 00-11-22-33-44-55

# Reset WAN MAC back to router factory default:
node tplink.js reset-mac
```

### 5. Manage Wireless (Wi-Fi) Settings
```bash
# View current 2.4 GHz & 5 GHz Wi-Fi settings (SSID, password, state):
node tplink.js wifi

# Update both 2.4 GHz & 5 GHz SSID and password:
node tplink.js set-wifi --ssid "MyHomeNetwork" --password "SecretPassword123"

# Update only 5 GHz band:
node tplink.js set-wifi --band 5g --ssid "MyHomeNetwork_5G" --password "SecretPassword123"

# Hide or disable wireless radio:
node tplink.js set-wifi --band 2.4g --hidden 1
node tplink.js set-wifi --band 5g --enable 0
```

### 6. Manage LAN IP Configuration
```bash
# View router LAN IP and subnet mask:
node tplink.js lan

# Update LAN IP and subnet mask:
node tplink.js set-lan --ip 10.0.0.1 --mask 255.255.255.0
```

### 7. Manage DHCP Server
```bash
# View current DHCP server configuration (status, pool range, lease duration):
node tplink.js dhcp

# Enable/disable DHCP server:
node tplink.js set-dhcp --enable 1
node tplink.js set-dhcp --enable 0

# Configure DHCP pool range, lease time, and custom DNS:
node tplink.js set-dhcp --enable 1 --start 10.0.0.100 --end 10.0.0.249 --lease 7200 --dns1 1.0.0.1 --dns2 1.1.1.1
```

### 8. View Connected Client Devices (LAN / Wi-Fi)
```bash
node tplink.js clients
# or
python tplink.py clients
```
Displays all connected devices with their IP address, MAC address, connection status (Online/Offline), reservation type (Static/Dynamic), and real-time network traffic throughput.

### 9. View IP-MAC Address Reservations (Static Bindings)
```bash
node tplink.js bindings
# or
python tplink.py bindings
```

### 10. Query Raw Router Data Blocks
```bash
# Query any data block by ID (e.g. Block 0 for device, Block 8 for DHCP, Block 23 for WAN status):
node tplink.js raw "8|1,0,0"
```

---

## Programmatic Usage in Code

```javascript
const TPLinkClient = require('./lib/tplinkClient');

async function run() {
    // Reads ROUTER_IP and ROUTER_PASSWORD from environment / .env
    const router = new TPLinkClient();
    
    // Login and negotiate AES session keys
    await router.login();
    
    // 1. Inspect Wi-Fi settings
    const wifi = await router.getWirelessSettings();
    console.log(`2.4G SSID: ${wifi['2.4g'].ssid}, 5G SSID: ${wifi['5g'].ssid}`);
    
    // 2. Inspect LAN configuration
    const lan = await router.getLanSettings();
    console.log(`LAN IP: ${lan.ip}, Subnet: ${lan.mask}`);
    
    // 3. Inspect DHCP server
    const dhcp = await router.getDhcpServer();
    console.log(`DHCP Enabled: ${dhcp.enabled}, Range: ${dhcp.poolStart} - ${dhcp.poolEnd}`);
    
    // 4. List connected clients
    const clients = await router.getConnectedClients();
    console.log(`Active clients found: ${clients.length}`);
}

run();
```
