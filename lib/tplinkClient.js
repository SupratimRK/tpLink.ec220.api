/**
 * TP-Link EC220-G5 tpEncrypt Client Library
 * Implements reverse-engineered authentication & encrypted RPC over HTTP.
 */

const fs = require('fs');
const path = require('path');

// Initialize browser runtime stubs required by tpEncrypt
global.window = global;
global.navigator = { appName: 'Netscape' };
global.localStorage = {
    _data: {},
    getItem(k) { return this._data[k] || null; },
    setItem(k, v) { this._data[k] = String(v); },
    removeItem(k) { delete this._data[k]; }
};
const jQuery = function() { return jQuery; };
jQuery.extend = Object.assign;
global.jQuery = jQuery;
global.$ = jQuery;

// Load cryptographic libraries
const cryptoPath = path.join(__dirname, 'cryptoJS.min.js');
const encryptPath = path.join(__dirname, 'tpEncrypt.new.js');
eval(fs.readFileSync(cryptoPath, 'utf8'));
eval(fs.readFileSync(encryptPath, 'utf8'));

/**
 * Normalizes a MAC address string into lowercase hyphen-delimited format (e.g. aa-bb-cc-dd-ee-ff).
 */
function normalizeMac(mac) {
    if (!mac || typeof mac !== 'string') {
        throw new Error("MAC address must be a non-empty string");
    }
    const cleaned = mac.trim().replace(/[:.]/g, '-').toLowerCase();
    if (!/^([0-9a-f]{2}-){5}[0-9a-f]{2}$/.test(cleaned)) {
        throw new Error(`Invalid MAC address format: "${mac}". Expected format: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX`);
    }
    return cleaned;
}

class TPLinkClient {
    /**
     * @param {string} [host] - Router IP (from env ROUTER_IP if omitted)
     * @param {string} [password] - Router Password (from env ROUTER_PASSWORD if omitted)
     */
    constructor(host, password) {
        this.host = host || process.env.ROUTER_IP;
        this.password = password || process.env.ROUTER_PASSWORD;

        if (!this.host) {
            throw new Error("Router IP is not configured. Set ROUTER_IP in your .env file or pass it to constructor.");
        }
        if (!this.password) {
            throw new Error("Router password is not configured. Set ROUTER_PASSWORD in your .env file or pass it to constructor.");
        }

        this.baseUrl = `http://${this.host}`;
        this.token = null;
        this.encryptor = null;
        this.headers = {
            'Referer': `${this.baseUrl}/`,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)',
            'Content-Type': 'text/plain;charset=UTF-8',
            'X-Requested-With': 'XMLHttpRequest'
        };
    }

    /**
     * Authenticate with router and initialize encrypted communication channel.
     */
    async login() {
        // Step 1: Request fresh seed & dictionary from loginCheck endpoint
        const resSeed = await fetch(`${this.baseUrl}/?code=2&asyn=1`, {
            method: 'POST',
            headers: this.headers,
            body: ''
        });
        const seedText = await resSeed.text();
        const seedLines = seedText.trim().split("\r\n");
        const seed = seedLines[3];
        const dict = seedLines[4];

        if (!seed || !dict) {
            throw new Error(`Failed to obtain login seed from router: ${seedText}`);
        }

        // Step 2: Fetch RSA parameters and initial sequence number
        const resRsa = await fetch(`${this.baseUrl}/?code=16&asyn=0`, {
            method: 'POST',
            headers: this.headers,
            body: 'get'
        });
        const rsaText = await resRsa.text();
        const rsaLines = rsaText.trim().split("\r\n");
        const ee = rsaLines[1];
        const nn = rsaLines[2];
        const seq = parseInt(rsaLines[3], 10);

        // Step 3: Instantiate local encryptor & generate new AES key
        this.encryptor = new jQuery.encrypt.encryptor();
        this.encryptor.setRSAKey(nn, ee);
        this.encryptor.setSeq(seq);
        this.encryptor.genAESKey();
        const encodedAesKey = this.encryptor.getEncodeAESKey();

        // Step 4: Encrypt password with proprietary two-stage XOR cipher
        const preEncryptedPwd = jQuery.su.encrypt(this.password);
        this.token = jQuery.su.encrypt(seed, preEncryptedPwd, dict);

        // Step 5: Send authentication request
        const authUrl = `${this.baseUrl}/?code=7&asyn=0&id=${encodeURIComponent(this.token)}`;
        const resAuth = await fetch(authUrl, {
            method: 'POST',
            headers: this.headers,
            body: ''
        });
        const authBody = await resAuth.text();
        if (parseInt(authBody.trim().split("\r\n")[0], 10) !== 0) {
            throw new Error(`Router authentication failed: ${authBody}`);
        }

        // Step 6: Synchronize AES session key with router
        const syncUrl = `${this.baseUrl}/?code=16&asyn=0&id=${encodeURIComponent(this.token)}`;
        const resSync = await fetch(syncUrl, {
            method: 'POST',
            headers: this.headers,
            body: `set ${encodedAesKey}`
        });
        const syncBody = await resSync.text();
        if (parseInt(syncBody.trim().split("\r\n")[0], 10) !== 0) {
            throw new Error(`Failed to sync AES encryption key with router: ${syncBody}`);
        }

        return true;
    }

    /**
     * Send an encrypted block read request (code=2).
     */
    async readBlock(blockIdentifier) {
        if (!this.token || !this.encryptor) {
            await this.login();
        }

        const encrypted = this.encryptor.dataEncrypt(blockIdentifier);
        const queryUrl = `${this.baseUrl}/?code=2&asyn=1&id=${encodeURIComponent(this.token)}`;
        const res = await fetch(queryUrl, {
            method: 'POST',
            headers: this.headers,
            body: `sign=${encrypted.sign}\r\ndata=${encrypted.data}`
        });

        if (res.status === 401 || res.status === 408) {
            // Re-authenticate and retry once
            await this.login();
            return this.readBlock(blockIdentifier);
        }

        const rawEncryptedResponse = await res.text();
        const decrypted = this.encryptor.dataDecrypt(rawEncryptedResponse);
        return this.parseBlockResponse(decrypted);
    }

    /**
     * Send an encrypted block write request (code=1).
     */
    async writeBlock(blockText) {
        if (!this.token || !this.encryptor) {
            await this.login();
        }

        const encrypted = this.encryptor.dataEncrypt(blockText);
        const writeUrl = `${this.baseUrl}/?code=1&asyn=0&id=${encodeURIComponent(this.token)}`;
        const res = await fetch(writeUrl, {
            method: 'POST',
            headers: this.headers,
            body: `sign=${encrypted.sign}\r\ndata=${encrypted.data}`
        });

        const rawEncryptedResponse = await res.text();
        const decrypted = this.encryptor.dataDecrypt(rawEncryptedResponse);
        return this.parseBlockResponse(decrypted);
    }

    /**
     * Parse plaintext block key-value response into clean JavaScript object.
     */
    parseBlockResponse(text) {
        const lines = text.trim().split("\r\n");
        const status = lines[0];
        const result = { _status: status, _raw: text };

        for (let i = 1; i < lines.length; i++) {
            const line = lines[i];
            if (!line) continue;
            const parts = line.split(" ");
            const key = parts[0];

            if (parts.length === 2) {
                result[key] = decodeURIComponent(parts[1]);
            } else if (parts.length >= 3) {
                const index = parseInt(parts[1], 10);
                const value = decodeURIComponent(parts.slice(2).join(" "));
                if (!Array.isArray(result[key])) {
                    result[key] = [];
                }
                result[key][index] = value;
            }
        }
        return result;
    }

    /**
     * Get router hardware and firmware info (Block 0).
     */
    async getDeviceInfo() {
        return this.readBlock('0|1,0,0');
    }

    /**
     * Get LAN IP and subnet settings (Block 4).
     */
    async getLanSettings() {
        const data = await this.readBlock('4|1,0,0');
        return {
            ip: data.ip,
            mask: data.mask,
            gateway: data.gateway || '0.0.0.0',
            mode: data.mode
        };
    }

    /**
     * Update LAN IP and subnet mask (Block 4).
     * @param {Object} cfg
     * @param {string} cfg.ip - Router LAN IP (e.g. 10.0.0.1)
     * @param {string} [cfg.mask="255.255.255.0"] - Subnet mask
     */
    async setLanSettings({ ip, mask = '255.255.255.0' }) {
        if (!ip) throw new Error("LAN IP address is required");
        const payload = `id 4|1,0,0\r\nip ${encodeURIComponent(ip)}\r\nmask ${encodeURIComponent(mask)}\r\n`;
        return this.writeBlock(payload);
    }

    /**
     * Get DHCP Server configuration (Block 8).
     */
    async getDhcpServer() {
        const data = await this.readBlock('8|1,0,0');
        const dns = Array.isArray(data.dns) ? data.dns : [data.dns || '0.0.0.0', '0.0.0.0'];
        return {
            enabled: data.enable === '1',
            poolStart: data.poolStart,
            poolEnd: data.poolEnd,
            leaseTime: parseInt(data.leaseTime || '7200', 10),
            leaseTimeMinutes: Math.floor(parseInt(data.leaseTime || '7200', 10) / 60),
            gateway: data.gateway || '0.0.0.0',
            primaryDns: dns[0] || '0.0.0.0',
            secondaryDns: dns[1] || '0.0.0.0'
        };
    }

    /**
     * Update DHCP Server configuration (Block 8).
     * @param {Object} cfg
     * @param {boolean} [cfg.enable] - Enable or disable DHCP server
     * @param {string} [cfg.poolStart] - Starting IP pool address (e.g. 10.0.0.100)
     * @param {string} [cfg.poolEnd] - Ending IP pool address (e.g. 10.0.0.249)
     * @param {number} [cfg.leaseTime] - Lease time in seconds (e.g. 7200)
     * @param {string} [cfg.gateway] - Optional gateway (0.0.0.0 for default)
     * @param {string} [cfg.primaryDns] - Optional primary DNS
     * @param {string} [cfg.secondaryDns] - Optional secondary DNS
     */
    async setDhcpServer({ enable, poolStart, poolEnd, leaseTime, gateway, primaryDns, secondaryDns } = {}) {
        const current = await this.getDhcpServer();

        const targetEnable = enable !== undefined ? (enable ? '1' : '0') : (current.enabled ? '1' : '0');
        const targetStart = poolStart || current.poolStart;
        const targetEnd = poolEnd || current.poolEnd;
        const targetLease = leaseTime !== undefined ? leaseTime : current.leaseTime;
        const targetGw = gateway !== undefined ? gateway : current.gateway;
        const targetDns1 = primaryDns !== undefined ? primaryDns : current.primaryDns;
        const targetDns2 = secondaryDns !== undefined ? secondaryDns : current.secondaryDns;

        let payload = `id 8|1,0,0\r\n`;
        payload += `enable ${targetEnable}\r\n`;
        payload += `poolStart ${encodeURIComponent(targetStart)}\r\n`;
        payload += `poolEnd ${encodeURIComponent(targetEnd)}\r\n`;
        payload += `leaseTime ${targetLease}\r\n`;
        payload += `gateway ${encodeURIComponent(targetGw)}\r\n`;
        payload += `dns 0 ${encodeURIComponent(targetDns1)}\r\n`;
        payload += `dns 1 ${encodeURIComponent(targetDns2)}\r\n`;

        return this.writeBlock(payload);
    }

    /**
     * Get live WAN connection status and metrics (Block 23).
     */
    async getWanStatus() {
        return this.readBlock('23|1,0,0');
    }

    /**
     * Get WAN static IP configuration (Block 24).
     */
    async getWanStaticSettings() {
        return this.readBlock('24|1,0,0');
    }

    /**
     * Update WAN Static IP settings.
     * Automatically preserves existing settings from the router for any omitted parameters.
     * @param {Object} cfg
     * @param {string} [cfg.ip] - WAN IP Address
     * @param {string} [cfg.mask] - Subnet Mask
     * @param {string} [cfg.gateway] - Default Gateway
     * @param {string} [cfg.priDns] - Primary DNS
     * @param {string} [cfg.sndDns] - Secondary DNS
     * @param {number} [cfg.mtu] - MTU size
     */
    async setWanStaticSettings({ ip, mask, gateway, priDns, sndDns, mtu } = {}) {
        if (!ip || !mask || !gateway || !priDns || !sndDns || mtu === undefined) {
            const current = await this.getWanStaticSettings();
            const currentDns = Array.isArray(current.dns) ? current.dns : [current.dns || '1.0.0.1', '1.1.1.1'];
            
            ip = ip || current.ip;
            mask = mask || current.mask;
            gateway = gateway || current.gateway;
            priDns = priDns || currentDns[0] || '1.0.0.1';
            sndDns = sndDns || currentDns[1] || '1.1.1.1';
            mtu = mtu !== undefined ? mtu : (parseInt(current.mtu, 10) || 1500);
        }

        if (!ip || !mask || !gateway) {
            throw new Error("Unable to determine full WAN configuration. Please specify --ip, --mask, and --gateway.");
        }

        let payload = `id 22|1,0,0\r\nlinkType 1\r\n`;
        payload += `id 24|1,0,0\r\n`;
        payload += `ip ${encodeURIComponent(ip)}\r\n`;
        payload += `mask ${encodeURIComponent(mask)}\r\n`;
        payload += `gateway ${encodeURIComponent(gateway)}\r\n`;
        payload += `mtu ${mtu}\r\n`;
        payload += `dns 0 ${encodeURIComponent(priDns)}\r\n`;
        payload += `dns 1 ${encodeURIComponent(sndDns)}\r\n`;

        return this.writeBlock(payload);
    }

    /**
     * Get WAN MAC address configuration (Block 1).
     */
    async getMacSettings() {
        const data = await this.readBlock('1|1,0,0');
        const wanMacType = parseInt(data.wanMacType || '0', 10);
        const typeLabels = { 0: 'Default (Router)', 1: 'Computer Clone', 2: 'Custom Cloned' };
        return {
            baseRouterMac: data.mac ? data.mac[0] : null,
            currentWanMac: data.mac ? data.mac[1] : null,
            wanMacType: wanMacType,
            wanMacTypeDescription: typeLabels[wanMacType] || 'Unknown'
        };
    }

    /**
     * Change WAN MAC address (clone a custom MAC).
     * @param {string} newMac - Target MAC address (e.g. "AA:BB:CC:DD:EE:FF" or "aa-bb-cc-dd-ee-ff")
     */
    async setWanMacAddress(newMac) {
        const formatted = normalizeMac(newMac);
        const payload = `id 1|1,0,0\r\nwanMacType 2\r\nmac 1 ${formatted}\r\n`;
        return this.writeBlock(payload);
    }

    /**
     * Restore WAN MAC address back to factory router default.
     */
    async resetWanMacAddress() {
        const macInfo = await this.getMacSettings();
        const baseMac = macInfo.baseRouterMac;
        let payload = `id 1|1,0,0\r\nwanMacType 0\r\n`;
        if (baseMac) {
            payload += `mac 1 ${baseMac}\r\n`;
        }
        return this.writeBlock(payload);
    }

    /**
     * Get wireless network configuration for 2.4GHz, 5GHz, or both.
     * @param {'2.4g'|'5g'|'both'} [band='both']
     */
    async getWirelessSettings(band = 'both') {
        const results = {};

        if (band === '2.4g' || band === 'both') {
            const data2g = await this.readBlock('33|1,1,0');
            results['2.4g'] = {
                band: '2.4 GHz',
                enabled: data2g.bEnable === '1',
                ssid: data2g.cSsid,
                hidden: data2g.bBcastSsid === '0',
                password: data2g.cPskSecret,
                security: data2g.uAuthType === '3' ? 'WPA/WPA2-Personal' : (data2g.uAuthType || 'None')
            };
        }

        if (band === '5g' || band === 'both') {
            const data5g = await this.readBlock('33|2,1,0');
            results['5g'] = {
                band: '5 GHz',
                enabled: data5g.bEnable === '1',
                ssid: data5g.cSsid,
                hidden: data5g.bBcastSsid === '0',
                password: data5g.cPskSecret,
                security: data5g.uAuthType === '3' ? 'WPA/WPA2-Personal' : (data5g.uAuthType || 'None')
            };
        }

        return band === 'both' ? results : results[band];
    }

    /**
     * Update wireless network settings (SSID, password, enable/disable, broadcast).
     * @param {Object} opts
     * @param {'2.4g'|'5g'|'both'} [opts.band='both']
     * @param {string} [opts.ssid]
     * @param {string} [opts.password]
     * @param {boolean} [opts.enabled]
     * @param {boolean} [opts.hidden]
     */
    async setWirelessSettings({ band = 'both', ssid, password, enabled, hidden } = {}) {
        const bandsToUpdate = band === 'both' ? ['2.4g', '5g'] : [band];
        const responses = {};

        for (const b of bandsToUpdate) {
            const layer = b === '2.4g' ? '1' : '2';
            const current = await this.getWirelessSettings(b);

            const targetEnable = enabled !== undefined ? (enabled ? 1 : 0) : (current.enabled ? 1 : 0);
            const targetSsid = ssid || current.ssid;
            const targetPassword = password || current.password;
            const targetHidden = hidden !== undefined ? (hidden ? 1 : 0) : (current.hidden ? 1 : 0);

            if (targetPassword && targetPassword.length < 8) {
                throw new Error("Wireless password must be at least 8 characters long.");
            }

            let payload = '';
            if (targetEnable === 0) {
                payload = `id 33|${layer},1,0\r\nbEnable 0\r\nid 32|${layer},0,0\r\nbEnabled 0\r\n`;
            } else {
                payload = `id 33|${layer},1,0\r\n`;
                payload += `bEnable 1\r\n`;
                payload += `cSsid ${encodeURIComponent(targetSsid)}\r\n`;
                payload += `bBcastSsid ${targetHidden === 1 ? 0 : 1}\r\n`;
                payload += `bSecurityEnable 1\r\n`;
                payload += `uAuthType 3\r\n`;
                payload += `uPSKSecOpt 2\r\n`;
                payload += `uPSKEncryptType 3\r\n`;
                payload += `cPskSecret ${encodeURIComponent(targetPassword)}\r\n`;
                payload += `id 32|${layer},0,0\r\n`;
                payload += `bEnabled 1\r\n`;
            }

            responses[b] = await this.writeBlock(payload);
        }

        return responses;
    }

    /**
     * Get list of active connected client devices on the LAN (Block 13).
     */
    async getConnectedClients() {
        const data = await this.readBlock('13|1,0,0');
        const clients = [];

        if (Array.isArray(data.ip)) {
            for (let i = 0; i < data.ip.length; i++) {
                const ip = data.ip[i];
                if (ip && ip !== '0.0.0.0') {
                    clients.push({
                        index: i,
                        ip: ip,
                        mac: (data.mac && data.mac[i]) ? data.mac[i] : null,
                        name: (data.name && data.name[i]) ? data.name[i] : (data.hostName && data.hostName[i] ? data.hostName[i] : 'Unknown'),
                        port: (data.port && data.port[i]) ? data.port[i] : 'br-lan',
                        online: (data.online && data.online[i]) === '1',
                        deviceType: (data.deviceType && data.deviceType[i]) ? data.deviceType[i] : '0',
                        upRate: parseInt((data.up && data.up[i]) || '0', 10),
                        downRate: parseInt((data.down && data.down[i]) || '0', 10),
                        blocked: (data.blocked && data.blocked[i]) === '1',
                        bound: (data.bindEntry && data.bindEntry[i]) === '1'
                    });
                }
            }
        }
        return clients;
    }

    /**
     * Get list of IP-MAC bindings / reserved addresses (Block 12).
     */
    async getIpBindings() {
        const data = await this.readBlock('12|1,0,0');
        const bindings = [];

        if (Array.isArray(data.ip)) {
            for (let i = 0; i < data.ip.length; i++) {
                const ip = data.ip[i];
                if (ip && ip !== '0.0.0.0') {
                    bindings.push({
                        index: i,
                        ip: ip,
                        mac: (data.mac && data.mac[i]) ? data.mac[i] : null,
                        bound: (data.bindEntry && data.bindEntry[i]) === '1'
                    });
                }
            }
        }
        return bindings;
    }
}

TPLinkClient.normalizeMac = normalizeMac;
module.exports = TPLinkClient;
