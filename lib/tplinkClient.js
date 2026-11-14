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
        return this.readBlock('4|1,0,0');
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
     * @param {Object} cfg
     * @param {string} cfg.ip - WAN IP Address
     * @param {string} cfg.mask - Subnet Mask
     * @param {string} cfg.gateway - Default Gateway
     * @param {string} [cfg.priDns="1.0.0.1"] - Primary DNS
     * @param {string} [cfg.sndDns="1.1.1.1"] - Secondary DNS
     * @param {number} [cfg.mtu=1500] - MTU size
     */
    async setWanStaticSettings({ ip, mask, gateway, priDns = '1.0.0.1', sndDns = '1.1.1.1', mtu = 1500 }) {
        if (!ip || !mask || !gateway) {
            throw new Error("Missing required parameters: ip, mask, gateway");
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
     * Get list of connected client devices (Block 13).
     */
    async getConnectedClients() {
        return this.readBlock('13|1,0,0');
    }
}

TPLinkClient.normalizeMac = normalizeMac;
module.exports = TPLinkClient;
