#!/usr/bin/env node

/**
 * CLI Tool for TP-Link EC220-G5 Router Management via Encrypted HTTP API (Method 2)
 * Reads router credentials dynamically from .env (no hardcoded credentials or network configs).
 */

const fs = require('fs');
const path = require('path');
const TPLinkClient = require('./lib/tplinkClient');

/**
 * Lightweight native .env loader (zero external dependencies required)
 */
function loadEnv() {
    const candidates = [
        path.join(__dirname, '.env'),
        path.join(process.cwd(), '.env')
    ];

    for (const envPath of candidates) {
        if (fs.existsSync(envPath)) {
            try {
                const content = fs.readFileSync(envPath, 'utf8');
                for (const line of content.split(/\r?\n/)) {
                    const trimmed = line.trim();
                    if (!trimmed || trimmed.startsWith('#')) continue;
                    const eqIndex = trimmed.indexOf('=');
                    if (eqIndex > 0) {
                        const key = trimmed.slice(0, eqIndex).trim();
                        let val = trimmed.slice(eqIndex + 1).trim();
                        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
                            val = val.slice(1, -1);
                        }
                        if (!process.env[key]) {
                            process.env[key] = val;
                        }
                    }
                }
                break;
            } catch (err) {
                // Ignore parse errors and continue
            }
        }
    }
}

loadEnv();

function parseArgs(args) {
    const options = {
        host: process.env.ROUTER_IP || null,
        password: process.env.ROUTER_PASSWORD || null,
        command: null,
        targetArg: null,
        params: {}
    };

    let i = 0;
    while (i < args.length) {
        const arg = args[i];
        if (arg === '--host') {
            options.host = args[++i];
        } else if (arg === '--password' || arg === '-p') {
            options.password = args[++i];
        } else if (arg.startsWith('--')) {
            const key = arg.slice(2);
            options.params[key] = args[++i];
        } else if (!options.command) {
            options.command = arg;
        } else if (!options.targetArg) {
            options.targetArg = arg;
        }
        i++;
    }
    return options;
}

function printUsage() {
    console.log(`
TP-Link EC220-G5 Encrypted API Control Tool (Method 2)
======================================================
Usage:
  node tplink.js <command> [arguments] [options]

Commands:
  status               Display router device info, LAN settings, and active WAN metrics
  wan                  Display current WAN connection details & static IP configuration
  set-wan              Update WAN Static IP configuration
                       Options:
                         --ip <ip>           WAN IP address (required)
                         --mask <mask>       Subnet mask (required)
                         --gateway <gw>      Default gateway (required)
                         --dns1 <ip>         Primary DNS (default: 1.0.0.1)
                         --dns2 <ip>         Secondary DNS (default: 1.1.1.1)
                         --mtu <bytes>       MTU size (default: 1500)

  mac                  Display current WAN MAC address and clone type
  set-mac <mac>        Change WAN MAC address (e.g. AA:BB:CC:DD:EE:FF or aa-bb-cc-dd-ee-ff)
  reset-mac            Reset WAN MAC address back to factory router default

  wifi                 Display current 2.4 GHz & 5 GHz wireless configuration (SSID, password, state)
  set-wifi             Update wireless network settings
                       Options:
                         --ssid <name>       New WiFi SSID name
                         --password <pwd>    New WiFi password (min 8 characters)
                         --band <band>       Band to update: 2.4g, 5g, or both (default: both)
                         --enable <0|1>      1 to enable radio, 0 to disable
                         --hidden <0|1>      1 to hide SSID broadcast, 0 to broadcast

  clients              Display connected devices on the network
  raw <blockId>        Query an arbitrary router block (e.g., "33|1,1,0", "1|1,0,0")

Options:
  --host <ip>          Router IP (overrides ROUTER_IP in .env)
  --password <pwd>     Admin password (overrides ROUTER_PASSWORD in .env)

Configuration:
  Set ROUTER_IP and ROUTER_PASSWORD in .env (see .env.example).
`);
}

async function main() {
    const args = process.argv.slice(2);
    const opts = parseArgs(args);

    if (!opts.command || opts.command === 'help' || opts.command === '--help') {
        printUsage();
        return;
    }

    if (!opts.host || !opts.password) {
        console.error("Error: ROUTER_IP and ROUTER_PASSWORD must be defined in your .env file or passed via CLI flags.");
        console.error("Example: create a .env file with:");
        console.error("  ROUTER_IP=10.0.0.1");
        console.error("  ROUTER_PASSWORD=your_password");
        process.exit(1);
    }

    const client = new TPLinkClient(opts.host, opts.password);

    try {
        console.log(`Connecting to TP-Link router at ${opts.host}...`);
        await client.login();
        console.log(`Authenticated successfully!`);

        switch (opts.command) {
            case 'status': {
                console.log("\n--- Device Information ---");
                const dev = await client.getDeviceInfo();
                console.log(`  Model:        ${dev.modelName || 'EC220-G5'} (Hardware: ${dev.hardVer || 'v3.0'})`);
                console.log(`  Description:  ${dev.fullName || 'AC1200 Router'}`);
                console.log(`  Firmware:     ${dev.softVer || 'N/A'}`);
                console.log(`  Serial:       ${dev.serialNumber || 'N/A'}`);

                console.log("\n--- LAN Configuration ---");
                const lan = await client.getLanSettings();
                console.log(`  Router IP:    ${lan.ip} / ${lan.mask}`);

                console.log("\n--- WAN Status ---");
                const wan = await client.getWanStatus();
                console.log(`  Status:       ${wan.status === '1' ? 'Connected' : 'Disconnected'}`);
                console.log(`  WAN IP:       ${wan.ip}`);
                console.log(`  Subnet Mask:  ${wan.mask}`);
                console.log(`  Gateway:      ${wan.gateway}`);
                console.log(`  DNS Servers:  ${Array.isArray(wan.dns) ? wan.dns.join(', ') : wan.dns}`);
                console.log(`  Uptime:       ${Math.floor(parseInt(wan.upTime || 0) / 60)} minutes`);
                console.log(`  Packets In:   ${wan.inPkts} (Bytes: ${wan.inOctets})`);
                console.log(`  Packets Out:  ${wan.outPkts} (Bytes: ${wan.outOctets})`);

                console.log("\n--- WAN MAC Address ---");
                const macInfo = await client.getMacSettings();
                console.log(`  Current WAN:  ${macInfo.currentWanMac}`);
                console.log(`  Type:         ${macInfo.wanMacTypeDescription}`);

                console.log("\n--- Wireless Networks ---");
                const wifi = await client.getWirelessSettings();
                console.log(`  2.4 GHz SSID: ${wifi['2.4g'].ssid} (State: ${wifi['2.4g'].enabled ? 'Enabled' : 'Disabled'})`);
                console.log(`  5 GHz SSID:   ${wifi['5g'].ssid} (State: ${wifi['5g'].enabled ? 'Enabled' : 'Disabled'})`);
                break;
            }

            case 'wan': {
                console.log("\n--- Live WAN Connection Status ---");
                const wan = await client.getWanStatus();
                const cleanWan = { ...wan };
                delete cleanWan._raw;
                console.log(JSON.stringify(cleanWan, null, 2));

                console.log("\n--- Static IP Settings (Block 24) ---");
                const wanStatic = await client.getWanStaticSettings();
                const cleanStatic = { ...wanStatic };
                delete cleanStatic._raw;
                console.log(JSON.stringify(cleanStatic, null, 2));
                break;
            }

            case 'set-wan': {
                const { ip, mask, gateway, dns1, dns2, mtu } = opts.params;
                if (!ip || !mask || !gateway) {
                    console.error("Error: --ip, --mask, and --gateway are required for set-wan.");
                    printUsage();
                    process.exit(1);
                }

                console.log(`Updating WAN static IP configuration...`);
                console.log(`  IP:      ${ip}`);
                console.log(`  Mask:    ${mask}`);
                console.log(`  Gateway: ${gateway}`);
                console.log(`  DNS:     ${dns1 || '1.0.0.1'}, ${dns2 || '1.1.1.1'}`);
                console.log(`  MTU:     ${mtu || 1500}`);

                const res = await client.setWanStaticSettings({
                    ip,
                    mask,
                    gateway,
                    priDns: dns1 || '1.0.0.1',
                    sndDns: dns2 || '1.1.1.1',
                    mtu: mtu ? parseInt(mtu, 10) : 1500
                });

                console.log("\nSettings update submitted successfully!");
                console.log("Router response status:", res._status === '00000' ? 'OK (00000)' : res._status);
                break;
            }

            case 'mac': {
                console.log("\n--- WAN MAC Address Configuration ---");
                const macInfo = await client.getMacSettings();
                console.log(`  Factory Base MAC:   ${macInfo.baseRouterMac}`);
                console.log(`  Active WAN MAC:     ${macInfo.currentWanMac}`);
                console.log(`  Clone Mode:         ${macInfo.wanMacType} (${macInfo.wanMacTypeDescription})`);
                break;
            }

            case 'set-mac': {
                const targetMac = opts.targetArg || opts.params.mac;
                if (!targetMac) {
                    console.error("Error: MAC address required. Usage: node tplink.js set-mac <AA:BB:CC:DD:EE:FF>");
                    process.exit(1);
                }

                console.log(`Changing WAN MAC address to: ${targetMac}...`);
                const res = await client.setWanMacAddress(targetMac);
                console.log("\nMAC Address change submitted successfully!");
                console.log("Router response status:", res._status === '00000' ? 'OK (00000)' : res._status);
                
                const updated = await client.getMacSettings();
                console.log(`New Active WAN MAC: ${updated.currentWanMac}`);
                break;
            }

            case 'reset-mac': {
                console.log(`Resetting WAN MAC address to factory router default...`);
                const res = await client.resetWanMacAddress();
                console.log("\nReset submitted successfully!");
                console.log("Router response status:", res._status === '00000' ? 'OK (00000)' : res._status);

                const updated = await client.getMacSettings();
                console.log(`Active WAN MAC is now: ${updated.currentWanMac} (${updated.wanMacTypeDescription})`);
                break;
            }

            case 'wifi': {
                console.log("\n--- Wireless Networks Configuration ---");
                const wifi = await client.getWirelessSettings();
                
                console.log("\n[2.4 GHz Band]");
                console.log(`  Radio State:  ${wifi['2.4g'].enabled ? 'Enabled' : 'Disabled'}`);
                console.log(`  SSID:         ${wifi['2.4g'].ssid}`);
                console.log(`  Broadcast:    ${wifi['2.4g'].hidden ? 'Hidden' : 'Visible'}`);
                console.log(`  Password:     ${wifi['2.4g'].password}`);
                console.log(`  Security:     ${wifi['2.4g'].security}`);

                console.log("\n[5 GHz Band]");
                console.log(`  Radio State:  ${wifi['5g'].enabled ? 'Enabled' : 'Disabled'}`);
                console.log(`  SSID:         ${wifi['5g'].ssid}`);
                console.log(`  Broadcast:    ${wifi['5g'].hidden ? 'Hidden' : 'Visible'}`);
                console.log(`  Password:     ${wifi['5g'].password}`);
                console.log(`  Security:     ${wifi['5g'].security}`);
                break;
            }

            case 'set-wifi': {
                const { ssid, password, band, enable, hidden } = opts.params;
                const targetBand = band || 'both';

                if (!ssid && !password && enable === undefined && hidden === undefined) {
                    console.error("Error: At least one wireless parameter must be specified (--ssid, --password, --enable, --hidden).");
                    printUsage();
                    process.exit(1);
                }

                console.log(`Updating Wireless Settings for band: ${targetBand}...`);
                if (ssid) console.log(`  SSID:        ${ssid}`);
                if (password) console.log(`  Password:    ${password}`);
                if (enable !== undefined) console.log(`  Radio:       ${enable === '1' || enable === 'true' ? 'Enable' : 'Disable'}`);
                if (hidden !== undefined) console.log(`  Broadcast:   ${hidden === '1' || hidden === 'true' ? 'Hidden' : 'Visible'}`);

                const res = await client.setWirelessSettings({
                    band: targetBand,
                    ssid: ssid || undefined,
                    password: password || undefined,
                    enabled: enable !== undefined ? (enable === '1' || enable === 'true') : undefined,
                    hidden: hidden !== undefined ? (hidden === '1' || hidden === 'true') : undefined
                });

                console.log("\nWireless settings submitted successfully!");
                console.log("Router response:", res);

                console.log("\nUpdated Settings:");
                const updated = await client.getWirelessSettings(targetBand);
                console.log(JSON.stringify(updated, null, 2));
                break;
            }

            case 'clients': {
                console.log("\n--- Connected Clients ---");
                const clients = await client.getConnectedClients();
                console.log(clients._raw || JSON.stringify(clients, null, 2));
                break;
            }

            case 'raw': {
                const blockId = opts.targetArg || '23|1,0,0';
                console.log(`\nQuerying Block: ${blockId}`);
                const data = await client.readBlock(blockId);
                console.log(data._raw || JSON.stringify(data, null, 2));
                break;
            }

            default:
                console.error(`Unknown command: ${opts.command}`);
                printUsage();
                process.exit(1);
        }
    } catch (err) {
        console.error("\n[Error executing command]:", err.message);
        process.exit(1);
    }
}

main();
