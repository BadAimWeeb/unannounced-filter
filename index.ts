import readline from "node:readline";
import { Address4 } from "ip-address";
import stream from "node:stream";
import fs from "node:fs";

const PULL_URL = "https://thyme.apnic.net/.combined/data-raw-table";

const DATA = await fetch(PULL_URL);
const rl = readline.createInterface({
    input: stream.Readable.fromWeb(DATA.body!)
});

try {
    fs.unlinkSync("blacklist.txt"); // Remove existing blacklist if it exists
} catch { }
const feedOut = fs.createWriteStream("blacklist.txt", { flush: true, flags: "w" });

let startAddress = 0x1000000n;

const ev = (line: string) => {
    let [addressStr, asn] = line.trim().split("\t");
    if (!addressStr || !asn) return;

    try {
        addressStr = addressStr.trim();
        //console.log(`Processing: ${addressStr} (ASN: ${asn})`);
        let cidr = new Address4(addressStr!);

        if (cidr.startAddress().bigInt() > startAddress) {
            // blacklist the range between the last address and the new one
            let blacklistStart = startAddress;
            let blacklistEnd = cidr.startAddress().bigInt() - BigInt(1);

            let current = blacklistStart;
            while (current <= blacklistEnd) {
                // Find the largest CIDR block that fits
                let prefixLength = 0;
                for (; prefixLength < 32; prefixLength++) {
                    let mask1 = 2n ** BigInt(32 - prefixLength) - 1n;

                    if ((current & ~mask1) === current && (current | mask1) <= blacklistEnd) {
                        break;
                    }
                }

                const cidrNotation = `${Address4.fromBigInt(current).address}/${prefixLength}`;
                switch (cidrNotation) {
                    // Skip private ranges
                    case "10.0.0.0/8":
                    case "172.16.0.0/12":
                    case "192.168.0.0/16":
                    // Skip CGNAT ranges
                    case "100.64.0.0/10":
                    // Skip loopback
                    case "127.0.0.0/8":
                    // Skip DS-Lite
                    case "192.0.0.0/24":
                        //console.log(`Skipped: ${cidrNotation}`);
                        break;
                    default:
                        feedOut.write(cidrNotation + "\n");
                    //console.log(`Blacklisted: ${cidrNotation}`);
                }

                current += BigInt(1) << BigInt(32 - prefixLength);
            }
        }

        startAddress = cidr.endAddress().bigInt() + 1n;
    } catch (e) {
        console.error(`Error processing line: ${addressStr}`, e);
    }
}

rl.on("line", ev);
rl.on("close", () => {
    ev("224.0.0.0/32\t0"); // Push multicast address to account for the final range after the last ASN block
    feedOut.close(() => process.exit(0));
})