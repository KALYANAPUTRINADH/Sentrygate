import net from "node:net";
import { lookup } from "node:dns/promises";

export function isLocalAddress(address) {
  if(net.isIPv4(address)) {
    const octets=address.split(".").map(Number),[a,b]=octets;
    return a===10||a===127||a===0||a===169&&b===254||a===172&&b>=16&&b<=31||a===192&&(b===168||b===0&&octets[2]===2)||a===198&&(b===18||b===19||b===51&&octets[2]===100)||a===203&&b===0&&octets[2]===113||a>=224;
  }
  if(net.isIPv6(address)) {
    const value=address.toLowerCase();
    if(value==="::1"||value==="::"||value.startsWith("fc")||value.startsWith("fd")||value.startsWith("fe8")||value.startsWith("fe9")||value.startsWith("fea")||value.startsWith("feb"))return true;
    const mapped=value.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    return Boolean(mapped&&isLocalAddress(mapped[1]));
  }
  return false;
}

export async function resolveLocalEndpoint(hostname,lookupImpl=lookup) {
  const host=hostname.replace(/^\[|\]$/g,"");
  const addresses=net.isIP(host)?[host]:(await lookupImpl(host,{all:true})).map((entry)=>entry.address).slice(0,64);
  if(!addresses.length||addresses.some((address)=>!isLocalAddress(address)))throw new Error("SentryGate backend must resolve exclusively to loopback/private/link-local addresses");
  return addresses;
}
