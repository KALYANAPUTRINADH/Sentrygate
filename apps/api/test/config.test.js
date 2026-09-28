import assert from "node:assert/strict";
import test from "node:test";
import { loadConfig } from "../src/config.js";

test("deployment config refuses insecure remote listeners and requires stable TLS settings in production",()=>{
  const prior=process.env.NODE_ENV;
  try{
    process.env.NODE_ENV="test";
    const local=loadConfig({host:"127.0.0.1",gatewayHost:"127.0.0.1",remoteAccessEnabled:false});
    assert.equal(local.remoteAccessEnabled,false);
    assert.equal(local.host,"127.0.0.1");
    assert.throws(()=>loadConfig({host:"0.0.0.0"}),/TLS certificates/);
    assert.throws(()=>loadConfig({apiBaseUrl:"http://api.example.invalid"}),/HTTPS/);
    assert.throws(()=>loadConfig({host:"10.77.0.1",remoteAccessEnabled:true}),/TLS certificates/);
    const privateIpConfig=loadConfig({host:"10.77.0.1",gatewayHost:"127.0.0.1",remoteAccessEnabled:true,tlsCertPath:"central.crt",tlsKeyPath:"central.key",apiBaseUrl:"https://10.77.0.1:4300"});
    assert.equal(privateIpConfig.host,"10.77.0.1");
    assert.equal(privateIpConfig.gatewayHost,"127.0.0.1");
    process.env.NODE_ENV="production";
    assert.throws(()=>loadConfig({sessionSecret:"configured-pilot-session-secret-32"}),/TLS certificates/);
    assert.throws(()=>loadConfig({sessionSecret:"configured-pilot-session-secret-32",tlsCertPath:"pilot.crt",tlsKeyPath:"pilot.key",host:"0.0.0.0",gatewayHost:"0.0.0.0",apiBaseUrl:"https://sentrygate.example.invalid"}),/explicit enablement/);
    const config=loadConfig({sessionSecret:"configured-pilot-session-secret-32",tlsCertPath:"pilot.crt",tlsKeyPath:"pilot.key",host:"0.0.0.0",gatewayHost:"0.0.0.0",apiBaseUrl:"https://sentrygate.example.invalid",remoteAccessEnabled:true});
    assert.equal(config.cookieSecure,true);
    assert.equal(config.remoteAccessEnabled,true);
    assert.equal(config.apiBaseUrl,"https://sentrygate.example.invalid");
  }finally{if(prior===undefined)delete process.env.NODE_ENV;else process.env.NODE_ENV=prior;}
});

test("standalone mode forces loopback-only HTTP and ignores remote listener overrides",()=>{
  const local=loadConfig({standalone:true,host:"0.0.0.0",gatewayHost:"0.0.0.0",remoteAccessEnabled:true,apiBaseUrl:"https://8.8.8.8:443",tlsCertPath:"ignored.crt",tlsKeyPath:"ignored.key",port:4317});
  assert.equal(local.standalone,true);
  assert.equal(local.host,"127.0.0.1");
  assert.equal(local.gatewayHost,"127.0.0.1");
  assert.equal(local.remoteAccessEnabled,false);
  assert.equal(local.tlsCertPath,"");
  assert.equal(local.apiBaseUrl,"http://127.0.0.1:4317");
});
