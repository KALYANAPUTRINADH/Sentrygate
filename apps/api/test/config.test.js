import assert from "node:assert/strict";
import test from "node:test";
import { loadConfig } from "../src/config.js";

test("deployment config refuses insecure remote listeners and requires stable TLS settings in production",()=>{
  const prior=process.env.NODE_ENV;
  try{
    process.env.NODE_ENV="test";
    assert.throws(()=>loadConfig({host:"0.0.0.0"}),/TLS certificates/);
    assert.throws(()=>loadConfig({apiBaseUrl:"http://api.example.invalid"}),/HTTPS/);
    process.env.NODE_ENV="production";
    assert.throws(()=>loadConfig({sessionSecret:"configured-pilot-session-secret-32"}),/TLS certificates/);
    const config=loadConfig({sessionSecret:"configured-pilot-session-secret-32",tlsCertPath:"pilot.crt",tlsKeyPath:"pilot.key",host:"0.0.0.0",gatewayHost:"0.0.0.0",apiBaseUrl:"https://sentrygate.example.invalid"});
    assert.equal(config.cookieSecure,true);
    assert.equal(config.apiBaseUrl,"https://sentrygate.example.invalid");
  }finally{if(prior===undefined)delete process.env.NODE_ENV;else process.env.NODE_ENV=prior;}
});
