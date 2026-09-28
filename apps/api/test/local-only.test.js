import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { isLocalAddress, resolveLocalEndpoint } from "../../../packages/shared/network-policy.js";

test("local network policy permits loopback/private endpoints and rejects public or unresolved names",async()=>{
  for(const ip of ["127.0.0.1","10.1.2.3","172.20.1.2","192.168.1.5","169.254.8.1","fd12::8","::1","203.0.113.40"])assert.equal(isLocalAddress(ip),true,ip);
  for(const ip of ["8.8.8.8","1.1.1.1","2001:4860:4860::8888"])assert.equal(isLocalAddress(ip),false,ip);
  await assert.rejects(()=>resolveLocalEndpoint("api.example.test",async()=>[{address:"8.8.8.8"}]),/loopback\/private/);
  await assert.rejects(()=>resolveLocalEndpoint("missing.example.test",async()=>[]),/loopback\/private/);
  assert.deepEqual(await resolveLocalEndpoint("10.0.0.4"),["10.0.0.4"]);
});

test("runtime manifests do not declare analytics, crash upload, cloud database, or AI SDK dependencies",()=>{
  for(const file of ["package.json","apps/agent/package.json"]) {
    const manifest=JSON.parse(fs.readFileSync(file,"utf8"));
    const dependencyNames=Object.keys({...manifest.dependencies,...manifest.devDependencies});
    assert.equal(dependencyNames.some((name)=>/(analytics|telemetry|crash|sentry|posthog|segment|amplitude|firebase|supabase|openai|anthropic)/i.test(name)),false,file);
  }
});
