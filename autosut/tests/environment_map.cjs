"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const {buildEnvironmentMap} = require("../web/environment-workbench/environment-map.js");

const result = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const zones = buildEnvironmentMap(result.plan, result.constraints);
const domains = zones.map((zone) => zone.domain);
assert.deepEqual(domains.slice(0, 3).filter((domain) => ["attacker", "boundary", "target"].includes(domain)),
  ["attacker", "boundary", "target"].filter((domain) => domains.includes(domain)));
assert.equal(zones.reduce((total, zone) => total + zone.steps.length, 0), result.plan.steps.length);
const mapped = new Set(zones.flatMap((zone) => zone.requirements.map((requirement) => requirement.requirement_id)));
assert.equal(mapped.size, result.constraints.requirements.length, "every requirement appears in some zone");
console.log(`zones ${domains.join(",")}`);
