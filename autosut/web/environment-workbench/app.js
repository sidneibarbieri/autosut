"use strict";
const element = Object.fromEntries(["example", "file", "plan", "resolve", "message", "empty", "result", "campaign", "download", "platforms", "coverage", "count", "uncovered", "hashes", "requirements", "json", "cli"].map(name => [name, document.getElementById(name)]));
let generation = 0;
let currentResult = null;

function invalidate() {
  generation += 1;
  currentResult = null;
  element.result.hidden = true;
  element.empty.hidden = false;
  element.resolve.disabled = false;
  element.message.textContent = "Input changed. Resolve again to obtain a matching result.";
}

async function readResponse(response) {
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(typeof payload.detail === "string" ? payload.detail : JSON.stringify(payload.detail || payload));
  }
  return payload;
}

function render(result) {
  const constraints = result.constraints;
  const resolution = constraints.platform_resolution;
  currentResult = result;
  element.campaign.textContent = `${result.plan.campaign_id} · ${result.plan.campaign_name}`;
  element.platforms.textContent = resolution.selected_platforms.join(", ") || "None";
  element.coverage.textContent = resolution.complete ? "Covered" : "Incomplete";
  element.count.textContent = String(constraints.requirements.length);
  element.uncovered.textContent = resolution.uncovered_technique_ids.length
    ? `Uncovered techniques: ${resolution.uncovered_technique_ids.join(", ")}`
    : "No uncovered platform requirements. Other requirements still need operational verification.";
  element.hashes.textContent = `Input: ${result.plan.content_sha256}\nConstraints: ${constraints.content_sha256}`;
  element.requirements.replaceChildren();
  for (const requirement of constraints.requirements) {
    const row = document.createElement("tr");
    for (const value of [requirement.kind, requirement.acceptable_values.join(", "), requirement.technique_ids.join(", "), `${requirement.source}: ${requirement.rationale}`]) {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.append(cell);
    }
    element.requirements.append(row);
  }
  element.json.textContent = JSON.stringify(result, null, 2);
  element.cli.textContent = ".venv/bin/python scripts/emulate.py /absolute/path/to/input.procedural-plan.json --output /absolute/new/planning.json";
  element.result.hidden = false;
  element.empty.hidden = true;
  document.dispatchEvent(new CustomEvent("planning:result", {detail: result}));
  element.message.textContent = "Requirements resolved. Operational status: not_run.";
}

async function resolvePlan() {
  invalidate();
  const revision = generation;
  element.resolve.disabled = true;
  element.message.textContent = "Verifying the input and resolving requirements…";
  try {
    if (new TextEncoder().encode(element.plan.value).length > 1024 * 1024) {
      throw new Error("the plan exceeds 1 MiB");
    }
    const payload = JSON.parse(element.plan.value);
    const result = await readResponse(await fetch("/api/plan", {
      method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload),
    }));
    if (revision === generation) render(result);
  } catch (error) {
    if (revision === generation) element.message.textContent = `Planning rejected: ${error.message}`;
  } finally {
    if (revision === generation) element.resolve.disabled = false;
  }
}

async function loadExample() {
  invalidate();
  const revision = generation;
  try {
    const plan = await readResponse(await fetch("/api/example"));
    if (revision !== generation) return;
    element.plan.value = JSON.stringify(plan, null, 2);
    element.message.textContent = "Pinned C0045 plan loaded. Resolve its requirements to inspect the result.";
  } catch (error) {
    if (revision === generation) element.message.textContent = `Example unavailable: ${error.message}`;
  }
}

async function importPlan() {
  invalidate();
  const revision = generation;
  const file = element.file.files[0];
  if (!file) return;
  if (file.size > 1024 * 1024) {
    element.message.textContent = "Import rejected: the plan exceeds 1 MiB.";
    return;
  }
  try {
    const contents = await file.text();
    if (revision !== generation) return;
    element.plan.value = contents;
    element.message.textContent = `Imported ${file.name} locally. Resolve its requirements to verify the content hash.`;
  } catch (error) {
    if (revision === generation) element.message.textContent = `Import failed: ${error.message}`;
  }
}

function download() {
  if (!currentResult) return;
  const name = currentResult.plan.campaign_id.replace(/[^a-zA-Z0-9_-]/g, "_");
  const url = URL.createObjectURL(new Blob([JSON.stringify(currentResult, null, 2) + "\n"], {type: "application/json"}));
  const link = document.createElement("a");
  link.href = url;
  link.download = `${name}.environment-planning.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

element.plan.addEventListener("input", invalidate);
element.file.addEventListener("change", importPlan);
element.example.addEventListener("click", loadExample);
element.resolve.addEventListener("click", resolvePlan);
element.download.addEventListener("click", download);
