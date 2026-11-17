"use strict";

// Environment map: where each step runs (attacker, boundary, target) and which
// requirements each zone must satisfy, with the origin of every requirement.

const ZONE_LABELS = {
  attacker: "Attacker side",
  boundary: "Exposed boundary",
  target: "Target system",
};
const SOURCE_LABELS = {stix_field: "from STIX", curated_rule: "rule"};

function zoneOrder(domains) {
  const known = Object.keys(ZONE_LABELS).filter((domain) => domains.has(domain));
  const others = [...domains].filter((domain) => !(domain in ZONE_LABELS)).sort();
  return [...known, ...others];
}

function buildEnvironmentMap(plan, constraints) {
  const domainByTechnique = new Map(plan.steps.map((step) => [step.technique_id, step.execution_domain]));
  const domains = new Set(domainByTechnique.values());
  return zoneOrder(domains).map((domain) => ({
    domain,
    label: ZONE_LABELS[domain] || domain,
    steps: plan.steps.filter((step) => step.execution_domain === domain),
    requirements: constraints.requirements.filter((requirement) =>
      requirement.technique_ids.some((techniqueId) => domainByTechnique.get(techniqueId) === domain)),
  }));
}

function textElement(tag, className, text) {
  const node = document.createElement(tag);
  node.className = className;
  node.textContent = text;
  return node;
}

function counted(count, noun) {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

function stepRow(step) {
  const row = document.createElement("li");
  row.className = "map-step";
  row.append(textElement("span", "map-step-id", step.technique_id), textElement("span", "map-step-name", step.name));
  return row;
}

function requirementRow(requirement) {
  const row = document.createElement("li");
  row.className = "map-requirement";
  row.append(
    textElement("span", "map-requirement-kind", requirement.kind),
    textElement("span", "map-requirement-values", requirement.acceptable_values.join(", ")),
    textElement("span", `map-source map-source-${requirement.source}`, SOURCE_LABELS[requirement.source] || requirement.source),
  );
  row.title = `${requirement.requirement_id}: ${requirement.rationale}`;
  return row;
}

function platformSummaryRow(requirements, selectedPlatforms) {
  const accepted = requirements.every((requirement) =>
    requirement.acceptable_values.some((value) => selectedPlatforms.includes(value)));
  const selection = selectedPlatforms.join(", ") || "no selected platform";
  const row = document.createElement("li");
  row.className = "map-requirement";
  row.append(
    textElement("span", "map-requirement-kind", "platform"),
    textElement("span", "map-requirement-values",
      `${counted(requirements.length, "technique")} · ${accepted ? "all accept" : "not all accept"} ${selection}`),
    textElement("span", `map-source map-source-${accepted ? "covered" : "uncovered"}`, accepted ? "covered" : "gap"),
  );
  row.title = requirements.map((requirement) =>
    `${requirement.requirement_id}: ${requirement.acceptable_values.join(", ")}`).join("\n");
  return row;
}

function requirementRows(requirements, selectedPlatforms) {
  const platforms = requirements.filter((requirement) => requirement.kind === "platform");
  const others = requirements.filter((requirement) => requirement.kind !== "platform");
  const rows = others.map(requirementRow);
  return platforms.length > 0 ? [platformSummaryRow(platforms, selectedPlatforms), ...rows] : rows;
}

function zoneCard(zone, resolution) {
  const card = document.createElement("section");
  card.className = `map-zone map-zone-${zone.domain}`;
  card.append(textElement("h4", "map-zone-title", zone.label));
  if (zone.domain === "target") {
    const platforms = resolution.selected_platforms.join(", ") || "none";
    card.append(textElement("p", "map-zone-platform", `Selected platform: ${platforms}`));
  }
  const steps = document.createElement("ul");
  steps.className = "map-steps";
  steps.append(...zone.steps.map(stepRow));
  const requirements = document.createElement("ul");
  requirements.className = "map-requirements";
  requirements.append(...requirementRows(zone.requirements, resolution.selected_platforms));
  card.append(textElement("p", "map-label", counted(zone.steps.length, "step")), steps,
    textElement("p", "map-label", zone.requirements.length === 0
      ? "No requirement from the CTI" : counted(zone.requirements.length, "requirement")), requirements);
  return card;
}

function renderEnvironmentMap(container, result) {
  const zones = buildEnvironmentMap(result.plan, result.constraints);
  const cards = zones.flatMap((zone, index) => {
    const card = zoneCard(zone, result.constraints.platform_resolution);
    return index === 0 ? [card] : [textElement("span", "map-arrow", "→"), card];
  });
  container.replaceChildren(...cards);
}

if (typeof module !== "undefined") {
  module.exports = {buildEnvironmentMap};
} else {
  document.addEventListener("planning:result", (event) => {
    renderEnvironmentMap(document.getElementById("environment-map"), event.detail);
  });
}
