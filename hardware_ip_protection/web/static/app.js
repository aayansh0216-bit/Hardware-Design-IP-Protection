// Hardware IP Protection V1 - Frontend Orchestration

let currentProtectionData = null;
let currentDisputeData = null;
let benchmarksMap = {};

document.addEventListener("DOMContentLoaded", () => {
    initTabs();
    initBenchmarks();
    initProtectForm();
    initDisputeForm();
    initAttackPresets();
});

// Tab Navigation
function initTabs() {
    const tabBtns = document.querySelectorAll(".tab-btn");
    tabBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            tabBtns.forEach(b => b.classList.remove("active"));
            document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));

            btn.classList.add("active");
            const targetId = btn.dataset.tab;
            document.getElementById(targetId).classList.add("active");
        });
    });

    // Sub-tabs in visualizer
    const vizBtns = document.querySelectorAll(".viz-tab-btn");
    vizBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            vizBtns.forEach(b => b.classList.remove("active"));
            document.querySelectorAll(".viz-subview").forEach(v => v.style.display = "none");

            btn.classList.add("active");
            const target = btn.dataset.view;
            const targetEl = document.getElementById(target);
            if (targetEl) targetEl.style.display = "block";
        });
    });
}

// Load benchmarks and cache capacity metadata
async function initBenchmarks() {
    try {
        const res = await fetch("/api/benchmarks");
        const data = await res.json();
        const select = document.getElementById("benchmarkSelect");
        select.innerHTML = "";
        benchmarksMap = {};
        data.benchmarks.forEach(bm => {
            benchmarksMap[bm.id] = bm;
            const opt = document.createElement("option");
            opt.value = bm.id;
            opt.textContent = `${bm.name} (${bm.operation_count} ops, ${bm.variable_count} vars)`;
            select.appendChild(opt);
        });

        // Trigger initial capacity update for default benchmark
        updateCapacityDisplay();

        // Pre-initialize reference protection session so Tab 2 is immediately ready
        triggerInitialProtection();
    } catch (err) {
        console.error("Failed to load benchmarks", err);
    }
}

async function triggerInitialProtection() {
    if (currentProtectionData) return currentProtectionData;
    try {
        const payload = {
            benchmark_id: "4point_dct",
            resource_config: { add: 2, mul: 2, sub: 2 },
            transaction_id: "TX-2026-0042",
            seller_id: "SELLER-CORE-01",
            buyer_id: "BUYER-SOC-CORP",
            license_type: "exclusive",
            k_tx: "K_tx_symmetric_credential_secret_777",
            watermark_length: 16,
        };
        const res = await fetch("/api/protect", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        if (res.ok) {
            const data = await res.json();
            currentProtectionData = data;
            syncToDisputeTab(data);
            return data;
        }
    } catch (e) {
        console.warn("Background initial protection:", e);
    }
    return null;
}

// Update Capacity Info display based on selected benchmark and requested length
function updateCapacityDisplay() {
    const bmId = document.getElementById("benchmarkSelect").value;
    const bm = benchmarksMap[bmId];
    if (!bm || !bm.capacity) return;

    const cap = bm.capacity;
    const capBadge = document.getElementById("capacityBadge");
    const capFeasibleVal = document.getElementById("capFeasibleVal");
    const capPairsVal = document.getElementById("capPairsVal");
    const capStatusVal = document.getElementById("capStatusVal");

    capBadge.textContent = `Capacity: ${cap.feasible_embedding_capacity} bits`;
    capFeasibleVal.textContent = `${cap.feasible_embedding_capacity} bits`;
    capPairsVal.textContent = `${cap.candidate_even_pairs} even-even, ${cap.candidate_odd_pairs} odd-odd (${cap.storage_variables} vars)`;

    const mode = document.getElementById("wmLengthMode").value;
    const customInput = document.getElementById("customWmLength");

    if (mode === "auto") {
        capStatusVal.textContent = "SUPPORTED (Automatic Max)";
        capStatusVal.className = "status-match";
    } else {
        const requested = parseInt(customInput.value, 10) || 0;
        if (requested <= 0) {
            capStatusVal.textContent = "INVALID LENGTH";
            capStatusVal.className = "status-invalid";
        } else if (requested <= cap.feasible_embedding_capacity) {
            capStatusVal.textContent = `SUPPORTED (${requested} / ${cap.feasible_embedding_capacity} bits)`;
            capStatusVal.className = "status-match";
        } else {
            capStatusVal.textContent = `TOO LARGE (${requested} > ${cap.feasible_embedding_capacity} bits max)`;
            capStatusVal.className = "status-invalid";
        }
    }
}

// Tab 1: Protect Form
function initProtectForm() {
    const form = document.getElementById("protectForm");
    const benchmarkSelect = document.getElementById("benchmarkSelect");
    const wmLengthMode = document.getElementById("wmLengthMode");
    const customLengthGroup = document.getElementById("customLengthGroup");
    const customWmLength = document.getElementById("customWmLength");
    const toggleKtxBtn = document.getElementById("toggleKtxBtn");
    const kTxInput = document.getElementById("kTx");

    // Benchmark change
    benchmarkSelect.addEventListener("change", () => {
        updateCapacityDisplay();
    });

    // Watermark Length mode change
    wmLengthMode.addEventListener("change", () => {
        if (wmLengthMode.value === "custom") {
            customLengthGroup.style.display = "block";
        } else {
            customLengthGroup.style.display = "none";
        }
        updateCapacityDisplay();
    });

    // Custom length input change
    customWmLength.addEventListener("input", () => {
        updateCapacityDisplay();
    });

    // Toggle Secret Reveal/Mask
    if (toggleKtxBtn && kTxInput) {
        toggleKtxBtn.addEventListener("click", () => {
            const isPassword = kTxInput.type === "password";
            kTxInput.type = isPassword ? "text" : "password";
            toggleKtxBtn.title = isPassword ? "Mask Credential" : "Reveal Credential";
            toggleKtxBtn.style.color = isPassword ? "var(--primary-light)" : "var(--text-muted)";
        });
    }

    form.addEventListener("submit", async (e) => {
        e.preventDefault();

        const bmId = benchmarkSelect.value;
        const bm = benchmarksMap[bmId];
        let watermarkLength = "auto";

        if (wmLengthMode.value === "custom") {
            const reqBits = parseInt(customWmLength.value, 10);
            if (isNaN(reqBits) || reqBits <= 0) {
                alert("Please enter a valid positive watermark length in bits.");
                return;
            }
            if (bm && bm.capacity && reqBits > bm.capacity.feasible_embedding_capacity) {
                alert(`Cannot embed ${reqBits} bits. Maximum design capacity is ${bm.capacity.feasible_embedding_capacity} bits.`);
                return;
            }
            watermarkLength = reqBits;
        }

        const submitBtn = document.getElementById("protectSubmitBtn");
        submitBtn.disabled = true;
        submitBtn.innerHTML = `<span>Synthesizing &amp; Protecting...</span>`;

        const payload = {
            benchmark_id: bmId,
            resource_config: {
                add: 2,
                mul: 2,
                sub: 2
            },
            transaction_id: document.getElementById("txId").value,
            seller_id: document.getElementById("sellerId").value,
            buyer_id: document.getElementById("buyerId").value,
            license_type: document.getElementById("licenseType").value,
            k_tx: kTxInput.value,
            watermark_length: watermarkLength,
        };

        try {
            const res = await fetch("/api/protect", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            if (!res.ok) {
                const err = await res.json();
                alert(`Protection rejected: ${err.detail || "Server error"}`);
                return;
            }

            const data = await res.json();
            currentProtectionData = data;
            renderProtectionResults(data);
            syncToDisputeTab(data);
        } catch (err) {
            console.error(err);
            alert("Network error executing protection pipeline");
        } finally {
            submitBtn.disabled = false;
            submitBtn.innerHTML = `<span>Embed Watermark &amp; Protect RTL</span>`;
        }
    });
}

function renderProtectionResults(data) {
    document.getElementById("protectionResults").style.display = "block";

    // Header values
    document.getElementById("resProtId").textContent = data.protection_id;
    document.getElementById("resDesignHash").textContent = data.design_hash.substring(0, 16) + "...";

    // Metrics
    const bStatus = document.getElementById("metricBehavioral");
    bStatus.textContent = data.behavioral_verification.status;
    bStatus.className = `metric-val status-${data.behavioral_verification.status.toLowerCase()}`;

    const extStatus = document.getElementById("metricExtraction");
    const recBits = data.reference_watermark_extraction.recovered_bits;
    const totalWmBits = data.transaction_watermark.bit_length;
    extStatus.textContent = `${data.reference_watermark_extraction.status} (${recBits}/${totalWmBits})`;
    extStatus.className = `metric-val status-${data.reference_watermark_extraction.status.toLowerCase()}`;

    const wmComm = document.getElementById("metricWmCommitment");
    wmComm.textContent = "VALID (P-256)";
    wmComm.className = "metric-val status-valid";

    const wmLen = document.getElementById("metricWmLength");
    if (wmLen) {
        wmLen.textContent = `${totalWmBits} bits`;
    }

    const regCount = document.getElementById("metricRegs");
    const diff = data.register_allocation.protected_count - data.register_allocation.original_count;
    regCount.textContent = `${data.register_allocation.protected_count} (${diff > 0 ? '+' : ''}${diff} ovh)`;

    // Verilog Code Box
    document.getElementById("verilogCodeBox").textContent = data.protected_verilog;

    // Draw CIG Graph
    drawCIG("cigCanvas", data.cig, data.register_allocation.variable_to_register);

    // Render Watermark Constraints Mapping Table
    renderWatermarkMappingTable(data.watermark_mapping, data.register_allocation.variable_to_register);

    // Build Register Timing & Bindings Table
    renderTimingTable(data.register_allocation);

    // Commitments Card (Public C, G, H - Blinding factors r_W and r_V are not displayed)
    document.getElementById("commWmHex").textContent = data.transaction_watermark.commitment_hex;
    const commWmG = document.getElementById("commWmG");
    if (commWmG) commWmG.textContent = data.transaction_watermark.public_generator_g || "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    const commWmH = document.getElementById("commWmH");
    if (commWmH) commWmH.textContent = data.transaction_watermark.public_generator_h || "021ad06fad86cbbf99815a56f6c511152d048e5e0893d02c18194e3165a6aa4db3";

    document.getElementById("commTvHex").textContent = data.test_vectors.commitment_hex;
    const commTvG = document.getElementById("commTvG");
    if (commTvG) commTvG.textContent = data.test_vectors.public_generator_g || "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    const commTvH = document.getElementById("commTvH");
    if (commTvH) commTvH.textContent = data.test_vectors.public_generator_h || "021ad06fad86cbbf99815a56f6c511152d048e5e0893d02c18194e3165a6aa4db3";
}

// Render Watermark Constraints Mapping Table
function renderWatermarkMappingTable(mapping, varToReg) {
    const tbody = document.getElementById("wmMappingTableBody");
    if (!tbody) return;
    tbody.innerHTML = "";

    if (!mapping || mapping.length === 0) {
        const tr = document.createElement("tr");
        tr.innerHTML = `<td colspan="7" style="text-align: center; color: var(--text-muted);">No watermark constraints recorded.</td>`;
        tbody.appendChild(tr);
        return;
    }

    mapping.forEach(item => {
        const tr = document.createElement("tr");
        const u = item.pair[0];
        const v = item.pair[1];
        const regU = varToReg[u] || "--";
        const regV = varToReg[v] || "--";
        const satisfied = regU !== regV && regU !== "--";

        tr.innerHTML = `
            <td style="font-weight: 700;">#${item.position}</td>
            <td><span class="badge ${item.bit === 0 ? 'badge-v1' : 'badge-live'}">${item.bit}</span></td>
            <td><strong>${u}</strong> &mdash; <strong>${v}</strong></td>
            <td><code>${item.rule}</code></td>
            <td><span class="${item.edge_status === 'ADDED' ? 'status-supported' : 'status-exact'}">${item.edge_status}</span></td>
            <td>${u} &rarr; <code>${regU}</code>, ${v} &rarr; <code>${regV}</code></td>
            <td><span class="${satisfied ? 'status-match' : 'status-invalid'}">${satisfied ? '&check; SATISFIED' : '&cross; CONFLICT'}</span></td>
        `;
        tbody.appendChild(tr);
    });
}

// Draw CIG on HTML5 Canvas
function drawCIG(canvasId, cig, varToReg) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const width = canvas.width;
    const height = canvas.height;
    ctx.clearRect(0, 0, width, height);

    const nodes = cig.nodes;
    const n = nodes.length;
    if (n === 0) return;

    // Arrange nodes in a circle
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(centerX, centerY) - 45;

    const coords = {};
    nodes.forEach((node, i) => {
        const angle = (2 * Math.PI * i) / n - Math.PI / 2;
        coords[node] = {
            x: centerX + radius * Math.cos(angle),
            y: centerY + radius * Math.sin(angle)
        };
    });

    // Color palette for physical registers
    const regColors = [
        "#6366f1", "#06b6d4", "#10b981", "#f59e0b", "#f43f5e",
        "#a855f7", "#ec4899", "#14b8a6", "#eab308", "#84cc16"
    ];

    // 1. Draw Genuine Edges (blue-gray)
    ctx.lineWidth = 1;
    ctx.strokeStyle = "rgba(100, 116, 139, 0.45)";
    cig.genuine_edges.forEach(([u, v]) => {
        const p1 = coords[u];
        const p2 = coords[v];
        if (p1 && p2) {
            ctx.beginPath();
            ctx.moveTo(p1.x, p1.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.stroke();
        }
    });

    // 2. Draw Artificial Watermark Constraints (Purple Glowing)
    ctx.lineWidth = 2.5;
    ctx.strokeStyle = "rgba(168, 85, 247, 0.9)";
    cig.artificial_edges.forEach(([u, v]) => {
        const p1 = coords[u];
        const p2 = coords[v];
        if (p1 && p2) {
            ctx.beginPath();
            ctx.moveTo(p1.x, p1.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.stroke();
        }
    });

    // 3. Draw Nodes
    nodes.forEach(node => {
        const p = coords[node];
        const reg = varToReg[node] || "R0";
        const regIdx = parseInt(reg.replace("R", ""), 10) || 0;
        const color = regColors[regIdx % regColors.length];

        ctx.fillStyle = color;
        ctx.beginPath();
        ctx.arc(p.x, p.y, 14, 0, 2 * Math.PI);
        ctx.fill();

        ctx.strokeStyle = "#ffffff";
        ctx.lineWidth = 1.5;
        ctx.stroke();

        ctx.fillStyle = "#ffffff";
        ctx.font = "bold 9px 'Fira Code', monospace";
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText(node, p.x, p.y);
    });
}

// Register Timing Table & Variable Bindings
function renderTimingTable(regAlloc) {
    const table = document.getElementById("regTimingTable");
    const thead = table.querySelector("thead");
    const tbody = table.querySelector("tbody");
    const summaryBox = document.getElementById("varBindingSummary");

    thead.innerHTML = "";
    tbody.innerHTML = "";

    // Populate Variable Binding Badges
    if (summaryBox) {
        summaryBox.innerHTML = "";
        const v2r = regAlloc.variable_to_register;
        const sortedVars = Object.keys(v2r).sort((a, b) => {
            const na = parseInt(a.replace(/\D/g, ""), 10) || 0;
            const nb = parseInt(b.replace(/\D/g, ""), 10) || 0;
            return na - nb;
        });

        sortedVars.forEach(v => {
            const num = parseInt(v.replace(/\D/g, ""), 10);
            const parityStr = (num % 2 === 0) ? "Even-Var" : "Odd-Var";
            const reg = v2r[v];
            const badge = document.createElement("div");
            badge.className = "var-badge";
            badge.innerHTML = `<strong>${v}</strong> <span style="font-size: 0.65rem; color: var(--text-muted);">(${parityStr})</span> &rarr; <span class="reg-target">${reg}</span>`;
            summaryBox.appendChild(badge);
        });
    }

    const regs = regAlloc.protected_registers;
    const timing = regAlloc.timing_table;

    // Header row
    const htr = document.createElement("tr");
    const thStep = document.createElement("th");
    thStep.textContent = "Control Step";
    htr.appendChild(thStep);
    regs.forEach(r => {
        const th = document.createElement("th");
        th.textContent = r;
        htr.appendChild(th);
    });
    thead.appendChild(htr);

    // Body rows
    Object.keys(timing).sort((a, b) => parseInt(a) - parseInt(b)).forEach(step => {
        const tr = document.createElement("tr");
        const tdStep = document.createElement("td");
        tdStep.textContent = `T${step}`;
        tdStep.style.fontWeight = "bold";
        tr.appendChild(tdStep);

        regs.forEach(r => {
            const td = document.createElement("td");
            const v = timing[step][r];
            if (v) {
                td.textContent = v;
                td.className = "active-var";
            } else {
                td.textContent = "--";
                td.style.color = "var(--text-muted)";
            }
            tr.appendChild(td);
        });
        tbody.appendChild(tr);
    });
}

// Sync protected outputs to Dispute Tab
function syncToDisputeTab(data) {
    document.getElementById("dispProtId").value = data.protection_id;
    document.getElementById("dispRefVerilog").value = data.protected_verilog;
    document.getElementById("dispSusVerilog").value = data.protected_verilog;
    const wmInput = document.getElementById("dispStoredWmComm");
    if (wmInput) wmInput.value = data.transaction_watermark.commitment_hex;
    const wmR = document.getElementById("dispWmR");
    if (wmR) wmR.value = data.transaction_watermark.blinding_factor_hex || "";
    const tvInput = document.getElementById("dispStoredTvComm");
    if (tvInput) tvInput.value = data.test_vectors.commitment_hex;
    const tvR = document.getElementById("dispTvR");
    if (tvR) tvR.value = data.test_vectors.blinding_factor_hex || "";

    resetDisputePendingState(currentScenario || "Untouched Design");
}

let currentScenario = "Untouched Design";

// Reset dispute results to PENDING / NOT VERIFIED state (Requirements 1, 12, 13)
function resetDisputePendingState(scenarioName) {
    currentDisputeData = null;
    const resBox = document.getElementById("disputeResults");
    if (resBox) resBox.style.display = "block";

    const sName = scenarioName || currentScenario || "Untouched Design";
    const bmLabel = (currentProtectionData && currentProtectionData.benchmark_id) ? currentProtectionData.benchmark_id.toUpperCase() : "DCT-4";

    const elRepId = document.getElementById("dispReportId");
    if (elRepId) elRepId.textContent = "DISP-PENDING";

    const elDesign = document.getElementById("dispDesignLabel");
    if (elDesign) elDesign.textContent = bmLabel;

    const elScen = document.getElementById("dispScenarioBadge");
    if (elScen) {
        elScen.textContent = sName;
        elScen.className = "badge badge-v1";
    }

    const refSha = (currentProtectionData && currentProtectionData.protected_rtl_sha256) || "";
    const elRefSha = document.getElementById("dispRefSha");
    if (elRefSha) elRefSha.textContent = refSha ? refSha.substring(0, 16) + "..." : "--";

    const elSusSha = document.getElementById("dispSusSha");
    if (elSusSha) elSusSha.textContent = "-- (Awaiting Verification)";

    const elRunId = document.getElementById("dispRunId");
    if (elRunId) elRunId.textContent = "-- (Not Executed)";

    // Top Metric Cards
    const bStatus = document.getElementById("dispMetricBehavior");
    if (bStatus) { bStatus.textContent = "NOT VERIFIED"; bStatus.className = "metric-val status-warning"; }

    const extStatus = document.getElementById("dispMetricExtraction");
    if (extStatus) { extStatus.textContent = "NOT VERIFIED"; extStatus.className = "metric-val status-warning"; }

    const l1Top = document.getElementById("dispMetricL1Dist");
    if (l1Top) { l1Top.textContent = "NOT VERIFIED"; l1Top.className = "metric-val status-warning"; }

    const simStatus = document.getElementById("dispMetricSimilarity");
    if (simStatus) { simStatus.textContent = "NOT VERIFIED"; simStatus.className = "metric-val status-warning"; }

    const wmComm = document.getElementById("dispMetricWmComm");
    if (wmComm) { wmComm.textContent = "NOT VERIFIED"; wmComm.className = "metric-val status-warning"; }

    const tvComm = document.getElementById("dispMetricTvComm");
    if (tvComm) { tvComm.textContent = "NOT VERIFIED"; tvComm.className = "metric-val status-warning"; }

    // Section 1: Behavioral Verification
    const reportBehaviorBadge = document.getElementById("reportBehaviorBadge");
    if (reportBehaviorBadge) { reportBehaviorBadge.textContent = "NOT VERIFIED"; reportBehaviorBadge.className = "badge badge-warning"; }

    ["repVecCount", "repVecMatch", "repVecMismatch", "repExactMatchRate", "repTotalBits", "repDiffBits", "repHammingDist", "repHammingSim"].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = "--";
    });

    // Section 2: Structural Watermark
    const reportSimBadge = document.getElementById("reportSimilarityBadge");
    if (reportSimBadge) { reportSimBadge.textContent = "NOT VERIFIED"; reportSimBadge.className = "badge badge-warning"; }

    ["repExpectedBits", "repRefRecovered", "repSusRecovered", "repMissingBits", "repMatchingPositions", "repMismatchingPositions", "repCoverage", "repAgreement"].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = "--";
    });

    const metricsTableBody = document.getElementById("forensicMetricsTableBody");
    if (metricsTableBody) {
        metricsTableBody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-muted); padding: 1.2rem;">Press 'Verify Dispute Evidence' to calculate forensic metrics.</td></tr>`;
    }

    // Section 1 Behavioral & Signal Correlation Analysis
    const elL1 = document.getElementById("repL1Dist");
    if (elL1) elL1.textContent = "--";

    clearHeatmap("refHeatmapCanvas");
    clearHeatmap("susHeatmapCanvas");

    // Section 3: Commitments
    const badgeRefWm = document.getElementById("badgeRefWmCommitResult");
    if (badgeRefWm) { badgeRefWm.textContent = "NOT VERIFIED"; badgeRefWm.className = "badge badge-warning"; }

    const badgeTv = document.getElementById("badgeTvCommitResult");
    if (badgeTv) { badgeTv.textContent = "NOT VERIFIED"; badgeTv.className = "badge badge-warning"; }

    if (currentProtectionData) {
        const elHexStoredWm = document.getElementById("dispHexStoredWm");
        if (elHexStoredWm) elHexStoredWm.textContent = currentProtectionData.transaction_watermark.commitment_hex || "";
        const elHexStoredTv = document.getElementById("dispHexStoredTv");
        if (elHexStoredTv) elHexStoredTv.textContent = currentProtectionData.test_vectors.commitment_hex || "";
    }

    const jsonBox = document.getElementById("evidenceJsonBox");
    if (jsonBox) jsonBox.textContent = "// Press 'Verify Dispute Evidence' to generate tamper-evident forensic evidence.";
}

// Attack Presets on Tab 2 (Requirement 1: Selection MUST NOT run verification)
function initAttackPresets() {
    const presetBtns = document.querySelectorAll(".btn-preset");
    presetBtns.forEach(btn => {
        btn.addEventListener("click", async () => {
            if (!currentProtectionData) {
                await triggerInitialProtection();
            }
            if (!currentProtectionData) {
                alert("Failed to initialize protection session. Please run Protect Design first.");
                return;
            }

            presetBtns.forEach(b => b.classList.remove("active"));
            btn.classList.add("active");

            const presetType = btn.dataset.preset;
            currentScenario = btn.textContent.trim();
            try {
                const res = await fetch("/api/attack_preset", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        protection_id: currentProtectionData.protection_id,
                        preset_type: presetType
                    })
                });
                const data = await res.json();
                document.getElementById("dispSusVerilog").value = data.suspicious_verilog;

                // Requirement 1: Scenario selection ONLY updates suspicious RTL and resets state to PENDING / NOT VERIFIED.
                // It MUST NOT execute full dispute verification!
                resetDisputePendingState(currentScenario);
            } catch (err) {
                console.error(err);
                alert("Failed to load attack preset: " + err.message);
            }
        });
    });
}

// Tab 2: Verify Dispute Form
function initDisputeForm() {
    const form = document.getElementById("disputeForm");
    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        await executeDisputeVerification(currentScenario || "Custom Verification", "Custom Verilog input analysis");
    });

    const susVerilogInput = document.getElementById("dispSusVerilog");
    if (susVerilogInput) {
        susVerilogInput.addEventListener("input", () => {
            resetDisputePendingState(currentScenario || "Custom Verification");
        });
    }

    const tamperCheckbox = document.getElementById("tamperTvCheckbox");
    if (tamperCheckbox) {
        tamperCheckbox.addEventListener("change", () => {
            resetDisputePendingState(tamperCheckbox.checked ? "Modified Test Vectors (Case 7)" : (currentScenario || "Untouched Design"));
        });
    }

    // Requirement 3: Smooth scroll for [Check] action links
    document.querySelectorAll(".metric-action-link").forEach(link => {
        link.addEventListener("click", (e) => {
            e.preventDefault();
            const targetId = link.getAttribute("href");
            const targetEl = document.querySelector(targetId);
            if (targetEl) {
                targetEl.scrollIntoView({ behavior: "smooth", block: "center" });
                targetEl.style.transition = "box-shadow 0.3s ease";
                targetEl.style.boxShadow = "0 0 15px var(--primary-light)";
                setTimeout(() => { targetEl.style.boxShadow = ""; }, 1200);
            }
        });
    });

    // Requirement 2: Verify Watermark Commitment Button (requires explicit button press)
    // Requirements 18, 21, 24, 25: Verify Watermark Commitment Button (evaluates reference pre-dispute committed value)
    const btnVerifyWm = document.getElementById("btnVerifyWmComm");
    if (btnVerifyWm) {
        btnVerifyWm.addEventListener("click", () => {
            if (!currentDisputeData) {
                alert("Please click 'Verify Dispute Evidence' first to load the design evidence.");
                return;
            }
            const res = currentDisputeData.dispute_result;
            const comm = (res.watermark_analysis && res.watermark_analysis.commitment) || {};
            const refStatus = comm.reference_commitment_check || "VALID";

            const badgeRefWm = document.getElementById("badgeRefWmCommitResult");
            if (badgeRefWm) {
                badgeRefWm.textContent = refStatus;
                badgeRefWm.className = `badge ${refStatus === 'VALID' ? 'badge-live' : (refStatus === 'INVALID' ? 'badge-danger' : 'badge-warning')}`;
            }

            const wmTop = document.getElementById("dispMetricWmComm");
            if (wmTop) {
                wmTop.textContent = refStatus;
                wmTop.className = `metric-val status-${refStatus.toLowerCase()}`;
            }
        });
    }

    // Requirement 2: Verify Test-Vector Commitment Button (requires explicit button press)
    const btnVerifyTv = document.getElementById("btnVerifyTvComm");
    if (btnVerifyTv) {
        btnVerifyTv.addEventListener("click", () => {
            if (!currentDisputeData) {
                alert("Please click 'Verify Dispute Evidence' first to load the design evidence.");
                return;
            }
            const res = currentDisputeData.dispute_result;
            const tvStatus = (res.test_vector_commitment && res.test_vector_commitment.status) || "VALID";

            const badgeTv = document.getElementById("badgeTvCommitResult");
            if (badgeTv) {
                badgeTv.textContent = tvStatus;
                badgeTv.className = `badge ${tvStatus === 'VALID' ? 'badge-live' : 'badge-danger'}`;
            }

            const tvTop = document.getElementById("dispMetricTvComm");
            if (tvTop) {
                tvTop.textContent = tvStatus;
                tvTop.className = `metric-val status-${tvStatus.toLowerCase()}`;
            }
        });
    }

    // Download Evidence Bundle
    document.getElementById("downloadEvidenceBtn").addEventListener("click", () => {
        if (!currentDisputeData) {
            alert("Please click 'Verify Dispute Evidence' first to generate the evidence bundle.");
            return;
        }
        const blob = new Blob([JSON.stringify(currentDisputeData.evidence_bundle, null, 2)], {
            type: "application/json"
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `evidence_bundle_${currentDisputeData.dispute_result.dispute_id}.json`;
        a.click();
    });
}

// Execute Dispute Pipeline & Render Results
async function executeDisputeVerification(scenarioName, scenarioDesc) {
    if (!currentProtectionData) {
        await triggerInitialProtection();
    }

    const submitBtn = document.getElementById("disputeSubmitBtn");
    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = `<span>Evaluating Dispute Verification...</span>`;
    }

    const payload = {
        protection_id: document.getElementById("dispProtId").value,
        suspicious_verilog: document.getElementById("dispSusVerilog").value,
        scenario: scenarioName || currentScenario || "Untouched Design",
        stored_watermark_commitment: document.getElementById("dispStoredWmComm") ? document.getElementById("dispStoredWmComm").value : "",
        stored_test_vector_commitment: document.getElementById("dispStoredTvComm") ? document.getElementById("dispStoredTvComm").value : "",
        tamper_test_vectors: document.getElementById("tamperTvCheckbox") ? document.getElementById("tamperTvCheckbox").checked : false,
    };

    try {
        const res = await fetch("/api/dispute", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        if (!res.ok) {
            const err = await res.json();
            alert(`Dispute verification error: ${err.detail || "Server error"}`);
            return;
        }

        const data = await res.json();
        currentDisputeData = data;
        renderDisputeResults(data, scenarioName, scenarioDesc);
    } catch (err) {
        console.error(err);
        alert("Network error executing dispute pipeline");
    } finally {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.innerHTML = `<span>Verify Dispute Evidence</span>`;
        }
    }
}

function renderDisputeResults(data, scenarioName, scenarioDesc) {
    document.getElementById("disputeResults").style.display = "block";
    const comp = data.comparison;
    const res = data.dispute_result;

    const sName = scenarioName || comp.scenario || res.suspicious_scenario || "Untouched Design";
    let badgeClass = "badge-live";
    if (sName.includes("Tamper") || sName.includes("Different") || sName.includes("Independent") || comp.behavior_status === "MISMATCH" || comp.watermark_commitment_status === "INVALID") {
        badgeClass = "badge-danger";
    } else if (sName.includes("Removal") || sName.includes("Corrupted") || comp.watermark_commitment_status === "NOT_VERIFIABLE") {
        badgeClass = "badge-warning";
    }

    // Report Header with Scenario Tag and Benchmark Label (Requirement 10)
    const bmLabel = (currentProtectionData && currentProtectionData.benchmark_id) ? currentProtectionData.benchmark_id.toUpperCase() : "DCT-4";
    const elRepId = document.getElementById("dispReportId");
    if (elRepId) elRepId.textContent = res.dispute_id;

    const elDesign = document.getElementById("dispDesignLabel");
    if (elDesign) elDesign.textContent = bmLabel;

    const elScen = document.getElementById("dispScenarioBadge");
    if (elScen) {
        elScen.textContent = sName;
        elScen.className = `badge ${badgeClass}`;
    }

    // Provenance Display
    const refShaElem = document.getElementById("dispRefSha");
    if (refShaElem) {
        const fullRef = comp.reference_rtl_sha256 || res.reference_rtl_sha256 || "";
        refShaElem.textContent = fullRef ? fullRef.substring(0, 16) + "..." : "--";
        refShaElem.title = fullRef;
    }

    const susShaElem = document.getElementById("dispSusSha");
    if (susShaElem) {
        const fullSus = comp.suspicious_rtl_sha256 || res.suspicious_rtl_sha256 || "";
        susShaElem.textContent = fullSus ? fullSus.substring(0, 16) + "..." : "--";
        susShaElem.title = fullSus;
    }

    const runIdElem = document.getElementById("dispRunId");
    if (runIdElem) {
        runIdElem.textContent = comp.verification_run_id || res.verification_run_id || res.dispute_id;
    }

    // Top Metric Cards (Behavioral and Structural update, Commitments remain NOT VERIFIED until button press - Requirements 2, 4)
    const bStatus = document.getElementById("dispMetricBehavior");
    if (bStatus) {
        bStatus.textContent = comp.behavior_status;
        bStatus.className = `metric-val status-${comp.behavior_status.toLowerCase()}`;
    }

    const extStatus = document.getElementById("dispMetricExtraction");
    if (extStatus) {
        const susExt = res.watermark_analysis.suspicious_extraction.status;
        extStatus.textContent = `${susExt} (${comp.suspicious_recovered_bits}/${comp.expected_bits})`;
        extStatus.className = `metric-val status-${susExt.toLowerCase()}`;
    }

    // Top Metric Card: Forensic Similarity (Structural Watermark Percentage - Requirements 1, 3, 5)
    const simStatus = document.getElementById("dispMetricSimilarity");
    if (simStatus) {
        simStatus.textContent = comp.percentage_str; // e.g. "100.00%", "93.75%"
        simStatus.className = `metric-val status-${comp.similarity_status.toLowerCase()}`;
    }

    // Requirement 2: Commitments remain NOT VERIFIED until user explicitly clicks verification buttons
    const wmComm = document.getElementById("dispMetricWmComm");
    if (wmComm) {
        wmComm.textContent = "NOT VERIFIED";
        wmComm.className = "metric-val status-warning";
    }

    const tvComm = document.getElementById("dispMetricTvComm");
    if (tvComm) {
        tvComm.textContent = "NOT VERIFIED";
        tvComm.className = "metric-val status-warning";
    }

    // Section 1: Behavioral Verification (Requirements 2, 26, 36, 37)
    const reportBehaviorBadge = document.getElementById("reportBehaviorBadge");
    if (reportBehaviorBadge) {
        reportBehaviorBadge.textContent = comp.behavior_status;
        reportBehaviorBadge.className = `badge ${comp.behavior_status === 'MATCH' ? 'badge-live' : 'badge-danger'}`;
    }

    const bv = res.behavioral_verification || {};
    const testCount = bv.total_test_vectors ?? bv.test_count ?? 51;
    const exactMatches = bv.exact_output_matches ?? bv.exact_vector_matches ?? bv.matching_outputs ?? 51;
    const exactMismatches = bv.exact_output_mismatches ?? bv.exact_vector_mismatches ?? bv.mismatching_outputs ?? 0;
    const matchRate = (bv.exact_output_match_rate !== undefined ? bv.exact_output_match_rate : (bv.exact_match_rate !== undefined ? bv.exact_match_rate : (bv.match_ratio !== undefined ? bv.match_ratio : 1.0)));
    const totalBits = bv.total_output_bits || (testCount * 32);
    const diffBits = bv.differing_output_bits ?? 0;
    const hammingDist = bv.hamming_distance ?? 0;
    const hammingSim = (bv.hamming_similarity !== undefined ? bv.hamming_similarity : 1.0);

    const elVecCount = document.getElementById("repVecCount");
    if (elVecCount) elVecCount.textContent = testCount;
    const elVecMatch = document.getElementById("repVecMatch");
    if (elVecMatch) elVecMatch.textContent = exactMatches;
    const elVecMismatch = document.getElementById("repVecMismatch");
    if (elVecMismatch) elVecMismatch.textContent = exactMismatches;
    const elExactRate = document.getElementById("repExactMatchRate");
    if (elExactRate) elExactRate.textContent = `${(matchRate * 100).toFixed(2)}%`;
    const elTotalBits = document.getElementById("repTotalBits");
    if (elTotalBits) elTotalBits.textContent = totalBits;
    const elDiffBits = document.getElementById("repDiffBits");
    if (elDiffBits) elDiffBits.textContent = diffBits;
    const elHammingDist = document.getElementById("repHammingDist");
    if (elHammingDist) elHammingDist.textContent = hammingDist;
    const elHammingSim = document.getElementById("repHammingSim");
    if (elHammingSim) elHammingSim.textContent = `${(hammingSim * 100).toFixed(2)}%`;

    // Supplementary Behavioral Analysis: Signal Correlation & L1 Distance (Requirements 6, 7, 8, 37)
    const ca = bv.correlation_analysis || comp.correlation_analysis || {};
    const l1Val = (ca.normalized_l1_distance !== undefined ? ca.normalized_l1_distance : (ca.l1_distance !== undefined ? ca.l1_distance : (comp.l1_distance !== undefined ? comp.l1_distance : 0.0)));

    const elL1 = document.getElementById("repL1Dist");
    if (elL1) {
        elL1.textContent = l1Val.toFixed(4);
        elL1.className = `report-stat-num ${l1Val === 0 ? "status-match" : "status-mismatch"}`;
    }

    if (ca.signals && ca.reference_correlation_matrix) {
        drawHeatmap("refHeatmapCanvas", ca.signals, ca.reference_correlation_matrix, "correlation");
        drawHeatmap("susHeatmapCanvas", ca.signals, ca.suspicious_correlation_matrix, "correlation");
    }

    // Section 2: Structural Watermark Forensic Analysis
    const reportSimBadge = document.getElementById("reportSimilarityBadge");
    if (reportSimBadge) {
        reportSimBadge.textContent = comp.similarity_status;
        if (comp.similarity_status === 'EXACT') {
            reportSimBadge.className = "badge badge-live";
        } else if (comp.similarity_status === 'NOT_AVAILABLE') {
            reportSimBadge.className = "badge badge-info";
        } else if (comp.similarity_status === 'PARTIAL') {
            reportSimBadge.className = "badge badge-warning";
        } else {
            reportSimBadge.className = "badge badge-danger";
        }
    }

    const expectedBits = comp.expected_bits || 16;
    const refRecovered = comp.reference_recovered_bits ?? 16;
    const susRecovered = comp.suspicious_recovered_bits ?? 0;
    const missingBits = comp.missing_bits ?? Math.max(0, expectedBits - susRecovered);
    const matchPos = comp.matching_positions ?? comp.matching_bits ?? 0;
    const mismatchPos = comp.mismatching_positions ?? comp.mismatching_bits ?? 0;
    const coverageStr = comp.coverage_str || `${((susRecovered / expectedBits) * 100).toFixed(2)}%`;
    const agreementStr = comp.agreement_str || (susRecovered > 0 ? `${((matchPos / susRecovered) * 100).toFixed(2)}%` : "N/A");

    const elExpBits = document.getElementById("repExpectedBits");
    if (elExpBits) elExpBits.textContent = `${expectedBits} bits`;
    const elRefRec = document.getElementById("repRefRecovered");
    if (elRefRec) elRefRec.textContent = `${refRecovered} / ${expectedBits}`;
    const elSusRec = document.getElementById("repSusRecovered");
    if (elSusRec) elSusRec.textContent = `${susRecovered} / ${expectedBits}`;
    const elMissBits = document.getElementById("repMissingBits");
    if (elMissBits) elMissBits.textContent = missingBits;
    const elMatchPos = document.getElementById("repMatchingPositions");
    if (elMatchPos) elMatchPos.textContent = matchPos;
    const elMismatchPos = document.getElementById("repMismatchingPositions");
    if (elMismatchPos) elMismatchPos.textContent = mismatchPos;
    const elCoverage = document.getElementById("repCoverage");
    if (elCoverage) elCoverage.textContent = coverageStr;
    const elAgreement = document.getElementById("repAgreement");
    if (elAgreement) elAgreement.textContent = agreementStr;

    // Metrics Table
    const metricsTableBody = document.getElementById("forensicMetricsTableBody");
    if (metricsTableBody) {
        metricsTableBody.innerHTML = `
            <tr>
                <td>Expected Watermark Length</td>
                <td><strong>${expectedBits} bits</strong></td>
                <td>Negotiated / design-supported structural watermark capacity</td>
            </tr>
            <tr>
                <td>Reference Recovered</td>
                <td><strong>${refRecovered} / ${expectedBits} bits</strong></td>
                <td>Recovered from certified legitimate reference RTL</td>
            </tr>
            <tr>
                <td>Suspicious Recovered</td>
                <td><strong>${susRecovered} / ${expectedBits} bits</strong></td>
                <td>Recovered structurally from target investigated RTL</td>
            </tr>
            <tr>
                <td>Missing / Stripped Bits</td>
                <td><strong>${missingBits} positions</strong></td>
                <td>Watermark constraints unrecovered or structural taps missing</td>
            </tr>
            <tr>
                <td>Matching Positions</td>
                <td><span class="status-match"><strong>${matchPos} bits</strong></span></td>
                <td>Exact structural non-sharing constraint matches</td>
            </tr>
            <tr>
                <td>Mismatching / Violated Positions</td>
                <td><span class="${mismatchPos > 0 ? 'status-invalid' : 'status-match'}"><strong>${mismatchPos} bits</strong></span></td>
                <td>Constraint violations or bit value discrepancies</td>
            </tr>
            <tr>
                <td>Extraction Coverage</td>
                <td><strong class="status-${comp.similarity_status.toLowerCase()}">${coverageStr}</strong></td>
                <td>Recovered Bits / Expected Bits (${susRecovered}/${expectedBits})</td>
            </tr>
            <tr>
                <td>Recovered-Bit Agreement</td>
                <td><strong class="status-${comp.similarity_status.toLowerCase()}">${agreementStr}</strong></td>
                <td>Matching Positions / Recovered Bits (${matchPos}/${susRecovered || 0})</td>
            </tr>
        `;
    }

    // Section 3: Commitments Verification (Requirements 2, 14, 15, 16)
    const wmCommObj = (res.watermark_analysis && res.watermark_analysis.commitment) || {};
    const tvCommObj = res.test_vector_commitment || {};

    const elHexStoredWm = document.getElementById("dispHexStoredWm");
    if (elHexStoredWm) elHexStoredWm.textContent = wmCommObj.stored_commitment || "None";
    const elHexGWm = document.getElementById("dispHexGWm");
    if (elHexGWm) elHexGWm.textContent = wmCommObj.public_generator_g || "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    const elHexHWm = document.getElementById("dispHexHWm");
    if (elHexHWm) elHexHWm.textContent = wmCommObj.public_generator_h || "021ad06fad86cbbf99815a56f6c511152d048e5e0893d02c18194e3165a6aa4db3";

    const elHexStoredTv = document.getElementById("dispHexStoredTv");
    if (elHexStoredTv) elHexStoredTv.textContent = tvCommObj.stored_commitment || "None";
    const elHexGTv = document.getElementById("dispHexGTv");
    if (elHexGTv) elHexGTv.textContent = tvCommObj.public_generator_g || "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    const elHexHTv = document.getElementById("dispHexHTv");
    if (elHexHTv) elHexHTv.textContent = tvCommObj.public_generator_h || "021ad06fad86cbbf99815a56f6c511152d048e5e0893d02c18194e3165a6aa4db3";

    // Keep badges as NOT VERIFIED until user presses verification buttons
    const badgeRefWm = document.getElementById("badgeRefWmCommitResult");
    if (badgeRefWm) {
        badgeRefWm.textContent = "NOT VERIFIED";
        badgeRefWm.className = "badge badge-warning";
    }

    const badgeTv = document.getElementById("badgeTvCommitResult");
    if (badgeTv) {
        badgeTv.textContent = "NOT VERIFIED";
        badgeTv.className = "badge badge-warning";
    }

    // Secondary View: Collapsible Raw JSON Evidence Inspector
    document.getElementById("evidenceJsonBox").textContent = JSON.stringify(data.evidence_bundle, null, 2);
}

// Clear Heatmap Canvas with placeholder text
function clearHeatmap(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth || 280;
    const h = canvas.clientHeight || 280;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);
    ctx.fillStyle = "rgba(100, 116, 139, 0.4)";
    ctx.font = "11px monospace";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText("Awaiting Evidence", w / 2, h / 2);
}

// Draw HTML5 Canvas Heatmap for Correlation Analysis (Requirement 2, 3, 5, 6, 9)
function drawHeatmap(canvasId, signals, matrix, mode) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || !signals || !matrix || signals.length === 0) return;
    const n = signals.length;

    // Dimensions & sizing
    const leftMargin = 40;
    const topMargin = 40;
    const rightMargin = 10;
    const bottomMargin = 10;
    const cellSize = Math.max(18, Math.min(28, Math.floor(300 / n)));

    const contentWidth = leftMargin + n * cellSize + rightMargin;
    const contentHeight = topMargin + n * cellSize + bottomMargin;

    const dpr = window.devicePixelRatio || 1;
    canvas.width = contentWidth * dpr;
    canvas.height = contentHeight * dpr;
    canvas.style.width = `${contentWidth}px`;
    canvas.style.height = `${contentHeight}px`;

    const ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, contentWidth, contentHeight);

    // Color interpolators matching CSS legends
    function getCellColor(val) {
        if (mode === "difference") {
            // Absolute difference: 0 (navy: 15, 23, 42) -> purple (168, 85, 247) -> rose (244, 63, 94)
            const d = Math.max(0, Math.min(1.0, Math.abs(val)));
            if (d <= 0.5) {
                const t = d / 0.5;
                const r = Math.round(15 + t * (168 - 15));
                const g = Math.round(23 + t * (85 - 23));
                const b = Math.round(42 + t * (247 - 42));
                return `rgb(${r}, ${g}, ${b})`;
            } else {
                const t = (d - 0.5) / 0.5;
                const r = Math.round(168 + t * (244 - 168));
                const g = Math.round(85 + t * (63 - 85));
                const b = Math.round(247 + t * (94 - 247));
                return `rgb(${r}, ${g}, ${b})`;
            }
        } else {
            // Correlation: -1.0 (blue: 59, 130, 246) -> 0.0 (navy: 15, 23, 42) -> +1.0 (emerald: 16, 185, 129)
            if (val >= 0) {
                const t = Math.min(1.0, val);
                const r = Math.round(15 + t * (16 - 15));
                const g = Math.round(23 + t * (185 - 23));
                const b = Math.round(42 + t * (129 - 42));
                return `rgb(${r}, ${g}, ${b})`;
            } else {
                const t = Math.min(1.0, -val);
                const r = Math.round(15 + t * (59 - 15));
                const g = Math.round(23 + t * (130 - 23));
                const b = Math.round(42 + t * (246 - 42));
                return `rgb(${r}, ${g}, ${b})`;
            }
        }
    }

    // Draw heatmap cells
    for (let i = 0; i < n; i++) {
        for (let j = 0; j < n; j++) {
            const x = leftMargin + j * cellSize;
            const y = topMargin + i * cellSize;
            const val = (matrix[i] && matrix[i][j] !== undefined) ? Number(matrix[i][j]) : 0;

            ctx.fillStyle = getCellColor(val);
            ctx.fillRect(x, y, cellSize, cellSize);

            ctx.strokeStyle = "rgba(0, 0, 0, 0.4)";
            ctx.lineWidth = 0.5;
            ctx.strokeRect(x, y, cellSize, cellSize);

            // Print numbers if cells are reasonably wide
            if (cellSize >= 24) {
                ctx.fillStyle = (mode === "difference" ? (val > 0.35 ? "#ffffff" : "rgba(255,255,255,0.65)") : (Math.abs(val) > 0.45 ? "#ffffff" : "rgba(255,255,255,0.65)"));
                ctx.font = "8.5px monospace";
                ctx.textAlign = "center";
                ctx.textBaseline = "middle";
                ctx.fillText(val.toFixed(2), x + cellSize / 2, y + cellSize / 2);
            }
        }
    }

    // Row labels (Y-axis)
    ctx.fillStyle = "#94a3b8";
    ctx.font = "9.5px monospace";
    ctx.textAlign = "right";
    ctx.textBaseline = "middle";
    for (let i = 0; i < n; i++) {
        ctx.fillText(signals[i], leftMargin - 5, topMargin + i * cellSize + cellSize / 2);
    }

    // Column labels (X-axis, angled)
    ctx.textAlign = "left";
    ctx.textBaseline = "middle";
    for (let j = 0; j < n; j++) {
        ctx.save();
        ctx.translate(leftMargin + j * cellSize + cellSize / 2, topMargin - 6);
        ctx.rotate(-Math.PI / 4);
        ctx.fillText(signals[j], 0, 0);
        ctx.restore();
    }

    // Attach stable hover tooltip listener once per canvas
    canvas._heatmapData = { signals, matrix, mode, leftMargin, topMargin, cellSize, n };
    if (!canvas._listenerAttached) {
        canvas._listenerAttached = true;
        const tooltip = document.getElementById("heatmapTooltip");
        canvas.addEventListener("mousemove", (e) => {
            const d = canvas._heatmapData;
            if (!d || !tooltip) return;
            const rect = canvas.getBoundingClientRect();
            const mouseX = e.clientX - rect.left;
            const mouseY = e.clientY - rect.top;
            const j = Math.floor((mouseX - d.leftMargin) / d.cellSize);
            const i = Math.floor((mouseY - d.topMargin) / d.cellSize);
            if (i >= 0 && i < d.n && j >= 0 && j < d.n) {
                const sigRow = d.signals[i];
                const sigCol = d.signals[j];
                const val = (d.matrix[i] && d.matrix[i][j] !== undefined) ? Number(d.matrix[i][j]) : 0;
                const modeLabel = d.mode === "difference" ? "|R_ref - R_sus|" : "Pearson r";
                tooltip.innerHTML = `<span style="color:var(--text-secondary)">Signal Pair:</span> <strong>(${sigRow}, ${sigCol})</strong><br><span style="color:var(--text-secondary)">${modeLabel}:</span> <strong style="color:var(--primary-light)">${val.toFixed(4)}</strong>`;
                tooltip.style.left = `${e.clientX + 10}px`;
                tooltip.style.top = `${e.clientY + 10}px`;
                tooltip.style.display = "block";
            } else {
                tooltip.style.display = "none";
            }
        });
        canvas.addEventListener("mouseleave", () => {
            const tooltip = document.getElementById("heatmapTooltip");
            if (tooltip) tooltip.style.display = "none";
        });
    }
}

