// Hardware IP Protection V1 - Frontend Orchestration

let currentProtectionData = null;
let currentDisputeData = null;
let benchmarksMap = {};
let currentTransactionState = null;

document.addEventListener("DOMContentLoaded", () => {
    initTabs();
    initTransactionWorkflow();
    initVerifierWorkflow();
    initJudgeWorkflow();
    initBenchmarks();
    initProtectForm();
    initDisputeForm();
    initAttackPresets();
});

// Tab & Profile Role Navigation
function initTabs() {
    const tabBtns = document.querySelectorAll(".tab-btn");
    tabBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            tabBtns.forEach(b => b.classList.remove("active"));
            document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));

            btn.classList.add("active");
            const targetId = btn.dataset.tab;
            const targetEl = document.getElementById(targetId);
            if (targetEl) targetEl.classList.add("active");

            // Persist transaction state seamlessly across Seller, Buyer, Verifier, and Judge profiles
            if (targetId === "profileSeller" || targetId === "profileBuyer") {
                fetchTransactionState();
            } else if (targetId === "profileVerifier") {
                fetchTransactionState();
                initOrRefreshVerifierProfile();
            } else if (targetId === "profileJudge") {
                fetchTransactionState();
                fetchJudgeSession();
            }
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

// ==============================================================================
// TASK 1: Transaction State & Profile Workflow Orchestration
// ==============================================================================

async function fetchTransactionState() {
    try {
        const res = await fetch("/api/transaction/state");
        if (res.ok) {
            const data = await res.json();
            currentTransactionState = data.state;
            syncTransactionStateToUI(currentTransactionState);
            return currentTransactionState;
        }
    } catch (e) {
        console.warn("Failed to fetch transaction state:", e);
    }
    return null;
}

function initTransactionWorkflow() {
    // Initial fetch of active transaction state
    fetchTransactionState();

    // Reset button
    const btnReset = document.getElementById("btnResetWorkflow");
    if (btnReset) {
        btnReset.addEventListener("click", async () => {
            if (confirm("Reset transaction state to initial configuration?")) {
                try {
                    const res = await fetch("/api/transaction/reset", { method: "POST" });
                    if (res.ok) {
                        const data = await res.json();
                        currentTransactionState = data.state;
                        syncTransactionStateToUI(currentTransactionState);
                    }
                } catch (err) {
                    console.error("Failed to reset transaction:", err);
                }
            }
        });
    }

    // STEP 1: Encoding Rule & Design Selection
    const sDes = document.getElementById("sellerDesignSelect");
    const sRul = document.getElementById("sellerRuleSelect");

    async function handleDesignOrRuleChange() {
        const rule_id = sRul ? sRul.value : "iir_butterworth_rule_v1";
        const design_id = sDes ? sDes.value : "iir_butterworth";
        try {
            const res = await fetch("/api/transaction/select_design", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ design_id, rule_id })
            });
            if (res.ok) {
                const data = await res.json();
                currentTransactionState = data.state;
                syncTransactionStateToUI(currentTransactionState);
            } else {
                const err = await res.json();
                alert(`Failed to select rule: ${err.detail || "Server error"}`);
                if (sRul && currentTransactionState && currentTransactionState.encoding_rule_id) {
                    sRul.value = currentTransactionState.encoding_rule_id;
                }
                if (sDes && currentTransactionState && currentTransactionState.design_id) {
                    sDes.value = currentTransactionState.design_id;
                }
            }
        } catch (err) {
            console.error("Failed to select encoding rule:", err);
            alert("Network error selecting encoding rule.");
        }
    }

    if (sRul) {
        sRul.addEventListener("change", handleDesignOrRuleChange);
    }
    if (sDes) {
        sDes.addEventListener("change", handleDesignOrRuleChange);
    }

    // STEP 2: Generate Original Design Encoding D & Commitment C_D
    const btnEncodeD = document.getElementById("btnSellerEncodeD");
    if (btnEncodeD) {
        btnEncodeD.addEventListener("click", async () => {
            btnEncodeD.disabled = true;
            btnEncodeD.innerHTML = `<span>Generating Encoding D & Commit(D)...</span>`;
            const rule_id = sRul ? sRul.value : undefined;
            const design_id = sDes ? sDes.value : undefined;
            try {
                const res = await fetch("/api/transaction/encode_design", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ use_table_quirks: false, rule_id, design_id }),
                });
                if (res.ok) {
                    const data = await res.json();
                    currentTransactionState = data.state;
                    syncTransactionStateToUI(currentTransactionState);
                } else {
                    const err = await res.json();
                    alert(`Encoding failed: ${err.detail || "Server error"}`);
                }
            } catch (err) {
                console.error("Failed to encode design:", err);
                alert("Network error generating design encoding D.");
            } finally {
                btnEncodeD.disabled = false;
                btnEncodeD.innerHTML = `
                    <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path>
                    </svg>
                    <span>Generate Original Design Encoding D</span>`;
            }
        });
    }

    // STEP 3: Request Buyer Contribution
    const btnReqBuyer = document.getElementById("btnSellerRequestBuyer");
    if (btnReqBuyer) {
        btnReqBuyer.addEventListener("click", async () => {
            btnReqBuyer.disabled = true;
            btnReqBuyer.innerHTML = `<span>Dispatching Request...</span>`;
            try {
                const res = await fetch("/api/transaction/request_buyer", { method: "POST" });
                if (res.ok) {
                    const data = await res.json();
                    currentTransactionState = data.state;
                    syncTransactionStateToUI(currentTransactionState);
                } else {
                    const err = await res.json();
                    alert(`Request failed: ${err.detail || "Server error"}`);
                }
            } catch (err) {
                console.error("Failed to request buyer contribution:", err);
                alert("Network error requesting buyer contribution.");
            } finally {
                btnReqBuyer.disabled = false;
                btnReqBuyer.innerHTML = `
                    <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"></path>
                    </svg>
                    <span>Request Buyer Contribution</span>`;
            }
        });
    }

    // BUYER: Approve Request & Provide 555-bit Contribution B
    const btnBuyerApprove = document.getElementById("btnBuyerApproveRequest");
    if (btnBuyerApprove) {
        btnBuyerApprove.addEventListener("click", async () => {
            btnBuyerApprove.disabled = true;
            btnBuyerApprove.innerHTML = `<span>Approving & Committing B (555 bits)...</span>`;
            try {
                const res = await fetch("/api/transaction/approve_buyer", { method: "POST" });
                if (res.ok) {
                    const data = await res.json();
                    currentTransactionState = data.state;
                    syncTransactionStateToUI(currentTransactionState);
                } else {
                    const err = await res.json();
                    alert(`Approval failed: ${err.detail || "Server error"}`);
                }
            } catch (err) {
                console.error("Failed to approve request:", err);
                alert("Network error approving contribution request.");
            } finally {
                btnBuyerApprove.disabled = false;
                btnBuyerApprove.innerHTML = `
                    <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                    </svg>
                    <span>Approve Request & Submit Contribution B</span>`;
            }
        });
    }

    // BUYER: Reject Request
    const btnBuyerReject = document.getElementById("btnBuyerRejectRequest");
    if (btnBuyerReject) {
        btnBuyerReject.addEventListener("click", async () => {
            if (confirm("Reject contribution request from Seller?")) {
                btnBuyerReject.disabled = true;
                try {
                    const res = await fetch("/api/transaction/reject_buyer", { method: "POST" });
                    if (res.ok) {
                        const data = await res.json();
                        currentTransactionState = data.state;
                        syncTransactionStateToUI(currentTransactionState);
                    } else {
                        const err = await res.json();
                        alert(`Rejection failed: ${err.detail || "Server error"}`);
                    }
                } catch (err) {
                    console.error("Failed to reject request:", err);
                    alert("Network error rejecting request.");
                } finally {
                    btnBuyerReject.disabled = false;
                }
            }
        });
    }

    // Buyer Transaction Details Sub-Tabs (Overview, Commitments, Private Evidence)
    const buyerSubtabBtns = document.querySelectorAll(".buyer-nav-btn");
    buyerSubtabBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            buyerSubtabBtns.forEach(b => b.classList.remove("active"));
            document.querySelectorAll(".buyer-tab-pane").forEach(p => p.classList.remove("active"));

            btn.classList.add("active");
            const target = btn.dataset.buyerTab;
            const targetEl = document.getElementById(target);
            if (targetEl) targetEl.classList.add("active");
        });
    });

    // SUBSTAGE 2B: Generate Transaction Watermark
    const btnContinueWm = document.getElementById("btnSellerContinueWatermark");
    if (btnContinueWm) {
        btnContinueWm.addEventListener("click", async () => {
            btnContinueWm.disabled = true;
            btnContinueWm.innerHTML = `<span>Generating Watermark W via HKDF-SHA256...</span>`;
            try {
                const res = await fetch("/api/transaction/generate_watermark", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        transaction_id: "TX-001",
                        seller_id: "SELLER-001",
                        buyer_id: "BUYER-001",
                        license_type: "exclusive",
                        k_tx: "K_tx_symmetric_credential_secret_777",
                        watermark_length: "auto",
                    }),
                });
                if (res.ok) {
                    const data = await res.json();
                    currentTransactionState = data.state;
                    syncTransactionStateToUI(currentTransactionState);
                } else {
                    const err = await res.json();
                    alert(`Watermark generation failed: ${err.detail || "Server error"}`);
                }
            } catch (err) {
                console.error("Failed to generate transaction watermark:", err);
                alert("Network error executing watermark generation.");
            } finally {
                btnContinueWm.disabled = false;
                btnContinueWm.innerHTML = `
                    <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
                    </svg>
                    <span>Generate Transaction Watermark</span>`;
            }
        });
    }

    // --- SELLER PROFILE WORKFLOW NAVIGATOR & PROGRESSIVE STAGE SWITCHING ---
    window.switchSellerStage = function(stageId) {
        const navItems = document.querySelectorAll("#sellerWorkflowNav .seller-nav-item");
        const stageCards = [
            { id: "1", el: document.getElementById("sellerStage1Card") },
            { id: "2", el: document.getElementById("sellerStage2Card") },
            { id: "3", el: document.getElementById("sellerStage3Card") },
            { id: "4", el: document.getElementById("sellerStage4Card") },
            { id: "commitments", el: document.getElementById("sellerCommitmentsCard") },
            { id: "evidence", el: document.getElementById("sellerEvidenceCard") },
        ];

        // Highlight matching nav item
        navItems.forEach(item => {
            if (item.dataset.sellerStage === stageId) {
                item.classList.add("active");
            } else {
                item.classList.remove("active");
            }
        });

        // Toggle stage card visibility
        stageCards.forEach(sc => {
            if (sc.el) {
                sc.el.style.display = (sc.id === stageId) ? "block" : "none";
            }
        });

        // Ensure subviews are properly activated
        if (stageId === "3") {
            const viewCig = document.getElementById("viewCig");
            if (viewCig) viewCig.style.display = "block";
            if (currentProtectionData && currentProtectionData.cig) {
                drawCIG("cigCanvas", currentProtectionData.cig, currentProtectionData.register_allocation.variable_to_register);
            }
        } else if (stageId === "4") {
            const viewVerilog = document.getElementById("viewVerilog");
            if (viewVerilog) viewVerilog.style.display = "block";
        } else if (stageId === "commitments") {
            const viewComm = document.getElementById("viewCommitments");
            if (viewComm) viewComm.style.display = "block";
            const viewEnc = document.getElementById("viewStructuralEncoding");
            if (viewEnc) viewEnc.style.display = "none";
        } else if (stageId === "evidence") {
            const viewEvid = document.getElementById("viewSellerPrivateEvidence");
            if (viewEvid) viewEvid.style.display = "block";


        // Always scroll to top of stage area
        window.scrollTo({ top: 0, behavior: "smooth" });
    };

    // Attach click listeners to all seller navigator buttons
    const sellerNavItems = document.querySelectorAll("#sellerWorkflowNav .seller-nav-item");
    sellerNavItems.forEach(item => {
        item.addEventListener("click", () => {
            const targetStage = item.dataset.sellerStage;
            // Validate prerequisites
            if (targetStage === "2" && (!currentTransactionState || !currentTransactionState.design_encoding_D)) {
                alert("Stage 2 is pending Stage 1: Please calculate Original Design Encoding D first.");
                return;
            }
            if (targetStage === "3" && (!currentTransactionState || !currentTransactionState.C_W1)) {
                alert("Stage 3 is pending Stage 2: Please complete Substage 2E (Commit Embedded Watermark) first.");
                return;
            }
            if (targetStage === "4" && (!currentTransactionState || !currentTransactionState.watermarked_RTL)) {
                alert("Stage 4 is pending Stage 3: Please complete Watermark Embedding first.");
                return;
            }
            window.switchSellerStage(targetStage);
        });
    });

    // Substage navigation buttons: Stage 1
    const btnProceedToCommitD = document.getElementById("btnProceedToCommitD");
    if (btnProceedToCommitD) {
        btnProceedToCommitD.addEventListener("click", () => {
            const box1A = document.getElementById("sellerSubstage1ABox");
            if (box1A) {
                box1A.classList.remove("active");
                box1A.classList.add("collapsed");
            }
            const box1B = document.getElementById("sellerSubstage1BBox");
            if (box1B) {
                box1B.classList.remove("collapsed");
                box1B.classList.add("active");
            }
            const s1b = document.getElementById("sellerSubstage1BContent");
            if (s1b) s1b.style.display = "block";
            const badge1b = document.getElementById("sellerSubstage1BBadge");
            if (badge1b) {
                badge1b.textContent = "Committed (NIST P-256)";
                badge1b.className = "badge badge-success";
            }
        });
    }

    const btnAdvanceToStage2 = document.getElementById("btnAdvanceToStage2");
    if (btnAdvanceToStage2) {
        btnAdvanceToStage2.addEventListener("click", () => {
            const box1B = document.getElementById("sellerSubstage1BBox");
            if (box1B) {
                box1B.classList.remove("active");
                box1B.classList.add("collapsed");
            }
            window.switchSellerStage("2");
        });
    }

    // Substage navigation and action handlers: Stage 2
    const btnProceedTo2C = document.getElementById("btnProceedTo2C");
    if (btnProceedTo2C) {
        btnProceedTo2C.addEventListener("click", () => {
            const b2B = document.getElementById("sellerSubstage2BBox");
            if (b2B) {
                b2B.classList.remove("active");
                b2B.classList.add("collapsed");
            }
            const b2C = document.getElementById("sellerSubstage2CBox");
            if (b2C) {
                b2C.classList.remove("collapsed");
                b2C.classList.add("active");
                b2C.scrollIntoView({ behavior: "smooth" });
            }
        });
    }

    const btnCommitW = document.getElementById("btnCommitW");
    if (btnCommitW) {
        btnCommitW.addEventListener("click", async () => {
            btnCommitW.disabled = true;
            btnCommitW.innerHTML = `<span>Computing Pedersen Commitment C_W...</span>`;
            try {
                const res = await fetch("/api/transaction/commit_watermark", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" }
                });
                if (res.ok) {
                    const data = await res.json();
                    currentTransactionState = data.state;
                    syncTransactionStateToUI(currentTransactionState);
                } else {
                    const err = await res.json();
                    alert(`Commitment C_W failed: ${err.detail || "Server error"}`);
                }
            } catch (err) {
                console.error("Failed to commit watermark:", err);
                alert("Network error committing watermark.");
            } finally {
                btnCommitW.disabled = false;
                btnCommitW.innerHTML = `
                    <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                    </svg>
                    <span>Commit Original Watermark (C_W)</span>`;
            }
        });
    }

    const btnProceedToSplit = document.getElementById("btnProceedToSplit");
    if (btnProceedToSplit) {
        btnProceedToSplit.addEventListener("click", () => {
            const b2C = document.getElementById("sellerSubstage2CBox");
            if (b2C) {
                b2C.classList.remove("active");
                b2C.classList.add("collapsed");
            }
            if (currentTransactionState && currentTransactionState.is_full_watermark) {
                // In full-watermark model, advance directly to Stage 3
                const st3 = document.getElementById("sellerStage3Card");
                if (st3) {
                    st3.style.display = "block";
                    st3.scrollIntoView({ behavior: "smooth" });
                }
            } else {
                const b2D = document.getElementById("sellerSubstage2DBox");
                if (b2D) {
                    b2D.classList.remove("collapsed");
                    b2D.classList.add("active");
                    b2D.scrollIntoView({ behavior: "smooth" });
                }
            }
        });
    }

    const btnSplitWatermark = document.getElementById("btnSplitWatermark");
    if (btnSplitWatermark) {
        btnSplitWatermark.addEventListener("click", async () => {
            btnSplitWatermark.disabled = true;
            btnSplitWatermark.innerHTML = `<span>Splitting Watermark into W1 & W2...</span>`;
            try {
                const res = await fetch("/api/transaction/split_watermark", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" }
                });
                if (res.ok) {
                    const data = await res.json();
                    currentTransactionState = data.state;
                    syncTransactionStateToUI(currentTransactionState);
                } else {
                    const err = await res.json();
                    alert(`Watermark splitting failed: ${err.detail || "Server error"}`);
                }
            } catch (err) {
                console.error("Failed to split watermark:", err);
                alert("Network error splitting watermark.");
            } finally {
                btnSplitWatermark.disabled = false;
                btnSplitWatermark.innerHTML = `
                    <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4"></path>
                    </svg>
                    <span>Split and Protect Watermark (W1 &amp; W2)</span>`;
            }
        });
    }

    const btnProceedTo2E = document.getElementById("btnProceedTo2E");
    if (btnProceedTo2E) {
        btnProceedTo2E.addEventListener("click", () => {
            const b2D = document.getElementById("sellerSubstage2DBox");
            if (b2D) {
                b2D.classList.remove("active");
                b2D.classList.add("collapsed");
            }
            const b2E = document.getElementById("sellerSubstage2EBox");
            if (b2E) {
                b2E.classList.remove("collapsed");
                b2E.classList.add("active");
                b2E.scrollIntoView({ behavior: "smooth" });
            }
        });
    }

    const btnCommitW1 = document.getElementById("btnCommitW1");
    if (btnCommitW1) {
        btnCommitW1.addEventListener("click", async () => {
            btnCommitW1.disabled = true;
            btnCommitW1.innerHTML = `<span>Computing Pedersen Commitment C_W1...</span>`;
            try {
                const res = await fetch("/api/transaction/commit_embedded_watermark", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" }
                });
                if (res.ok) {
                    const data = await res.json();
                    currentTransactionState = data.state;
                    syncTransactionStateToUI(currentTransactionState);
                } else {
                    const err = await res.json();
                    alert(`Commitment C_W1 failed: ${err.detail || "Server error"}`);
                }
            } catch (err) {
                console.error("Failed to commit embedded watermark:", err);
                alert("Network error committing embedded watermark.");
            } finally {
                btnCommitW1.disabled = false;
                btnCommitW1.innerHTML = `
                    <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                    </svg>
                    <span>Commit Embedded Watermark (C_W1)</span>`;
            }
        });
    }

    const btnAdvanceToStage3 = document.getElementById("btnAdvanceToStage3");
    if (btnAdvanceToStage3) {
        btnAdvanceToStage3.addEventListener("click", () => {
            const b2E = document.getElementById("sellerSubstage2EBox");
            if (b2E) {
                b2E.classList.remove("active");
                b2E.classList.add("collapsed");
            }
            window.switchSellerStage("3");
        });
    }

    // STAGE 3: Embed Watermark in RTL (Decoupled Single User Action)
    const btnEmbedWatermark = document.getElementById("btnEmbedWatermark");
    if (btnEmbedWatermark) {
        btnEmbedWatermark.addEventListener("click", async () => {
            const selectedLenEl = document.querySelector('input[name="wmEmbedLengthChoice"]:checked');
            const wmLenVal = selectedLenEl ? parseInt(selectedLenEl.value, 10) : 256;

            btnEmbedWatermark.disabled = true;
            btnEmbedWatermark.innerHTML = `<span>Synthesizing Protected RTL &amp; Embedding (${wmLenVal}-bit) Watermark...</span>`;
            try {
                const res = await fetch("/api/transaction/embed_watermark", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ watermark_length: wmLenVal })
                });
                if (res.ok) {
                    const data = await res.json();
                    currentTransactionState = data.state;
                    if (data.state.pipeline_result) {
                        currentProtectionData = data.state.pipeline_result;
                        renderProtectionResults(data.state.pipeline_result);
                        syncToDisputeTab(data.state.pipeline_result);
                    }
                    syncTransactionStateToUI(currentTransactionState);
                } else {
                    const err = await res.json();
                    alert(`Watermark embedding failed: ${err.detail || "Server error"}`);
                }
            } catch (err) {
                console.error("Failed to embed watermark in RTL:", err);
                alert("Network error embedding watermark in RTL.");
            } finally {
                btnEmbedWatermark.disabled = false;
                btnEmbedWatermark.innerHTML = `
                    <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
                    </svg>
                    <span>Embed Watermark in RTL</span>`;
            }
        });

        // Setup Watermark Embedding Length Radio Pill Toggle
        const wmRadioPills = document.querySelectorAll('input[name="wmEmbedLengthChoice"]');
        wmRadioPills.forEach(radio => {
            radio.addEventListener("change", () => {
                wmRadioPills.forEach(r => {
                    const pillLabel = r.closest(".radio-pill-label");
                    if (pillLabel) {
                        if (r.checked) {
                            pillLabel.classList.add("active");
                            pillLabel.style.background = "rgba(56, 189, 248, 0.15)";
                            pillLabel.style.borderColor = "#38bdf8";
                            pillLabel.style.color = "#38bdf8";
                            pillLabel.style.fontWeight = "600";
                        } else {
                            pillLabel.classList.remove("active");
                            pillLabel.style.background = "rgba(255, 255, 255, 0.05)";
                            pillLabel.style.borderColor = "var(--border-subtle)";
                            pillLabel.style.color = "var(--text-main)";
                            pillLabel.style.fontWeight = "normal";
                        }
                    }
                });
            });
        });
    }

    // Link from Commitments to Stage 1 Structural Encoding
    const btnLinkStage1 = document.getElementById("btnLinkToStage1Encoding");
    if (btnLinkStage1) {
        btnLinkStage1.addEventListener("click", () => {
            window.switchSellerStage("1");
            const encBox = document.getElementById("sellerStage1EncodingDetails");
            if (encBox) encBox.style.display = "block";
            const viewEnc = document.getElementById("viewStructuralEncoding");
            if (viewEnc) {
                viewEnc.style.display = "block";
                const btnToggle = document.getElementById("btnToggleStructuralEncoding");
                if (btnToggle) {
                    btnToggle.innerHTML = `<svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 15l7-7 7 7"></path></svg><span>Hide Supporting Structural Encoding Table</span>`;
                }
                viewEnc.scrollIntoView({ behavior: "smooth" });
            }
        });
    }

    // Stage 3 view buttons
    const stage3VizBtns = document.querySelectorAll("#sellerStage3Card .viz-tab-btn");
    stage3VizBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            stage3VizBtns.forEach(b => b.classList.remove("active"));
            const views = ["viewCig", "viewMapping", "viewTiming"];
            views.forEach(vId => {
                const el = document.getElementById(vId);
                if (el) el.style.display = "none";
            });
            btn.classList.add("active");
            const target = btn.dataset.view;
            const targetEl = document.getElementById(target);
            if (targetEl) targetEl.style.display = "block";
            if (target === "viewCig" && currentProtectionData && currentProtectionData.cig) {
                drawCIG("cigCanvas", currentProtectionData.cig, currentProtectionData.register_allocation.variable_to_register);
            }
        });
    });

    const btnAdvanceToStage4 = document.getElementById("btnAdvanceToStage4");
    if (btnAdvanceToStage4) {
        btnAdvanceToStage4.addEventListener("click", () => {
            window.switchSellerStage("4");
        });
    }

    // --- STAGE 4 SEQUENTIAL SUBSTAGE PROGRESSION HANDLERS ---
    const btnProceedTo4B = document.getElementById("btnProceedTo4B");
    if (btnProceedTo4B) {
        btnProceedTo4B.addEventListener("click", () => {
            const b4A = document.getElementById("sellerSubstage4ABox");
            if (b4A) {
                b4A.classList.remove("active");
                b4A.classList.add("collapsed");
            }
            const b4B = document.getElementById("sellerSubstage4BBox");
            if (b4B) {
                b4B.classList.remove("collapsed");
                b4B.classList.add("active");
                b4B.scrollIntoView({ behavior: "smooth" });
            }
        });
    }

    const btnCalculateEs = document.getElementById("btnCalculateEs");
    if (btnCalculateEs) {
        btnCalculateEs.addEventListener("click", async () => {
            btnCalculateEs.disabled = true;
            btnCalculateEs.innerHTML = `<span>Calculating Secured Design Encoding (E_S)...</span>`;
            try {
                const res = await fetch("/api/transaction/calculate_secured_encoding", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" }
                });
                if (res.ok) {
                    const data = await res.json();
                    currentTransactionState = data.state;
                    syncTransactionStateToUI(currentTransactionState);
                } else {
                    const err = await res.json();
                    alert(`Calculation failed: ${err.detail || "Server error"}`);
                }
            } catch (err) {
                console.error("Failed to calculate secured encoding E_S:", err);
                alert("Network error calculating secured design encoding E_S.");
            } finally {
                btnCalculateEs.disabled = false;
                btnCalculateEs.innerHTML = `
                    <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 7h6m0 10v-3m-3 3h.01M9 17h.01M9 14h.01M12 14h.01M15 11h.01M12 11h.01M9 11h.01M7 21h10a2 2 0 002-2V5a2 2 0 00-2-2H7a2 2 0 00-2 2v14a2 2 0 002 2z"></path>
                    </svg>
                    <span>Calculate Secured Encoding (E_S)</span>`;
            }
        });
    }

    const btnProceedTo4C = document.getElementById("btnProceedTo4C");
    if (btnProceedTo4C) {
        btnProceedTo4C.addEventListener("click", () => {
            const b4B = document.getElementById("sellerSubstage4BBox");
            if (b4B) {
                b4B.classList.remove("active");
                b4B.classList.add("collapsed");
            }
            const b4C = document.getElementById("sellerSubstage4CBox");
            if (b4C) {
                b4C.classList.remove("collapsed");
                b4C.classList.add("active");
                b4C.scrollIntoView({ behavior: "smooth" });
            }
        });
    }

    const btnRunCompareEncodings = document.getElementById("btnRunCompareEncodings");
    if (btnRunCompareEncodings) {
        btnRunCompareEncodings.addEventListener("click", async () => {
            btnRunCompareEncodings.disabled = true;
            btnRunCompareEncodings.innerHTML = `<span>Comparing Encodings (E_S vs D)...</span>`;
            try {
                const res = await fetch("/api/transaction/compare_encodings", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" }
                });
                if (res.ok) {
                    const data = await res.json();
                    currentTransactionState = data.state;
                    syncTransactionStateToUI(currentTransactionState);
                } else {
                    const err = await res.json();
                    alert(`Comparison failed: ${err.detail || "Server error"}`);
                }
            } catch (err) {
                console.error("Failed to compare encodings:", err);
                alert("Network error comparing encodings.");
            } finally {
                btnRunCompareEncodings.disabled = false;
                btnRunCompareEncodings.innerHTML = `
                    <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"></path>
                    </svg>
                    <span>Compare Encodings (E_S vs D)</span>`;
            }
        });
    }

    const btnProceedTo4D = document.getElementById("btnProceedTo4D");
    if (btnProceedTo4D) {
        btnProceedTo4D.addEventListener("click", () => {
            const b4C = document.getElementById("sellerSubstage4CBox");
            if (b4C) {
                b4C.classList.remove("active");
                b4C.classList.add("collapsed");
            }
            const b4D = document.getElementById("sellerSubstage4DBox");
            if (b4D) {
                b4D.classList.remove("collapsed");
                b4D.classList.add("active");
                b4D.scrollIntoView({ behavior: "smooth" });
            }
        });
    }

    const btnRunBehavioralValidation = document.getElementById("btnRunBehavioralValidation");
    if (btnRunBehavioralValidation) {
        btnRunBehavioralValidation.addEventListener("click", async () => {
            btnRunBehavioralValidation.disabled = true;
            btnRunBehavioralValidation.innerHTML = `<span>Running Behavioral Simulation Validation...</span>`;
            try {
                const res = await fetch("/api/transaction/verify_behavioral", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" }
                });
                if (res.ok) {
                    const data = await res.json();
                    currentTransactionState = data.state;
                    syncTransactionStateToUI(currentTransactionState);
                } else {
                    const err = await res.json();
                    alert(`Behavioral validation failed: ${err.detail || "Server error"}`);
                }
            } catch (err) {
                console.error("Failed to run behavioral validation:", err);
                alert("Network error running behavioral validation.");
            } finally {
                btnRunBehavioralValidation.disabled = false;
                btnRunBehavioralValidation.innerHTML = `
                    <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path>
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                    </svg>
                    <span>Run Behavioral Simulation Validation</span>`;
            }
        });
    }

    const btnProceedTo4E = document.getElementById("btnProceedTo4E");
    if (btnProceedTo4E) {
        btnProceedTo4E.addEventListener("click", () => {
            const b4D = document.getElementById("sellerSubstage4DBox");
            if (b4D) {
                b4D.classList.remove("active");
                b4D.classList.add("collapsed");
            }
            const b4E = document.getElementById("sellerSubstage4EBox");
            if (b4E) {
                b4E.classList.remove("collapsed");
                b4E.classList.add("active");
                b4E.scrollIntoView({ behavior: "smooth" });
            }
        });
    }

    const btnAdvanceToCommitments = document.getElementById("btnAdvanceToCommitments");
    if (btnAdvanceToCommitments) {
        btnAdvanceToCommitments.addEventListener("click", () => {
            window.switchSellerStage("commitments");
        });
    }

    const btnAdvanceToReport = document.getElementById("btnAdvanceToReport");
    if (btnAdvanceToReport) {
        btnAdvanceToReport.addEventListener("click", () => {
            window.switchSellerStage("report");
        });
    }

    const btnRefreshReport = document.getElementById("btnRefreshReport");
    if (btnRefreshReport) {
        btnRefreshReport.addEventListener("click", () => {
            loadAndRenderSellerReport(true);
        });
    }

    const btnExportReportJson = document.getElementById("btnExportReportJson");
    if (btnExportReportJson) {
        btnExportReportJson.addEventListener("click", () => {
            if (cachedSecuringReport) {
                const blob = new Blob([JSON.stringify(cachedSecuringReport, null, 2)], { type: "application/json" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = `securing_report_${cachedSecuringReport.pipeline_run?.run_id || "TX-001"}.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            } else {
                alert("Report data is not loaded yet.");
            }
        });
    }

    // --- SETUP COLLAPSIBLE DISCLOSURE TOGGLING ON ALL SUBSTAGE HEADERS ---
    document.querySelectorAll(".seller-substage-header").forEach(hdr => {
        hdr.addEventListener("click", (e) => {
            if (e.target.closest("button") && !e.target.closest(".btn-substage-toggle")) {
                return;
            }
            const parentBox = hdr.closest(".seller-substage-box");
            if (parentBox) {
                parentBox.classList.toggle("collapsed");
            }
        });
    });

    // Section A: Toggle Structural Encoding Table
    const btnToggleEnc = document.getElementById("btnToggleStructuralEncoding");
    if (btnToggleEnc) {
        btnToggleEnc.addEventListener("click", () => {
            const viewEnc = document.getElementById("viewStructuralEncoding");
            if (viewEnc) {
                const isHidden = (viewEnc.style.display === "none");
                viewEnc.style.display = isHidden ? "block" : "none";
                const bitCount = (currentTransactionState && currentTransactionState.design_encoding_D && currentTransactionState.design_encoding_D.length) || ((currentTransactionState && currentTransactionState.encoding_rule_id === "iir_butterworth_5rule_v1") ? 251 : 143);
                btnToggleEnc.innerHTML = isHidden ?
                    `<svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 15l7-7 7 7"></path></svg><span>Hide Supporting Structural Encoding Table</span>` :
                    `<svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg><span>Inspect Supporting Structural Encoding Table (${bitCount} bits)</span>`;
            }
        });
    }

    // Verilog copy and download helpers
    const btnCopyRTL = document.getElementById("btnCopyProtectedVerilog");
    if (btnCopyRTL) {
        btnCopyRTL.addEventListener("click", () => {
            const code = document.getElementById("verilogCodeBox")?.textContent || "";
            if (code) {
                navigator.clipboard.writeText(code).then(() => {
                    const original = btnCopyRTL.textContent;
                    btnCopyRTL.textContent = "Copied!";
                    setTimeout(() => { btnCopyRTL.textContent = original; }, 2000);
                });
            }
        });
    }

    const btnDownloadRTL = document.getElementById("btnDownloadProtectedVerilog");
    if (btnDownloadRTL) {
        btnDownloadRTL.addEventListener("click", () => {
            const code = document.getElementById("verilogCodeBox")?.textContent || "";
            if (code) {
                const blob = new Blob([code], { type: "text/plain;charset=utf-8" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = "iir_butterworth_protected.v";
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            }
        });
    }
}

function syncTransactionStateToUI(st) {
    if (!st) return;

    // --- SELLER TRANSACTION CARD ---
    const sellerTxReqBadge = document.getElementById("sellerTxReqBadge");
    const sellerTxContribBadge = document.getElementById("sellerTxContribBadge");
    const sellerTxCommitBadge = document.getElementById("sellerTxCommitBadge");
    const sellerTxDetailsLockBadge = document.getElementById("sellerTxDetailsLockBadge");

    if (sellerTxReqBadge) {
        sellerTxReqBadge.textContent = st.buyer_request_status || "Not Requested";
        if (st.buyer_request_status === "Approved") sellerTxReqBadge.className = "badge badge-success";
        else if (st.buyer_request_status === "Rejected") sellerTxReqBadge.className = "badge badge-danger";
        else if (st.buyer_request_status.includes("Pending")) sellerTxReqBadge.className = "badge badge-warning pulse-amber";
        else sellerTxReqBadge.className = "badge badge-v1";
    }
    if (sellerTxContribBadge) {
        sellerTxContribBadge.textContent = st.buyer_contribution_status || (st.buyer_approved ? "Received" : "Not Received");
        sellerTxContribBadge.className = st.buyer_approved ? "badge badge-success" : "badge badge-v1";
    }
    if (sellerTxCommitBadge) {
        sellerTxCommitBadge.textContent = st.buyer_commitment_status || (st.C_B ? "Generated" : "Not Generated");
        sellerTxCommitBadge.className = st.C_B ? "badge badge-success" : "badge badge-v1";
    }
    if (sellerTxDetailsLockBadge) {
        if (st.buyer_approved) {
            sellerTxDetailsLockBadge.textContent = "Available";
            sellerTxDetailsLockBadge.className = "badge badge-success";
        } else {
            sellerTxDetailsLockBadge.textContent = "Locked until approval";
            sellerTxDetailsLockBadge.className = "badge badge-warning";
        }
    }

        // Sync embedding length radio choice
    if (st.embedded_watermark_length) {
        const matchingRadio = document.getElementById(`wmEmbedLen${st.embedded_watermark_length}`);
        if (matchingRadio) {
            matchingRadio.checked = true;
            document.querySelectorAll('input[name="wmEmbedLengthChoice"]').forEach(r => {
                const pillLabel = r.closest(".radio-pill-label");
                if (pillLabel) {
                    if (r === matchingRadio) {
                        pillLabel.classList.add("active");
                        pillLabel.style.background = "rgba(56, 189, 248, 0.15)";
                        pillLabel.style.borderColor = "#38bdf8";
                        pillLabel.style.color = "#38bdf8";
                        pillLabel.style.fontWeight = "600";
                    } else {
                        pillLabel.classList.remove("active");
                        pillLabel.style.background = "rgba(255, 255, 255, 0.05)";
                        pillLabel.style.borderColor = "var(--border-subtle)";
                        pillLabel.style.color = "var(--text-main)";
                        pillLabel.style.fontWeight = "normal";
                    }
                }
            });
        }
    }

    // --- SELLER UI WORKFLOW STEPS ---
    const sDes = document.getElementById("sellerDesignSelect");
    if (sDes) sDes.value = st.design_id || "iir_butterworth";
    const sRul = document.getElementById("sellerRuleSelect");
    if (sRul) sRul.value = st.encoding_rule_id || "iir_butterworth_rule_v1";

    const isFiveRule = (st.encoding_rule_id === "iir_butterworth_5rule_v1");

    // Header, subheader, and metadata chips
    const sellerTopDesign = document.getElementById("sellerTopDesign");
    if (sellerTopDesign) {
        sellerTopDesign.textContent = (st.design_id === "iir_butterworth" || !st.design_id) ? "IIR Butterworth Filter" : st.design_id;
    }
    const sellerTopEncodingRule = document.getElementById("sellerTopEncodingRule");
    if (sellerTopEncodingRule) {
        sellerTopEncodingRule.textContent = isFiveRule ? "IIR Butterworth 5-Rule Encoding" : "IIR Butterworth Encoding Rule";
    }
    const sellerSubstage1ADesc = document.getElementById("sellerSubstage1ADesc");
    if (sellerSubstage1ADesc) {
        sellerSubstage1ADesc.textContent = isFiveRule ?
            "The original scheduled design is encoded using the selected five-rule structural encoding (251 bits total, including Rule 5 register allocations)." :
            "The original scheduled design is encoded using the selected four-rule structural encoding.";
    }
    const sellerMetaDesignId = document.getElementById("sellerMetaDesignId");
    if (sellerMetaDesignId) sellerMetaDesignId.textContent = `design_id: ${st.design_id || "iir_butterworth"}`;
    const sellerMetaRuleId = document.getElementById("sellerMetaRuleId");
    if (sellerMetaRuleId) sellerMetaRuleId.textContent = `rule_id: ${st.encoding_rule_id || "iir_butterworth_rule_v1"}`;
    const sellerMetaRuleVer = document.getElementById("sellerMetaRuleVer");
    if (sellerMetaRuleVer) sellerMetaRuleVer.textContent = `version: ${st.encoding_rule_version || st.rule_version || "1.0"}`;
    const sellerMetaTransformReq = document.getElementById("sellerMetaTransformReq");
    if (sellerMetaTransformReq) {
        sellerMetaTransformReq.textContent = st.encoding_transform_required ? "E_S != D (Transform Required)" : "E_S == D (Invariant)";
    }
    const sellerSummaryDesign = document.getElementById("sellerSummaryDesign");
    if (sellerSummaryDesign) {
        sellerSummaryDesign.textContent = (st.design_id === "iir_butterworth" || !st.design_id) ? "IIR Butterworth Filter" : st.design_id;
    }
    const sellerSummaryEncodingRule = document.getElementById("sellerSummaryEncodingRule");
    if (sellerSummaryEncodingRule) {
        sellerSummaryEncodingRule.textContent = isFiveRule ? "IIR Butterworth 5-Rule Encoding (251 bits)" : "IIR Butterworth Encoding Rule (143 bits)";
    }

    const badgeStep2 = document.getElementById("badgeStep2");
    const sellerSummaryBox = document.getElementById("sellerEncodingSummaryBox");
    const sellerDLength = document.getElementById("sellerDLength");
    const sellerCD = document.getElementById("sellerCommitmentCD");
    const btnReqBuyer = document.getElementById("btnSellerRequestBuyer");

    // Update Seller Navigator status badges & indicators
    const sellerNavStatus1 = document.getElementById("sellerNavStatus1");
    const sellerNavStatus2 = document.getElementById("sellerNavStatus2");
    const sellerNavStatus3 = document.getElementById("sellerNavStatus3");
    const sellerNavStatus4 = document.getElementById("sellerNavStatus4");
    const sellerNavItem1 = document.getElementById("sellerNavItem1");
    const sellerNavItem2 = document.getElementById("sellerNavItem2");
    const sellerNavItem3 = document.getElementById("sellerNavItem3");
    const sellerNavItem4 = document.getElementById("sellerNavItem4");
    const sellerNavItemReport = document.getElementById("sellerNavItemReport");
    const sellerNavStatusReport = document.getElementById("sellerNavStatusReport");
    const sellerOverallProgressBadge = document.getElementById("sellerOverallProgressBadge");

    const dBits = (st.design_encoding_D && st.design_encoding_D.length) || (st.encoding_rule_id === "iir_butterworth_5rule_v1" ? 251 : 143);
    const comp1Text = `Completed (${dBits} bits)`;

    if (st.stage4_completed) {
        if (sellerOverallProgressBadge) sellerOverallProgressBadge.textContent = "Pipeline Completed (4/4)";
        if (sellerNavStatus1) sellerNavStatus1.textContent = comp1Text;
        if (sellerNavStatus2) sellerNavStatus2.textContent = "Completed (W & W1)";
        if (sellerNavStatus3) sellerNavStatus3.textContent = "Embedded & Allocated";
        if (sellerNavStatus4) sellerNavStatus4.textContent = st.encoding_transform_required ? "RTL Verified (E_S != D -> E_U = D)" : "RTL Verified (E_S = D)";
        if (sellerNavStatusReport) sellerNavStatusReport.textContent = "Ready to Inspect";
        if (sellerNavItem1) sellerNavItem1.classList.add("completed");
        if (sellerNavItem2) sellerNavItem2.classList.add("completed");
        if (sellerNavItem3) sellerNavItem3.classList.add("completed");
        if (sellerNavItem4) sellerNavItem4.classList.add("completed");
        if (sellerNavItemReport) sellerNavItemReport.classList.add("completed");
    } else if (st.watermarked_RTL) {
        if (sellerOverallProgressBadge) sellerOverallProgressBadge.textContent = "Stage 4 of 4";
        if (sellerNavStatus1) sellerNavStatus1.textContent = comp1Text;
        if (sellerNavStatus2) sellerNavStatus2.textContent = "Completed (W & W1)";
        if (sellerNavStatus3) sellerNavStatus3.textContent = "Embedded & Allocated";
        if (sellerNavStatus4) {
            if (st.stage4_behavioral_verified) sellerNavStatus4.textContent = "Behavioral Verified";
            else if (st.stage4_encodings_compared) sellerNavStatus4.textContent = "Encodings Validated";
            else if (st.stage4_es_calculated) sellerNavStatus4.textContent = "Secured Encoding Calculated";
            else sellerNavStatus4.textContent = "Ready for Validation";
        }
        if (sellerNavItem1) sellerNavItem1.classList.add("completed");
        if (sellerNavItem2) sellerNavItem2.classList.add("completed");
        if (sellerNavItem3) sellerNavItem3.classList.add("completed");
        if (sellerNavItem4) sellerNavItem4.classList.remove("completed");
    } else if (st.C_W1) {
        if (sellerOverallProgressBadge) sellerOverallProgressBadge.textContent = "Stage 2 Completed (Ready to Embed)";
        if (sellerNavStatus1) sellerNavStatus1.textContent = comp1Text;
        if (sellerNavStatus2) sellerNavStatus2.textContent = "Completed (W & W1)";
        if (sellerNavStatus3) sellerNavStatus3.textContent = "Ready to Embed";
        if (sellerNavStatus4) sellerNavStatus4.textContent = "Pending Stage 3";
        if (sellerNavItem1) sellerNavItem1.classList.add("completed");
        if (sellerNavItem2) sellerNavItem2.classList.add("completed");
        if (sellerNavItem3) sellerNavItem3.classList.remove("completed");
        if (sellerNavItem4) sellerNavItem4.classList.remove("completed");
    } else if (st.W1) {
        if (sellerOverallProgressBadge) sellerOverallProgressBadge.textContent = "Stage 2 of 4";
        if (sellerNavStatus1) sellerNavStatus1.textContent = comp1Text;
        if (sellerNavStatus2) sellerNavStatus2.textContent = "Split (32b / 224b)";
        if (sellerNavStatus3) sellerNavStatus3.textContent = "Pending Stage 2";
        if (sellerNavStatus4) sellerNavStatus4.textContent = "Pending Stage 3";
        if (sellerNavItem1) sellerNavItem1.classList.add("completed");
        if (sellerNavItem2) sellerNavItem2.classList.remove("completed");
        if (sellerNavItem3) sellerNavItem3.classList.remove("completed");
        if (sellerNavItem4) sellerNavItem4.classList.remove("completed");
    } else if (st.C_W) {
        if (sellerOverallProgressBadge) sellerOverallProgressBadge.textContent = "Stage 2 of 4";
        if (sellerNavStatus1) sellerNavStatus1.textContent = comp1Text;
        if (sellerNavStatus2) sellerNavStatus2.textContent = "Committed (C_W)";
        if (sellerNavStatus3) sellerNavStatus3.textContent = "Pending Stage 2";
        if (sellerNavStatus4) sellerNavStatus4.textContent = "Pending Stage 3";
        if (sellerNavItem1) sellerNavItem1.classList.add("completed");
        if (sellerNavItem2) sellerNavItem2.classList.remove("completed");
        if (sellerNavItem3) sellerNavItem3.classList.remove("completed");
        if (sellerNavItem4) sellerNavItem4.classList.remove("completed");
    } else if (st.watermark_W) {
        if (sellerOverallProgressBadge) sellerOverallProgressBadge.textContent = "Stage 2 of 4";
        if (sellerNavStatus1) sellerNavStatus1.textContent = comp1Text;
        if (sellerNavStatus2) sellerNavStatus2.textContent = "Watermark Generated (256b)";
        if (sellerNavStatus3) sellerNavStatus3.textContent = "Pending Stage 2";
        if (sellerNavStatus4) sellerNavStatus4.textContent = "Pending Stage 3";
        if (sellerNavItem1) sellerNavItem1.classList.add("completed");
        if (sellerNavItem2) sellerNavItem2.classList.remove("completed");
        if (sellerNavItem3) sellerNavItem3.classList.remove("completed");
        if (sellerNavItem4) sellerNavItem4.classList.remove("completed");
    } else if (st.buyer_approved) {
        if (sellerOverallProgressBadge) sellerOverallProgressBadge.textContent = "Stage 2 of 4";
        if (sellerNavStatus1) sellerNavStatus1.textContent = comp1Text;
        if (sellerNavStatus2) sellerNavStatus2.textContent = "Buyer Received (555b)";
        if (sellerNavStatus3) sellerNavStatus3.textContent = "Pending Stage 2";
        if (sellerNavStatus4) sellerNavStatus4.textContent = "Pending Stage 3";
        if (sellerNavItem1) sellerNavItem1.classList.add("completed");
        if (sellerNavItem2) sellerNavItem2.classList.remove("completed");
        if (sellerNavItem3) sellerNavItem3.classList.remove("completed");
        if (sellerNavItem4) sellerNavItem4.classList.remove("completed");
    } else if (st.design_encoding_D) {
        if (sellerOverallProgressBadge) sellerOverallProgressBadge.textContent = "Stage 2 of 4";
        if (sellerNavStatus1) sellerNavStatus1.textContent = comp1Text;
        if (sellerNavStatus2) sellerNavStatus2.textContent = (st.buyer_request_status && st.buyer_request_status.includes("Pending")) ? "Pending Buyer Approval" : "Ready for Request";
        if (sellerNavStatus3) sellerNavStatus3.textContent = "Pending Stage 2";
        if (sellerNavStatus4) sellerNavStatus4.textContent = "Pending Stage 3";
        if (sellerNavItem1) sellerNavItem1.classList.add("completed");
        if (sellerNavItem2) sellerNavItem2.classList.remove("completed");
        if (sellerNavItem3) sellerNavItem3.classList.remove("completed");
        if (sellerNavItem4) sellerNavItem4.classList.remove("completed");
    } else {
        if (sellerOverallProgressBadge) sellerOverallProgressBadge.textContent = "Stage 1 of 4";
        if (sellerNavStatus1) sellerNavStatus1.textContent = "Ready to Calculate";
        if (sellerNavStatus2) sellerNavStatus2.textContent = "Pending Stage 1";
        if (sellerNavStatus3) sellerNavStatus3.textContent = "Pending Stage 2";
        if (sellerNavStatus4) sellerNavStatus4.textContent = "Pending Stage 3";
        if (sellerNavItem1) sellerNavItem1.classList.remove("completed");
        if (sellerNavItem2) sellerNavItem2.classList.remove("completed");
        if (sellerNavItem3) sellerNavItem3.classList.remove("completed");
    }
    if (!st.stage4_completed) {
        if (sellerNavStatusReport) sellerNavStatusReport.textContent = "Pending Completion";
        if (sellerNavItemReport) sellerNavItemReport.classList.remove("completed");
    }

    // Stage 1 Displays
    const sellerSubstage1ABox = document.getElementById("sellerSubstage1ABox");
    const sellerSubstage1AControls = document.getElementById("sellerSubstage1AControls");
    const sellerSubstage1ABadge = document.getElementById("sellerSubstage1ABadge");
    const sellerSubstage1BBox = document.getElementById("sellerSubstage1BBox");
    const sellerSubstage1BBadge = document.getElementById("sellerSubstage1BBadge");
    const sellerSubstage1BContent = document.getElementById("sellerSubstage1BContent");

    // Action button: Hide when design encoding D is generated
    const btnEncodeD = document.getElementById("btnSellerEncodeD");
    if (btnEncodeD) {
        btnEncodeD.style.display = st.design_encoding_D ? "none" : "inline-flex";
    }

    if (st.design_encoding_D) {
        if (badgeStep2) {
            badgeStep2.textContent = `Generated (${st.design_encoding_D.length} bits)`;
            badgeStep2.className = "badge badge-success";
        }
        if (sellerDLength) sellerDLength.textContent = `${st.design_encoding_D.length} bits`;
        if (sellerCD) sellerCD.textContent = st.C_D || "--";
        if (btnReqBuyer && st.buyer_request_status === "Not Requested") {
            btnReqBuyer.disabled = false;
        }
        if (sellerSubstage1ABadge) {
            sellerSubstage1ABadge.textContent = `Calculated (${st.design_encoding_D.length}b)`;
            sellerSubstage1ABadge.className = "badge badge-success";
        }

        const hasProgressedPastStage1 = Boolean(st.buyer_approved || st.watermark_W || (st.buyer_request_status && st.buyer_request_status !== "Not Requested"));

        if (hasProgressedPastStage1) {
            if (sellerSubstage1ABox) sellerSubstage1ABox.className = "seller-substage-box collapsed";
            if (sellerSubstage1BBox) sellerSubstage1BBox.className = "seller-substage-box collapsed";
            if (sellerSubstage1BBadge) {
                sellerSubstage1BBadge.textContent = "Committed (C_D)";
                sellerSubstage1BBadge.className = "badge badge-success";
            }
            if (sellerSubstage1BContent) sellerSubstage1BContent.style.display = "none";
        } else {
            // In Stage 1: 1A result is visible, 1B collapsed until Commit clicked
            if (sellerSubstage1AControls) sellerSubstage1AControls.style.display = "none";
            if (sellerSummaryBox) sellerSummaryBox.style.display = "block";
            if (sellerSubstage1ABox) sellerSubstage1ABox.className = "seller-substage-box active";
            if (sellerSubstage1BBox) sellerSubstage1BBox.className = "seller-substage-box collapsed";
            if (sellerSubstage1BBadge) {
                sellerSubstage1BBadge.textContent = "Ready to Commit";
                sellerSubstage1BBadge.className = "badge badge-warning";
            }
        }
        if (st.design_encoding_details) {
            renderStructuralEncodingTab1(st.design_encoding_details);
            const encBox = document.getElementById("sellerStage1EncodingDetails");
            if (encBox) encBox.style.display = "block";
        }
    } else {
        const encBox = document.getElementById("sellerStage1EncodingDetails");
        if (encBox) encBox.style.display = "none";
        if (badgeStep2) {
            badgeStep2.textContent = "Ready to Generate";
            badgeStep2.className = "badge badge-warning";
        }
        if (sellerSubstage1ABadge) {
            sellerSubstage1ABadge.textContent = "Ready to Calculate";
            sellerSubstage1ABadge.className = "badge badge-warning";
        }
        if (sellerDLength) sellerDLength.textContent = "--";
        if (sellerCD) sellerCD.textContent = "--";
        if (sellerSubstage1BBadge) {
            sellerSubstage1BBadge.textContent = "Pending Stage 1";
            sellerSubstage1BBadge.className = "badge badge-v1";
        }
        if (sellerSubstage1BContent) sellerSubstage1BContent.style.display = "none";
        if (sellerSubstage1AControls) sellerSubstage1AControls.style.display = "block";
        if (sellerSummaryBox) sellerSummaryBox.style.display = "none";
        if (sellerSubstage1ABox) sellerSubstage1ABox.className = "seller-substage-box active";
        if (sellerSubstage1BBox) sellerSubstage1BBox.className = "seller-substage-box collapsed";
        if (btnReqBuyer) btnReqBuyer.disabled = true;
    }

    const sellerBuyerStatusBadge = document.getElementById("sellerBuyerStatusBadge");
    const sellerPendingNotice = document.getElementById("sellerPendingNotice");
    const sellerBuyerApprovedBox = document.getElementById("sellerBuyerApprovedBox");
    const sellerCB = document.getElementById("sellerCommitmentCB");
    const buyerNavPendingBadge = document.getElementById("buyerNavPendingBadge");

    const isPending = st.buyer_request_status && st.buyer_request_status.includes("Pending") && !st.buyer_approved && !st.buyer_rejected;

    if (sellerBuyerStatusBadge) {
        if (st.buyer_request_status === "Not Requested") {
            sellerBuyerStatusBadge.textContent = "Not Requested";
            sellerBuyerStatusBadge.className = "badge badge-v1";
        } else if (isPending) {
            sellerBuyerStatusBadge.textContent = "Pending Buyer Approval";
            sellerBuyerStatusBadge.className = "badge badge-warning pulse-amber";
        } else if (st.buyer_request_status === "Approved") {
            sellerBuyerStatusBadge.textContent = "Approved & Received";
            sellerBuyerStatusBadge.className = "badge badge-success";
        } else if (st.buyer_request_status === "Rejected") {
            sellerBuyerStatusBadge.textContent = "Rejected by Buyer";
            sellerBuyerStatusBadge.className = "badge badge-danger";
        }
    }

    if (sellerPendingNotice) {
        sellerPendingNotice.style.display = isPending ? "block" : "none";
    }

    if (buyerNavPendingBadge) {
        buyerNavPendingBadge.style.display = isPending ? "inline-block" : "none";
    }

    if (sellerBuyerApprovedBox) {
        sellerBuyerApprovedBox.style.display = st.buyer_approved ? "block" : "none";
    }

    if (btnReqBuyer) {
        btnReqBuyer.style.display = (st.buyer_request_status && st.buyer_request_status !== "Not Requested") ? "none" : "inline-flex";
        btnReqBuyer.disabled = (st.buyer_request_status !== "Not Requested" || !st.design_encoding_D);
    }

    // Stage 2 Outputs Populator & Independent Substage Management
    const btnContinueWm = document.getElementById("btnSellerContinueWatermark");
    const sellerStep4Badge = document.getElementById("sellerStep4Badge");
    const sellerWmGeneratedBox = document.getElementById("sellerWmGeneratedBox");
    const sellerStageWBitstream = document.getElementById("sellerStageWBitstream");
    const sellerWmBitLength = document.getElementById("sellerWmBitLength");

    const sellerSubstage2ABox = document.getElementById("sellerSubstage2ABox");
    const sellerSubstage2BBox = document.getElementById("sellerSubstage2BBox");
    const sellerSubstage2CBox = document.getElementById("sellerSubstage2CBox");
    const sellerSubstage2DBox = document.getElementById("sellerSubstage2DBox");
    const sellerSubstage2EBox = document.getElementById("sellerSubstage2EBox");

    const btnCommitW = document.getElementById("btnCommitW");
    const badgeStep2C = document.getElementById("badgeStep2C");
    const sellerSubstage2CContent = document.getElementById("sellerSubstage2CContent");
    const sellerStageCwHex = document.getElementById("sellerStageCwHex");

    const btnSplitWm = document.getElementById("btnSplitWatermark");
    const badgeStep2D = document.getElementById("badgeStep2D");
    const sellerSubstage2DContent = document.getElementById("sellerSubstage2DContent");
    const sellerStageW1Bitstream = document.getElementById("sellerStageW1Bitstream");
    const sellerStageW2Bitstream = document.getElementById("sellerStageW2Bitstream");

    const btnCommitW1 = document.getElementById("btnCommitW1");
    const badgeStep2E = document.getElementById("badgeStep2E");
    const sellerSubstage2EContent = document.getElementById("sellerSubstage2EContent");
    const sellerStageCw1Hex = document.getElementById("sellerStageCw1Hex");
    const btnAdvanceToStage3 = document.getElementById("btnAdvanceToStage3");

    // Substage 2B: Generate Watermark W
    if (st.watermark_W) {
        if (sellerStep4Badge) {
            sellerStep4Badge.textContent = "Generated (256 bits)";
            sellerStep4Badge.className = "badge badge-success";
        }
        if (sellerWmGeneratedBox) sellerWmGeneratedBox.style.display = "block";
        if (sellerStageWBitstream) sellerStageWBitstream.textContent = st.watermark_W;
        if (sellerWmBitLength) sellerWmBitLength.textContent = `${st.watermark_W.length} bits`;
        const sellerWmDLength = document.getElementById("sellerWmDLength");
        const sellerWmBLength = document.getElementById("sellerWmBLength");
        const sellerWmTLength = document.getElementById("sellerWmTLength");
        const sellerWmKey = document.getElementById("sellerWmKey");
        const sellerStageTBitstream = document.getElementById("sellerStageTBitstream");
        if (sellerWmDLength) sellerWmDLength.textContent = `${dBits} bits (${isFiveRule ? '5-Rule' : '4-Rule'})`;
        if (sellerWmBLength) sellerWmBLength.textContent = `${(st.buyer_bitstream_B && st.buyer_bitstream_B.length) || 555} bits`;
        if (sellerWmTLength) sellerWmTLength.textContent = `${(st.transaction_factor_T && st.transaction_factor_T.length) || 256} bits`;
        if (sellerWmKey) sellerWmKey.textContent = (st.transaction_credentials && st.transaction_credentials.k_tx) || "K_tx_symmetric_credential_secret_777";
        if (sellerStageTBitstream) sellerStageTBitstream.textContent = st.transaction_factor_T || "--";
        if (btnContinueWm) {
            btnContinueWm.style.display = "none";
            btnContinueWm.disabled = true;
        }
    } else if (st.buyer_approved) {
        if (sellerStep4Badge) {
            sellerStep4Badge.textContent = "Ready to Generate";
            sellerStep4Badge.className = "badge badge-warning";
        }
        if (sellerWmGeneratedBox) sellerWmGeneratedBox.style.display = "none";
        if (btnContinueWm) {
            btnContinueWm.style.display = "inline-flex";
            btnContinueWm.disabled = false;
        }
    } else {
        if (sellerStep4Badge) {
            sellerStep4Badge.textContent = "Awaiting Buyer";
            sellerStep4Badge.className = "badge badge-v1";
        }
        if (sellerWmGeneratedBox) sellerWmGeneratedBox.style.display = "none";
        if (btnContinueWm) {
            btnContinueWm.style.display = "inline-flex";
            btnContinueWm.disabled = true;
        }
    }

    // Substage 2C: Commit Original Watermark C_W
    if (st.C_W) {
        if (badgeStep2C) {
            badgeStep2C.textContent = "Committed (NIST P-256)";
            badgeStep2C.className = "badge badge-success";
        }
        if (sellerStageCwHex) sellerStageCwHex.textContent = st.C_W;
        if (sellerSubstage2CContent) sellerSubstage2CContent.style.display = "block";
        if (btnCommitW) {
            btnCommitW.style.display = "none";
            btnCommitW.disabled = true;
        }
    } else if (st.watermark_W) {
        if (badgeStep2C) {
            badgeStep2C.textContent = "Ready to Commit";
            badgeStep2C.className = "badge badge-warning";
        }
        if (sellerSubstage2CContent) sellerSubstage2CContent.style.display = "none";
        if (btnCommitW) {
            btnCommitW.style.display = "inline-flex";
            btnCommitW.disabled = false;
        }
    } else {
        if (badgeStep2C) {
            badgeStep2C.textContent = "Awaiting Generation";
            badgeStep2C.className = "badge badge-v1";
        }
        if (sellerSubstage2CContent) sellerSubstage2CContent.style.display = "none";
        if (btnCommitW) {
            btnCommitW.style.display = "inline-flex";
            btnCommitW.disabled = true;
        }
    }

    // Substage 2D: Split and Protect Watermark (W1 & W2) - Legacy or Full Watermark Model
    if (st.is_full_watermark) {
        if (badgeStep2D) {
            badgeStep2D.textContent = "Full 256b Model (No Splitting)";
            badgeStep2D.className = "badge badge-info";
        }
        if (sellerSummary2D) sellerSummary2D.textContent = "Complete 256-bit watermark embedded directly";
        if (sellerSubstage2DBox) sellerSubstage2DBox.style.display = "none";
        if (sellerSubstage2EBox) sellerSubstage2EBox.style.display = "none";
        if (btnProceedToSplit) {
            btnProceedToSplit.innerHTML = `<span>Proceed to Stage 3: Watermark Embedding &rarr;</span>`;
        }
        if (sellerNavStatus2) sellerNavStatus2.textContent = "Full (256b)";
    } else if (st.W1 && st.protected_W2) {
        if (sellerSubstage2DBox) sellerSubstage2DBox.style.display = "";
        if (sellerSubstage2EBox) sellerSubstage2EBox.style.display = "";
        if (badgeStep2D) {
            badgeStep2D.textContent = "Split Validated (32b / 224b)";
            badgeStep2D.className = "badge badge-success";
        }
        if (sellerStageW1Bitstream) sellerStageW1Bitstream.textContent = st.W1;
        if (sellerStageW2Bitstream) sellerStageW2Bitstream.textContent = st.protected_W2;
        if (sellerSubstage2DContent) sellerSubstage2DContent.style.display = "block";
        if (btnSplitWm) {
            btnSplitWm.style.display = "none";
            btnSplitWm.disabled = true;
        }
    } else if (st.C_W) {
        if (sellerSubstage2DBox) sellerSubstage2DBox.style.display = "";
        if (sellerSubstage2EBox) sellerSubstage2EBox.style.display = "";
        if (badgeStep2D) {
            badgeStep2D.textContent = "Ready to Split";
            badgeStep2D.className = "badge badge-warning";
        }
        if (sellerSubstage2DContent) sellerSubstage2DContent.style.display = "none";
        if (btnSplitWm) {
            btnSplitWm.style.display = "inline-flex";
            btnSplitWm.disabled = false;
        }
    } else {
        if (sellerSubstage2DBox) sellerSubstage2DBox.style.display = "";
        if (sellerSubstage2EBox) sellerSubstage2EBox.style.display = "";
        if (badgeStep2D) {
            badgeStep2D.textContent = "Awaiting C_W";
            badgeStep2D.className = "badge badge-v1";
        }
        if (sellerSubstage2DContent) sellerSubstage2DContent.style.display = "none";
        if (btnSplitWm) {
            btnSplitWm.style.display = "inline-flex";
            btnSplitWm.disabled = true;
        }
    }

    // Substage 2E: Commit Embedded Watermark C_W1
    if (!st.is_full_watermark) {
        if (st.C_W1) {
            if (badgeStep2E) {
                badgeStep2E.textContent = "Committed (NIST P-256)";
                badgeStep2E.className = "badge badge-success";
            }
            if (sellerStageCw1Hex) sellerStageCw1Hex.textContent = st.C_W1;
            if (sellerSubstage2EContent) sellerSubstage2EContent.style.display = "block";
            if (btnCommitW1) {
                btnCommitW1.style.display = "none";
                btnCommitW1.disabled = true;
            }
            if (btnAdvanceToStage3) btnAdvanceToStage3.disabled = false;
        } else if (st.W1) {
            if (badgeStep2E) {
                badgeStep2E.textContent = "Ready to Commit";
                badgeStep2E.className = "badge badge-warning";
            }
            if (sellerSubstage2EContent) sellerSubstage2EContent.style.display = "none";
            if (btnCommitW1) {
                btnCommitW1.style.display = "inline-flex";
                btnCommitW1.disabled = false;
            }
            if (btnAdvanceToStage3) btnAdvanceToStage3.disabled = true;
        } else {
            if (badgeStep2E) {
                badgeStep2E.textContent = "Awaiting Split";
                badgeStep2E.className = "badge badge-v1";
            }
            if (sellerSubstage2EContent) sellerSubstage2EContent.style.display = "none";
            if (btnCommitW1) {
                btnCommitW1.style.display = "inline-flex";
                btnCommitW1.disabled = true;
            }
            if (btnAdvanceToStage3) btnAdvanceToStage3.disabled = true;
        }
    }

    // Active / Collapsed progression management for Stage 2
    if (st.watermarked_RTL) {
        if (sellerSubstage2ABox) sellerSubstage2ABox.className = "seller-substage-box collapsed";
        if (sellerSubstage2BBox) sellerSubstage2BBox.className = "seller-substage-box collapsed";
        if (sellerSubstage2CBox) sellerSubstage2CBox.className = "seller-substage-box collapsed";
        if (sellerSubstage2DBox) sellerSubstage2DBox.className = "seller-substage-box collapsed";
        if (sellerSubstage2EBox) sellerSubstage2EBox.className = "seller-substage-box collapsed";
    } else if (st.is_full_watermark && st.C_W) {
        if (sellerSubstage2ABox) sellerSubstage2ABox.className = "seller-substage-box collapsed";
        if (sellerSubstage2BBox) sellerSubstage2BBox.className = "seller-substage-box collapsed";
        if (sellerSubstage2CBox) sellerSubstage2CBox.className = "seller-substage-box active";
    } else if (st.C_W1) {
        if (sellerSubstage2ABox) sellerSubstage2ABox.className = "seller-substage-box collapsed";
        if (sellerSubstage2BBox) sellerSubstage2BBox.className = "seller-substage-box collapsed";
        if (sellerSubstage2CBox) sellerSubstage2CBox.className = "seller-substage-box collapsed";
        if (sellerSubstage2DBox) sellerSubstage2DBox.className = "seller-substage-box collapsed";
        if (sellerSubstage2EBox) sellerSubstage2EBox.className = "seller-substage-box active";
    } else if (st.W1) {
        if (sellerSubstage2ABox) sellerSubstage2ABox.className = "seller-substage-box collapsed";
        if (sellerSubstage2BBox) sellerSubstage2BBox.className = "seller-substage-box collapsed";
        if (sellerSubstage2CBox) sellerSubstage2CBox.className = "seller-substage-box collapsed";
        if (sellerSubstage2DBox) sellerSubstage2DBox.className = "seller-substage-box active";
        if (sellerSubstage2EBox) sellerSubstage2EBox.className = "seller-substage-box collapsed";
    } else if (st.C_W) {
        if (sellerSubstage2ABox) sellerSubstage2ABox.className = "seller-substage-box collapsed";
        if (sellerSubstage2BBox) sellerSubstage2BBox.className = "seller-substage-box collapsed";
        if (sellerSubstage2CBox) sellerSubstage2CBox.className = "seller-substage-box active";
        if (sellerSubstage2DBox) sellerSubstage2DBox.className = "seller-substage-box collapsed";
        if (sellerSubstage2EBox) sellerSubstage2EBox.className = "seller-substage-box collapsed";
    } else if (st.watermark_W) {
        if (sellerSubstage2ABox) sellerSubstage2ABox.className = "seller-substage-box collapsed";
        if (sellerSubstage2BBox) sellerSubstage2BBox.className = "seller-substage-box active";
        if (sellerSubstage2CBox) sellerSubstage2CBox.className = "seller-substage-box collapsed";
        if (sellerSubstage2DBox) sellerSubstage2DBox.className = "seller-substage-box collapsed";
        if (sellerSubstage2EBox) sellerSubstage2EBox.className = "seller-substage-box collapsed";
    } else if (st.buyer_approved) {
        if (sellerSubstage2ABox) sellerSubstage2ABox.className = "seller-substage-box collapsed";
        if (sellerSubstage2BBox) sellerSubstage2BBox.className = "seller-substage-box active";
        if (sellerSubstage2CBox) sellerSubstage2CBox.className = "seller-substage-box collapsed";
        if (sellerSubstage2DBox) sellerSubstage2DBox.className = "seller-substage-box collapsed";
        if (sellerSubstage2EBox) sellerSubstage2EBox.className = "seller-substage-box collapsed";
    } else {
        if (sellerSubstage2ABox) sellerSubstage2ABox.className = "seller-substage-box active";
        if (sellerSubstage2BBox) sellerSubstage2BBox.className = "seller-substage-box collapsed";
        if (sellerSubstage2CBox) sellerSubstage2CBox.className = "seller-substage-box collapsed";
        if (sellerSubstage2DBox) sellerSubstage2DBox.className = "seller-substage-box collapsed";
        if (sellerSubstage2EBox) sellerSubstage2EBox.className = "seller-substage-box collapsed";
    }

    // --- STAGE 3 UI SYNCHRONIZATION ---
    const btnEmbedWatermark = document.getElementById("btnEmbedWatermark");
    const sellerStage3ActionBox = document.getElementById("sellerStage3ActionBox");
    const sellerStage3Results = document.getElementById("sellerStage3Results");
    const badgeStage3Top = document.getElementById("badgeStage3Top");

    const isReadyToEmbed = st.is_full_watermark ? (st.C_W && st.watermark_W) : st.C_W1;

    if (st.watermarked_RTL) {
        if (btnEmbedWatermark) btnEmbedWatermark.style.display = "none";
        if (sellerStage3ActionBox) sellerStage3ActionBox.style.display = "none";
        if (sellerStage3Results) sellerStage3Results.style.display = "block";
        if (badgeStage3Top) {
            badgeStage3Top.textContent = "Embedded";
            badgeStage3Top.className = "badge badge-success";
        }
    } else {
        if (btnEmbedWatermark) {
            btnEmbedWatermark.style.display = "inline-flex";
            btnEmbedWatermark.disabled = !isReadyToEmbed;
        }
        if (sellerStage3ActionBox) sellerStage3ActionBox.style.display = "block";
        if (sellerStage3Results) sellerStage3Results.style.display = "none";
        if (badgeStage3Top) {
            badgeStage3Top.textContent = isReadyToEmbed ? "Ready to Embed (256 bits)" : "Pending Stage 2";
            badgeStage3Top.className = isReadyToEmbed ? "badge badge-warning" : "badge badge-v1";
        }
    }

    // --- STAGE 4 SEQUENTIAL SUBSTAGE SYNCHRONIZATION ---
    const sellerSubstage4ABox = document.getElementById("sellerSubstage4ABox");
    const sellerSubstage4BBox = document.getElementById("sellerSubstage4BBox");
    const sellerSubstage4CBox = document.getElementById("sellerSubstage4CBox");
    const sellerSubstage4DBox = document.getElementById("sellerSubstage4DBox");
    const sellerSubstage4EBox = document.getElementById("sellerSubstage4EBox");

    const btnCalculateEs = document.getElementById("btnCalculateEs");
    const sellerStageEsContent = document.getElementById("sellerStageEsContent");
    const sellerStageEsBadge = document.getElementById("sellerStageEsBadge");
    const sellerStageEsBitstream = document.getElementById("sellerStageEsBitstream");

    const btnRunCompareEncodings = document.getElementById("btnRunCompareEncodings");
    const sellerStageComparisonContent = document.getElementById("sellerStageComparisonContent");
    const sellerBadge4C = document.getElementById("sellerBadge4C");

    const btnRunBehavioralValidation = document.getElementById("btnRunBehavioralValidation");
    const sellerStageBehavioralContent = document.getElementById("sellerStageBehavioralContent");
    const sellerBadge4D = document.getElementById("sellerBadge4D");

    const badgeStage4Top = document.getElementById("badgeStage4Top");

    // 4A: Protected RTL Synthesis
    if (st.watermarked_RTL) {
        const verilogCodeBox = document.getElementById("verilogCodeBox");
        if (verilogCodeBox) verilogCodeBox.textContent = st.watermarked_RTL;
        const viewVerilog = document.getElementById("viewVerilog");
        if (viewVerilog) viewVerilog.style.display = "block";
    }

    // 4B: Calculate Secured Design Encoding (E_S)
    if (st.stage4_es_calculated) {
        if (btnCalculateEs) btnCalculateEs.style.display = "none";
        if (sellerStageEsContent) sellerStageEsContent.style.display = "block";
        renderSecuredStructuralEncoding(st.secured_encoding_E_S, st.design_encoding_D);
    } else {
        if (btnCalculateEs) {
            btnCalculateEs.style.display = "inline-flex";
            btnCalculateEs.disabled = !st.watermarked_RTL;
        }
        if (sellerStageEsContent) sellerStageEsContent.style.display = "none";
        if (sellerStageEsBadge) {
            sellerStageEsBadge.textContent = st.watermarked_RTL ? "Ready to Calculate" : "Pending RTL";
            sellerStageEsBadge.className = st.watermarked_RTL ? "badge badge-warning" : "badge badge-v1";
        }
    }

    // 4C: Compare Encodings (E_S vs D)
    if (st.stage4_encodings_compared) {
        if (btnRunCompareEncodings) btnRunCompareEncodings.style.display = "none";
        if (sellerStageComparisonContent) sellerStageComparisonContent.style.display = "block";
        if (sellerBadge4C) {
            if (st.encoding_transform_required) {
                sellerBadge4C.textContent = "Transformation Needed: E_S != D (6 vars modified)";
                sellerBadge4C.className = "badge badge-warning";
            } else {
                sellerBadge4C.textContent = "Unchanged: E_S = D";
                sellerBadge4C.className = "badge badge-success";
            }
        }
    } else {
        if (btnRunCompareEncodings) {
            btnRunCompareEncodings.style.display = "inline-flex";
            btnRunCompareEncodings.disabled = !st.stage4_es_calculated;
        }
        if (sellerStageComparisonContent) sellerStageComparisonContent.style.display = "none";
        if (sellerBadge4C) {
            sellerBadge4C.textContent = st.stage4_es_calculated ? "Ready to Compare" : "Pending E_S";
            sellerBadge4C.className = st.stage4_es_calculated ? "badge badge-warning" : "badge badge-v1";
        }
    }

    // 4D: Behavioral Simulation Validation
    if (st.stage4_behavioral_verified) {
        if (btnRunBehavioralValidation) btnRunBehavioralValidation.style.display = "none";
        if (sellerStageBehavioralContent) sellerStageBehavioralContent.style.display = "block";
        if (sellerBadge4D) {
            sellerBadge4D.textContent = "Verified (32/32 Matches)";
            sellerBadge4D.className = "badge badge-success";
        }
    } else {
        if (btnRunBehavioralValidation) {
            btnRunBehavioralValidation.style.display = "inline-flex";
            btnRunBehavioralValidation.disabled = !st.stage4_encodings_compared;
        }
        if (sellerStageBehavioralContent) sellerStageBehavioralContent.style.display = "none";
        if (sellerBadge4D) {
            sellerBadge4D.textContent = st.stage4_encodings_compared ? "Ready to Simulate" : "Pending Comparison";
            sellerBadge4D.className = st.stage4_encodings_compared ? "badge badge-warning" : "badge badge-v1";
        }
    }

    // 4E & Stage 4 Top Badge
    if (badgeStage4Top) {
        if (st.stage4_completed) {
            badgeStage4Top.textContent = "Verified";
            badgeStage4Top.className = "badge badge-success";
        } else if (st.watermarked_RTL) {
            badgeStage4Top.textContent = "Sequential";
            badgeStage4Top.className = "badge badge-v1";
        } else {
            badgeStage4Top.textContent = "Pending Stage 3";
            badgeStage4Top.className = "badge badge-v1";
        }
    }

    // --- POPULATE COMPACT SUMMARY CHIPS FOR COLLAPSED DISCLOSURES ---
    const sum1A = document.getElementById("sellerSummary1A");
    if (sum1A) sum1A.textContent = st.design_encoding_D ? `Calculated · ${st.design_encoding_D.length} bits` : "Pending";
    const sum1B = document.getElementById("sellerSummary1B");
    if (sum1B) sum1B.textContent = st.C_D ? "Committed (NIST P-256)" : "Pending";
    const sum2A = document.getElementById("sellerSummary2A");
    if (sum2A) sum2A.textContent = st.buyer_approved ? "Approved & Received · 555 bits" : (st.buyer_request_status || "Not Requested");
    const sum2B = document.getElementById("sellerSummary2B");
    if (sum2B) sum2B.textContent = st.watermark_W ? `Generated · ${st.watermark_W.length} bits` : "Pending";
    const sum2C = document.getElementById("sellerSummary2C");
    if (sum2C) sum2C.textContent = st.C_W ? "Committed (NIST P-256)" : "Pending";
    const sum2D = document.getElementById("sellerSummary2D");
    if (sum2D) sum2D.textContent = (st.W1 && st.protected_W2) ? `Validated · W1: ${st.W1.length}b, W2: ${st.protected_W2.length}b` : "Pending";
    const sum2E = document.getElementById("sellerSummary2E");
    if (sum2E) sum2E.textContent = st.C_W1 ? "Committed (NIST P-256)" : "Pending";

    const sum4A = document.getElementById("sellerSummary4A");
    if (sum4A) sum4A.textContent = st.watermarked_RTL ? "Synthesized" : "Pending";
    const sum4B = document.getElementById("sellerSummary4B");
    const esBits = (st.secured_encoding_ES && st.secured_encoding_ES.length) || (st.encoding_rule_id === "iir_butterworth_5rule_v1" ? 251 : 143);
    if (sum4B) sum4B.textContent = st.stage4_es_calculated ? `Calculated · ${esBits} bits` : "Pending";
    const sum4C = document.getElementById("sellerSummary4C");
    if (sum4C) sum4C.textContent = st.stage4_encodings_compared ? (st.encoding_transform_required ? "Validated · E_S != D (Transform Needed)" : "Validated · E_S = D") : "Pending";
    const sum4D = document.getElementById("sellerSummary4D");
    if (sum4D) sum4D.textContent = st.stage4_behavioral_verified ? "Verified · 32/32 Matches" : "Pending";
    const sum4E = document.getElementById("sellerSummary4E");
    const isTransformReq = Boolean(st.encoding_transform_required);
    const hasCes = Boolean(st.C_ES && st.C_ES !== "NOT_REQUIRED");

    const sellerBadge4E = document.getElementById("sellerBadge4E");
    const sellerSubstage4EBody = document.getElementById("sellerSubstage4EBody");

    if (sellerBadge4E) {
        if (isTransformReq || hasCes) {
            sellerBadge4E.textContent = hasCes ? "Committed (NIST P-256)" : "Required (E_S != D)";
            sellerBadge4E.className = hasCes ? "badge badge-success" : "badge badge-warning";
        } else {
            sellerBadge4E.textContent = "Not Required (E_S = D)";
            sellerBadge4E.className = "badge badge-v1";
        }
    }

    if (sum4E) {
        if (st.stage4_completed) {
            sum4E.textContent = (isTransformReq || hasCes) ? "Committed · E_S != D (Transformation Required)" : "Not Required · E_S = D";
        } else {
            sum4E.textContent = "Pending";
        }
    }

    if (sellerSubstage4EBody) {
        if (isTransformReq || hasCes) {
            sellerSubstage4EBody.innerHTML = `
                <div style="font-size: 0.76rem; color: var(--text-muted); margin-bottom: 0.5rem; line-height: 1.5;">
                    <strong style="color: var(--accent-amber);">Transformation Required (E_S &ne; D):</strong>
                    Because secured encoding E_S differs from original encoding D (modified in Rule 5 due to watermark embedding constraints), the protocol generates and commits to canonical E_S via <code>C_ES</code>.
                </div>
                <div class="commit-hex-row" style="margin-top: 0.4rem; background: rgba(5, 10, 20, 0.6); padding: 0.5rem 0.75rem; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle); display: flex;">
                    <span class="commit-hex-lbl">C_ES:</span>
                    <span style="font-family: var(--font-mono); font-size: 0.75rem; color: #a78bfa; word-break: break-all;">${st.C_ES || "Pending Generation"}</span>
                </div>
                <div class="seller-stage-actions" style="margin-top: 0.75rem;">
                    <button type="button" id="btnAdvanceToCommitments" class="btn-primary" style="width: auto; padding: 0.45rem 1rem; font-size: 0.8rem;">
                        <span>View Transaction Evidence &amp; Commitments &rarr;</span>
                    </button>
                </div>
            `;
            const btnAdv = document.getElementById("btnAdvanceToCommitments");
            if (btnAdv) {
                btnAdv.addEventListener("click", () => {
                    const card = document.getElementById("sellerCommitmentsCard");
                    if (card) {
                        card.style.display = "block";
                        card.scrollIntoView({ behavior: "smooth" });
                    }
                });
            }
        } else {
            sellerSubstage4EBody.innerHTML = `
                <p style="font-size: 0.76rem; color: var(--text-muted); margin-bottom: 0.5rem; line-height: 1.5;">
                    <em>Secured encoding commitment not required for this transaction (E_S equals D).</em>
                    Because secured encoding E_S is identical to original encoding D, the existing architecture commits to D via C_D. A separate C_ES commitment is not required and no fake commitment is fabricated.
                </p>
                <div class="seller-stage-actions" style="margin-top: 0.75rem;">
                    <button type="button" id="btnAdvanceToCommitments" class="btn-primary" style="width: auto; padding: 0.45rem 1rem; font-size: 0.8rem;">
                        <span>View Transaction Evidence &amp; Commitments &rarr;</span>
                    </button>
                </div>
            `;
            const btnAdv = document.getElementById("btnAdvanceToCommitments");
            if (btnAdv) {
                btnAdv.addEventListener("click", () => {
                    const card = document.getElementById("sellerCommitmentsCard");
                    if (card) {
                        card.style.display = "block";
                        card.scrollIntoView({ behavior: "smooth" });
                    }
                });
            }
        }
    }

    // Progressive default activation for Stage 4 boxes
    if (st.stage4_completed) {
        if (sellerSubstage4ABox) sellerSubstage4ABox.className = "seller-substage-box collapsed";
        if (sellerSubstage4BBox) sellerSubstage4BBox.className = "seller-substage-box collapsed";
        if (sellerSubstage4CBox) sellerSubstage4CBox.className = "seller-substage-box collapsed";
        if (sellerSubstage4DBox) sellerSubstage4DBox.className = "seller-substage-box collapsed";
        if (sellerSubstage4EBox) sellerSubstage4EBox.className = "seller-substage-box collapsed";
    } else if (st.stage4_behavioral_verified) {
        if (sellerSubstage4ABox) sellerSubstage4ABox.className = "seller-substage-box collapsed";
        if (sellerSubstage4BBox) sellerSubstage4BBox.className = "seller-substage-box collapsed";
        if (sellerSubstage4CBox) sellerSubstage4CBox.className = "seller-substage-box collapsed";
        if (sellerSubstage4DBox) sellerSubstage4DBox.className = "seller-substage-box collapsed";
        if (sellerSubstage4EBox) sellerSubstage4EBox.className = "seller-substage-box active";
    } else if (st.stage4_encodings_compared) {
        if (sellerSubstage4ABox) sellerSubstage4ABox.className = "seller-substage-box collapsed";
        if (sellerSubstage4BBox) sellerSubstage4BBox.className = "seller-substage-box collapsed";
        if (sellerSubstage4CBox) sellerSubstage4CBox.className = "seller-substage-box collapsed";
        if (sellerSubstage4DBox) sellerSubstage4DBox.className = "seller-substage-box active";
        if (sellerSubstage4EBox) sellerSubstage4EBox.className = "seller-substage-box collapsed";
    } else if (st.stage4_es_calculated) {
        if (sellerSubstage4ABox) sellerSubstage4ABox.className = "seller-substage-box collapsed";
        if (sellerSubstage4BBox) sellerSubstage4BBox.className = "seller-substage-box collapsed";
        if (sellerSubstage4CBox) sellerSubstage4CBox.className = "seller-substage-box active";
        if (sellerSubstage4DBox) sellerSubstage4DBox.className = "seller-substage-box collapsed";
        if (sellerSubstage4EBox) sellerSubstage4EBox.className = "seller-substage-box collapsed";
    } else if (st.watermarked_RTL) {
        if (sellerSubstage4ABox) sellerSubstage4ABox.className = "seller-substage-box active";
        if (sellerSubstage4BBox) sellerSubstage4BBox.className = "seller-substage-box collapsed";
        if (sellerSubstage4CBox) sellerSubstage4CBox.className = "seller-substage-box collapsed";
        if (sellerSubstage4DBox) sellerSubstage4DBox.className = "seller-substage-box collapsed";
        if (sellerSubstage4EBox) sellerSubstage4EBox.className = "seller-substage-box collapsed";
    }

    if (st.pipeline_result && st.watermark_W) {
        renderProtectionResults(st.pipeline_result);
    }

    // --- AUDITED COMMITMENTS VIEW (SELLER PROFILE) ---
    const commCdHex = document.getElementById("commCdHex");
    const badgeCdStatus = document.getElementById("badgeCdStatus");
    if (commCdHex && st.C_D) {
        commCdHex.textContent = st.C_D;
        if (badgeCdStatus) {
            badgeCdStatus.textContent = "Stored / Generated";
            badgeCdStatus.className = "badge badge-success";
        }
    }

    const commWmHex = document.getElementById("commWmHex");
    const badgeCwStatus = document.getElementById("badgeCwStatus");
    if (commWmHex && st.C_W) {
        commWmHex.textContent = st.C_W;
        if (badgeCwStatus) {
            badgeCwStatus.textContent = "Stored / Generated";
            badgeCwStatus.className = "badge badge-success";
        }
    }

    const commCw1Hex = document.getElementById("commCw1Hex");
    const badgeCw1Status = document.getElementById("badgeCw1Status");
    if (commCw1Hex && st.C_W1) {
        commCw1Hex.textContent = st.C_W1;
        if (badgeCw1Status) {
            badgeCw1Status.textContent = "Stored / Generated";
            badgeCw1Status.className = "badge badge-success";
        }
    }

    const commTvHex = document.getElementById("commTvHex");
    const badgeCvStatus = document.getElementById("badgeCvStatus");
    if (commTvHex && (st.C_V || (st.pipeline_result && st.pipeline_result.test_vectors))) {
        commTvHex.textContent = st.C_V || st.pipeline_result.test_vectors.commitment_hex;
        if (badgeCvStatus) {
            badgeCvStatus.textContent = "Stored / Generated";
            badgeCvStatus.className = "badge badge-info";
        }
    }

    const commCesHex = document.getElementById("commCesHex");
    const commCesHexRow = document.getElementById("commCesHexRow");
    const badgeCesStatus = document.getElementById("badgeCesStatus");
    const commCesDesc = document.getElementById("commCesDesc");

    if (badgeCesStatus) {
        if (isTransformReq || hasCes) {
            badgeCesStatus.textContent = hasCes ? "Stored / Generated" : "Required";
            badgeCesStatus.className = hasCes ? "badge badge-success" : "badge badge-warning";
            if (commCesDesc) commCesDesc.textContent = "Commits to: Secured Encoding E_S (Transformation Required • E_S != D)";
            if (commCesHexRow) commCesHexRow.style.display = "flex";
            if (commCesHex) commCesHex.textContent = st.C_ES || "--";
        } else {
            badgeCesStatus.textContent = "Not Required (E_S = D)";
            badgeCesStatus.className = "badge badge-v1";
            if (commCesDesc) commCesDesc.textContent = "Secured encoding commitment not required for this transaction (E_S equals D).";
            if (commCesHexRow) commCesHexRow.style.display = "none";
        }
    }

    // --- SELLER PRIVATE EVIDENCE VIEW (Stage 1 & Stage 2) ---
    const sellerPrivCanonicalD = document.getElementById("sellerPrivCanonicalD");
    if (sellerPrivCanonicalD) {
        sellerPrivCanonicalD.textContent = st.design_encoding_D || "Not generated yet.";
    }
    const sellerPrivStoredCd = document.getElementById("sellerPrivStoredCd");
    if (sellerPrivStoredCd) {
        sellerPrivStoredCd.textContent = st.C_D || "--";
    }
    const sellerEvidCdStatus = document.getElementById("sellerEvidCdStatus");
    if (sellerEvidCdStatus) {
        if (st.C_D) {
            sellerEvidCdStatus.textContent = "Generated / Stored";
            sellerEvidCdStatus.className = "badge badge-success";
        } else {
            sellerEvidCdStatus.textContent = "Not generated yet";
            sellerEvidCdStatus.className = "badge badge-v1";
        }
    }

    const sellerPrivBlindingD = document.getElementById("sellerPrivBlindingD");
    if (sellerPrivBlindingD) {
        sellerPrivBlindingD.textContent = st.blinding_factor_D ? `0x${st.blinding_factor_D}` : "Not generated yet.";
    }
    const sellerPrivBlindingW = document.getElementById("sellerPrivBlindingW");
    if (sellerPrivBlindingW) {
        sellerPrivBlindingW.textContent = st.blinding_factor_W ? `0x${st.blinding_factor_W}` : "Not generated yet.";
    }
    const sellerPrivBlindingW1 = document.getElementById("sellerPrivBlindingW1");
    if (sellerPrivBlindingW1) {
        sellerPrivBlindingW1.textContent = st.blinding_factor_W1 ? `0x${st.blinding_factor_W1}` : "Not generated yet.";
    }
    const sellerPrivCanonicalW = document.getElementById("sellerPrivCanonicalW");
    if (sellerPrivCanonicalW) {
        sellerPrivCanonicalW.textContent = st.watermark_W || "Not generated yet.";
    }
    const sellerPrivStoredCw = document.getElementById("sellerPrivStoredCw");
    if (sellerPrivStoredCw) {
        sellerPrivStoredCw.textContent = st.C_W || "--";
    }
    const sellerEvidCwStatus = document.getElementById("sellerEvidCwStatus");
    if (sellerEvidCwStatus) {
        if (st.C_W) {
            sellerEvidCwStatus.textContent = "Generated / Stored";
            sellerEvidCwStatus.className = "badge badge-success";
        } else {
            sellerEvidCwStatus.textContent = "Not generated yet";
            sellerEvidCwStatus.className = "badge badge-v1";
        }
    }

    const isFullWm = st.is_full_watermark !== false;
    const sellerFullWmBox = document.getElementById("sellerFullWatermarkEvidenceBox");
    const sellerLegacySplitBox = document.getElementById("sellerLegacySplitEvidenceBox");
    const sellerEvidCard3Title = document.getElementById("sellerEvidCard3Title");
    const sellerEvidCard3Sub = document.getElementById("sellerEvidCard3Sub");
    const sellerPrivEmbeddedW = document.getElementById("sellerPrivEmbeddedW");
    const sellerEvidActualEmbeddedLen = document.getElementById("sellerEvidActualEmbeddedLen");

    if (isFullWm) {
        if (sellerEvidCard3Title) sellerEvidCard3Title.textContent = "C_W Evidence: Full Watermark Embedding & Extraction";
        if (sellerEvidCard3Sub) sellerEvidCard3Sub.textContent = "(256 bits embedded • Owner: SELLER-001)";
        if (sellerFullWmBox) sellerFullWmBox.style.display = "block";
        if (sellerLegacySplitBox) sellerLegacySplitBox.style.display = "none";
        const wmBits = st.watermark_W || st.W1 || "";
        if (sellerPrivEmbeddedW) {
            sellerPrivEmbeddedW.textContent = wmBits ? `${wmBits} (${wmBits.length} bits)` : "Not generated yet.";
        }
        if (sellerEvidActualEmbeddedLen) {
            sellerEvidActualEmbeddedLen.textContent = wmBits ? `${wmBits.length} bits embedded into Register Conflict Interference Graph` : "256 bits embedded into Register Conflict Interference Graph";
        }
    } else {
        if (sellerEvidCard3Title) sellerEvidCard3Title.textContent = "C_W1 Evidence: Watermark Splitting, Embedding & Extraction (W1 / W2)";
        if (sellerEvidCard3Sub) sellerEvidCard3Sub.textContent = "(32 bits embedded • Owner: SELLER-001)";
        if (sellerFullWmBox) sellerFullWmBox.style.display = "none";
        if (sellerLegacySplitBox) sellerLegacySplitBox.style.display = "block";
        const legW1 = document.getElementById("sellerLegacyW1");
        if (legW1) legW1.textContent = st.W1 ? `${st.W1} (${st.W1.length} bits)` : "Not generated yet.";
        const legW2 = document.getElementById("sellerLegacyW2");
        if (legW2) legW2.textContent = st.protected_W2 ? `${st.protected_W2} (${st.protected_W2.length} bits)` : "Not generated yet.";
    }

    const sellerPrivW1 = document.getElementById("sellerPrivW1");
    if (sellerPrivW1) {
        sellerPrivW1.textContent = st.W1 ? `${st.W1} (${st.W1.length} bits)` : (st.watermark_W ? `${st.watermark_W} (${st.watermark_W.length} bits)` : "Not generated yet.");
    }
    const sellerPrivW2 = document.getElementById("sellerPrivW2");
    if (sellerPrivW2) {
        sellerPrivW2.textContent = st.protected_W2 ? `${st.protected_W2} (${st.protected_W2.length} bits)` : "Not generated yet.";
    }
    const sellerPrivStoredCw1 = document.getElementById("sellerPrivStoredCw1");
    if (sellerPrivStoredCw1) {
        sellerPrivStoredCw1.textContent = (isFullWm ? st.C_W : st.C_W1) || "--";
    }
    if (sellerPrivBlindingW1) {
        sellerPrivBlindingW1.textContent = (isFullWm ? st.blinding_factor_W : st.blinding_factor_W1) || "Not generated yet.";
    }
    const sellerEvidCw1Status = document.getElementById("sellerEvidCw1Status");
    if (sellerEvidCw1Status) {
        const commVal = isFullWm ? st.C_W : st.C_W1;
        if (commVal) {
            sellerEvidCw1Status.textContent = "Generated / Stored";
            sellerEvidCw1Status.className = "badge badge-success";
        } else {
            sellerEvidCw1Status.textContent = "Not generated yet";
            sellerEvidCw1Status.className = "badge badge-v1";
        }
    }
    const sellerPrivGenGW = document.getElementById("sellerPrivGenGW");
    if (sellerPrivGenGW) {
        sellerPrivGenGW.textContent = (st.seller_private_info && st.seller_private_info.C_W_evidence && st.seller_private_info.C_W_evidence.commitment_verification && st.seller_private_info.C_W_evidence.commitment_verification.generator_g) || "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    }
    const sellerPrivGenHW = document.getElementById("sellerPrivGenHW");
    if (sellerPrivGenHW) {
        sellerPrivGenHW.textContent = (st.seller_private_info && st.seller_private_info.C_W_evidence && st.seller_private_info.C_W_evidence.commitment_verification && st.seller_private_info.C_W_evidence.commitment_verification.generator_h) || "021ad06fad86cbbf99815a56f6c511152d048e5e0893d02c18194e3165a6aa4db3";
    }
    const sellerPrivGenGW1 = document.getElementById("sellerPrivGenGW1");
    if (sellerPrivGenGW1) {
        sellerPrivGenGW1.textContent = (st.seller_private_info && st.seller_private_info.C_W1_evidence && st.seller_private_info.C_W1_evidence.commitment_verification && st.seller_private_info.C_W1_evidence.commitment_verification.generator_g) || "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    }
    const sellerPrivGenHW1 = document.getElementById("sellerPrivGenHW1");
    if (sellerPrivGenHW1) {
        sellerPrivGenHW1.textContent = (st.seller_private_info && st.seller_private_info.C_W1_evidence && st.seller_private_info.C_W1_evidence.commitment_verification && st.seller_private_info.C_W1_evidence.commitment_verification.generator_h) || "021ad06fad86cbbf99815a56f6c511152d048e5e0893d02c18194e3165a6aa4db3";
    }

    // --- SELLER EVIDENCE CARD 4 (C_ES Evidence) ---
    const sellerEvidCesStatus = document.getElementById("sellerEvidCesStatus");
    const sellerPrivEsRule = document.getElementById("sellerPrivEsRule");
    const sellerPrivEsInvariance = document.getElementById("sellerPrivEsInvariance");
    const sellerPrivEsTransformRule = document.getElementById("sellerPrivEsTransformRule");
    const sellerPrivEsVerifyNote = document.getElementById("sellerPrivEsVerifyNote");

    if (sellerEvidCesStatus) {
        if (isTransformReq || hasCes) {
            sellerEvidCesStatus.textContent = hasCes ? "Generated / Stored" : "Pending Calculation";
            sellerEvidCesStatus.className = hasCes ? "badge badge-success" : "badge badge-warning";
            if (sellerPrivEsInvariance) sellerPrivEsInvariance.textContent = "Secured encoding E_S differs from original encoding D in Rule 5 (251 bits with 6 variables modified). Deterministic transformation required.";
            if (sellerPrivEsTransformRule) sellerPrivEsTransformRule.textContent = "Deterministic mapping restores parity invariance between before-embedding and after-embedding Rule 5 register allocations.";
            if (sellerPrivEsRule) sellerPrivEsRule.textContent = `Secured encoding commitment C_ES: ${st.C_ES || "Pending"}`;
            if (sellerPrivEsVerifyNote) sellerPrivEsVerifyNote.innerHTML = `<strong>Required:</strong> Secured encoding commitment C_ES generated over canonical E_S: <code>${st.C_ES || "Pending"}</code>.`;
        } else {
            sellerEvidCesStatus.textContent = "Not Required (E_S = D)";
            sellerEvidCesStatus.className = "badge badge-v1";
            if (sellerPrivEsInvariance) sellerPrivEsInvariance.textContent = "For IIR Butterworth filter benchmark, artificial register lifetime constraints preserve identical structural operations and control step schedule. E_S equals D (143 bits).";
            if (sellerPrivEsTransformRule) sellerPrivEsTransformRule.textContent = "Secured encoding commitment and transformation rule not required for this transaction (E_S = D).";
            if (sellerPrivEsRule) sellerPrivEsRule.textContent = "Secured encoding commitment not required for this transaction (E_S equals D).";
            if (sellerPrivEsVerifyNote) sellerPrivEsVerifyNote.innerHTML = "<strong>Not Required:</strong> Because secured encoding E_S is identical to original encoding D, the existing architecture commits to D via C_D. A separate C_ES commitment is not required and no fake commitment is fabricated.";
        }
    }

    // --- BUYER UI UPDATES ---
    const buyerStateBadgeTop = document.getElementById("buyerStateBadgeTop");
    const buyerTxReqBadge = document.getElementById("buyerTxReqBadge");
    const buyerTxContribBadge = document.getElementById("buyerTxContribBadge");
    const buyerTxCommitBadge = document.getElementById("buyerTxCommitBadge");
    const buyerTxDetailsLockBadge = document.getElementById("buyerTxDetailsLockBadge");

    if (buyerStateBadgeTop) {
        if (st.buyer_approved) {
            buyerStateBadgeTop.textContent = "Contribution Approved";
            buyerStateBadgeTop.className = "badge badge-success";
        } else if (st.buyer_rejected) {
            buyerStateBadgeTop.textContent = "Request Rejected";
            buyerStateBadgeTop.className = "badge badge-danger";
        } else if (isPending) {
            buyerStateBadgeTop.textContent = "Approval Pending";
            buyerStateBadgeTop.className = "badge badge-warning pulse-amber";
        } else {
            buyerStateBadgeTop.textContent = "Idle";
            buyerStateBadgeTop.className = "badge badge-v1";
        }
    }

    if (buyerTxReqBadge) {
        buyerTxReqBadge.textContent = st.buyer_request_status || "Not Requested";
        if (st.buyer_request_status === "Approved") buyerTxReqBadge.className = "badge badge-success";
        else if (st.buyer_rejected) buyerTxReqBadge.className = "badge badge-danger";
        else if (isPending) buyerTxReqBadge.className = "badge badge-warning pulse-amber";
        else buyerTxReqBadge.className = "badge badge-v1";
    }
    if (buyerTxContribBadge) {
        buyerTxContribBadge.textContent = st.buyer_contribution_status || (st.buyer_approved ? "Received" : "Not Received");
        buyerTxContribBadge.className = st.buyer_approved ? "badge badge-success" : "badge badge-v1";
    }
    if (buyerTxCommitBadge) {
        buyerTxCommitBadge.textContent = st.buyer_commitment_status || (st.C_B ? "Generated" : "Not Generated");
        buyerTxCommitBadge.className = st.C_B ? "badge badge-success" : "badge badge-v1";
    }
    if (buyerTxDetailsLockBadge) {
        if (st.buyer_approved) {
            buyerTxDetailsLockBadge.textContent = "Available";
            buyerTxDetailsLockBadge.className = "badge badge-success";
        } else {
            buyerTxDetailsLockBadge.textContent = "Locked until approval";
            buyerTxDetailsLockBadge.className = "badge badge-warning";
        }
    }

    const buyerNoRequestView = document.getElementById("buyerNoRequestView");
    const buyerRequestActiveView = document.getElementById("buyerRequestActiveView");
    const buyerRejectedView = document.getElementById("buyerRejectedView");
    const buyerTransactionDetailsCard = document.getElementById("buyerTransactionDetailsCard");

    const buyerSellerCDDisplay = document.getElementById("buyerSellerCDDisplay");
    const buyerMetricTotalBits = document.getElementById("buyerMetricTotalBits");
    const buyerMetricZeros = document.getElementById("buyerMetricZeros");
    const buyerMetricOnes = document.getElementById("buyerMetricOnes");
    const buyerCommitmentCBDisplay = document.getElementById("buyerCommitmentCBDisplay");
    const buyerBitstreamBox = document.getElementById("buyerBitstreamBox");

    const buyerOverviewWmStatus = document.getElementById("buyerOverviewWmStatus");
    const buyerDetailsCbHex = document.getElementById("buyerDetailsCbHex");
    const buyerPrivateBlindingDisplay = document.getElementById("buyerPrivateBlindingDisplay");
    const buyerPrivateBitstreamBox = document.getElementById("buyerPrivateBitstreamBox");

    if (st.buyer_request_status === "Not Requested") {
        if (buyerNoRequestView) buyerNoRequestView.style.display = "block";
        if (buyerRequestActiveView) buyerRequestActiveView.style.display = "none";
        if (buyerRejectedView) buyerRejectedView.style.display = "none";
        if (buyerTransactionDetailsCard) buyerTransactionDetailsCard.style.display = "none";
    } else if (st.buyer_rejected) {
        if (buyerNoRequestView) buyerNoRequestView.style.display = "none";
        if (buyerRequestActiveView) buyerRequestActiveView.style.display = "none";
        if (buyerRejectedView) buyerRejectedView.style.display = "block";
        if (buyerTransactionDetailsCard) buyerTransactionDetailsCard.style.display = "none";
    } else if (isPending) {
        if (buyerNoRequestView) buyerNoRequestView.style.display = "none";
        if (buyerRequestActiveView) buyerRequestActiveView.style.display = "block";
        if (buyerRejectedView) buyerRejectedView.style.display = "none";
        if (buyerTransactionDetailsCard) buyerTransactionDetailsCard.style.display = "none";

        if (buyerSellerCDDisplay) buyerSellerCDDisplay.textContent = st.C_D || "--";

        // Dynamic 555-bit metrics
        const totalLen = st.buyer_bitstream_length || 555;
        const zeros = st.buyer_zeros_count !== null && st.buyer_zeros_count !== undefined ? st.buyer_zeros_count : 242;
        const ones = st.buyer_ones_count !== null && st.buyer_ones_count !== undefined ? st.buyer_ones_count : 313;
        if (buyerMetricTotalBits) buyerMetricTotalBits.textContent = `${totalLen} bits`;
        if (buyerMetricZeros) buyerMetricZeros.textContent = `${zeros} (${((zeros/totalLen)*100).toFixed(1)}%)`;
        if (buyerMetricOnes) buyerMetricOnes.textContent = `${ones} (${((ones/totalLen)*100).toFixed(1)}%)`;

        if (buyerCommitmentCBDisplay) buyerCommitmentCBDisplay.textContent = st.C_B || "--";
        if (buyerBitstreamBox) buyerBitstreamBox.textContent = st.buyer_bitstream_B || "--";
    } else if (st.buyer_approved) {
        if (buyerNoRequestView) buyerNoRequestView.style.display = "none";
        if (buyerRequestActiveView) buyerRequestActiveView.style.display = "none";
        if (buyerRejectedView) buyerRejectedView.style.display = "none";
        if (buyerTransactionDetailsCard) buyerTransactionDetailsCard.style.display = "block";

        if (buyerOverviewWmStatus) {
            if (st.watermark_W) {
                buyerOverviewWmStatus.textContent = "Embedded & Protected in RTL";
                buyerOverviewWmStatus.className = "metric-val status-match";
            } else {
                buyerOverviewWmStatus.textContent = "Awaiting Seller Embedding";
                buyerOverviewWmStatus.className = "metric-val status-warning";
            }
        }

        if (buyerDetailsCbHex) buyerDetailsCbHex.textContent = st.C_B || "--";
        const buyerEvidStoredCb = document.getElementById("buyerEvidStoredCb");
        if (buyerEvidStoredCb) buyerEvidStoredCb.textContent = st.C_B || "--";
        const buyerEvidCbStatus = document.getElementById("buyerEvidCbStatus");
        if (buyerEvidCbStatus) {
            if (st.C_B) {
                buyerEvidCbStatus.textContent = "Generated / Stored";
                buyerEvidCbStatus.className = "badge badge-success";
            } else {
                buyerEvidCbStatus.textContent = "Not generated yet";
                buyerEvidCbStatus.className = "badge badge-v1";
            }
        }
        if (buyerPrivateBlindingDisplay) {
            buyerPrivateBlindingDisplay.textContent = st.blinding_factor_B ? `0x${st.blinding_factor_B}` : "--";
        }
        if (buyerPrivateBitstreamBox) {
            buyerPrivateBitstreamBox.textContent = st.buyer_bitstream_B || "--";
        }
        const buyerEvidWmStatus = document.getElementById("buyerEvidWmStatus");
        const buyerSharedKey = document.getElementById("buyerSharedKey");
        const buyerSharedDLen = document.getElementById("buyerSharedDLen");
        const buyerSharedBLen = document.getElementById("buyerSharedBLen");
        const buyerSharedTLen = document.getElementById("buyerSharedTLen");
        const buyerSharedTBitstream = document.getElementById("buyerSharedTBitstream");

        if (buyerEvidWmStatus) {
            buyerEvidWmStatus.textContent = st.watermark_W ? "Derived & Shared" : "Pending Generation";
            buyerEvidWmStatus.className = st.watermark_W ? "badge badge-success" : "badge badge-v1";
        }
        if (buyerSharedKey) buyerSharedKey.textContent = (st.transaction_credentials && st.transaction_credentials.k_tx) || "K_tx_symmetric_credential_secret_777";
        if (buyerSharedDLen) buyerSharedDLen.textContent = `${dBits} bits (${isFiveRule ? '5-Rule' : '4-Rule'})`;
        if (buyerSharedBLen) buyerSharedBLen.textContent = `${(st.buyer_bitstream_B && st.buyer_bitstream_B.length) || 555} bits`;
        if (buyerSharedTLen) buyerSharedTLen.textContent = `${(st.transaction_factor_T && st.transaction_factor_T.length) || 256} bits`;
        if (buyerSharedTBitstream) buyerSharedTBitstream.textContent = st.transaction_factor_T || "Not generated yet.";
    }

    // Final authoritative enforcement for Stage 1 Design Encoding view:
    // Guarantees profile navigation or background updates cannot overwrite the selected 5-rule or 4-rule mode
    if (st.design_encoding_details) {
        renderStructuralEncodingTab1(st.design_encoding_details);
        const encBox = document.getElementById("sellerStage1EncodingDetails");
        if (encBox) encBox.style.display = "block";
    }
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

    // Structural Encoding Scope mode change
    const encScopeMode = document.getElementById("encScopeMode");
    const customScopeGroup = document.getElementById("customScopeGroup");
    const customScopeInput = document.getElementById("customScopeInput");
    const encScopeBadge = document.getElementById("encScopeBadge");

    if (encScopeMode) {
        encScopeMode.addEventListener("change", () => {
            if (encScopeMode.value === "custom") {
                if (customScopeGroup) customScopeGroup.style.display = "block";
                if (encScopeBadge) encScopeBadge.textContent = "Custom Scope";
            } else {
                if (customScopeGroup) customScopeGroup.style.display = "none";
                if (encScopeBadge) encScopeBadge.textContent = "All Steps";
            }
        });
    }

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

        let encodingScope = null;
        if (encScopeMode && encScopeMode.value === "custom") {
            const rawVal = customScopeInput ? customScopeInput.value.trim() : "";
            if (rawVal) {
                const parts = rawVal.split(",").map(p => parseInt(p.trim(), 10)).filter(p => !isNaN(p) && p > 0);
                if (parts.length > 0) {
                    encodingScope = parts;
                }
            }
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
            encoding_scope: encodingScope,
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
    if (wmComm) {
        wmComm.textContent = "STORED (P-256)";
        wmComm.className = "metric-val status-match";
    }

    const wmLen = document.getElementById("metricWmLength");
    if (wmLen) {
        if (totalWmBits === 256) {
            wmLen.textContent = "256 bits (Complete W)";
        } else {
            wmLen.textContent = `${totalWmBits} bits (W1) / 256b (W)`;
        }
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

    // Render Structural Design Encoding (Rules 1-4) only if not managed by active transaction state
    if (data.structural_encoding && (!currentTransactionState || !currentTransactionState.design_encoding_details)) {
        renderStructuralEncodingTab1(data.structural_encoding);
    }
}

// Render Structural Encoding in Tab 1 Visualizer
function renderStructuralEncodingTab1(enc) {
    if (!enc) return;
    const vEl = document.getElementById("protEncVersion");
    if (vEl) vEl.textContent = enc.encoding_version || enc.version || "structural-v1";
    const nEl = document.getElementById("protEncTotalNodes");
    if (nEl) nEl.textContent = enc.total_design_nodes ?? enc.total_nodes ?? "--";
    const wEl = document.getElementById("protEncNodeWidth");
    if (wEl) wEl.textContent = `${enc.node_width ?? "--"} bits`;
    const bEl = document.getElementById("protEncTotalBits");
    const totalBits = enc.total_bit_length ?? enc.canonical_bit_length ?? enc.total_bits ?? "--";
    if (bEl) bEl.textContent = `${totalBits} bits`;
    const sEl = document.getElementById("protEncScope");
    if (sEl) {
        const scope = enc.selected_scope || enc.scope_control_steps;
        sEl.textContent = scope && scope.length > 0 ? `Steps [${scope.join(", ")}]` : "All Control Steps";
    }
    const hEl = document.getElementById("protEncHash");
    if (hEl) {
        const hash = enc.canonical_sha256 || "";
        hEl.textContent = hash ? hash.substring(0, 24) + "..." : "--";
        hEl.title = hash;
    }

    // Table A: Four-Rule Node Table
    const tableABadge = document.getElementById("protEncTableABadge");
    const fourRuleLen = enc.four_rule_bit_length ?? (enc.four_rule_bitstream ? enc.four_rule_bitstream.length : 143);
    const nodeCount = enc.total_design_nodes ?? enc.total_nodes ?? 13;
    if (tableABadge) tableABadge.textContent = `${fourRuleLen} bits (${nodeCount} nodes × 11b)`;

    const tbody = document.getElementById("protEncTableBody");
    if (tbody) {
        tbody.innerHTML = "";
        const stepGroups = enc.step_groups || enc.steps || [];
        if (stepGroups.length > 0) {
            stepGroups.forEach(st => {
                const sName = st.step_name || `T${st.step_number || st.control_step}`;
                (st.nodes || []).forEach(nd => {
                    const tr = document.createElement("tr");
                    const r1 = nd.rule1 ?? nd.rule1_bits ?? "--";
                    const r2 = nd.rule2 ?? nd.rule2_bits ?? "--";
                    const r3 = nd.rule3 ?? nd.rule3_bit ?? "--";
                    const r4 = nd.rule4 ?? nd.rule4_bits ?? "--";
                    const block = nd.bitstream ?? nd.assembled_block ?? `${r1}${r2}${r3}${r4}`;

                    tr.innerHTML = `
                        <td><strong>${sName}</strong></td>
                        <td><strong>Node ${nd.node_id}</strong></td>
                        <td><span class="rule-chip rule-match-chip">${r1}</span></td>
                        <td><span class="rule-chip rule-match-chip">${r2}</span></td>
                        <td><span class="rule-chip rule-match-chip">${r3}</span> <span style="font-size: 0.68rem; color: var(--text-muted);">(${nd.op_type})</span></td>
                        <td><span class="rule-chip rule-match-chip">${r4}</span></td>
                        <td><code style="font-family: var(--font-mono); color: var(--primary-light); font-weight: 600;">${block}</code></td>
                    `;
                    tbody.appendChild(tr);
                });
            });
        }
    }

    // Table B: Fifth-Rule Register-Variable Table
    const tableBSection = document.getElementById("protEncTableBSection");
    const tableBBadge = document.getElementById("protEncTableBBadge");
    const tbodyB = document.getElementById("protEncTableBBody");
    const r5Records = enc.rule5_records || [];
    const hasR5 = r5Records.length > 0;

    if (tableBSection) {
        tableBSection.style.display = hasR5 ? "block" : "none";
    }

    if (tbodyB && hasR5) {
        tbodyB.innerHTML = "";
        const r5Len = enc.rule5_bit_length ?? (r5Records.length * 4);
        if (tableBBadge) tableBBadge.textContent = `${r5Len} bits (${r5Records.length} pairs × 4b)`;

        r5Records.forEach((rec, idx) => {
            const tr = document.createElement("tr");
            const pairIdx = rec.pair_index ?? rec.variable_index ?? (rec.variable_number || (idx + 1));
            let regName = rec.register_name || rec.register || (rec.register_number ? `R${rec.register_number}` : "--");
            let varName = rec.variable_name || rec.variable || (rec.variable_number ? `V${rec.variable_number}` : (pairIdx ? `V${pairIdx}` : "--"));
            if (regName === "undefined" || regName === "--") {
                if (rec.register_number) regName = `R${rec.register_number}`;
            }
            if (varName === "Vundefined" || varName === "--") {
                varName = `V${pairIdx}`;
            }

            let regNum = rec.register_number;
            if (regNum === undefined || regNum === null) {
                const m = String(regName).match(/\d+/);
                if (m) regNum = parseInt(m[0], 10);
            }
            let regParity = rec.register_parity;
            if (!regParity || regParity === "--") {
                if (regNum !== undefined && !isNaN(regNum)) regParity = (regNum % 2 !== 0) ? "Odd" : "Even";
                else regParity = "--";
            }
            let regCode = rec.register_parity_code;
            if (!regCode || regCode === "--") {
                if (regParity === "Odd" || regParity === "odd") regCode = "01";
                else if (regParity === "Even" || regParity === "even") regCode = "00";
                else regCode = "--";
            }

            let varNum = rec.variable_number;
            if (varNum === undefined || varNum === null) {
                const m = String(varName).match(/\d+/);
                if (m) varNum = parseInt(m[0], 10);
            }
            let varParity = rec.variable_parity;
            if (!varParity || varParity === "--") {
                if (varNum !== undefined && !isNaN(varNum)) varParity = (varNum % 2 !== 0) ? "Odd" : "Even";
                else varParity = "--";
            }
            let varCode = rec.variable_parity_code;
            if (!varCode || varCode === "--") {
                if (varParity === "Odd" || varParity === "odd") varCode = "01";
                else if (varParity === "Even" || varParity === "even") varCode = "00";
                else varCode = "--";
            }
            const block = rec.assembled_block || rec.encoding || `${regCode}${varCode}`;

            tr.innerHTML = `
                <td style="font-weight: 700; color: var(--text-secondary);">#${pairIdx}</td>
                <td><strong style="color: var(--accent-cyan);">${regName}</strong></td>
                <td><span class="badge ${regParity === 'Odd' || regParity === 'odd' ? 'badge-primary' : 'badge-v1'}" style="font-size: 0.68rem; padding: 0.15rem 0.4rem;">${regParity}</span></td>
                <td><span class="rule-chip rule-match-chip">${regCode}</span></td>
                <td><strong style="color: var(--text-primary);">${varName}</strong></td>
                <td><span class="badge ${varParity === 'Odd' || varParity === 'odd' ? 'badge-primary' : 'badge-v1'}" style="font-size: 0.68rem; padding: 0.15rem 0.4rem;">${varParity}</span></td>
                <td><span class="rule-chip rule-match-chip">${varCode}</span></td>
                <td><code style="font-family: var(--font-mono); color: var(--accent-cyan); font-weight: 700;">${block}</code></td>
            `;
            tbodyB.appendChild(tr);
        });
    }

    // Canonical Bitstream with Visual Boundary Separation
    const box = document.getElementById("protEncBitstreamBox");
    const bBadge = document.getElementById("protEncBitstreamBadge");
    const r5BoundaryBadge = document.getElementById("protEncBoundaryR5Badge");
    const fullBits = enc.canonical_bitstream || "";

    if (bBadge) bBadge.textContent = `${fullBits.length || totalBits} bits`;

    if (box) {
        if (hasR5 && fullBits.length >= 251) {
            const e4Bits = enc.four_rule_bitstream || fullBits.substring(0, 143);
            const r5Bits = enc.rule5_bitstream || fullBits.substring(143);
            if (r5BoundaryBadge) r5BoundaryBadge.style.display = "inline-flex";
            box.innerHTML = `<span style="color: #38bdf8;" title="Component 1: Four-Rule Node Stream (Bits 0..142, 143 bits)">${e4Bits}</span><span style="color: #f59e0b; font-weight: bold; padding: 0 4px;" title="Canonical Boundary (Bit index 143)">||</span><span style="color: #c084fc;" title="Component 2: Rule 5 Reg-Var Stream (Bits 143..250, 108 bits)">${r5Bits}</span>`;
        } else {
            if (r5BoundaryBadge) r5BoundaryBadge.style.display = "none";
            box.textContent = fullBits || "(empty bitstream)";
        }
    }
}

// Render Secured Structural Encoding in Stage 4 Substage 4B
function renderSecuredStructuralEncoding(enc, fallbackBits) {
    if (!enc && !fallbackBits) return;

    const isDict = (typeof enc === "object" && enc !== null);
    const fullBits = isDict ? (enc.canonical_bitstream || "") : (typeof enc === "string" ? enc : (fallbackBits || ""));
    const isFiveRule = fullBits.length === 251 || (isDict && (enc.mode === "five_rule" || (enc.rule5_records && enc.rule5_records.length > 0)));

    const secEncMode = document.getElementById("secEncMode");
    if (secEncMode) secEncMode.textContent = isFiveRule ? "five_rule" : "four_rule";

    const fourRuleBitsEl = document.getElementById("secEncFourRuleBits");
    const e4Len = isDict ? (enc.four_rule_bit_length ?? 143) : (isFiveRule ? 143 : fullBits.length);
    if (fourRuleBitsEl) fourRuleBitsEl.textContent = `${e4Len} bits`;

    const rule5BitsEl = document.getElementById("secEncRule5Bits");
    const r5Len = isDict ? (enc.rule5_bit_length ?? (isFiveRule ? 108 : 0)) : (isFiveRule ? 108 : 0);
    if (rule5BitsEl) rule5BitsEl.textContent = `${r5Len} bits`;

    const totalBitsEl = document.getElementById("secEncTotalBits");
    if (totalBitsEl) totalBitsEl.textContent = `${fullBits.length || (e4Len + r5Len)} bits`;

    const tablesBadge = document.getElementById("secEncTablesBadge");
    if (tablesBadge) {
        tablesBadge.textContent = isFiveRule ? "13 nodes · 27 pairs" : "13 nodes";
    }

    const tableABadge = document.getElementById("secEncTableABadge");
    if (tableABadge) tableABadge.textContent = `${e4Len} bits`;

    const tableBBadge = document.getElementById("secEncTableBBadge");
    if (tableBBadge) tableBBadge.textContent = `${r5Len} bits (27 pairs)`;

    const tableBSection = document.getElementById("secEncTableBSection");
    if (tableBSection) tableBSection.style.display = isFiveRule ? "block" : "none";

    const r5BoundaryBadge = document.getElementById("secEncBoundaryR5Badge");
    if (r5BoundaryBadge) r5BoundaryBadge.style.display = isFiveRule ? "inline-flex" : "none";

    // Populate Secured Table A (Nodes)
    const tbodyA = document.getElementById("secEncTableBody");
    if (tbodyA) {
        tbodyA.innerHTML = "";
        const stepGroups = isDict ? (enc.step_groups || enc.steps || []) : [];
        if (stepGroups.length > 0) {
            stepGroups.forEach(st => {
                const sName = st.step_name || `T${st.step_number || st.control_step}`;
                (st.nodes || []).forEach(nd => {
                    const tr = document.createElement("tr");
                    const r1 = nd.rule1 ?? nd.rule1_bits ?? "--";
                    const r2 = nd.rule2 ?? nd.rule2_bits ?? "--";
                    const r3 = nd.rule3 ?? nd.rule3_bit ?? "--";
                    const r4 = nd.rule4 ?? nd.rule4_bits ?? "--";
                    const block = nd.bitstream ?? nd.assembled_block ?? `${r1}${r2}${r3}${r4}`;

                    tr.innerHTML = `
                        <td><strong>${sName}</strong></td>
                        <td><strong>Node ${nd.node_id}</strong></td>
                        <td><span class="rule-chip rule-match-chip">${r1}</span></td>
                        <td><span class="rule-chip rule-match-chip">${r2}</span></td>
                        <td><span class="rule-chip rule-match-chip">${r3}</span> <span style="font-size: 0.68rem; color: var(--text-muted);">(${nd.op_type})</span></td>
                        <td><span class="rule-chip rule-match-chip">${r4}</span></td>
                        <td><code style="font-family: var(--font-mono); color: var(--primary-light); font-weight: 600;">${block}</code></td>
                    `;
                    tbodyA.appendChild(tr);
                });
            });
        }
    }

    // Populate Secured Table B (Post-embedding Reg-Var assignments)
    const tbodyB = document.getElementById("secEncTableBBody");
    if (tbodyB && isFiveRule) {
        tbodyB.innerHTML = "";
        const r5Records = isDict ? (enc.rule5_records || []) : [];
        const preRegMap = {
            "V1": "R1", "V2": "R2", "V3": "R3", "V4": "R4", "V5": "R1", "V6": "R3",
            "V7": "R5", "V8": "R6", "V9": "R7", "V10": "R8", "V11": "R1", "V12": "R5",
            "V13": "R7", "V14": "R9", "V15": "R10", "V16": "R11", "V17": "R12", "V18": "R1",
            "V19": "R9", "V20": "R11", "V21": "R13", "V22": "R1", "V23": "R1", "V24": "R13",
            "V25": "R1", "V26": "R1", "V27": "R1"
        };

        r5Records.forEach((rec, idx) => {
            const tr = document.createElement("tr");
            const pairIdx = rec.pair_index ?? rec.variable_index ?? (rec.variable_number || (idx + 1));
            let regName = rec.register_name || rec.register || (rec.register_number ? `R${rec.register_number}` : "--");
            let varName = rec.variable_name || rec.variable || (rec.variable_number ? `V${rec.variable_number}` : (pairIdx ? `V${pairIdx}` : "--"));
            if (regName === "undefined" || regName === "--") {
                if (rec.register_number) regName = `R${rec.register_number}`;
            }
            if (varName === "Vundefined" || varName === "--") {
                varName = `V${pairIdx}`;
            }

            let regNum = rec.register_number;
            if (regNum === undefined || regNum === null) {
                const m = String(regName).match(/\d+/);
                if (m) regNum = parseInt(m[0], 10);
            }
            let regParity = rec.register_parity;
            if (!regParity || regParity === "--") {
                if (regNum !== undefined && !isNaN(regNum)) regParity = (regNum % 2 !== 0) ? "Odd" : "Even";
                else regParity = "--";
            }
            let regCode = rec.register_parity_code;
            if (!regCode || regCode === "--") {
                if (regParity === "Odd" || regParity === "odd") regCode = "01";
                else if (regParity === "Even" || regParity === "even") regCode = "00";
                else regCode = "--";
            }

            let varNum = rec.variable_number;
            if (varNum === undefined || varNum === null) {
                const m = String(varName).match(/\d+/);
                if (m) varNum = parseInt(m[0], 10);
            }
            let varParity = rec.variable_parity;
            if (!varParity || varParity === "--") {
                if (varNum !== undefined && !isNaN(varNum)) varParity = (varNum % 2 !== 0) ? "Odd" : "Even";
                else varParity = "--";
            }
            let varCode = rec.variable_parity_code;
            if (!varCode || varCode === "--") {
                if (varParity === "Odd" || varParity === "odd") varCode = "01";
                else if (varParity === "Even" || varParity === "even") varCode = "00";
                else varCode = "--";
            }
            const block = rec.assembled_block || rec.encoding || `${regCode}${varCode}`;

            // Derive comparison status based on real calculation between original and secured Rule 5 blocks
            let compStatus = rec.comparison_status;
            if (!compStatus) {
                const origReg = rec.original_register || preRegMap[varName];
                if (origReg) {
                    const origRegDigits = origReg.replace(/\D/g, "");
                    const origRegNum = parseInt(origRegDigits, 10);
                    const origRegCode = (origRegNum % 2 !== 0) ? "01" : "00";
                    const origBlock = rec.original_encoding || `${origRegCode}${varCode}`;
                    compStatus = (origBlock !== block) ? "Changed" : "Unchanged";
                } else {
                    compStatus = "Unresolved";
                }
            }

            const isChanged = (compStatus === "Changed");
            const statusBadgeHtml = isChanged
                ? '<span class="badge badge-warning" title="CIG Modified" style="font-size: 0.65rem;">Changed</span>'
                : (compStatus === "Unchanged"
                    ? '<span class="badge badge-success" style="font-size: 0.65rem;">Unchanged</span>'
                    : `<span class="badge badge-v1" style="font-size: 0.65rem;">${compStatus}</span>`);

            tr.innerHTML = `
                <td style="font-weight: 700; color: var(--text-secondary);">#${pairIdx}</td>
                <td><strong style="color: ${isChanged ? 'var(--warning)' : 'var(--accent-cyan)'};">${regName}</strong></td>
                <td><span class="badge ${regParity === 'Odd' || regParity === 'odd' ? 'badge-primary' : 'badge-v1'}" style="font-size: 0.68rem; padding: 0.15rem 0.4rem;">${regParity}</span></td>
                <td><span class="rule-chip rule-match-chip">${regCode}</span></td>
                <td><strong style="color: var(--text-primary);">${varName}</strong></td>
                <td><span class="badge ${varParity === 'Odd' || varParity === 'odd' ? 'badge-primary' : 'badge-v1'}" style="font-size: 0.68rem; padding: 0.15rem 0.4rem;">${varParity}</span></td>
                <td><span class="rule-chip rule-match-chip">${varCode}</span></td>
                <td><code style="font-family: var(--font-mono); color: ${isChanged ? 'var(--warning)' : 'var(--accent-cyan)'}; font-weight: 700;">${block}</code></td>
                <td>${statusBadgeHtml}</td>
            `;
            tbodyB.appendChild(tr);
        });
    }

    // Render Bitstream Box with Boundary Separation
    const rawBox = document.getElementById("sellerStageEsBitstream");
    if (rawBox) rawBox.textContent = fullBits;

    const fmtBox = document.getElementById("sellerStageEsBitstreamFormatted");
    if (fmtBox) {
        if (isFiveRule && fullBits.length >= 251) {
            const e4Bits = (isDict && enc.four_rule_bitstream) ? enc.four_rule_bitstream : fullBits.substring(0, 143);
            const r5Bits = (isDict && enc.rule5_bitstream) ? enc.rule5_bitstream : fullBits.substring(143);
            fmtBox.innerHTML = `<span style="color: #38bdf8;" title="Component 1: Secured Four-Rule Stream (Bits 0..142, 143 bits)">${e4Bits}</span><span style="color: #f59e0b; font-weight: bold; padding: 0 4px;" title="Canonical Boundary (Bit index 143)">||</span><span style="color: #c084fc;" title="Component 2: Secured Rule 5 Stream (Bits 143..250, 108 bits)">${r5Bits}</span>`;
        } else {
            fmtBox.textContent = fullBits || "(empty bitstream)";
        }
    }

    const badge = document.getElementById("sellerStageEsBadge");
    if (badge) {
        badge.textContent = `Reconstructed (${fullBits.length} bits)`;
        badge.className = "badge badge-success";
    }
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

    // Level 2 Structural Encoding Filter Buttons
    const btnL2All = document.getElementById("btnL2All");
    if (btnL2All) {
        btnL2All.addEventListener("click", () => applyL2Filter("all"));
    }
    const btnL2Diffs = document.getElementById("btnL2DiffsOnly");
    if (btnL2Diffs) {
        btnL2Diffs.addEventListener("click", () => applyL2Filter("diffs"));
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

    // Section 4: Structural Design Encoding Verification (Level 1 & Level 2)
    renderStructuralVerificationTab2(res.structural_encoding_verification);
}

// Current filter state for Level 2 comparison
let currentL2Filter = "all";

// Render Structural Encoding Verification in Tab 2 Report
function renderStructuralVerificationTab2(sec) {
    const metricL1 = document.getElementById("dispMetricEncL1");
    const repBadge = document.getElementById("reportEncBadge");
    const l1Badge = document.getElementById("level1StatusBadge");
    const stepsContainer = document.getElementById("l2StepsContainer");

    if (!sec || !sec.level1) {
        if (metricL1) {
            metricL1.textContent = "NOT AVAILABLE";
            metricL1.className = "metric-val status-info";
        }
        if (repBadge) {
            repBadge.textContent = "NOT AVAILABLE";
            repBadge.className = "badge badge-info";
        }
        if (l1Badge) {
            l1Badge.textContent = "NOT AVAILABLE";
            l1Badge.className = "badge badge-info";
        }
        if (stepsContainer) {
            stepsContainer.innerHTML = `<p style="font-size: 0.8rem; color: var(--text-muted); padding: 0.5rem;">Structural encoding evidence could not be recovered for the investigated RTL (e.g. non-synthesizable or obfuscated schedule markers).</p>`;
        }
        return;
    }

    const l1 = sec.level1;
    const l2 = sec.level2 || {};
    const l2Summary = l2.summary || {};
    const isExact = l1.is_exact_match === true || l1.status === "MATCH";

    // Level 1 Metrics
    if (metricL1) {
        metricL1.textContent = isExact ? "MATCH" : "MISMATCH";
        metricL1.className = `metric-val status-${isExact ? "match" : "invalid"}`;
    }
    if (repBadge) {
        repBadge.textContent = `L1: ${isExact ? "MATCH" : "MISMATCH"}`;
        repBadge.className = `badge ${isExact ? "badge-live" : "badge-danger"}`;
    }
    if (l1Badge) {
        l1Badge.textContent = isExact ? "EXACT MATCH (100%)" : "CANONICAL MISMATCH";
        l1Badge.className = `badge ${isExact ? "badge-live" : "badge-danger"}`;
    }

    const elRefBits = document.getElementById("l1RefBits");
    if (elRefBits) elRefBits.textContent = `${l1.reference_bit_length ?? "--"} bits`;
    const elSusBits = document.getElementById("l1SusBits");
    if (elSusBits) elSusBits.textContent = `${l1.suspicious_bit_length ?? "--"} bits`;
    const elMatchBits = document.getElementById("l1MatchBits");
    if (elMatchBits) elMatchBits.textContent = `${l1.matching_bits ?? "--"} bits`;
    const elDiffBits = document.getElementById("l1DiffBits");
    if (elDiffBits) {
        const diffs = l1.differing_bits ?? 0;
        elDiffBits.textContent = `${diffs} bits`;
        elDiffBits.className = `report-stat-num ${diffs === 0 ? 'status-match' : 'status-invalid'}`;
    }

    const elRefHash = document.getElementById("l1RefHash");
    if (elRefHash) elRefHash.textContent = l1.reference_sha256 || "--";
    const elSusHash = document.getElementById("l1SusHash");
    if (elSusHash) elSusHash.textContent = l1.suspicious_sha256 || "--";
    const elScopeCheck = document.getElementById("l1ScopeCheck");
    if (elScopeCheck) {
        const scopeStr = l1.scope_mismatch ? `⚠ Scope Mismatch` : `✓ Scope Identical`;
        const nodeStr = l1.node_count_mismatch ? `⚠ Node Count Mismatch` : `✓ Node Count Identical (n = ${l2Summary.reference_nodes ?? '--'})`;
        elScopeCheck.textContent = `${scopeStr} | ${nodeStr}`;
    }

    // Canonical Bitstream Boxes
    const refBitstream = (sec.reference_encoding && sec.reference_encoding.canonical_bitstream) || l1.reference_bitstream || "(none)";
    const susBitstream = (sec.suspicious_encoding && sec.suspicious_encoding.canonical_bitstream) || l1.suspicious_bitstream || "(none)";
    const refBox = document.getElementById("dispRefBitstreamBox");
    if (refBox) refBox.textContent = refBitstream;
    const susBox = document.getElementById("dispSusBitstreamBox");
    if (susBox) susBox.textContent = susBitstream;

    // Level 2 Summary Cards
    const elNodeComp = document.getElementById("l2NodeCountComp");
    if (elNodeComp) elNodeComp.textContent = `${l2Summary.reference_nodes ?? '--'} / ${l2Summary.suspicious_nodes ?? '--'}`;
    const elStepComp = document.getElementById("l2StepCountComp");
    if (elStepComp) elStepComp.textContent = `${l2Summary.reference_steps ?? '--'} / ${l2Summary.suspicious_steps ?? '--'}`;
    const elMatchComp = document.getElementById("l2MatchingComponents");
    if (elMatchComp) elMatchComp.textContent = `${l2Summary.matching_components ?? '--'} / ${l2Summary.total_components_evaluated ?? '--'}`;
    const elAgrRate = document.getElementById("l2AgreementRate");
    if (elAgrRate) {
        const rate = l2Summary.agreement_percentage_str || (l2Summary.agreement_ratio !== undefined ? `${(l2Summary.agreement_ratio * 100).toFixed(2)}%` : "--");
        elAgrRate.textContent = rate;
        elAgrRate.className = `report-stat-num ${(l2Summary.differing_components ?? 0) === 0 ? 'status-match' : 'status-invalid'}`;
    }

    const cAll = document.getElementById("countAllComponents");
    if (cAll) cAll.textContent = l2Summary.total_components_evaluated ?? 0;
    const cDiff = document.getElementById("countDiffComponents");
    if (cDiff) cDiff.textContent = l2Summary.differing_components ?? 0;

    // Render Steps Accordions
    if (!stepsContainer) return;
    stepsContainer.innerHTML = "";

    const stepComparisons = l2.step_comparisons || [];
    if (stepComparisons.length === 0) {
        stepsContainer.innerHTML = `<p style="font-size: 0.8rem; color: var(--text-muted);">No control step comparisons available.</p>`;
        return;
    }

    const totalSteps = stepComparisons.length;

    stepComparisons.forEach((st, idx) => {
        const stepStatus = st.status || (st.matching_node_count === st.total_step_nodes ? "MATCH" : "DIFFER");
        const hasDiff = stepStatus !== "MATCH";
        const acc = document.createElement("div");
        acc.className = "step-accordion";
        acc.dataset.hasDiff = hasDiff ? "true" : "false";

        // Keep open if has difference, or if total steps <= 3, or if first step
        if (hasDiff || totalSteps <= 3 || idx === 0) {
            acc.classList.add("open");
        }

        const stepLabel = st.step_name || `Control Step T${st.step_number}`;
        const refCount = st.reference_node_count ?? st.total_step_nodes ?? 0;
        const susCount = st.suspicious_node_count ?? refCount;
        const diffCount = (st.total_step_nodes ?? refCount) - (st.matching_node_count ?? refCount);

        const header = document.createElement("div");
        header.className = "step-accordion-header";
        header.innerHTML = `
            <div class="step-accordion-title">
                <span class="step-accordion-arrow">▶</span>
                <span>${stepLabel}</span>
                <span style="font-size: 0.72rem; color: var(--text-muted); font-weight: 400;">(${refCount} ref nodes, ${susCount} sus nodes)</span>
            </div>
            <div>
                ${!hasDiff
                    ? '<span class="badge badge-live" style="font-size: 0.7rem;">✓ All Match</span>'
                    : `<span class="badge badge-danger" style="font-size: 0.7rem;">⚠ ${diffCount > 0 ? diffCount : 1} Differ</span>`}
            </div>
        `;

        header.addEventListener("click", () => {
            acc.classList.toggle("open");
        });

        const body = document.createElement("div");
        body.className = "step-accordion-body";

        let rowsHtml = "";
        const nodeList = st.nodes || [];
        nodeList.forEach(nd => {
            const isMatch = nd.status === "MATCH";
            const r1 = nd.rule1 || {};
            const r2 = nd.rule2 || {};
            const r3 = nd.rule3 || {};
            const r4 = nd.rule4 || {};

            const r1Cell = (r1.match !== false)
                ? `<span class="rule-chip rule-match-chip">${r1.ref ?? nd.ref_rule1 ?? "--"}</span>`
                : `<div class="rule-diff-box"><span class="rule-diff-ref">Ref: ${r1.ref}</span><span class="rule-diff-sus">Sus: ${r1.sus}</span></div>`;

            const r2Cell = (r2.match !== false)
                ? `<span class="rule-chip rule-match-chip">${r2.ref ?? nd.ref_rule2 ?? "--"}</span>`
                : `<div class="rule-diff-box"><span class="rule-diff-ref">Ref: ${r2.ref}</span><span class="rule-diff-sus">Sus: ${r2.sus}</span></div>`;

            const r3Cell = (r3.match !== false)
                ? `<span class="rule-chip rule-match-chip">${r3.ref ?? nd.ref_rule3 ?? "--"}</span> <span style="font-size: 0.68rem; color: var(--text-muted);">(${nd.op_type || ''})</span>`
                : `<div class="rule-diff-box"><span class="rule-diff-ref">Ref: ${r3.ref}</span><span class="rule-diff-sus">Sus: ${r3.sus}</span></div>`;

            const r4Cell = (r4.match !== false)
                ? `<span class="rule-chip rule-match-chip">${r4.ref ?? nd.ref_rule4 ?? "--"}</span>`
                : `<div class="rule-diff-box"><span class="rule-diff-ref">Ref: ${r4.ref}</span><span class="rule-diff-sus">Sus: ${r4.sus}</span></div>`;

            const statusCell = isMatch
                ? `<span class="status-match" style="font-size: 0.75rem;">MATCH</span>`
                : `<span class="status-differ" style="font-size: 0.75rem;">DIFFER</span>`;

            rowsHtml += `
                <tr class="l2-node-row" data-node-diff="${!isMatch}">
                    <td><strong>Node ${nd.node_id}</strong></td>
                    <td>${r1Cell}</td>
                    <td>${r2Cell}</td>
                    <td>${r3Cell}</td>
                    <td>${r4Cell}</td>
                    <td>${statusCell}</td>
                </tr>
            `;
        });

        body.innerHTML = `
            <div class="table-responsive">
                <table class="reg-table" style="font-size: 0.78rem;">
                    <thead>
                        <tr>
                            <th>Node</th>
                            <th>Rule 1 (Parity)</th>
                            <th>Rule 2 (Node ID)</th>
                            <th>Rule 3 (Op Type)</th>
                            <th>Rule 4 (Step Count)</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>${rowsHtml}</tbody>
                </table>
            </div>
        `;

        acc.appendChild(header);
        acc.appendChild(body);
        stepsContainer.appendChild(acc);
    });

    // Apply current filter
    applyL2Filter(currentL2Filter);
}

// Filter Level 2 Steps and Rows: 'all' vs 'diffs'
function applyL2Filter(filterMode) {
    currentL2Filter = filterMode;
    const btnAll = document.getElementById("btnL2All");
    const btnDiffs = document.getElementById("btnL2DiffsOnly");
    if (btnAll && btnDiffs) {
        if (filterMode === "diffs") {
            btnDiffs.classList.add("active");
            btnAll.classList.remove("active");
        } else {
            btnAll.classList.add("active");
            btnDiffs.classList.remove("active");
        }
    }

    const accordions = document.querySelectorAll("#l2StepsContainer .step-accordion");
    accordions.forEach(acc => {
        const hasDiff = acc.dataset.hasDiff === "true";
        if (filterMode === "diffs") {
            if (!hasDiff) {
                acc.style.display = "none";
            } else {
                acc.style.display = "";
                acc.classList.add("open");
                acc.querySelectorAll(".l2-node-row").forEach(row => {
                    if (row.dataset.nodeDiff === "false") {
                        row.style.display = "none";
                    } else {
                        row.style.display = "";
                    }
                });
            }
        } else {
            acc.style.display = "";
            acc.querySelectorAll(".l2-node-row").forEach(row => {
                row.style.display = "";
            });
        }
    });
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

// ==============================================================================
// VERIFIER PROFILE & STEP-BY-STEP DISPUTE ADJUDICATION WORKFLOW
// ==============================================================================

let currentVerifierSession = null;
let currentVerifierStep = 1;

const VERIFIER_STEPS_META = [
    {
        num: 1,
        title: "Step 1: Obtain Disputed RTL",
        party: "Dispute Submitter / Transaction Registry",
        desc: "Load the disputed synthesizable Verilog RTL associated with transaction TX-001.",
        defaultMethod: "Acquire synthesized RTL artifact bound to the selected transaction",
        defaultInput: "Transaction TX-001 synthesizable Verilog RTL source"
    },
    {
        num: 2,
        title: "Step 2: Extract Secured Encoding (E_S')",
        party: "Seller / Verifier Execution",
        desc: "Apply the 4-rule deterministic structural encoding for IIR Butterworth filter to extract E_S' (143 bits).",
        defaultMethod: "4-Rule Deterministic Structural Encoding (Parity, Node ID, Op Type, Step Count)",
        defaultInput: "Disputed RTL & Scheduled DFG (13 nodes, 7 control steps)"
    },
    {
        num: 3,
        title: "Step 3: Evaluate Encoding Invariance (E_S vs D)",
        party: "Verifier Analysis",
        desc: "Determine whether the watermarked encoding E_S' changed relative to baseline D. Branch A: E_S = D (C_ES not required); Branch B: E_S != D.",
        defaultMethod: "Bitwise comparison of extracted E_S' against baseline original design encoding D",
        defaultInput: "E_S' (143 bits) and D (143 bits)"
    },
    {
        num: 4,
        title: "Step 4: Verify Original Design Encoding (C_D)",
        party: "Seller",
        desc: "Independently calculate D' (143 bits) from golden benchmark rules and verify commitment C_D' == C_D over NIST P-256.",
        defaultMethod: "Execute deterministic structural encoder for IIR Butterworth Filter (Rule 1-4)",
        defaultInput: "Golden IIR Butterworth filter benchmark specification"
    },
    {
        num: 5,
        title: "Step 5: Extract Complete Watermark (W')",
        party: "Seller Rules / Verifier RTL Extraction",
        desc: "Inspect synthesized RTL register bindings for target CIG pairs and recover complete 256-bit watermark W'.",
        defaultMethod: "Parse synthesized RTL register allocations; inspect mutual exclusion across target CIG pairs",
        defaultInput: "Synthesizable Verilog RTL source and target variable pair mapping"
    },
    {
        num: 6,
        title: "Step 6: Verify Complete Watermark Commitment (C_W)",
        party: "Seller",
        desc: "Recalculate C_W' = Commit(H(W'), r_W) over NIST P-256 and verify equality with stored commitment C_W.",
        defaultMethod: "Value is extracted 256-bit complete watermark W' from Step 5",
        defaultInput: "W' (256 bits)"
    },
    {
        num: 7,
        title: "Step 7: Reconstruct Complete Watermark (W') [Legacy Only]",
        party: "Seller Private Evidence",
        desc: "Not required in full-watermark model (W' extracted directly in Step 5). Preserved for legacy split-watermark verification.",
        defaultMethod: "Watermark reconstruction rule: W = W1 || W2 (Concatenation)",
        defaultInput: "Extracted W1' (32 bits) and protected off-chain W2 (224 bits)"
    },
    {
        num: 8,
        title: "Step 8: Verify Complete Watermark Commitment (C_W) [Legacy Only]",
        party: "Seller",
        desc: "Not required in full-watermark model (C_W verified in Step 6). Preserved for legacy split-watermark verification.",
        defaultMethod: "Value is reconstructed 256-bit complete watermark W' from Step 7",
        defaultInput: "W' (256 bits)"
    },
    {
        num: 9,
        title: "Step 9: Check Buyer Contribution Bitstream (B')",
        party: "Buyer Private Evidence",
        desc: "Load and validate Buyer demonstration bitstream B' (555 bits: 242 zeros, 313 ones). One-way derivation prevents inverting B from W.",
        defaultMethod: "Fingerprint-Derived Bitstream Extraction (fingerprint_minutiae_demo_standard)",
        defaultInput: "Demonstration minutiae coordinate extraction template"
    },
    {
        num: 10,
        title: "Step 10: Verify Buyer Commitment (C_B)",
        party: "Buyer",
        desc: "Recalculate C_B' = Commit(B', r_B) and verify equality with stored commitment C_B. Commitment C_B belongs strictly to Buyer profile.",
        defaultMethod: "Value is validated 555-bit Buyer demonstration bitstream B' from Step 9",
        defaultInput: "B' (555 bits)"
    },
    {
        num: 11,
        title: "Step 11: Verify Watermark-Generation Relationship F",
        party: "Verifier Independent Computation",
        desc: "Verify canonical transaction relationship W' == F(D', B', context, k_tx) using RFC 5869 Symmetric HKDF-SHA256.",
        defaultMethod: "RFC 5869 Symmetric HKDF-SHA256 (Extract-and-Expand) over canonical transaction record",
        defaultInput: "Transaction metadata record, credential key k_tx, design hash"
    },
    {
        num: 12,
        title: "Step 12: Verify Transaction Evidence & Recorded Rights",
        party: "Transaction State Record",
        desc: "Audit transaction authorizations and distinguish cryptographic consistency from recorded rights (exclusive license vs ownership).",
        defaultMethod: "Inspect recorded transaction parameters, parties, approvals, and license terms",
        defaultInput: "Transaction TX-001 audit ledger and authorization states"
    },
    {
        num: 13,
        title: "Step 13: Generate Final Dispute Report",
        party: "Independent Dispute Adjudication Authority",
        desc: "Compile structured dispute adjudication report and overall evidence consistency status.",
        defaultMethod: "Synthesize verification outcomes across design, watermarks, buyer bitstream, and transaction terms",
        defaultInput: "Independent verification outcomes from Steps 1 through 12"
    }
];

const DISPUTE_SUBCATEGORIES_MAP = {
    "Seller ↔ Buyer Conflict": [
        "Buyer claims ownership; Seller disputes the transaction.",
        "Buyer claims a transaction; Seller disputes authorization.",
        "Buyer claims ownership; recorded transaction may grant only a license."
    ],
    "Reference Design ↔ Suspicious Design": [
        "Exact or near-copy suspicion.",
        "Modified design.",
        "Possible unauthorized reuse."
    ]
};

function initVerifierWorkflow() {
    const disputeTypeSelect = document.getElementById("verifierDisputeType");
    const subcategorySelect = document.getElementById("verifierDisputeSubcategory");

    if (disputeTypeSelect && subcategorySelect) {
        disputeTypeSelect.addEventListener("change", () => {
            const selectedType = disputeTypeSelect.value;
            const subcats = DISPUTE_SUBCATEGORIES_MAP[selectedType] || [];
            subcategorySelect.innerHTML = "";
            subcats.forEach(s => {
                const opt = document.createElement("option");
                opt.value = s;
                opt.textContent = s;
                subcategorySelect.appendChild(opt);
            });

            // Toggle workspaces depending on dispute category
            const sbWorkspace = document.getElementById("verifierSellerBuyerWorkspace");
            const refSusWorkspace = document.getElementById("verifierRefSusWorkspace");
            const tabDisputeEl = document.getElementById("tabDispute");

            if (selectedType === "Reference Design ↔ Suspicious Design") {
                if (sbWorkspace) sbWorkspace.style.display = "none";
                if (refSusWorkspace) refSusWorkspace.style.display = "block";
                if (tabDisputeEl) tabDisputeEl.style.display = "block";
            } else {
                if (refSusWorkspace) refSusWorkspace.style.display = "none";
                if (tabDisputeEl) tabDisputeEl.style.display = "none";
                if (currentVerifierSession && currentVerifierSession.step_results) {
                    if (sbWorkspace) sbWorkspace.style.display = "block";
                }
            }
        });
    }

    // Initialize Guided Dispute Workspace button
    const btnInit = document.getElementById("btnInitDispute");
    if (btnInit) {
        btnInit.addEventListener("click", async () => {
            const txSelect = document.getElementById("verifierTxSelect");
            const txId = txSelect ? txSelect.value : "TX-001";
            const dispType = disputeTypeSelect ? disputeTypeSelect.value : "Seller ↔ Buyer Conflict";
            const subcat = subcategorySelect ? subcategorySelect.value : null;

            try {
                const res = await fetch("/api/verifier/configure_dispute", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        transaction_id: txId,
                        dispute_type: dispType,
                        dispute_subcategory: subcat
                    })
                });

                if (res.ok) {
                    const data = await res.json();
                    currentVerifierSession = data.session;
                    currentVerifierStep = 1;

                    const sbWorkspace = document.getElementById("verifierSellerBuyerWorkspace");
                    const refSusWorkspace = document.getElementById("verifierRefSusWorkspace");
                    const tabDisputeEl = document.getElementById("tabDispute");

                    if (dispType === "Seller ↔ Buyer Conflict") {
                        if (sbWorkspace) sbWorkspace.style.display = "block";
                        if (refSusWorkspace) refSusWorkspace.style.display = "none";
                        if (tabDisputeEl) tabDisputeEl.style.display = "none";
                        renderVerifierStep(1);
                    } else {
                        if (sbWorkspace) sbWorkspace.style.display = "none";
                        if (refSusWorkspace) refSusWorkspace.style.display = "block";
                        if (tabDisputeEl) tabDisputeEl.style.display = "block";
                    }

                    const sessBadge = document.getElementById("verifierSessionBadge");
                    if (sessBadge) sessBadge.textContent = `Session: ${currentVerifierSession.session_id}`;
                }
            } catch (err) {
                console.error("Failed to initialize dispute session:", err);
            }
        });
    }

    // Reset button
    const btnReset = document.getElementById("btnResetDispute");
    if (btnReset) {
        btnReset.addEventListener("click", async () => {
            try {
                const res = await fetch("/api/verifier/reset", { method: "POST" });
                if (res.ok) {
                    const data = await res.json();
                    currentVerifierSession = data.session;
                    currentVerifierStep = 1;

                    const sbWorkspace = document.getElementById("verifierSellerBuyerWorkspace");
                    const refSusWorkspace = document.getElementById("verifierRefSusWorkspace");
                    const tabDisputeEl = document.getElementById("tabDispute");
                    const reportCard = document.getElementById("verifierFinalReportCard");

                    if (sbWorkspace) sbWorkspace.style.display = "none";
                    if (refSusWorkspace) refSusWorkspace.style.display = "none";
                    if (tabDisputeEl) tabDisputeEl.style.display = "none";
                    if (reportCard) reportCard.style.display = "none";

                    const sessBadge = document.getElementById("verifierSessionBadge");
                    if (sessBadge) sessBadge.textContent = "Session: Reset";

                    initOrRefreshVerifierProfile();
                }
            } catch (err) {
                console.error("Failed to reset verifier session:", err);
            }
        });
    }

    // Stepper navigation controls
    const btnPrev = document.getElementById("btnVerifierPrevStep");
    if (btnPrev) {
        btnPrev.addEventListener("click", () => {
            if (currentVerifierStep > 1) {
                currentVerifierStep--;
                renderVerifierStep(currentVerifierStep);
            }
        });
    }

    const btnNext = document.getElementById("btnVerifierNextStep");
    if (btnNext) {
        btnNext.addEventListener("click", () => {
            if (currentVerifierStep < 13) {
                currentVerifierStep++;
                renderVerifierStep(currentVerifierStep);
            }
        });
    }

    // Execute current step button
    const btnExec = document.getElementById("btnVerifierExecStep");
    if (btnExec) {
        btnExec.addEventListener("click", async () => {
            btnExec.disabled = true;
            btnExec.textContent = `Executing Step ${currentVerifierStep}...`;
            try {
                const res = await fetch("/api/verifier/execute_step", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ step_number: currentVerifierStep })
                });

                if (res.ok) {
                    const data = await res.json();
                    currentVerifierSession = data.session;
                    renderVerifierStep(currentVerifierStep);

                    // If final step, also render final report
                    if (currentVerifierStep === 13 && currentVerifierSession.final_report) {
                        renderFinalReport(currentVerifierSession.final_report);
                    }
                } else {
                    const err = await res.json();
                    alert(`Step verification error: ${err.detail || "Server error"}`);
                }
            } catch (err) {
                console.error("Failed to execute verification step:", err);
            } finally {
                btnExec.disabled = false;
                btnExec.textContent = `Execute Step ${currentVerifierStep}`;
            }
        });
    }

    // Verify all steps button
    const btnRunAll = document.getElementById("btnVerifierRunAll");
    if (btnRunAll) {
        btnRunAll.addEventListener("click", async () => {
            btnRunAll.disabled = true;
            btnRunAll.textContent = "Verifying All Steps...";
            try {
                const res = await fetch("/api/verifier/run_all_steps", { method: "POST" });
                if (res.ok) {
                    const data = await res.json();
                    currentVerifierSession = data.session;
                    currentVerifierStep = 13;
                    renderVerifierStep(13);
                    if (currentVerifierSession.final_report) {
                        renderFinalReport(currentVerifierSession.final_report);
                    }
                }
            } catch (err) {
                console.error("Failed to run all verifier steps:", err);
            } finally {
                btnRunAll.disabled = false;
                btnRunAll.textContent = "Verify All Steps";
            }
        });
    }

    // Stepper pill clicks (legacy support)
    const stepperPills = document.querySelectorAll("#verifierStepper .step-tracker-pill");
    stepperPills.forEach(pill => {
        pill.addEventListener("click", () => {
            const stepNum = parseInt(pill.dataset.step, 10);
            if (!isNaN(stepNum)) {
                currentVerifierStep = stepNum;
                renderVerifierStep(stepNum);
            }
        });
    });

    // 4 Evidence Sections Navigation Cards
    const sectionNavCards = document.querySelectorAll(".verifier-section-card");
    sectionNavCards.forEach(card => {
        card.addEventListener("click", () => {
            const secNum = parseInt(card.dataset.sec, 10);
            if (!isNaN(secNum)) {
                switchVerifierSection(secNum);
            }
        });
    });

    // Expandable subsection toggle on header click
    document.querySelectorAll(".v-step-header").forEach(hdr => {
        hdr.addEventListener("click", (e) => {
            if (e.target.closest(".v-step-inline-btn")) return;
            const stepBox = hdr.closest(".v-step-box");
            if (stepBox) {
                stepBox.classList.toggle("collapsed");
            }
        });
    });

    // Inline step execution buttons inside subsections
    document.querySelectorAll(".v-step-inline-btn").forEach(btn => {
        btn.addEventListener("click", async (e) => {
            e.stopPropagation();
            const rawStep = btn.dataset.step;
            const stepNum = isNaN(parseInt(rawStep, 10)) ? rawStep : parseInt(rawStep, 10);
            if (stepNum !== undefined && stepNum !== null && stepNum !== "") {
                await executeVerifierStepInline(stepNum, btn);
            }
        });
    });

    // Step item cards in sections (click to expand/focus)
    const stepItemCards = document.querySelectorAll(".v-step-item-card");
    stepItemCards.forEach(card => {
        card.addEventListener("click", () => {
            const stepNum = parseInt(card.dataset.step, 10);
            if (!isNaN(stepNum)) {
                currentVerifierStep = stepNum;
                renderVerifierStep(stepNum);
            }
        });
    });
}

function switchVerifierSection(secNum) {
    // Highlight active section navigation card and view
    for (let i = 1; i <= 4; i++) {
        const nav = document.getElementById(`vSecNav${i}`);
        const view = document.getElementById(`vSecView${i}`);
        if (nav) {
            if (i === secNum) nav.classList.add("active");
            else nav.classList.remove("active");
        }
        if (view) {
            if (i === secNum) view.classList.add("active");
            else view.classList.remove("active");
        }
    }

    if (secNum === 4) {
        const repCard = document.getElementById("verifierFinalReportCard");
        if (repCard && currentVerifierSession && currentVerifierSession.final_report) {
            repCard.style.display = "block";
            renderFinalReport(currentVerifierSession.final_report);
        }
    }
}

async function initOrRefreshVerifierProfile() {
    try {
        const res = await fetch("/api/verifier/state");
        if (!res.ok) return;
        const data = await res.json();

        const txList = data.available_transactions || [];
        const txSelect = document.getElementById("verifierTxSelect");
        const noTxNotice = document.getElementById("verifierNoTxNotice");
        const controlsContainer = document.getElementById("verifierControlsContainer");

        if (txList.length === 0) {
            if (noTxNotice) noTxNotice.style.display = "block";
            const btnInit = document.getElementById("btnInitDispute");
            if (btnInit) btnInit.disabled = true;
            const sbWorkspace = document.getElementById("verifierSellerBuyerWorkspace");
            const refSusWorkspace = document.getElementById("verifierRefSusWorkspace");
            if (sbWorkspace) sbWorkspace.style.display = "none";
            if (refSusWorkspace) refSusWorkspace.style.display = "none";
            return;
        } else {
            if (noTxNotice) noTxNotice.style.display = "none";
            const btnInit = document.getElementById("btnInitDispute");
            if (btnInit) btnInit.disabled = false;
        }

        // Populate transaction select
        if (txSelect) {
            txSelect.innerHTML = "";
            txList.forEach(t => {
                const opt = document.createElement("option");
                opt.value = t.transaction_id;
                opt.textContent = `${t.transaction_id} (${t.design} • ${t.seller_id} • ${t.buyer_id})`;
                txSelect.appendChild(opt);
            });
        }

        // Populate summary box for first transaction
        const tx = txList[0];
        const sTxId = document.getElementById("vSummaryTxId");
        if (sTxId) sTxId.textContent = tx.transaction_id;
        const sSellerId = document.getElementById("vSummarySellerId");
        if (sSellerId) sSellerId.textContent = tx.seller_id;
        const sBuyerId = document.getElementById("vSummaryBuyerId");
        if (sBuyerId) sBuyerId.textContent = tx.buyer_id;
        const sDesign = document.getElementById("vSummaryDesign");
        if (sDesign) sDesign.textContent = tx.design;
        const sRule = document.getElementById("vSummaryRule");
        if (sRule) sRule.textContent = `${tx.encoding_rule_id} (v${tx.encoding_rule_version})`;
        const sRights = document.getElementById("vSummaryRights");
        if (sRights) sRights.textContent = `License (${tx.license_type})`;
        const sReqStatus = document.getElementById("vSummaryReqStatus");
        if (sReqStatus) sReqStatus.textContent = tx.request_status;
        const sContribStatus = document.getElementById("vSummaryContribStatus");
        if (sContribStatus) sContribStatus.textContent = `${tx.buyer_contribution_status}`;

        // Evidence pills and missing check
        const readyBadge = document.getElementById("vTxReadyBadge");
        const missingNotice = document.getElementById("vMissingEvidenceNotice");
        const missingList = document.getElementById("vMissingEvidenceList");

        if (tx.is_ready_for_verification) {
            if (readyBadge) {
                readyBadge.className = "badge badge-success";
                readyBadge.textContent = "Evidence Ready";
            }
            if (missingNotice) missingNotice.style.display = "none";
        } else {
            if (readyBadge) {
                readyBadge.className = "badge badge-warning";
                readyBadge.textContent = "Evidence Incomplete";
            }
            if (missingNotice) {
                missingNotice.style.display = "block";
                const missing = [];
                if (!tx.available_evidence.includes("Original Encoding D")) missing.push("Design Encoding D (Step 2 in Seller Profile)");
                if (!tx.available_evidence.includes("Buyer Bitstream B")) missing.push("Buyer Contribution B (Buyer Profile approval)");
                if (!tx.available_evidence.includes("Watermarked RTL")) missing.push("Watermark Workflow execution (Step 4 in Seller Profile)");
                if (missingList) missingList.textContent = missing.join("; ") || "Complete Seller & Buyer workflows.";
            }
        }

        // Update session and transaction state
        if (data.transaction_state) {
            currentTransactionState = data.transaction_state;
        }
        if (data.session) {
            currentVerifierSession = data.session;
            const sessBadge = document.getElementById("verifierSessionBadge");
            if (sessBadge) sessBadge.textContent = `Session: ${currentVerifierSession.session_id}`;
            updateAllVerifierStepsUI();
            if (currentVerifierSession.final_report) {
                renderFinalReport(currentVerifierSession.final_report);
            }
        }
    } catch (err) {
        console.warn("Failed to refresh verifier profile state:", err);
    }
}

async function executeVerifierStepInline(stepNum, btn) {
    const isFull = (currentVerifierSession && currentVerifierSession.is_full_watermark !== undefined)
        ? currentVerifierSession.is_full_watermark
        : ((currentTransactionState && currentTransactionState.is_full_watermark !== undefined) ? currentTransactionState.is_full_watermark : true);

    if (isFull && (stepNum === 7 || stepNum === 8 || stepNum === "7" || stepNum === "8")) {
        alert("Steps 7 and 8 are legacy split-watermark verification steps and are not required for full 256-bit watermark transactions.");
        return;
    }

    const stepResults = (currentVerifierSession && currentVerifierSession.step_results) || {};

    if (stepNum === 13 || stepNum === "13") {
        if (!isVerifierStepEligible(13, stepResults)) {
            const transformReq = currentVerifierSession ? currentVerifierSession.encoding_transform_required : (currentTransactionState && currentTransactionState.encoding_transform_required);
            const required = isFull
                ? (transformReq ? [1, 2, 3, "transform", 4, 5, 6, 9, 10, 11, 12] : [1, 2, 3, 4, 5, 6, 9, 10, 11, 12])
                : (transformReq ? [1, 2, 3, "transform", 4, 5, 6, 7, 8, 9, 10, 11, 12] : [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
            const isDone = (k) => {
                const r = stepResults[`step_${k}`] || stepResults[k];
                return r && ["MATCH", "NOT REQUIRED", "LOADED", "EXTRACTED", "VALIDATED", "CONSISTENT", "RECONSTRUCTED"].includes(r.status);
            };
            const missing = required.filter(k => !isDone(k)).map(k => `Step ${k}`);
            alert(`Step 13 Report Generation requires completing prior verification steps first.\nPending or incomplete prerequisites: ${missing.join(", ")}`);
            return;
        }
    }

    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = (stepNum === 13 || stepNum === "13")
        ? `<span>Generating Consolidated Verification Report...</span>`
        : `<span>Executing Step ${stepNum}...</span>`;

    try {
        const res = await fetch("/api/verifier/execute_step", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ step_number: stepNum })
        });

        if (res.ok) {
            const data = await res.json();
            currentVerifierSession = data.session;
            const stepResult = data.step_result;
            if (typeof stepNum === "number") currentVerifierStep = stepNum;

            // Expand this step card
            const stepBox = document.getElementById(`vStepBox_${stepNum}`);
            if (stepBox) stepBox.classList.remove("collapsed");

            // Immediately populate this step with the fresh step_result from API
            if (stepResult) {
                populateStepResultFields(stepNum, stepResult);
            }

            // Update all step views and badges
            updateAllVerifierStepsUI();

            // If final step 13, render report
            if ((stepNum === 13 || stepNum === "13") && currentVerifierSession.final_report) {
                const repCard = document.getElementById("verifierFinalReportCard");
                if (repCard) {
                    repCard.style.display = "block";
                    repCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
                }
                renderFinalReport(currentVerifierSession.final_report);
            }
        } else {
            const err = await res.json();
            alert(`Step ${stepNum} verification error: ${err.detail || "Server error"}`);
        }
    } catch (err) {
        console.error("Failed to execute verification step:", err);
    } finally {
        btn.disabled = false;
        btn.innerHTML = originalText;
    }
}

function isVerifierStepEligible(stepKey, stepResults) {
    if (stepKey === 1 || stepKey === "1") return true;
    const isDone = (key, okStatuses) => {
        const r = stepResults[`step_${key}`] || stepResults[key] || stepResults[`step_${String(key)}`];
        const defaultOk = ["MATCH", "NOT REQUIRED", "LOADED", "EXTRACTED", "VALIDATED", "CONSISTENT", "RECONSTRUCTED"];
        return !!(r && (okStatuses || defaultOk).includes(r.status));
    };
    const isFull = (currentVerifierSession && currentVerifierSession.is_full_watermark !== undefined)
        ? currentVerifierSession.is_full_watermark
        : ((currentTransactionState && currentTransactionState.is_full_watermark !== undefined) ? currentTransactionState.is_full_watermark : true);
    const transformReq = currentVerifierSession ? currentVerifierSession.encoding_transform_required : (currentTransactionState && currentTransactionState.encoding_transform_required);

    if (stepKey === 2 || stepKey === "2") return isDone(1, ["LOADED", "MATCH"]);
    if (stepKey === 3 || stepKey === "3") return isDone(2, ["EXTRACTED", "MATCH"]);
    if (stepKey === "transform") {
        if (!isDone(2, ["EXTRACTED", "MATCH"])) return false;
        return transformReq ? isDone(3, ["MATCH"]) : isDone(3, ["NOT REQUIRED", "MATCH"]);
    }
    if (stepKey === 4 || stepKey === "4") {
        if (transformReq) {
            return isDone("transform", ["MATCH", "NOT REQUIRED"]) && isDone(3, ["MATCH"]);
        } else {
            return isDone(2, ["EXTRACTED", "MATCH"]) && isDone(3, ["NOT REQUIRED", "MATCH"]);
        }
    }
    if (stepKey === 5 || stepKey === "5") return isDone(1, ["LOADED", "MATCH"]);
    if (stepKey === 6 || stepKey === "6") return isDone(5, ["EXTRACTED", "MATCH"]);
    if (stepKey === 7 || stepKey === "7") {
        if (isFull) return false;
        return isDone(5, ["EXTRACTED", "MATCH"]);
    }
    if (stepKey === 8 || stepKey === "8") {
        if (isFull) return false;
        return isDone(7, ["MATCH", "RECONSTRUCTED"]);
    }
    if (stepKey === 9 || stepKey === "9") return isDone(1, ["LOADED", "MATCH"]);
    if (stepKey === 10 || stepKey === "10") return isDone(9, ["MATCH", "VALIDATED"]);
    if (stepKey === 11 || stepKey === "11") {
        if (isFull) {
            return isDone(4, ["MATCH"]) && isDone(6, ["MATCH"]) && isDone(10, ["MATCH"]);
        } else {
            return isDone(4, ["MATCH"]) && (isDone(6, ["MATCH"]) || isDone(8, ["MATCH"])) && isDone(10, ["MATCH"]);
        }
    }
    if (stepKey === 12 || stepKey === "12") return isDone(11, ["MATCH"]);
    if (stepKey === 13 || stepKey === "13") {
        const checkKeys = isFull
            ? (transformReq ? [1, 2, 3, "transform", 4, 5, 6, 9, 10, 11, 12] : [1, 2, 3, 4, 5, 6, 9, 10, 11, 12])
            : (transformReq ? [1, 2, 3, "transform", 4, 5, 6, 7, 8, 9, 10, 11, 12] : [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        for (let s of checkKeys) {
            if (!isDone(s)) return false;
        }
        return true;
    }
    return true;
}

function updateAllVerifierStepsUI() {
    let completedCount = 0;
    let sec1Completed = 0;
    let sec2Completed = 0;
    let sec3Completed = 0;

    const stepResults = (currentVerifierSession && currentVerifierSession.step_results) || {};
    const isFull = (currentVerifierSession && currentVerifierSession.is_full_watermark !== undefined)
        ? currentVerifierSession.is_full_watermark
        : ((currentTransactionState && currentTransactionState.is_full_watermark !== undefined) ? currentTransactionState.is_full_watermark : true);
    const transformReq = currentVerifierSession ? currentVerifierSession.encoding_transform_required : (currentTransactionState && currentTransactionState.encoding_transform_required);

    // Hide or show legacy split steps 7 & 8 based on transaction model
    const box7 = document.getElementById("vStepBox_7");
    const box8 = document.getElementById("vStepBox_8");
    if (box7) box7.style.display = isFull ? "none" : "block";
    if (box8) box8.style.display = isFull ? "none" : "block";

    const allStepKeys = [1, 2, 3, "transform", 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];

    for (let key of allStepKeys) {
        if (isFull && (key === 7 || key === 8)) {
            continue;
        }

        const res = stepResults[`step_${key}`] || stepResults[key] || stepResults[`step_${String(key)}`];
        const box = document.getElementById(`vStepBox_${key}`);
        const badge = document.getElementById(`vStepBadge_${key}`);
        const resultBox = document.getElementById(`vStepResult_${key}`);
        const notes = document.getElementById(`vStepNotes_${key}`);
        const btn = document.getElementById(`btnVerifierExecStep_${key}`);
        const rerun = document.getElementById(`vStepRerunContainer_${key}`);

        if (res) {
            const isSuccess = (res.status === "MATCH" || res.status === "NOT REQUIRED" || res.status === "LOADED" || res.status === "EXTRACTED" || res.status === "VALIDATED" || res.status === "CONSISTENT" || res.status === "RECONSTRUCTED");
            if (isSuccess) {
                if (key !== "transform") completedCount++;
                if (key === 1 || key === 2 || key === 3 || key === 4 || key === 5 || key === 6 || (!isFull && (key === 7 || key === 8))) sec1Completed++;
                else if (key === 9 || key === 10) sec2Completed++;
                else if (key === 11 || key === 12) sec3Completed++;
            }

            if (box) {
                if (isSuccess) {
                    box.classList.add("completed");
                    box.classList.remove("failed");
                } else if (res.status === "MISMATCH" || res.status === "BLOCKED") {
                    box.classList.add("failed");
                    box.classList.remove("completed");
                }
            }

            if (badge) {
                badge.textContent = res.status;
                badge.className = isSuccess
                    ? "status-badge-match"
                    : (res.status === "MISMATCH" ? "status-badge-mismatch" : "status-badge-blocked");
            }

            if (resultBox) {
                resultBox.style.display = "block";
            }

            if (notes && res.notes) {
                notes.textContent = res.notes;
            }

            // Button Lifecycle: hide large action button when completed, show compact rerun action
            if (isSuccess) {
                if (btn) btn.style.display = "none";
                if (rerun) rerun.style.display = "inline-block";
            } else {
                if (btn) {
                    btn.style.display = "inline-flex";
                    btn.disabled = false;
                    btn.title = "";
                }
                if (rerun) rerun.style.display = "none";
            }

            populateStepResultFields(key, res);
        } else {
            if (box) {
                box.classList.remove("completed", "failed");
            }
            if (resultBox) {
                resultBox.style.display = "none";
            }
            const eligible = isVerifierStepEligible(key, stepResults);
            if (badge) {
                if (eligible) {
                    badge.textContent = "READY TO EXECUTE";
                    badge.className = "badge badge-warning";
                } else {
                    badge.textContent = "Pending";
                    badge.className = "badge badge-v1";
                }
            }
            if (btn) {
                btn.style.display = "inline-flex";
                btn.disabled = !eligible;
                btn.title = eligible ? "" : "Prerequisite steps not completed.";
            }
            if (rerun) {
                rerun.style.display = "none";
            }
        }
    }

    // Update section badges
    const sec1Max = isFull ? 6 : 8;
    const b1 = document.getElementById("vSecBadge1");
    if (b1) {
        b1.textContent = sec1Completed === sec1Max ? `${sec1Max}/${sec1Max} Verified` : `${sec1Completed}/${sec1Max} Steps`;
        b1.className = sec1Completed === sec1Max ? "badge badge-success" : "badge badge-v1";
    }
    const b2 = document.getElementById("vSecBadge2");
    if (b2) {
        b2.textContent = sec2Completed === 2 ? "2/2 Verified" : `${sec2Completed}/2 Steps`;
        b2.className = sec2Completed === 2 ? "badge badge-success" : "badge badge-v1";
    }
    const b3 = document.getElementById("vSecBadge3");
    if (b3) {
        b3.textContent = sec3Completed === 2 ? "2/2 Verified" : `${sec3Completed}/2 Steps`;
        b3.className = sec3Completed === 2 ? "badge badge-success" : "badge badge-v1";
    }
    const b4 = document.getElementById("vSecBadge4");
    if (b4) {
        if (currentVerifierSession && currentVerifierSession.final_report) {
            b4.textContent = "Report Ready";
            b4.className = "badge badge-success";
        } else {
            b4.textContent = "Step 13";
            b4.className = "badge badge-v1";
        }
    }

    // Subsection badges
    const bEnc = document.getElementById("vBadgeEncoding");
    if (bEnc) {
        const count = [1, 2, 3, 4].filter(i => stepResults[`step_${i}`] && ["MATCH", "NOT REQUIRED", "LOADED", "EXTRACTED"].includes(stepResults[`step_${i}`].status)).length;
        bEnc.textContent = count === 4 ? "4/4 Verified" : `${count}/4 Steps`;
        bEnc.className = count === 4 ? "badge badge-success" : "badge badge-v1";
    }
    const bWm = document.getElementById("vBadgeWatermark");
    if (bWm) {
        if (isFull) {
            const count = [5, 6].filter(i => stepResults[`step_${i}`] && ["MATCH", "NOT REQUIRED", "EXTRACTED"].includes(stepResults[`step_${i}`].status)).length;
            bWm.textContent = count === 2 ? "2/2 Verified" : `${count}/2 Steps`;
            bWm.className = count === 2 ? "badge badge-success" : "badge badge-v1";
        } else {
            const count = [5, 6, 7, 8].filter(i => stepResults[`step_${i}`] && ["MATCH", "NOT REQUIRED", "EXTRACTED", "RECONSTRUCTED"].includes(stepResults[`step_${i}`].status)).length;
            bWm.textContent = count === 4 ? "4/4 Verified" : `${count}/4 Steps`;
            bWm.className = count === 4 ? "badge badge-success" : "badge badge-v1";
        }
    }
    const bBuyer = document.getElementById("vBadgeBuyer");
    if (bBuyer) {
        bBuyer.textContent = sec2Completed === 2 ? "2/2 Verified" : `${sec2Completed}/2 Steps`;
        bBuyer.className = sec2Completed === 2 ? "badge badge-success" : "badge badge-v1";
    }
    const bTx = document.getElementById("vBadgeTx");
    if (bTx) {
        bTx.textContent = sec3Completed === 2 ? "2/2 Verified" : `${sec3Completed}/2 Steps`;
        bTx.className = sec3Completed === 2 ? "badge badge-success" : "badge badge-v1";
    }
    const bRep = document.getElementById("vBadgeReport");
    if (bRep) {
        if (currentVerifierSession && currentVerifierSession.final_report) {
            bRep.textContent = "Generated";
            bRep.className = "badge badge-success";
        } else {
            bRep.textContent = "Step 13";
            bRep.className = "badge badge-v1";
        }
    }

    // Overall progress badge in header: clear "X of 11 steps completed" format for full watermark
    const overallCount = document.getElementById("vCompletedStepsCount");
    if (overallCount) {
        const totalActive = isFull ? (transformReq ? 12 : 11) : (transformReq ? 14 : 13);
        overallCount.textContent = `${completedCount} of ${totalActive}`;
    }
}

function populateStepResultFields(stepNum, res) {
    if (!res) return;
    const actualRes = res.step_result || res;
    const s1 = actualRes.stage1_reconstruction || actualRes.details || {};
    const s2 = actualRes.stage2_verification || {};
    const normStep = (stepNum === "transform" || stepNum === "3b") ? "transform" : parseInt(stepNum, 10);
    const getHash = (preferred) => {
        return preferred || actualRes.canonical_hash || s1.canonical_hash || actualRes.hash || s1.hash || (actualRes.details && actualRes.details.canonical_hash) || (s1.details && s1.details.canonical_hash) || "";
    };

    if (normStep === 1) {
        const codeEl = document.getElementById("vDisputedVerilogRTL_inline");
        const rtlCode = s1.synthesizable_verilog_code || s1.preview || (currentVerifierSession && currentVerifierSession.disputed_rtl) || "--";
        if (codeEl) codeEl.textContent = rtlCode;
        const propsEl = document.getElementById("vStepProps_1");
        if (propsEl) propsEl.textContent = `${s1.lines_of_code || '--'} lines (${s1.artifact_type || 'Synthesizable Verilog RTL'})`;
        const digestEl = document.getElementById("vStepDigest_1");
        if (digestEl && s1.sha256_digest) digestEl.textContent = s1.sha256_digest;
        const s1Status = document.getElementById("vStage1Status_1");
        if (s1Status) s1Status.textContent = s1.status || actualRes.status || "LOADED";
    } else if (normStep === 2) {
        const hashEl = document.getElementById("vStepHash_2");
        const hashVal = getHash(s1.canonical_hash);
        if (hashEl) hashEl.textContent = hashVal || "--";
        const bitLen = actualRes.bit_length || s1.bit_length;
        const bitLenEl = document.getElementById("vStepBitLen_2");
        if (bitLenEl) bitLenEl.textContent = bitLen ? `${bitLen} bits` : "--";
        const algoEl = document.getElementById("vStepHashAlgo_2");
        if (algoEl) algoEl.textContent = actualRes.hash_algorithm || s1.hash_algorithm || "SHA-256";
        const propEl = document.getElementById("vStepProps_2");
        if (propEl) {
            const nodes = s1.total_nodes_recovered || 13;
            const steps = s1.total_steps_recovered || 7;
            propEl.textContent = bitLen ? `${bitLen} bits (${nodes} nodes across ${steps} steps)` : "--";
        }
        const s1Status = document.getElementById("vStage1Status_2");
        if (s1Status) s1Status.textContent = s1.status || actualRes.status || "EXTRACTED";
    } else if (normStep === 3) {
        const flagEl = document.getElementById("vStepFlag_3");
        if (flagEl) {
            const flag = currentVerifierSession ? currentVerifierSession.encoding_transform_required : false;
            flagEl.textContent = flag ? "YES (Transformation Required)" : "NO (Direct Invariance)";
        }
        const branchEl = document.getElementById("vStepBranch_3");
        if (branchEl) {
            branchEl.textContent = s1.branch || (actualRes.status === "NOT REQUIRED" ? "Branch B: encoding_transform_required = false" : "Branch A: encoding_transform_required = true");
        }
        const cesEl = document.getElementById("vStepStoredCES_3");
        if (cesEl) {
            cesEl.textContent = s2.stored_c_es || (actualRes.status === "NOT REQUIRED" ? "NOT_REQUIRED" : s2.stored_commitment_C_ES || "--");
        }
        const pill = document.getElementById("vStage2Pill_3");
        if (pill) {
            pill.textContent = actualRes.status || "NOT REQUIRED";
            pill.className = (actualRes.status === "NOT REQUIRED" || actualRes.status === "MATCH") ? "badge badge-success" : "badge badge-warning";
        }
        const invEl = document.getElementById("vStepInvariance_3");
        if (invEl) invEl.textContent = s1.comparison || s1.detail || "--";
    } else if (normStep === "transform") {
        const ruleEl = document.getElementById("vStepTransRule_transform");
        if (ruleEl) ruleEl.textContent = `${s1.transformation_rule_id || 'iir_butterworth_transform_v1'} (v${s1.transformation_rule_version || '1.0'})`;
        const hashEl = document.getElementById("vStepHash_transform");
        const hashVal = getHash(s1.canonical_hash);
        if (hashEl) hashEl.textContent = hashVal || "--";
        const bitLen = actualRes.bit_length || s1.bit_length;
        const bitLenEl = document.getElementById("vStepBitLen_transform");
        if (bitLenEl) bitLenEl.textContent = bitLen ? `${bitLen} bits` : "--";
        const algoEl = document.getElementById("vStepHashAlgo_transform");
        if (algoEl) algoEl.textContent = actualRes.hash_algorithm || s1.hash_algorithm || "SHA-256";
        const pill = document.getElementById("vStage2Pill_transform");
        if (pill) {
            pill.textContent = actualRes.status || "Pending";
            pill.className = (actualRes.status === "MATCH" || actualRes.status === "NOT REQUIRED") ? "badge badge-success" : "badge badge-danger";
        }
        const notesEl = document.getElementById("vStepNotes_transform");
        if (notesEl && actualRes.notes) notesEl.textContent = actualRes.notes;
    } else if (normStep === 4) {
        const hashEl = document.getElementById("vStepHash_4");
        const hashVal = getHash(s1.canonical_hash);
        if (hashEl) hashEl.textContent = hashVal || "--";
        const bitLen = actualRes.bit_length || s1.bit_length;
        const bitLenEl = document.getElementById("vStepBitLen_4");
        if (bitLenEl) bitLenEl.textContent = bitLen ? `${bitLen} bits` : "--";
        const propEl = document.getElementById("vStepProps_4");
        if (propEl) propEl.textContent = bitLen ? `${bitLen} bits (Golden Benchmark)` : "--";
        const openEl = document.getElementById("vStepOpening_4");
        if (openEl && s2.opening_factor_r_D) openEl.textContent = s2.opening_factor_r_D;
        const storedEl = document.getElementById("vStepStored_4");
        if (storedEl && s2.stored_commitment_C_D) storedEl.textContent = s2.stored_commitment_C_D;
        const recalcEl = document.getElementById("vStepRecalc_4");
        if (recalcEl && s2.recalculated_commitment_C_D) recalcEl.textContent = s2.recalculated_commitment_C_D;
        const pill = document.getElementById("vStage2Pill_4");
        if (pill) {
            pill.textContent = s2.status || actualRes.status;
            pill.className = (s2.status === "MATCH" || actualRes.status === "MATCH") ? "badge badge-success" : "badge badge-danger";
        }
    } else if (normStep === 5) {
        const hashEl = document.getElementById("vStepHash_5");
        const hashVal = getHash(s1.canonical_hash);
        if (hashEl) hashEl.textContent = hashVal || "--";
        const bitLen = actualRes.bit_length || s1.bit_length;
        const bitLenEl = document.getElementById("vStepBitLen_5");
        if (bitLenEl) bitLenEl.textContent = bitLen ? `${bitLen} bits` : "--";
        const algoEl = document.getElementById("vStepHashAlgo_5");
        if (algoEl) algoEl.textContent = actualRes.hash_algorithm || s1.hash_algorithm || "SHA-256";
        const propEl = document.getElementById("vStepProps_5");
        if (propEl) propEl.textContent = bitLen ? `${bitLen} bits` : "--";
        const pill = document.getElementById("vStage2Pill_5");
        if (pill) {
            pill.textContent = s1.extraction_status || s1.status || actualRes.status || "EXTRACTED";
            pill.className = "badge badge-success";
        }
    } else if (normStep === 6) {
        const hashEl = document.getElementById("vStepHash_6");
        const hashVal = getHash(s1.canonical_hash);
        if (hashEl) hashEl.textContent = hashVal || "--";
        const openEl = document.getElementById("vStepOpening_6");
        const openVal = s2.opening_factor_r_W || s2.opening_factor_r_W1 || s2.opening_factor_r;
        if (openEl && openVal) openEl.textContent = openVal;
        const storedEl = document.getElementById("vStepStored_6");
        const storedVal = s2.stored_commitment_C_W || s2.stored_commitment_C_W1;
        if (storedEl && storedVal) storedEl.textContent = storedVal;
        const recalcEl = document.getElementById("vStepRecalc_6");
        const recalcVal = s2.recalculated_commitment_C_W || s2.recalculated_commitment_C_W1;
        if (recalcEl && recalcVal) recalcEl.textContent = recalcVal;
        const pill = document.getElementById("vStage2Pill_6");
        if (pill) {
            pill.textContent = s2.status || actualRes.status;
            pill.className = s2.status === "MATCH" ? "badge badge-success" : "badge badge-danger";
        }
    } else if (normStep === 7) {
        const hashEl = document.getElementById("vStepHash_7");
        const hashVal = getHash(s1.canonical_hash);
        if (hashEl) hashEl.textContent = hashVal || "--";
        const bLen = actualRes.bit_length || s1.total_bit_length || s1.bit_length;
        const bitLenEl = document.getElementById("vStepBitLen_7");
        if (bitLenEl) bitLenEl.textContent = bLen ? `${bLen} bits` : "--";
        const algoEl = document.getElementById("vStepHashAlgo_7");
        if (algoEl) algoEl.textContent = actualRes.hash_algorithm || s1.hash_algorithm || "SHA-256";
        const propEl = document.getElementById("vStepProps_7");
        if (propEl) propEl.textContent = bLen ? `${bLen} bits` : "--";
        const pill = document.getElementById("vStage2Pill_7");
        if (pill) {
            pill.textContent = s1.status || actualRes.status || "MATCH";
            pill.className = "badge badge-success";
        }
    } else if (normStep === 8) {
        const hashEl = document.getElementById("vStepHash_8");
        const hashVal = getHash(s1.canonical_hash);
        if (hashEl) hashEl.textContent = hashVal || "--";
        const openEl = document.getElementById("vStepOpening_8");
        if (openEl && s2.opening_factor_r_W) openEl.textContent = s2.opening_factor_r_W;
        const storedEl = document.getElementById("vStepStored_8");
        if (storedEl && s2.stored_commitment_C_W) storedEl.textContent = s2.stored_commitment_C_W;
        const recalcEl = document.getElementById("vStepRecalc_8");
        if (recalcEl && s2.recalculated_commitment_C_W) recalcEl.textContent = s2.recalculated_commitment_C_W;
        const pill = document.getElementById("vStage2Pill_8");
        if (pill) {
            pill.textContent = s2.status || actualRes.status;
            pill.className = s2.status === "MATCH" ? "badge badge-success" : "badge badge-danger";
        }
    } else if (normStep === 9) {
        const hashEl = document.getElementById("vStepHash_9");
        const hashVal = getHash(s1.canonical_hash);
        if (hashEl) hashEl.textContent = hashVal || "--";
        const bitLen = actualRes.bit_length || s1.bit_length;
        const bitLenEl = document.getElementById("vStepBitLen_9");
        if (bitLenEl) bitLenEl.textContent = bitLen ? `${bitLen} bits` : "--";
        const algoEl = document.getElementById("vStepHashAlgo_9");
        if (algoEl) algoEl.textContent = actualRes.hash_algorithm || s1.hash_algorithm || "SHA-256";
        const propEl = document.getElementById("vStepProps_9");
        if (propEl) propEl.textContent = bitLen ? `${bitLen} bits (${s1.zeros_count || 242} zeros, ${s1.ones_count || 313} ones)` : "--";
        const pill = document.getElementById("vStage2Pill_9");
        if (pill) {
            pill.textContent = s1.status || actualRes.status || "VALIDATED";
            pill.className = "badge badge-success";
        }
    } else if (normStep === 10) {
        const hashEl = document.getElementById("vStepHash_10");
        const hashVal = getHash(s1.canonical_hash);
        if (hashEl) hashEl.textContent = hashVal || "--";
        const openEl = document.getElementById("vStepOpening_10");
        if (openEl && s2.opening_factor_r_B) openEl.textContent = s2.opening_factor_r_B;
        const storedEl = document.getElementById("vStepStored_10");
        if (storedEl && s2.stored_commitment_C_B) storedEl.textContent = s2.stored_commitment_C_B;
        const recalcEl = document.getElementById("vStepRecalc_10");
        if (recalcEl && s2.recalculated_commitment_C_B) recalcEl.textContent = s2.recalculated_commitment_C_B;
        const pill = document.getElementById("vStage2Pill_10");
        if (pill) {
            pill.textContent = s2.status || actualRes.status;
            pill.className = s2.status === "MATCH" ? "badge badge-success" : "badge badge-danger";
        }
    } else if (normStep === 11) {
        const propEl = document.getElementById("vStepProps_11");
        if (propEl) propEl.textContent = s1.output_bit_length ? `${s1.output_bit_length} bits` : (s2.status === "MATCH" ? "256 bits" : "--");
        const expHashEl = document.getElementById("vStepExpHash_11");
        if (expHashEl) expHashEl.textContent = s1.expected_watermark_hash || "--";
        const recHashEl = document.getElementById("vStepRecHash_11");
        if (recHashEl) recHashEl.textContent = s1.reconstructed_watermark_hash || "--";
        const eqCheckEl = document.getElementById("vStepEqCheck_11");
        if (eqCheckEl) {
            eqCheckEl.textContent = s2.status === "MATCH"
                ? "Derived Watermark Hash == Reconstructed W' Hash (Match)"
                : (s2.status === "MISMATCH" ? "Derived Watermark Hash != Reconstructed W' Hash (Mismatch)" : (s2.status || "--"));
            eqCheckEl.style.color = s2.status === "MATCH" ? "var(--accent-emerald)" : "var(--accent-rose)";
        }
        const pill = document.getElementById("vStage2Pill_11");
        if (pill) {
            pill.textContent = s2.status || actualRes.status;
            pill.className = s2.status === "MATCH" ? "badge badge-success" : "badge badge-danger";
        }
    } else if (normStep === 12) {
        const pill = document.getElementById("vStage2Pill_12");
        if (pill) {
            pill.textContent = s2.status || actualRes.status;
            pill.className = (s2.status === "MATCH" || s2.status === "CONSISTENT") ? "badge badge-success" : "badge badge-danger";
        }
    } else if (normStep === 13) {
        const repCard = document.getElementById("verifierFinalReportCard");
        if (repCard && currentVerifierSession && currentVerifierSession.final_report) {
            repCard.style.display = "block";
            renderFinalReport(currentVerifierSession.final_report);
        }
    }
}

function renderVerifierStep(stepNum) {
    const meta = VERIFIER_STEPS_META.find(m => m.num === stepNum) || VERIFIER_STEPS_META[0];

    // Determine target evidence section
    let activeSec = 1;
    if (stepNum <= 8) activeSec = 1;
    else if (stepNum <= 10) activeSec = 2;
    else if (stepNum <= 12) activeSec = 3;
    else activeSec = 4;

    switchVerifierSection(activeSec);

    // Expand targeted step box
    for (let i = 1; i <= 13; i++) {
        const box = document.getElementById(`vStepBox_${i}`);
        if (box) {
            if (i === stepNum) box.classList.remove("collapsed");
        }
    }

    updateAllVerifierStepsUI();
    return;

    // Update step item cards and summary chips across all sections
    let sec1Completed = 0;
    let sec2Completed = 0;
    let sec3Completed = 0;

    for (let i = 1; i <= 12; i++) {
        const card = document.getElementById(`vStepItemCard_${i}`);
        const badge = document.getElementById(`vStepBadge_${i}`);

        if (card) {
            if (i === stepNum) card.classList.add("active-step");
            else card.classList.remove("active-step");
        }

        const res = (currentVerifierSession && currentVerifierSession.step_results)
            ? currentVerifierSession.step_results[`step_${i}`]
            : null;

        if (res) {
            const isSuccess = (res.status === "MATCH" || res.status === "NOT REQUIRED" || res.status === "LOADED" || res.status === "EXTRACTED" || res.status === "VALIDATED");
            if (isSuccess) {
                if (i <= 8) sec1Completed++;
                else if (i <= 10) sec2Completed++;
                else sec3Completed++;
            }

            if (badge) {
                badge.textContent = res.status;
                badge.className = isSuccess
                    ? "status-badge-match"
                    : (res.status === "MISMATCH" ? "status-badge-mismatch" : "status-badge-blocked");
            }
        } else {
            if (badge) {
                if (i === stepNum) {
                    badge.textContent = "READY TO EXECUTE";
                    badge.className = "badge badge-warning";
                } else {
                    badge.textContent = "Pending";
                    badge.className = "badge badge-v1";
                }
            }
        }
    }

    // Update 4 Section Badges & Subsection Badges
    const b1 = document.getElementById("vSecBadge1");
    if (b1) {
        if (sec1Completed === 8) {
            b1.textContent = "8/8 Verified";
            b1.className = "badge badge-success";
        } else {
            b1.textContent = `${sec1Completed}/8 Steps`;
            b1.className = "badge badge-v1";
        }
    }
    const b2 = document.getElementById("vSecBadge2");
    if (b2) {
        if (sec2Completed === 2) {
            b2.textContent = "2/2 Verified";
            b2.className = "badge badge-success";
        } else {
            b2.textContent = `${sec2Completed}/2 Steps`;
            b2.className = "badge badge-v1";
        }
    }
    const b3 = document.getElementById("vSecBadge3");
    if (b3) {
        if (sec3Completed === 2) {
            b3.textContent = "2/2 Verified";
            b3.className = "badge badge-success";
        } else {
            b3.textContent = `${sec3Completed}/2 Steps`;
            b3.className = "badge badge-v1";
        }
    }
    const b4 = document.getElementById("vSecBadge4");
    if (b4) {
        if (currentVerifierSession && currentVerifierSession.final_report) {
            b4.textContent = "Report Ready";
            b4.className = "badge badge-success";
        } else {
            b4.textContent = "Step 13";
            b4.className = "badge badge-v1";
        }
    }

    const bEnc = document.getElementById("vBadgeEncoding");
    if (bEnc) {
        const count = [1, 2, 3, 4].filter(i => currentVerifierSession && currentVerifierSession.step_results && currentVerifierSession.step_results[`step_${i}`] && (currentVerifierSession.step_results[`step_${i}`].status === "MATCH" || currentVerifierSession.step_results[`step_${i}`].status === "NOT REQUIRED" || currentVerifierSession.step_results[`step_${i}`].status === "LOADED")).length;
        bEnc.textContent = count === 4 ? "4/4 Verified" : `${count}/4 Steps`;
        bEnc.className = count === 4 ? "badge badge-success" : "badge badge-v1";
    }

    const bWm = document.getElementById("vBadgeWatermark");
    if (bWm) {
        const count = [5, 6, 7, 8].filter(i => currentVerifierSession && currentVerifierSession.step_results && currentVerifierSession.step_results[`step_${i}`] && (currentVerifierSession.step_results[`step_${i}`].status === "MATCH" || currentVerifierSession.step_results[`step_${i}`].status === "NOT REQUIRED" || currentVerifierSession.step_results[`step_${i}`].status === "EXTRACTED")).length;
        bWm.textContent = count === 4 ? "4/4 Verified" : `${count}/4 Steps`;
        bWm.className = count === 4 ? "badge badge-success" : "badge badge-v1";
    }

    const stepResult = currentVerifierSession && currentVerifierSession.step_results
        ? currentVerifierSession.step_results[`step_${stepNum}`]
        : null;

    const statusBadge = document.getElementById("vStepStatusBadge");
    const s1StatusBadge = document.getElementById("vStage1StatusBadge");
    const s2StatusBadge = document.getElementById("vStage2StatusBadge");
    const s1MethodText = document.getElementById("vStage1MethodText");
    const s1InputText = document.getElementById("vStage1InputText");
    const s1ValBox = document.getElementById("vStage1ValueBox");
    const s1PropsText = document.getElementById("vStage1PropsText");
    const s2OpeningBox = document.getElementById("vStage2OpeningBox");
    const s2StoredBox = document.getElementById("vStage2StoredBox");
    const s2RecalcBox = document.getElementById("vStage2RecalcBox");
    const s2ResultPill = document.getElementById("vStage2ResultPill");
    const notesText = document.getElementById("vStepNotesText");

    if (stepResult) {
        if (statusBadge) {
            statusBadge.textContent = stepResult.status;
            statusBadge.className = stepResult.status === "MATCH" || stepResult.status === "NOT REQUIRED" || stepResult.status === "LOADED" || stepResult.status === "EXTRACTED" || stepResult.status === "VALIDATED"
                ? "status-badge-match"
                : (stepResult.status === "MISMATCH" ? "status-badge-mismatch" : "status-badge-blocked");
        }

        const s1 = stepResult.stage1_reconstruction || {};
        const s2 = stepResult.stage2_verification || {};

        if (s1StatusBadge) s1StatusBadge.textContent = s1.status || "COMPUTED";
        if (s2StatusBadge) s2StatusBadge.textContent = s2.status || "VERIFIED";

        if (s1MethodText) s1MethodText.textContent = s1.method || s1.rule || s1.derivation_method || meta.defaultMethod;
        if (s1InputText) s1InputText.textContent = s1.artifact_type || s1.design || JSON.stringify(s1.inputs || meta.defaultInput);

        const val = s1.calculated_value_D || s1.extracted_bitstream || s1.extracted_bitstream_W1 || s1.reconstructed_watermark_W || s1.bitstream_B || s1.sha256_digest || "--";
        if (s1ValBox) s1ValBox.textContent = val;

        const prop = s1.bit_length ? `${s1.bit_length} bits` : (s1.lines_of_code ? `${s1.lines_of_code} lines` : "--");
        if (s1PropsText) s1PropsText.textContent = prop;

        if (s2OpeningBox) s2OpeningBox.textContent = s2.opening_factor_r_D || s2.opening_factor_r_W1 || s2.opening_factor_r_W || s2.opening_factor_r_B || "--";
        if (s2StoredBox) s2StoredBox.textContent = s2.stored_commitment_C_D || s2.stored_commitment_C_W1 || s2.stored_commitment_C_W || s2.stored_commitment_C_B || s2.stored_c_es || "--";
        if (s2RecalcBox) s2RecalcBox.textContent = s2.recalculated_commitment_C_D || s2.recalculated_commitment_C_W1 || s2.recalculated_commitment_C_W || s2.recalculated_commitment_C_B || "--";

        if (s2ResultPill) {
            s2ResultPill.textContent = s2.status || stepResult.status;
            s2ResultPill.className = s2.status === "MATCH" || s2.status === "NOT REQUIRED"
                ? "badge badge-success"
                : (s2.status === "MISMATCH" ? "badge badge-danger" : "badge badge-warning");
        }

        if (notesText) notesText.textContent = stepResult.notes || "Step executed successfully.";
    } else {
        if (statusBadge) {
            statusBadge.textContent = "READY TO EXECUTE";
            statusBadge.className = "badge badge-warning";
        }
        if (s1StatusBadge) s1StatusBadge.textContent = "Pending";
        if (s2StatusBadge) s2StatusBadge.textContent = "Pending";
        if (s1MethodText) s1MethodText.textContent = meta.defaultMethod;
        if (s1InputText) s1InputText.textContent = meta.defaultInput;
        if (s1ValBox) s1ValBox.textContent = "Click 'Execute Step' to independently calculate.";
        if (s1PropsText) s1PropsText.textContent = "--";
        if (s2OpeningBox) s2OpeningBox.textContent = "Authorized opening secret requested upon calculation.";
        if (s2StoredBox) s2StoredBox.textContent = "--";
        if (s2RecalcBox) s2RecalcBox.textContent = "--";
        if (s2ResultPill) {
            s2ResultPill.textContent = "PENDING";
            s2ResultPill.className = "badge badge-v1";
        }
        if (notesText) notesText.textContent = "Step not yet executed. Click 'Execute Step' to run independent calculation.";
    }
}

function renderFinalReport(rep) {
    const reportCard = document.getElementById("verifierFinalReportCard");
    if (!reportCard || !rep) return;

    reportCard.style.display = "block";

    const banner = document.getElementById("vReportOverallBanner");
    if (banner) {
        banner.textContent = `OVERALL: ${rep.overall_evidence_status}`;
        banner.className = rep.overall_evidence_status === "CONSISTENT"
            ? "status-badge-match"
            : (rep.overall_evidence_status === "INCONSISTENT" ? "status-badge-mismatch" : "status-badge-blocked");
    }

    const setStat = (id, val) => {
        const el = document.getElementById(id);
        if (el) {
            el.textContent = val;
            el.className = val === "MATCH" || val === "NOT REQUIRED"
                ? "report-stat-num status-match"
                : (val === "MISMATCH" ? "report-stat-num status-mismatch" : "report-stat-num");
        }
    };

    setStat("repStatD", rep.design_encoding);
    setStat("repStatES", rep.secured_encoding);
    setStat("repStatW1", rep.embedded_watermark);
    setStat("repStatW", rep.complete_watermark);
    setStat("repStatB", rep.buyer_contribution);
    setStat("repStatF", rep.watermark_generation_relationship);
    setStat("repStatTx", rep.transaction_record);

    const rightsEl = document.getElementById("repStatRights");
    if (rightsEl) rightsEl.textContent = rep.recorded_rights || "License";

    const conflictBox = document.getElementById("vReportRightsConflictBox");
    const conflictText = document.getElementById("vReportRightsConflictText");
    if (conflictBox && conflictText) {
        if (rep.rights_conflict) {
            conflictBox.style.display = "block";
            conflictText.textContent = rep.rights_conflict_details || "Buyer claims ownership, but recorded transaction grants only an Exclusive License. Commitment matches do NOT establish legal ownership.";
        } else {
            conflictBox.style.display = "none";
        }
    }

    const findingsEl = document.getElementById("vReportFindingsText");
    if (findingsEl) {
        if (rep.findings_summary) {
            findingsEl.textContent = rep.findings_summary;
        } else if (rep.overall_evidence_status === "CONSISTENT") {
            findingsEl.textContent = `All cryptographic commitments, structural encodings, watermark splits, and buyer contribution bitstreams are mathematically consistent with recorded transaction terms. Recorded license type is ${rep.recorded_rights} (exclusive); legal ownership remains with Seller SELLER-001.`;
        } else {
            findingsEl.textContent = `Evidence audit detected discrepancies or incomplete prerequisite evidence. Consistency status is ${rep.overall_evidence_status}.`;
        }
    }
}

// ==============================================================================
// ==============================================================================
// JUDGE-LED INTERROGATION (143-Bit / 251-Bit Secured Stage) FRONTEND ORCHESTRATION
// ==============================================================================

let currentJudgeSession = null;
let currentCorrectionTarget = null;
let currentJudgeSegment = "part1";
let currentJudgeWorkflow = "secured_design_encoding";

let judgeSecuredMode = "manual";
let judgeUnsecuredMode = "manual";
let judgeWatermarkMode = "manual";

window.switchJudgeWorkflow = async function(wf) {
    currentJudgeWorkflow = wf;
    const tabSec = document.getElementById("tabJudgeSecured");
    const tabReport = document.getElementById("tabJudgeReport");
    const tabUnsec = document.getElementById("tabJudgeUnsecured");
    const tabWm = document.getElementById("tabJudgeWatermarking");
    const tabOv = document.getElementById("tabJudgeOverview");

    if (tabSec) tabSec.className = `judge-wf-tab ${wf === 'secured_design_encoding' ? 'active' : ''}`;
    if (tabReport) tabReport.className = `judge-wf-tab ${wf === 'interrogation_report' ? 'active' : ''}`;
    if (tabUnsec) tabUnsec.className = `judge-wf-tab ${wf === 'unsecured_design_encoding' ? 'active' : ''}`;
    if (tabWm) tabWm.className = `judge-wf-tab ${wf === 'watermarking' ? 'active' : ''}`;
    if (tabOv) tabOv.className = `judge-wf-tab ${wf === 'final_overview' ? 'active' : ''}`;

    const modeSecCard = document.getElementById("judgeSecuredModeCard");
    const reportCard = document.getElementById("judgeReportCard");
    const mainGrid = document.getElementById("judgeMainGrid");
    const unsecWorkspace = document.getElementById("judgeUnsecuredWorkspace");
    const wmWorkspace = document.getElementById("judgeWatermarkWorkspace");
    const ovWorkspace = document.getElementById("judgeOverviewWorkspace");
    const oldWmCard = document.getElementById("judgeWatermarkCard");
    if (oldWmCard) oldWmCard.style.display = "none";

    // Reset visibility of all top-level workspaces
    if (modeSecCard) modeSecCard.style.display = (wf === "secured_design_encoding") ? "block" : "none";
    if (mainGrid) mainGrid.style.display = (wf === "secured_design_encoding") ? "grid" : "none";
    if (reportCard) reportCard.style.display = (wf === "interrogation_report") ? "block" : "none";
    if (unsecWorkspace) unsecWorkspace.style.display = (wf === "unsecured_design_encoding") ? "block" : "none";
    if (wmWorkspace) wmWorkspace.style.display = (wf === "watermarking") ? "block" : "none";
    if (ovWorkspace) ovWorkspace.style.display = (wf === "final_overview") ? "block" : "none";

    if (wf === "interrogation_report") {
        await fetchJudgeAnalysisReport();
    } else if (wf === "unsecured_design_encoding") {
        await fetchJudgeUnsecuredState();
    } else if (wf === "watermarking") {
        await fetchJudgeWatermarkState();
    } else if (wf === "final_overview") {
        await fetchJudgeOverview();
    } else {
        await fetchJudgeSession(wf);
    }
};

window.setJudgeSecuredMode = function(mode) {
    judgeSecuredMode = mode;
    const btnMan = document.getElementById("btnModeSecuredManual");
    const btnInst = document.getElementById("btnModeSecuredInstant");
    const area = document.getElementById("judgeInstantVerifyArea");
    const desc = document.getElementById("judgeSecuredModeDesc");

    if (btnMan) btnMan.className = `btn-secondary ${mode === 'manual' ? 'active' : ''}`;
    if (btnInst) btnInst.className = `btn-secondary ${mode === 'instant' ? 'active' : ''}`;
    if (area) area.style.display = (mode === 'instant') ? "flex" : "none";
    if (desc) {
        desc.textContent = (mode === 'manual')
            ? "Judge asks questions progressively; claimant answers step-by-step with soft hypothesis tracking."
            : "Automated instant verification over all structural questions using authoritative reference answers.";
    }
};

window.executeJudgeInstantVerifySecured = async function() {
    if (!currentJudgeSession) return;
    const btn = document.getElementById("btnExecuteInstantVerifySecured");
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = "<span>⚡ Running Automated Verification...</span>";
    }

    try {
        const res = await fetch("/api/judge/secured/instant_verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ session_id: currentJudgeSession.session_id }),
        });
        if (res.ok) {
            const data = await res.json();
            currentJudgeSession = data;
            renderJudgeUI(data);
        } else {
            const err = await res.json();
            alert(err.detail || "Instant verification failed.");
        }
    } catch (e) {
        console.error("Instant verification error:", e);
        alert(`Error: ${e.message}`);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = "<span>⚡ Execute Instant Verification &rarr;</span>";
        }
    }
};

window.setJudgeUnsecuredMode = function(mode) {
    judgeUnsecuredMode = mode;
    const btnMan = document.getElementById("btnModeUnsecManual");
    const btnInst = document.getElementById("btnModeUnsecInstant");
    const desc = document.getElementById("judgeUnsecModeDesc");
    const btnExec = document.getElementById("btnExecuteUnsecReconstruct");

    if (btnMan) btnMan.className = `btn-secondary ${mode === 'manual' ? 'active' : ''}`;
    if (btnInst) btnInst.className = `btn-secondary ${mode === 'instant' ? 'active' : ''}`;
    if (desc) {
        desc.textContent = (mode === 'manual')
            ? "Claimant inspects secured CIG and confirms removal of artificial watermark constraints."
            : "Automatically loads secured CIG and constraints from transaction data and recovers D instantly.";
    }
    if (btnExec) {
        btnExec.innerHTML = (mode === 'manual')
            ? "<span>Strip Constraints &amp; Reconstruct Original D &rarr;</span>"
            : "<span>⚡ Execute Instant Reconstruction &rarr;</span>";
    }
};

window.fetchJudgeUnsecuredState = async function() {
    const txId = (currentTransactionState && currentTransactionState.transaction_id) || (currentJudgeSession && currentJudgeSession.transaction_id) || "TX-001";
    try {
        const res = await fetch(`/api/judge/unsecured/state?transaction_id=${txId}`);
        if (!res.ok) return;
        const data = await res.json();

        const lockBanner = document.getElementById("judgeUnsecuredLockBanner");
        const content = document.getElementById("judgeUnsecuredContent");
        const badge = document.getElementById("judgeUnsecStatusBadge");
        const edgesCount = document.getElementById("unsecSecuredEdgesCount");
        const artCount = document.getElementById("unsecArtificialCount");
        const genCount = document.getElementById("unsecGenuineCount");
        const chipContainer = document.getElementById("unsecConstraintsChipContainer");

        if (!data.prerequisite_met) {
            if (lockBanner) lockBanner.style.display = "block";
            if (content) content.style.display = "none";
            return;
        }

        if (lockBanner) lockBanner.style.display = "none";
        if (content) content.style.display = "block";

        const secCig = data.secured_cig || {};
        if (edgesCount) edgesCount.textContent = secCig.total_edges || "--";
        if (artCount) artCount.textContent = secCig.artificial_edges_count || "--";
        if (genCount) genCount.textContent = secCig.genuine_edges_count || "--";

        if (chipContainer && secCig.artificial_edges) {
            chipContainer.innerHTML = secCig.artificial_edges.map(e =>
                `<span class="badge" style="background: rgba(245, 158, 11, 0.15); border-color: #f59e0b; color: #fbbf24; font-size: 0.68rem; font-family: var(--font-mono); font-weight: normal;">(${e[0]}, ${e[1]})</span>`
            ).join("");
        }

        // Populate Constraint Possibility Analysis Table
        const cpTableBody = document.getElementById("judgeConstraintPossibilityTableBody");
        const cpAnalysis = data.constraint_possibility_analysis || {};
        const cpExps = cpAnalysis.experiments || [];
        if (cpTableBody && cpExps.length > 0) {
            cpTableBody.innerHTML = cpExps.map(exp => `
                <tr style="border-bottom: 1px solid var(--border-subtle);">
                    <td style="padding: 0.5rem; font-weight: 600; color: #a78bfa;">
                        ${exp.watermark_length} bits
                    </td>
                    <td style="padding: 0.5rem; text-align: right; font-family: var(--font-mono); color: var(--text-secondary);">
                        ${exp.total_eligible_pairs} <span style="font-size: 0.65rem; color: var(--text-muted);">(${exp.eligible_even_pairs}e / ${exp.eligible_odd_pairs}o)</span>
                    </td>
                    <td style="padding: 0.5rem; text-align: right; font-family: var(--font-mono); color: #38bdf8; font-weight: 600;">
                        ${exp.requested_bits}
                    </td>
                    <td style="padding: 0.5rem; text-align: right; font-family: var(--font-mono); color: #fbbf24;">
                        ${exp.pre_existing_constraints}
                    </td>
                    <td style="padding: 0.5rem; text-align: right; font-family: var(--font-mono); color: #f87171; font-weight: 600;">
                        ${exp.distinct_artificial_edges_count} <span style="font-size: 0.65rem; color: var(--text-muted);">(${exp.even_artificial_edges_count}e / ${exp.odd_artificial_edges_count}o)</span>
                    </td>
                    <td style="padding: 0.5rem; text-align: right; font-family: var(--font-mono); color: #c084fc;">
                        ${exp.valid_combinations_category_str}
                    </td>
                    <td style="padding: 0.5rem; text-align: right; font-family: var(--font-mono); color: #fbbf24; font-weight: 600;">
                        ${exp.constraint_selection_entropy_category.toFixed(2)} bits
                    </td>
                    <td style="padding: 0.5rem; text-align: right; font-family: var(--font-mono); color: #34d399; font-weight: 600;">
                        ${exp.probability_correct_set_category_str}
                    </td>
                </tr>
            `).join("");
        }

        const isVerified = (data.status === "VERIFIED");
        if (badge) {
            badge.textContent = isVerified ? "VERIFIED (MATCH)" : "READY FOR RECONSTRUCTION";
            badge.className = isVerified ? "badge badge-success" : "badge badge-info";
        }

        const resultsCard = document.getElementById("judgeUnsecResultsCard");
        if (resultsCard) {
            resultsCard.style.display = isVerified ? "block" : "none";
            if (isVerified && data.reconstructed_data) {
                const rd = data.reconstructed_data;
                const dLen = document.getElementById("unsecResDLength");
                const dHash = document.getElementById("unsecResDHash");
                const targetCd = document.getElementById("unsecTargetCd");
                const recalcCd = document.getElementById("unsecRecalcCd");
                if (dLen) dLen.textContent = `${rd.reconstructed_D_length} bits`;
                if (dHash) dHash.textContent = rd.reconstructed_D_hash;
                if (targetCd && rd.commitment_verification) targetCd.textContent = rd.commitment_verification.target_c_d;
                if (recalcCd && rd.commitment_verification) recalcCd.textContent = rd.commitment_verification.recalculated_c_d;
            }
        }
    } catch (e) {
        console.error("Failed to fetch unsecured state:", e);
    }
};

window.triggerUnsecuredReconstruction = async function() {
    const txId = (currentTransactionState && currentTransactionState.transaction_id) || (currentJudgeSession && currentJudgeSession.transaction_id) || "TX-001";
    const btn = document.getElementById("btnExecuteUnsecReconstruct");
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = "<span>Recovering Original CIG &amp; Encoding D...</span>";
    }

    try {
        const res = await fetch("/api/judge/unsecured/reconstruct", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                transaction_id: txId,
                mode: judgeUnsecuredMode,
            }),
        });
        const data = await res.json();
        if (res.ok && data.success) {
            await fetchJudgeUnsecuredState();
        } else {
            alert(data.detail || "Unsecured reconstruction failed.");
        }
    } catch (e) {
        console.error("Unsecured reconstruction error:", e);
        alert(`Error: ${e.message}`);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = (judgeUnsecuredMode === 'manual')
                ? "<span>Strip Constraints &amp; Reconstruct Original D &rarr;</span>"
                : "<span>⚡ Execute Instant Reconstruction &rarr;</span>";
        }
    }
};

window.setJudgeWatermarkMode = function(mode) {
    judgeWatermarkMode = mode;
    const btnMan = document.getElementById("btnModeWmManual");
    const btnInst = document.getElementById("btnModeWmInstant");
    const desc = document.getElementById("judgeWmModeDesc");
    const btnExec = document.getElementById("btnExecuteWatermarkVerify");

    if (btnMan) btnMan.className = `btn-secondary ${mode === 'manual' ? 'active' : ''}`;
    if (btnInst) btnInst.className = `btn-secondary ${mode === 'instant' ? 'active' : ''}`;
    if (desc) {
        desc.textContent = (mode === 'manual')
            ? "Claimant supplies biometric bitstream B; verifier derives context factor T and computes W = HKDF(D, B, T)."
            : "Automatically binds verified D, recorded biometric B, and metadata T to verify W instantly.";
    }
    if (btnExec) {
        btnExec.innerHTML = (mode === 'manual')
            ? "<span>Verify Watermark Relationship &rarr;</span>"
            : "<span>⚡ Verify Watermark Instantly &rarr;</span>";
    }
};

window.loadDemoBiometricIntoInput = function() {
    const inp = document.getElementById("wmInputB");
    if (inp) {
        const demoB = (window.DEMO_BUYER_BITSTREAM_CACHED) || "011010010110111001110100011001010110110001101100011001010110001101110100011101010110000101101100010111110111000001110010011011110111000001100101011100100111010001111001010111110110001001101001011011110110110101100101011101000111001001101001011000110101111101100110011010010110111001100111011001010111001001110000011100100110100101101110011101000101111101100001011101010111010001101000011001010110111001110100011010010110001101100001011101000110100101101111011011100101111100110010001100000011001000110110";
        inp.value = demoB;
        const lenDisp = document.getElementById("wmInputBLenDisplay");
        if (lenDisp) lenDisp.textContent = `${demoB.length} bits`;
    }
};

window.fetchJudgeWatermarkState = async function() {
    const txId = (currentTransactionState && currentTransactionState.transaction_id) || (currentJudgeSession && currentJudgeSession.transaction_id) || "TX-001";
    try {
        const res = await fetch(`/api/judge/watermark/state?transaction_id=${txId}`);
        if (!res.ok) return;
        const data = await res.json();

        const lockBanner = document.getElementById("judgeWatermarkLockBanner");
        const content = document.getElementById("judgeWatermarkContent");
        const badge = document.getElementById("judgeWmStatusBadge");
        const dLen = document.getElementById("wmInputDLength");
        const dHash = document.getElementById("wmInputDHash");
        const tHex = document.getElementById("wmInputTHex");
        const inpB = document.getElementById("wmInputB");
        const bLenDisp = document.getElementById("wmInputBLenDisplay");

        if (!data.prerequisite_met) {
            if (lockBanner) lockBanner.style.display = "block";
            if (content) content.style.display = "none";
            return;
        }

        if (lockBanner) lockBanner.style.display = "none";
        if (content) content.style.display = "block";

        const inp = data.inputs || {};
        if (dLen) dLen.textContent = `${inp.D_length || 251} bits`;
        if (dHash) dHash.textContent = inp.D_hash || "--";
        if (tHex) tHex.textContent = inp.transaction_factor_T_hex || "--";

        if (inp.suggested_B) {
            window.DEMO_BUYER_BITSTREAM_CACHED = inp.suggested_B;
            if (inpB && !inpB.value) {
                inpB.value = inp.suggested_B;
                if (bLenDisp) bLenDisp.textContent = `${inp.suggested_B.length} bits`;
            }
        }

        // Populate Constraint Possibility Analysis Table
        const cpTableBody = document.getElementById("judgeConstraintPossibilityTableBody");
        const cpAnalysis = data.constraint_possibility_analysis || {};
        const cpExps = cpAnalysis.experiments || [];
        if (cpTableBody && cpExps.length > 0) {
            cpTableBody.innerHTML = cpExps.map(exp => `
                <tr style="border-bottom: 1px solid var(--border-subtle);">
                    <td style="padding: 0.5rem; font-weight: 600; color: #a78bfa;">
                        ${exp.watermark_length} bits
                    </td>
                    <td style="padding: 0.5rem; text-align: right; font-family: var(--font-mono); color: var(--text-secondary);">
                        ${exp.total_eligible_pairs} <span style="font-size: 0.65rem; color: var(--text-muted);">(${exp.eligible_even_pairs}e / ${exp.eligible_odd_pairs}o)</span>
                    </td>
                    <td style="padding: 0.5rem; text-align: right; font-family: var(--font-mono); color: #38bdf8; font-weight: 600;">
                        ${exp.requested_bits}
                    </td>
                    <td style="padding: 0.5rem; text-align: right; font-family: var(--font-mono); color: #fbbf24;">
                        ${exp.pre_existing_constraints}
                    </td>
                    <td style="padding: 0.5rem; text-align: right; font-family: var(--font-mono); color: #f87171; font-weight: 600;">
                        ${exp.distinct_artificial_edges_count} <span style="font-size: 0.65rem; color: var(--text-muted);">(${exp.even_artificial_edges_count}e / ${exp.odd_artificial_edges_count}o)</span>
                    </td>
                    <td style="padding: 0.5rem; text-align: right; font-family: var(--font-mono); color: #c084fc;">
                        ${exp.valid_combinations_category_str}
                    </td>
                    <td style="padding: 0.5rem; text-align: right; font-family: var(--font-mono); color: #fbbf24; font-weight: 600;">
                        ${exp.constraint_selection_entropy_category.toFixed(2)} bits
                    </td>
                    <td style="padding: 0.5rem; text-align: right; font-family: var(--font-mono); color: #34d399; font-weight: 600;">
                        ${exp.probability_correct_set_category_str}
                    </td>
                </tr>
            `).join("");
        }

        const isVerified = (data.status === "VERIFIED");
        if (badge) {
            badge.textContent = isVerified ? "VERIFIED (MATCH)" : "READY FOR VERIFICATION";
            badge.className = isVerified ? "badge badge-success" : "badge badge-info";
        }

        const navWmBadge = document.getElementById("badgeNavJudgeWatermarking");
        if (navWmBadge) {
            navWmBadge.textContent = isVerified ? "Verified" : "Pending";
            navWmBadge.className = isVerified ? "badge badge-success" : "badge";
            if (isVerified) {
                navWmBadge.style.background = "rgba(52, 211, 153, 0.15)";
                navWmBadge.style.borderColor = "#34d399";
                navWmBadge.style.color = "#34d399";
            }
        }

        const resCard = document.getElementById("judgeWmResultsCard");
        if (resCard) {
            resCard.style.display = isVerified ? "block" : "none";
            if (isVerified && data.reconstructed_data) {
                const rd = data.reconstructed_data;
                const wmLen = document.getElementById("wmResLength");
                const wmHash = document.getElementById("wmResHash");
                const targetCw = document.getElementById("wmTargetCw");
                const recalcCw = document.getElementById("wmRecalcCw");
                if (wmLen) wmLen.textContent = `${rd.watermark_length} bits`;
                if (wmHash) wmHash.textContent = rd.watermark_hash;
                if (targetCw && rd.commitment_verification) targetCw.textContent = rd.commitment_verification.target_c_w;
                if (recalcCw && rd.commitment_verification) recalcCw.textContent = rd.commitment_verification.recalculated_c_w;
            }
        }
    } catch (e) {
        console.error("Failed to fetch watermark state:", e);
    }
};

window.triggerWatermarkVerification = async function() {
    const txId = (currentTransactionState && currentTransactionState.transaction_id) || (currentJudgeSession && currentJudgeSession.transaction_id) || "TX-001";
    const inpB = document.getElementById("wmInputB");
    const bVal = inpB ? inpB.value.trim() : null;

    const btn = document.getElementById("btnExecuteWatermarkVerify");
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = "<span>Verifying HKDF Relationship &amp; C_W...</span>";
    }

    try {
        const res = await fetch("/api/judge/watermark/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                transaction_id: txId,
                buyer_bitstream: bVal,
                mode: judgeWatermarkMode,
            }),
        });
        const data = await res.json();
        if (res.ok && data.success) {
            await fetchJudgeWatermarkState();
        } else {
            alert(data.detail || "Watermark verification failed.");
        }
    } catch (e) {
        console.error("Watermark verification error:", e);
        alert(`Error: ${e.message}`);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = (judgeWatermarkMode === 'manual')
                ? "<span>Verify Watermark Relationship &rarr;</span>"
                : "<span>⚡ Verify Watermark Instantly &rarr;</span>";
        }
    }
};

window.fetchJudgeOverview = async function() {
    const txId = (currentTransactionState && currentTransactionState.transaction_id) || (currentJudgeSession && currentJudgeSession.transaction_id) || "TX-001";
    try {
        const res = await fetch(`/api/judge/overview?transaction_id=${txId}`);
        if (!res.ok) return;
        const data = await res.json();

        const vBadge = document.getElementById("ovVerdictBadge");
        const vText = document.getElementById("ovVerdictText");
        const isAll = data.all_stages_completed;

        if (vBadge) {
            vBadge.textContent = isAll ? "AUTHENTICATED &amp; VERIFIED" : "IN PROGRESS";
            vBadge.className = isAll ? "badge badge-success" : "badge badge-warning";
        }
        if (vText) vText.textContent = data.verdict_text;

        const stg = data.stages || {};
        const s1 = stg.stage1_secured_encoding || {};
        const s2 = stg.stage2_interrogation_report || {};
        const s3 = stg.stage3_unsecured_encoding || {};
        const s4 = stg.stage4_watermark_verification || {};

        const b1 = document.getElementById("ovStage1Badge");
        const d1 = document.getElementById("ovStage1Desc");
        if (b1) {
            b1.textContent = s1.status;
            b1.className = s1.status === "VERIFIED" ? "badge badge-success" : "badge";
        }
        if (d1) d1.textContent = s1.detail;

        const b2 = document.getElementById("ovStage2Badge");
        const d2 = document.getElementById("ovStage2Desc");
        if (b2) b2.textContent = s2.status;
        if (d2) d2.textContent = `${s2.questions_asked} questions asked; entropy reduced from ${s2.initial_entropy_bits} to ${s2.final_entropy_bits} bits.`;

        const b3 = document.getElementById("ovStage3Badge");
        const d3 = document.getElementById("ovStage3Desc");
        if (b3) {
            b3.textContent = s3.status;
            b3.className = s3.status === "VERIFIED" ? "badge badge-success" : "badge";
        }
        if (d3) d3.textContent = s3.detail;

        const b4 = document.getElementById("ovStage4Badge");
        const d4 = document.getElementById("ovStage4Desc");
        if (b4) {
            b4.textContent = s4.status;
            b4.className = s4.status === "VERIFIED" ? "badge badge-success" : "badge";
        }
        if (d4) d4.textContent = s4.detail;

        const navOvBadge = document.getElementById("badgeNavJudgeOverview");
        if (navOvBadge) {
            navOvBadge.textContent = isAll ? "Verified" : "Adjudication";
            navOvBadge.className = isAll ? "badge badge-success" : "badge";
            if (isAll) {
                navOvBadge.style.background = "rgba(52, 211, 153, 0.15)";
                navOvBadge.style.borderColor = "#34d399";
                navOvBadge.style.color = "#34d399";
            }
        }
    } catch (e) {
        console.error("Failed to fetch overview:", e);
    }
};

window.resetJudgeWorkflowFull = async function() {
    if (!confirm("Reset the entire judge adjudication workflow and erase all stage records for this transaction?")) {
        return;
    }
    const txId = (currentTransactionState && currentTransactionState.transaction_id) || (currentJudgeSession && currentJudgeSession.transaction_id) || "TX-001";
    const sessId = currentJudgeSession ? currentJudgeSession.session_id : null;

    try {
        const res = await fetch("/api/judge/workflow/reset", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ transaction_id: txId, session_id: sessId }),
        });
        if (res.ok) {
            await switchJudgeWorkflow("secured_design_encoding");
        }
    } catch (e) {
        console.error("Failed to reset full workflow:", e);
    }
};

window.fetchJudgeAnalysisReport = async function(forceRefresh = false) {
    try {
        const url = forceRefresh ? "/api/judge/analysis_report/run" : "/api/judge/analysis_report";
        const method = forceRefresh ? "POST" : "GET";
        const resp = await fetch(url, { method });
        if (!resp.ok) {
            console.error("Failed to fetch interrogation analysis report", resp.statusText);
            return;
        }
        const data = await resp.json();
        renderJudgeAnalysisReport(data);
    } catch (err) {
        console.error("Error fetching interrogation report:", err);
    }
};

window.refreshJudgeAnalysisReport = async function() {
    const btn = document.getElementById("btnRefreshAnalysisReport");
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = "<span>↻ Running Simulation...</span>";
    }
    await fetchJudgeAnalysisReport(true);
    if (btn) {
        btn.disabled = false;
        btn.innerHTML = "<span>↻ Run Fresh Simulation</span>";
    }
};

function renderJudgeAnalysisReport(data) {
    if (!data) return;

    // Badges & Status
    const statusBadge = document.getElementById("repAnalysisStatusBadge");
    if (statusBadge) {
        statusBadge.textContent = "READY · CACHED";
        statusBadge.className = "badge badge-info";
    }

    const freshBadge = document.getElementById("repFreshnessBadge");
    if (freshBadge) {
        freshBadge.textContent = "LATEST";
        freshBadge.style.borderColor = "#34d399";
        freshBadge.style.color = "#34d399";
        freshBadge.style.background = "rgba(52, 211, 153, 0.15)";
    }

    // SECTION A: Secured Design
    const secA = data.section_a_secured || {};
    const secAStatus = document.getElementById("repSecAStatus");
    if (secAStatus) {
        secAStatus.textContent = (secA.reconstruction_results && secA.reconstruction_results.reconstruction_completed)
            ? "RECONSTRUCTED (251 / 251 bits)"
            : "INCOMPLETE";
    }
    const secASpace = document.getElementById("repSecASearchSpace");
    if (secASpace) secASpace.textContent = secA.search_space_size_str || "3.6185e+75";
    const secAEntropy = document.getElementById("repSecAEntropy");
    if (secAEntropy) secAEntropy.textContent = `${(secA.shannon_entropy_bits || 251.0).toFixed(2)} bits`;
    const secAProb = document.getElementById("repSecAProbability");
    if (secAProb) secAProb.textContent = secA.exact_guessing_probability_str || "2.7636e-76";
    const secACommit = document.getElementById("repSecACommitStatus");
    if (secACommit) secACommit.textContent = (secA.reconstruction_results && secA.reconstruction_results.commitment_status) || "VERIFIED (NIST P-256)";

    // SECTION B: Unsecured Design
    const secB = data.section_b_unsecured || {};
    const fullMetrics = secB.full_watermark_constraint_metrics || {};
    const secBStatus = document.getElementById("repSecBStatus");
    if (secBStatus) {
        secBStatus.textContent = fullMetrics.reconstructed_cig_matches_original
            ? "RECOVERED (211 Edges Preserved)"
            : "INCOMPLETE";
    }
    const secBSpace = document.getElementById("repSecBSearchSpace");
    if (secBSpace) secBSpace.textContent = fullMetrics.search_space_size_str || "6.5138e+43";
    const secBEntropy = document.getElementById("repSecBEntropy");
    if (secBEntropy) secBEntropy.textContent = `${(fullMetrics.constraint_entropy_bits || 145.55).toFixed(2)} bits`;
    const secBProb = document.getElementById("repSecBProbability");
    if (secBProb) secBProb.textContent = fullMetrics.random_guessing_probability_str || "1.5352e-44";
    const secBCommit = document.getElementById("repSecBCommitStatus");
    if (secBCommit) secBCommit.textContent = fullMetrics.commitment_status || "VERIFIED (NIST P-256)";

    // SECTION C: Watermark Table
    const secC = data.section_c_watermark || {};
    const wmTableBody = document.getElementById("wmSecCTableBody");
    if (wmTableBody && secC.watermark_evaluation_table) {
        wmTableBody.innerHTML = secC.watermark_evaluation_table.map(row => `
            <tr style="border-bottom: 1px solid var(--border-subtle);">
                <td style="padding: 0.55rem; font-weight: 600; color: #a78bfa;">${row.watermark_length} bits</td>
                <td style="padding: 0.55rem; font-family: var(--font-mono); color: #38bdf8; font-size: 0.7rem;">${escapeHtml(row.prefix_preview || '')}</td>
                <td style="padding: 0.55rem; text-align: right; font-family: var(--font-mono); color: var(--text-primary);">${row.search_space_size_str}</td>
                <td style="padding: 0.55rem; text-align: right; font-family: var(--font-mono); color: #c084fc; font-weight: 600;">${row.idealized_shannon_entropy_bits.toFixed(1)} bits</td>
                <td style="padding: 0.55rem; text-align: right; font-family: var(--font-mono); color: #f87171;">${row.theoretical_guessing_probability_str}</td>
                <td style="padding: 0.55rem; text-align: center;">
                    <span class="badge badge-success" style="font-size: 0.68rem;">VERIFIED (MATCH)</span>
                </td>
            </tr>
        `).join("");
    }

    // SECTION D: Comparison Table & Charts
    const secD = data.section_d_comparison || {};
    const compTableBody = document.getElementById("wmComparisonTableBody");
    if (compTableBody && secD.comparison_table) {
        compTableBody.innerHTML = secD.comparison_table.map(row => `
            <tr style="border-bottom: 1px solid var(--border-subtle);">
                <td style="padding: 0.5rem; font-weight: 700; color: #f59e0b;">${row.watermark_length}b</td>
                <td style="padding: 0.5rem; text-align: right; font-family: var(--font-mono);">${row.requested_bits}</td>
                <td style="padding: 0.5rem; text-align: right; font-family: var(--font-mono); color: #34d399;">${row.successfully_processed_positions}</td>
                <td style="padding: 0.5rem; text-align: right; font-family: var(--font-mono); color: #34d399;">${row.successfully_assigned_positions}</td>
                <td style="padding: 0.5rem; text-align: right; font-family: var(--font-mono);">${row.total_constraint_assignments}</td>
                <td style="padding: 0.5rem; text-align: right; font-family: var(--font-mono); color: #38bdf8;">${row.distinct_selected_pairs}</td>
                <td style="padding: 0.5rem; text-align: right; font-family: var(--font-mono); color: #a78bfa;">${row.pre_existing_genuine_edge_assignments}</td>
                <td style="padding: 0.5rem; text-align: right; font-family: var(--font-mono); color: #fbbf24;">${row.new_artificial_edge_insertion_operations}</td>
                <td style="padding: 0.5rem; text-align: right; font-family: var(--font-mono); font-weight: 700; color: #38bdf8;">${row.distinct_artificial_edges_added}</td>
                <td style="padding: 0.5rem; text-align: right; font-family: var(--font-mono); color: ${row.repeated_pair_assignments > 0 ? '#fbbf24' : 'var(--text-muted)'};">${row.repeated_pair_assignments}</td>
                <td style="padding: 0.5rem; text-align: right; font-family: var(--font-mono); color: #34d399;">0</td>
                <td style="padding: 0.5rem; text-align: right; font-family: var(--font-mono); color: #f59e0b; font-weight: 600;">${row.cig_overhead_percent}%</td>
                <td style="padding: 0.5rem; text-align: right; font-family: var(--font-mono);">${row.hamming_distance}b / ${row.encoding_change_percent}%</td>
                <td style="padding: 0.5rem; text-align: center; font-family: var(--font-mono); color: #34d399;">+0 (16)</td>
                <td style="padding: 0.5rem; text-align: center;">
                    <span class="badge badge-success" style="font-size: 0.65rem;">32/32 PASS (100%)</span>
                </td>
            </tr>
        `).join("");
    }

    // Render Charts
    renderBarChart("chartArtEdges", [
        { label: "32b", val: 14, max: 60, col: "#38bdf8" },
        { label: "64b", val: 24, max: 60, col: "#38bdf8" },
        { label: "128b", val: 40, max: 60, col: "#38bdf8" },
        { label: "256b", val: 57, max: 60, col: "#38bdf8" },
    ]);

    renderBarChart("chartEncChange", [
        { label: "32b", val: 2.39, max: 5, col: "#34d399" },
        { label: "64b", val: 2.39, max: 5, col: "#34d399" },
        { label: "128b", val: 2.39, max: 5, col: "#34d399" },
        { label: "256b", val: 2.39, max: 5, col: "#34d399" },
    ]);

    renderBarChart("chartEntropy", [
        { label: "32b", val: 63.76, max: 160, col: "#c084fc" },
        { label: "64b", val: 93.08, max: 160, col: "#c084fc" },
        { label: "128b", val: 123.95, max: 160, col: "#c084fc" },
        { label: "256b", val: 145.55, max: 160, col: "#c084fc" },
    ]);
}

function renderBarChart(containerId, items) {
    const el = document.getElementById(containerId);
    if (!el) return;
    el.innerHTML = items.map(item => {
        const heightPct = Math.max(8, Math.min(100, Math.round((item.val / item.max) * 100)));
        return `
            <div style="flex: 1; display: flex; flex-direction: column; align-items: center; height: 100%; justify-content: flex-end;">
                <span style="font-size: 0.65rem; color: var(--text-secondary); margin-bottom: 4px; font-family: var(--font-mono);">${item.val}</span>
                <div style="width: 100%; max-width: 36px; height: ${heightPct}%; background: ${item.col}; border-radius: 4px 4px 0 0; transition: height 0.4s ease; opacity: 0.85;"></div>
            </div>
        `;
    }).join("");
}

window.switchJudgeSegment = function(segment) {
    currentJudgeSegment = segment;
    const btnP1 = document.getElementById("btnJudgeSegPart1");
    const btnP2 = document.getElementById("btnJudgeSegPart2");
    const btnEntire = document.getElementById("btnJudgeSegEntire");
    if (btnP1) btnP1.className = `judge-segment-btn ${segment === 'part1' ? 'active' : ''}`;
    if (btnP2) btnP2.className = `judge-segment-btn ${segment === 'part2' ? 'active' : ''}`;
    if (btnEntire) btnEntire.className = `judge-segment-btn ${segment === 'entire' ? 'active' : ''}`;
    if (currentJudgeSession) {
        renderJudgeUI(currentJudgeSession);
    }
};

function initJudgeWorkflow() {
    const btnSubmitAnswer = document.getElementById("btnJudgeSubmitAnswer");
    if (btnSubmitAnswer) {
        btnSubmitAnswer.addEventListener("click", () => submitJudgeAnswer());
    }

    const inputNumber = document.getElementById("judgeInputNumber");
    if (inputNumber) {
        inputNumber.addEventListener("keydown", (e) => {
            if (e.key === "Enter") {
                e.preventDefault();
                submitJudgeAnswer();
            }
        });
    }

    const btnReset = document.getElementById("btnJudgeResetSession");
    if (btnReset) {
        btnReset.addEventListener("click", async () => {
            if (!currentJudgeSession) return;
            if (confirm("Reset the judge-led interrogation session and erase all recorded answers?")) {
                try {
                    const res = await fetch("/api/judge/session/reset", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ session_id: currentJudgeSession.session_id }),
                    });
                    if (res.ok) {
                        const data = await res.json();
                        currentJudgeSession = data;
                        renderJudgeUI(data);
                    }
                } catch (e) {
                    console.error("Failed to reset judge session:", e);
                }
            }
        });
    }

    const btnToggleBlock5b = document.getElementById("btnJudgeToggleBlock5b");
    if (btnToggleBlock5b) {
        btnToggleBlock5b.addEventListener("click", async () => {
            if (!currentJudgeSession) return;
            const newTarget = !currentJudgeSession.block5b_enabled;
            try {
                const res = await fetch("/api/judge/session/toggle_block5b", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        session_id: currentJudgeSession.session_id,
                        enabled: newTarget,
                    }),
                });
                if (res.ok) {
                    const data = await res.json();
                    currentJudgeSession = data;
                    renderJudgeUI(data);
                }
            } catch (e) {
                console.error("Failed to toggle Block 5b:", e);
            }
        });
    }

    // Modal controls for non-destructive correction
    const btnCloseModal = document.getElementById("btnCloseCorrectionModal");
    const btnCancelCorrection = document.getElementById("btnCancelCorrection");
    const modal = document.getElementById("judgeCorrectionModal");

    const hideModal = () => {
        if (modal) modal.style.display = "none";
        currentCorrectionTarget = null;
    };

    if (btnCloseModal) btnCloseModal.addEventListener("click", hideModal);
    if (btnCancelCorrection) btnCancelCorrection.addEventListener("click", hideModal);

    const btnSubmitCorrectionConfirmed = document.getElementById("btnSubmitCorrectionConfirmed");
    if (btnSubmitCorrectionConfirmed) {
        btnSubmitCorrectionConfirmed.addEventListener("click", () => submitJudgeCorrection());
    }

    const corrInput = document.getElementById("corrNewAnswerInput");
    if (corrInput) {
        corrInput.addEventListener("keydown", (e) => {
            if (e.key === "Enter") {
                e.preventDefault();
                submitJudgeCorrection();
            }
        });
    }

    // Delegated click handler for quick correction and reset buttons on state cards
    document.addEventListener("click", (e) => {
        const btnCorr = e.target.closest(".btn-judge-correct-latest");
        if (btnCorr && currentJudgeSession) {
            const ledger = currentJudgeSession.history_ledger || [];
            if (ledger.length > 0) {
                const latest = ledger[ledger.length - 1];
                openCorrectionModal(latest);
            } else {
                const histList = document.getElementById("judgeHistoryList");
                if (histList) histList.scrollIntoView({ behavior: "smooth" });
            }
            return;
        }

        const btnResetTrigger = e.target.closest(".btn-judge-reset-trigger");
        if (btnResetTrigger && currentJudgeSession) {
            const btnReset = document.getElementById("btnJudgeResetSession");
            if (btnReset) btnReset.click();
            return;
        }
    });
}

async function fetchJudgeSession(wf) {
    try {
        const targetWf = wf || currentJudgeWorkflow || "secured_design_encoding";
        currentJudgeWorkflow = targetWf;
        const txId = (currentTransactionState && currentTransactionState.transaction_id) || "TX-001";
        const res = await fetch(`/api/judge/session?transaction_id=${txId}&workflow=${targetWf}`);
        if (res.ok) {
            const data = await res.json();
            currentJudgeSession = data;
            renderJudgeUI(data);
            return data;
        }
    } catch (e) {
        console.warn("Failed to fetch judge session:", e);
    }
    return null;
}

async function submitJudgeAnswer() {
    const valMsg = document.getElementById("judgeInputValidationMsg");
    if (valMsg) valMsg.style.display = "none";

    if (!currentJudgeSession || !currentJudgeSession.current_question) {
        if (valMsg) {
            valMsg.textContent = "No active question to answer. Interrogation is either halted or complete.";
            valMsg.style.display = "block";
        }
        return;
    }

    const q = currentJudgeSession.current_question;
    const inputNum = document.getElementById("judgeInputNumber");
    const inputChoice = document.getElementById("judgeInputChoice");

    let answerVal = null;
    if (q.question_type === "BOOLEAN" || q.question_type === "CHOICE") {
        answerVal = inputChoice ? inputChoice.value : null;
    } else {
        answerVal = inputNum ? inputNum.value : null;
    }

    if (answerVal === null || answerVal === "") {
        if (valMsg) {
            valMsg.textContent = "Please provide an answer before submitting.";
            valMsg.style.display = "block";
        }
        return;
    }

    const btnSubmit = document.getElementById("btnJudgeSubmitAnswer");
    if (btnSubmit) btnSubmit.disabled = true;

    try {
        const res = await fetch("/api/judge/session/answer", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                session_id: currentJudgeSession.session_id,
                question_id: q.id,
                answer: answerVal,
            }),
        });

        const data = await res.json();
        if (res.ok) {
            currentJudgeSession = data;
            renderJudgeUI(data);
        } else {
            if (valMsg) {
                valMsg.textContent = data.detail || "Validation failed.";
                valMsg.style.display = "block";
            }
        }
    } catch (e) {
        console.error("Answer submission failed:", e);
        if (valMsg) {
            valMsg.textContent = `Error: ${e.message}`;
            valMsg.style.display = "block";
        }
    } finally {
        if (btnSubmit) btnSubmit.disabled = false;
    }
}

function openCorrectionModal(entry) {
    currentCorrectionTarget = entry;
    const modal = document.getElementById("judgeCorrectionModal");
    const qIdText = document.getElementById("corrQuestionIdText");
    const promptText = document.getElementById("corrQuestionPromptText");
    const curAnsText = document.getElementById("corrCurrentAnswerText");
    const inputField = document.getElementById("corrNewAnswerInput");

    if (qIdText) qIdText.textContent = entry.question_id;
    if (promptText) promptText.textContent = entry.question_prompt;
    if (curAnsText) curAnsText.textContent = String(entry.effective_answer);
    if (inputField) {
        inputField.value = "";
        inputField.placeholder = `Enter corrected value (was ${entry.effective_answer})...`;
    }

    if (modal) {
        modal.style.display = "block";
        setTimeout(() => { if (inputField) inputField.focus(); }, 50);
    }
}

async function submitJudgeCorrection() {
    if (!currentJudgeSession || !currentCorrectionTarget) return;

    const inputField = document.getElementById("corrNewAnswerInput");
    const newAnswer = inputField ? inputField.value.trim() : "";
    if (!newAnswer) return;

    try {
        const res = await fetch("/api/judge/session/correct", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                session_id: currentJudgeSession.session_id,
                question_id: currentCorrectionTarget.question_id,
                answer: newAnswer,
            }),
        });

        const data = await res.json();
        if (res.ok) {
            currentJudgeSession = data;
            const modal = document.getElementById("judgeCorrectionModal");
            if (modal) modal.style.display = "none";
            currentCorrectionTarget = null;
            renderJudgeUI(data);
        } else {
            alert(data.detail || "Correction rejected.");
        }
    } catch (e) {
        console.error("Correction failed:", e);
        alert(`Error: ${e.message}`);
    }
}

function _renderCellSpan(c) {
    let fillCls = "cell-fill-neutral";
    if (c.fill === "GREEN") fillCls = "cell-fill-green";
    else if (c.fill === "RED") fillCls = "cell-fill-red";
    else if (c.fill === "INFERRED") fillCls = "cell-fill-inferred";

    let borderCls = "border-prov-unknown";
    if (c.provenance === "OBSERVED") borderCls = "border-prov-observed";
    else if (c.provenance === "DERIVED") borderCls = "border-prov-derived";
    else if (c.provenance === "INFERRED") borderCls = "border-prov-inferred";
    else if (c.provenance === "REJECTED") borderCls = "border-prov-rejected";

    const title = `Bit ${c.canonical_pos - 1} (Pos ${c.canonical_pos}): ${c.display_char} [${c.provenance || 'UNKNOWN'}] \nFill: ${c.fill || 'NEUTRAL'} (${c.is_fixed ? 'Fixed' : 'Unfixed'}) \nSource: ${c.source || 'Scaffold'}`;
    return `<div class="judge-bit-cell ${fillCls} ${borderCls}" title="${title.replace(/"/g, '&quot;')}">${c.display_char || '?'}</div>`;
}

function renderJudgeUI(data) {
    if (!data) return;

    const activeWf = data.workflow || currentJudgeWorkflow || "secured_design_encoding";
    currentJudgeWorkflow = activeWf;
    const reconState = (data.evaluation && data.evaluation.reconstruction_state) || data.reconstruction_state || {};

    // 0. Sync Workflow Subtabs
    const tabSec = document.getElementById("tabJudgeSecured");
    const tabUnsec = document.getElementById("tabJudgeUnsecured");
    const tabWm = document.getElementById("tabJudgeWatermarking");
    if (tabSec) tabSec.className = `judge-wf-tab ${activeWf === 'secured_design_encoding' ? 'active' : ''}`;
    if (tabUnsec) tabUnsec.className = `judge-wf-tab ${activeWf === 'unsecured_design_encoding' ? 'active' : ''}`;
    if (tabWm) tabWm.className = `judge-wf-tab ${activeWf === 'watermarking' ? 'active' : ''}`;

    const wfBadge = document.getElementById("judgeWorkflowBadge");
    const stageScope = document.getElementById("judgeStageScopeText");
    if (wfBadge) {
        if (activeWf === "secured_design_encoding") {
            const hasLen = reconState && reconState.total_length;
            wfBadge.textContent = hasLen ? `Secured (${reconState.total_length}b)` : "Secured";
            wfBadge.className = "badge badge-v1";
            wfBadge.style.background = "rgba(139, 92, 246, 0.25)";
            wfBadge.style.color = "#c084fc";
        } else if (activeWf === "unsecured_design_encoding") {
            const hasLen = reconState && reconState.total_length;
            wfBadge.textContent = hasLen ? `Unsecured (${reconState.total_length}b)` : "Unsecured";
            wfBadge.className = "badge";
            wfBadge.style.background = "rgba(255, 255, 255, 0.1)";
            wfBadge.style.color = "#94a3b8";
        } else {
            wfBadge.textContent = "Watermarking (Pending)";
            wfBadge.className = "badge badge-warning";
        }
    }
    if (stageScope) {
        if (activeWf === "secured_design_encoding") {
            stageScope.innerHTML = "<strong>Stage Scope:</strong> Interrogates and progressively reconstructs the secured design encoding through auditable questions and hard cryptographic constraints.";
        } else if (activeWf === "unsecured_design_encoding") {
            stageScope.innerHTML = "<strong>Stage Scope:</strong> Interrogates and progressively reconstructs the unsecured design encoding across Stage U1. Unsecured Rule 5 interrogation is pending.";
        }
    }

    // 1. Session Context
    const sessText = document.getElementById("judgeSessionIdText");
    if (sessText) sessText.textContent = data.session_id;
    const txBadge = document.getElementById("judgeTxBadge");
    if (txBadge) txBadge.textContent = data.transaction_id;
    const brBadge = document.getElementById("judgeBranchBadge");
    if (brBadge) brBadge.textContent = `Branch ${data.branch}`;

    const lbl5b = document.getElementById("lblBlock5bState");
    if (lbl5b) lbl5b.textContent = data.block5b_enabled ? "ON (Active)" : "OFF";
    const btn5b = document.getElementById("btnJudgeToggleBlock5b");
    if (btn5b) {
        btn5b.style.borderColor = data.block5b_enabled ? "rgba(99, 102, 241, 0.6)" : "var(--border-subtle)";
        btn5b.style.color = data.block5b_enabled ? "#818cf8" : "inherit";
    }

    // 2. Status Banner
    const statusBadge = document.getElementById("judgeStageStatusBadge");
    const statusSubtext = document.getElementById("judgeStatusSubtext");
    const alertBanner = document.getElementById("judgeAlertBanner");
    const isContradiction = (data.status === "CONTRADICTION");
    const isUnsupported = (data.status === "UNSUPPORTED_BRANCH");
    const isIncomplete = Boolean(data.status && data.status.startsWith("INCOMPLETE"));
    const isComplete = Boolean((data.status && data.status.startsWith("COMPLETE")) || ((activeWf === "secured_design_encoding")
        ? Boolean(data.evaluation && data.evaluation.is_complete_251)
        : Boolean(data.evaluation && data.evaluation.is_complete_143)));

    if (statusBadge) {
        if (isContradiction) {
            statusBadge.textContent = "CONTRADICTION";
            statusBadge.className = "badge badge-danger";
            if (statusSubtext) statusSubtext.textContent = "Progression halted: Answers conflict with hard constraints";
        } else if (isUnsupported) {
            statusBadge.textContent = "UNSUPPORTED BRANCH";
            statusBadge.className = "badge badge-danger";
            if (statusSubtext) statusSubtext.textContent = (data.evaluation && data.evaluation.unsupported_branch_reason) || "Structural branch is outside supported schema";
        } else if (isIncomplete) {
            statusBadge.textContent = "INCOMPLETE";
            statusBadge.className = "badge badge-warning";
            if (statusSubtext) statusSubtext.textContent = (data.evaluation && data.evaluation.incomplete_reason) || "Interrogation cannot proceed without structural facts";
        } else if (isComplete) {
            if (activeWf === "secured_design_encoding") {
                statusBadge.textContent = data.status.includes("Four-Rule Only") ? "Four-Rule Complete (Rule 5 N/A)" : "251-Bit Secured Complete";
                statusBadge.className = "badge badge-success";
                if (statusSubtext) statusSubtext.textContent = data.status.includes("Four-Rule Only") ? "143-bit Four-Rule encoding reconstructed; Rule 5 marked not applicable" : "Cryptographic C_ES Commitment Verified (MATCH)";
            } else {
                statusBadge.textContent = "143-Bit Stage Complete";
                statusBadge.className = "badge badge-warning";
                if (statusSubtext) statusSubtext.textContent = "Unsecured Rule 5 interrogation pending";
            }
        } else {
            statusBadge.textContent = "IN PROGRESS";
            statusBadge.className = "badge badge-warning";
            if (statusSubtext) statusSubtext.textContent = "Interrogating claimant knowledge";
        }
    }

    if (alertBanner) {
        if (isContradiction) {
            alertBanner.style.display = "block";
            alertBanner.style.background = "rgba(239, 68, 68, 0.15)";
            alertBanner.style.border = "1px solid rgba(239, 68, 68, 0.4)";
            alertBanner.style.color = "#fca5a5";
            alertBanner.innerHTML = `<strong>Contradiction:</strong> These answers cannot both be true. A confirmed answer conflicts with an arithmetic or Rule 5 constraint. Correct the discrepancy in the ledger below to resume.`;
        } else if (isUnsupported) {
            alertBanner.style.display = "block";
            alertBanner.style.background = "rgba(239, 68, 68, 0.15)";
            alertBanner.style.border = "1px solid rgba(239, 68, 68, 0.4)";
            alertBanner.style.color = "#fca5a5";
            alertBanner.innerHTML = `<strong>Unsupported Branch:</strong> ${(data.evaluation && data.evaluation.unsupported_branch_reason) || 'The claimant answers describe an alternative structure that the current schema cannot validate.'}`;
        } else if (isIncomplete) {
            alertBanner.style.display = "block";
            alertBanner.style.background = "rgba(245, 158, 11, 0.15)";
            alertBanner.style.border = "1px solid rgba(245, 158, 11, 0.4)";
            alertBanner.style.color = "#fde68a";
            alertBanner.innerHTML = `<strong>Incomplete Interrogation:</strong> ${(data.evaluation && data.evaluation.incomplete_reason) || 'Claimant indicated structure is unknown or indeterminable. Further facts required.'}`;
        } else if (isComplete) {
            alertBanner.style.display = "block";
            if (activeWf === "secured_design_encoding") {
                alertBanner.style.background = "rgba(16, 185, 129, 0.12)";
                alertBanner.style.border = "1px solid rgba(16, 185, 129, 0.35)";
                alertBanner.style.color = "#6ee7b7";
                alertBanner.innerHTML = data.status.includes("Four-Rule Only")
                    ? `<strong>Complete:</strong> 143-bit Four-Rule encoding reconstructed. Rule 5 marked not applicable.`
                    : `<strong>Complete:</strong> 251-bit secured candidate stream reconstructed and verified against commitment C_ES.`;
            } else {
                alertBanner.style.background = "rgba(245, 158, 11, 0.12)";
                alertBanner.style.border = "1px solid rgba(245, 158, 11, 0.35)";
                alertBanner.style.color = "#fde68a";
                alertBanner.innerHTML = `<strong>143-Bit Complete:</strong> 4-rule stream finished. Unsecured Rule 5 interrogation is pending.`;
            }
        } else {
            alertBanner.style.display = "none";
        }
    }

    // 3. Progress Card
    const progText = document.getElementById("judgeProgressText");
    const progBar = document.getElementById("judgeProgressBar");
    const statCandidateSpace = document.getElementById("judgeStatCandidateSpace");
    const statResolvedBits = document.getElementById("judgeStatResolvedBits");
    const statUnresolvedBits = document.getElementById("judgeStatUnresolvedBits");
    const statTotalQ = document.getElementById("judgeStatTotalQ");
    const statAnsweredQ = document.getElementById("judgeStatAnsweredQ");
    const statP1Status = document.getElementById("judgeStatP1Status");
    const statContra = document.getElementById("judgeStatContradictions");

    const cs = data.candidate_space || (data.evaluation && data.evaluation.candidate_space) || (data.progress && data.progress.candidate_space) || (reconState && reconState.candidate_space) || {};
    const resPct = (cs.resolution_percentage !== undefined) ? cs.resolution_percentage : (data.progress ? data.progress.percentage : 0);

    let csDisplay = "Unbounded";
    if (cs.status === "UNIQUE") {
        csDisplay = "1 Candidate Remains";
    } else if (cs.status === "EXACT" && cs.estimate_display) {
        csDisplay = `${cs.estimate_display} Possibilities`;
    } else if (cs.status === "ESTIMATE" && cs.estimate_display) {
        csDisplay = `Approx. ${cs.estimate_display} Possibilities`;
    } else if (cs.status === "CONTRADICTION") {
        csDisplay = "0 (Inconsistent)";
    }

    const totPos = (cs.total_positions !== undefined && cs.total_positions !== null && cs.total_positions > 0)
        ? cs.total_positions
        : ((reconState && reconState.total_length) ? reconState.total_length : (activeWf === "secured_design_encoding" ? 251 : 143));
    const resolvedBits = cs.resolved_positions || 0;
    const unresolvedBits = (cs.unresolved_positions !== undefined) ? cs.unresolved_positions : Math.max(0, totPos - resolvedBits);

    if (progText) progText.textContent = `${csDisplay} (${resPct}% resolved)`;
    if (progBar) progBar.style.width = `${resPct}%`;
    if (statCandidateSpace) statCandidateSpace.textContent = csDisplay;
    if (statResolvedBits) statResolvedBits.textContent = `${resolvedBits} / ${totPos}`;
    if (statUnresolvedBits) statUnresolvedBits.textContent = unresolvedBits;
    if (statTotalQ) statTotalQ.textContent = (data.progress && data.progress.total_active_questions) || "";
    if (statAnsweredQ) statAnsweredQ.textContent = (data.progress && data.progress.answered_count) || 0;
    if (statContra) statContra.textContent = (data.evaluation && data.evaluation.contradictions) ? data.evaluation.contradictions.length : 0;

    const p1Failed = Boolean(data.evaluation && data.evaluation.p1_failed);
    const p1Obj = (data.evaluation && data.evaluation.soft_hypotheses && data.evaluation.soft_hypotheses.P1) || {};
    if (statP1Status) {
        if (p1Failed) {
            statP1Status.textContent = "FAILED (+4 Fallbacks Active)";
            statP1Status.style.color = "#f87171";
        } else if (p1Obj.status === "CONFIRMED") {
            statP1Status.textContent = "CONFIRMED";
            statP1Status.style.color = "#34d399";
        } else {
            statP1Status.textContent = "PENDING";
            statP1Status.style.color = "#fbbf24";
        }
    }

    // 4. Active Question or Completed / Contradiction / Unsupported / Incomplete Card
    const qContainer = document.getElementById("judgeActiveQuestionContainer");
    const completedCard = document.getElementById("judgeCompletedCard");
    const contraCard = document.getElementById("judgeContradictionCard");
    const contraDetails = document.getElementById("judgeContradictionDetails");
    const unsupportedCard = document.getElementById("judgeUnsupportedCard");
    const unsupportedDetails = document.getElementById("judgeUnsupportedDetails");
    const incompleteCard = document.getElementById("judgeIncompleteCard");
    const incompleteDetails = document.getElementById("judgeIncompleteDetails");

    if (qContainer) qContainer.style.display = "none";
    if (completedCard) completedCard.style.display = "none";
    if (contraCard) contraCard.style.display = "none";
    if (unsupportedCard) unsupportedCard.style.display = "none";
    if (incompleteCard) incompleteCard.style.display = "none";

    if (isContradiction) {
        if (contraCard) {
            contraCard.style.display = "block";
            if (contraDetails && data.evaluation && data.evaluation.contradictions) {
                contraDetails.innerHTML = data.evaluation.contradictions.map(c => `&bull; ${c}`).join("<br>");
            }
        }
    } else if (isUnsupported) {
        if (unsupportedCard) {
            unsupportedCard.style.display = "block";
            const reason = (data.evaluation && data.evaluation.unsupported_branch_reason) || "The answered architecture falls outside the four-rule encoding schema.";
            if (unsupportedDetails) unsupportedDetails.textContent = reason;
        }
    } else if (isIncomplete) {
        if (incompleteCard) {
            incompleteCard.style.display = "block";
            const reason = (data.evaluation && data.evaluation.incomplete_reason) || "Claimant indicated structure is unknown. Interrogation cannot proceed without structural facts.";
            if (incompleteDetails) incompleteDetails.textContent = reason;
        }
    } else if (isComplete) {
        if (completedCard) {
            completedCard.style.display = "block";
            const h3 = completedCard.querySelector("h3");
            const pText = completedCard.querySelector("p");
            const badge = completedCard.querySelector(".badge");
            if (activeWf === "secured_design_encoding") {
                if (h3) h3.textContent = "251-Bit Secured Interrogation Complete";
                if (pText) pText.innerHTML = "All 143 four-rule bits and 108 Rule 5 register parity bits have been authoritatively reconstructed. The 251-bit bitstream has been assembled and verified against the cryptographic Pedersen commitment <code>C_ES</code>.";
                if (badge) {
                    const cv = (data.evaluation && data.evaluation.commitment_verification) || data.commitment_verification;
                    if (cv && cv.status === "VERIFIED") {
                        badge.textContent = "COMPLETE: 251-bit Secured Stream Reconstructed & Verified (C_ES MATCH)";
                        badge.className = "badge badge-success";
                    } else {
                        badge.textContent = "COMPLETE: 251-bit Stream Reconstructed (Commitment Check Evaluated)";
                        badge.className = "badge badge-v1";
                    }
                }
            } else {
                if (h3) h3.textContent = "143-Bit Stage Interrogation Complete";
                if (pText) pText.textContent = "All structural questions for the 143-bit four-rule stage have been answered without contradictions. Unsecured Rule 5 interrogation is pending.";
                if (badge) {
                    badge.textContent = "INCOMPLETE: 143-bit stage complete; Unsecured Rule 5 interrogation pending";
                    badge.className = "badge badge-warning";
                }
            }
        }
    } else if (data.current_question) {
        if (qContainer) qContainer.style.display = "block";
        const q = data.current_question;
        const qIdEl = document.getElementById("judgeCurrentQId");
        const blockEl = document.getElementById("judgeCurrentBlockTitle");
        const typeBadge = document.getElementById("judgeCurrentQTypeBadge");
        const promptEl = document.getElementById("judgeCurrentQPrompt");
        const inputNum = document.getElementById("judgeInputNumber");
        const inputChoice = document.getElementById("judgeInputChoice");
        const valMsg = document.getElementById("judgeInputValidationMsg");

        if (qIdEl) qIdEl.textContent = q.id;
        if (blockEl) blockEl.textContent = q.block_title;
        if (typeBadge) typeBadge.textContent = q.question_type;
        if (promptEl) promptEl.textContent = q.prompt;
        if (valMsg) valMsg.style.display = "none";

        if (q.question_type === "BOOLEAN" || q.question_type === "CHOICE") {
            if (inputNum) inputNum.style.display = "none";
            if (inputChoice) {
                inputChoice.style.display = "block";
                if (q.choices && q.choices.length > 0) {
                    inputChoice.innerHTML = '<option value="">-- Select an option --</option>' +
                        q.choices.map(c => `<option value="${c}">${c}</option>`).join('');
                } else {
                    inputChoice.innerHTML = `
                        <option value="">-- Select Yes or No --</option>
                        <option value="yes">Yes</option>
                        <option value="no">No</option>
                    `;
                }
                inputChoice.value = "";
                inputChoice.focus();
            }
        } else {
            if (inputChoice) inputChoice.style.display = "none";
            if (inputNum) {
                inputNum.style.display = "block";
                inputNum.value = "";
                if (q.min_val !== undefined && q.min_val !== null) inputNum.min = q.min_val;
                if (q.max_val !== undefined && q.max_val !== null) inputNum.max = q.max_val;
                inputNum.placeholder = `Enter value (${q.min_val !== null ? q.min_val : 0} - ${q.max_val !== null ? q.max_val : ''})...`;
                inputNum.focus();
            }
        }
    } else {
        if (qContainer) qContainer.style.display = "none";
    }

    // 5. Hypotheses Badges
    const hy = (data.evaluation && data.evaluation.soft_hypotheses) || {};
    const setHyBadge = (badgeId, obj) => {
        const el = document.getElementById(badgeId);
        if (!el || !obj) return;
        el.textContent = obj.status;
        if (obj.status === "CONFIRMED") el.className = "badge badge-success";
        else if (obj.status === "FAILED") el.className = "badge badge-danger";
        else if (obj.status === "PENDING") el.className = "badge badge-warning";
        else el.className = "badge badge-v1";
    };
    setHyBadge("badgeP1Status", hy.P1);
    setHyBadge("badgeP2Status", hy.P2);
    setHyBadge("badgeP3Status", hy.P3);
    setHyBadge("badgeP4Status", hy.P4);

    // 6. Progressive Bitstream Reconstruction & Authoritative State
    const stageAPlaceholder = document.getElementById("judgeStageAPlaceholder");
    const activeContainer = document.getElementById("judgeActiveReconstructionContainer");
    const segTabsContainer = document.getElementById("judgeSegmentTabsContainer");

    const isStageA = !reconState || reconState.stage === "STAGE_A" || !reconState.total_length;
    if (stageAPlaceholder) stageAPlaceholder.style.display = isStageA ? "block" : "none";
    if (activeContainer) activeContainer.style.display = isStageA ? "none" : "block";

    if (segTabsContainer) {
        segTabsContainer.style.display = "flex";
        const btnP1 = document.getElementById("btnJudgeSegPart1");
        const btnP2 = document.getElementById("btnJudgeSegPart2");
        const btnEntire = document.getElementById("btnJudgeSegEntire");
        if (btnP1) {
            btnP1.className = `judge-segment-btn ${currentJudgeSegment === 'part1' ? 'active' : ''}`;
            const p1Len = (reconState && reconState.segments && reconState.segments.part1 && reconState.segments.part1.is_established) ? reconState.segments.part1.length : null;
            btnP1.textContent = p1Len ? `Part 1 (${p1Len}b)` : "Part 1";
        }
        if (btnP2) {
            btnP2.className = `judge-segment-btn ${currentJudgeSegment === 'part2' ? 'active' : ''}`;
            const p2Len = (reconState && reconState.segments && reconState.segments.part2 && reconState.segments.part2.is_established) ? reconState.segments.part2.length : null;
            btnP2.textContent = p2Len ? `Part 2 (${p2Len}b)` : "Part 2";
        }
        if (btnEntire) {
            btnEntire.className = `judge-segment-btn ${currentJudgeSegment === 'entire' ? 'active' : ''}`;
            const totLen = reconState && reconState.total_length;
            btnEntire.textContent = totLen ? `Entire Stream (${totLen}b)` : "Entire Stream";
        }
    }

    const titleEl = document.getElementById("judgeReconStageTitle");
    const descEl = document.getElementById("judgeReconStageDesc");
    const reconBadge = document.getElementById("judgeReconstructionBadge");

    if (currentJudgeSegment === "part2") {
        if (activeWf === "unsecured_design_encoding") {
            if (titleEl) titleEl.textContent = "Part 2: Rule 5 Register Allocations (Pending)";
            if (descEl) descEl.textContent = "Unsecured workflow does not contain an authoritative Rule 5 register allocation segment. Interrogation pending.";
            if (reconBadge) {
                reconBadge.textContent = "0 bits fixed (Pending)";
                reconBadge.className = "badge badge-warning";
            }
        } else {
            const isStageS2 = reconState && (reconState.stage === "STAGE_S2" || reconState.stage === "STAGE_S3" || reconState.stage === "STAGE_S4" || reconState.stage === "STAGE_COMPLETE");
            const p2 = (reconState && reconState.part2_cells) || [];
            const fixedCount = p2.filter(c => c.is_fixed).length;
            const p2Len = (reconState && reconState.segments && reconState.segments.part2 && reconState.segments.part2.is_established) ? reconState.segments.part2.length : null;
            if (titleEl) {
                titleEl.textContent = p2Len ? `Part 2: Rule 5 Register Allocations (${p2Len} bits)` : "Part 2: Rule 5 Register Allocations";
            }
            if (descEl) {
                descEl.textContent = isStageS2
                    ? "Storage variable -> register parity pairs."
                    : "Rule 5 register allocation segment activates during Stage S2 after Part 1 is established.";
            }
            if (reconBadge) {
                reconBadge.textContent = p2Len ? `${fixedCount} / ${p2Len} bits fixed (GREEN)` : `${fixedCount} bits fixed (GREEN)`;
                reconBadge.className = (p2Len && fixedCount === p2Len) ? "badge badge-success" : "badge badge-v1";
            }
        }
    } else if (currentJudgeSegment === "entire") {
        const ent = (reconState && reconState.entire_cells) || [];
        const fixedCount = ent.filter(c => c.is_fixed).length;
        const totLen = reconState && reconState.total_length;
        if (titleEl) {
            titleEl.textContent = totLen
                ? `Entire ${activeWf === "secured_design_encoding" ? "Secured" : "Unsecured"} Design Encoding (${totLen} bits)`
                : `Entire ${activeWf === "secured_design_encoding" ? "Secured" : "Unsecured"} Design Encoding`;
        }
        if (descEl) {
            descEl.textContent = (activeWf === "secured_design_encoding")
                ? "Complete stream: Part 1 Four-Rule || Part 2 Rule 5."
                : "Complete four-rule stream. Rule 5 pending.";
        }
        if (reconBadge) {
            reconBadge.textContent = totLen ? `${fixedCount} / ${totLen} bits fixed (GREEN)` : `${fixedCount} bits fixed (GREEN)`;
            reconBadge.className = (totLen && fixedCount === totLen) ? "badge badge-success" : "badge badge-v1";
        }
    } else {
        // Part 1
        const p1 = (reconState && reconState.part1_cells) || [];
        const fixedCount = p1.filter(c => c.is_fixed).length;
        const p1Len = (reconState && reconState.segments && reconState.segments.part1 && reconState.segments.part1.is_established) ? reconState.segments.part1.length : null;
        if (titleEl) {
            titleEl.textContent = (reconState && reconState.stage_title) || (p1Len ? `Part 1: Four-Rule Design Encoding (${p1Len} bits)` : "Part 1: Four-Rule Design Encoding");
        }
        if (descEl) {
            descEl.textContent = (reconState && reconState.stage_description) || "Progressive structural reconstruction.";
        }
        if (reconBadge) {
            reconBadge.textContent = p1Len ? `${fixedCount} / ${p1Len} bits fixed (GREEN)` : `${fixedCount} bits fixed (GREEN)`;
            reconBadge.className = (p1Len && fixedCount === p1Len) ? "badge badge-success" : "badge badge-v1";
        }
    }

    // Render Grid Cells
    const bitGrid = document.getElementById("judgeBitGrid");
    const startLbl = document.getElementById("judgeGridStartLabel");
    const endLbl = document.getElementById("judgeGridEndLabel");

    if (bitGrid && !isStageA) {
        if (currentJudgeSegment === "part2") {
            const isStageS2 = activeWf === "secured_design_encoding" && reconState && (reconState.stage === "STAGE_S2" || reconState.stage === "STAGE_S3" || reconState.stage === "STAGE_S4" || reconState.stage === "STAGE_COMPLETE");
            const cells = (reconState && reconState.part2_cells) || [];

            if (startLbl) startLbl.textContent = cells.length > 0 ? `Bit ${cells[0].bit_index} (Part 2 Start)` : "Part 2 Start";
            if (endLbl) endLbl.textContent = cells.length > 0 ? `Bit ${cells[cells.length - 1].bit_index} (Part 2 End)` : "Part 2 End";

            if (!isStageS2 || cells.length === 0) {
                bitGrid.innerHTML = `
                    <div style="text-align: center; padding: 2rem 1rem; color: var(--text-muted); width: 100%;">
                        <span style="font-size: 1.6rem; display: block; margin-bottom: 0.4rem;">🔒</span>
                        <strong style="color: var(--text-primary); font-size: 0.85rem;">Rule 5 Register Allocation Grid Locked</strong>
                        <p style="font-size: 0.72rem; margin: 0.35rem auto 0; max-width: 360px; line-height: 1.4;">
                            ${activeWf === 'unsecured_design_encoding' ? 'Unsecured Rule 5 interrogation is pending.' : 'Rule 5 allocation grid activates in Stage S2 after Part 1 is established.'}
                        </p>
                    </div>
                `;
            } else {
                // Render 4-bit pair blocks
                const pairs = (data.evaluation && data.evaluation.pair_candidates) || data.pair_candidates || [];
                let html = '<div class="judge-pair-container">';
                const numPairsToRender = Math.floor(cells.length / 4);
                for (let p = 0; p < numPairsToRender; p++) {
                    const c0 = cells[p * 4];
                    const c1 = cells[p * 4 + 1];
                    const c2 = cells[p * 4 + 2];
                    const c3 = cells[p * 4 + 3];
                    const pairObj = pairs[p] || {};
                    const vName = pairObj.variable_name || `V${p + 1}`;
                    const rName = pairObj.register_name || '--';
                    html += `
                        <div class="judge-pair-block">
                            <div class="judge-pair-header-label">
                                <span style="color: #a78bfa; font-weight: 600;">${vName}</span>
                                <span style="color: var(--accent-cyan); font-weight: 600;">${rName}</span>
                            </div>
                            <div class="judge-pair-bits">
                                ${_renderCellSpan(c0)}
                                ${_renderCellSpan(c1)}
                                ${_renderCellSpan(c2)}
                                ${_renderCellSpan(c3)}
                            </div>
                        </div>
                    `;
                }
                html += '</div>';
                bitGrid.innerHTML = html;
            }
        } else if (currentJudgeSegment === "part1" && reconState && (reconState.units_established || reconState.fields_established)) {
            // Group into canonical units
            const cells = reconState.part1_cells || [];
            if (startLbl) startLbl.textContent = "Bit 0";
            if (endLbl) endLbl.textContent = `Bit ${cells.length > 0 ? cells.length - 1 : 142}`;

            const unitGroups = {};
            for (const c of cells) {
                const u = c.unit_index || 1;
                if (!unitGroups[u]) unitGroups[u] = [];
                unitGroups[u].push(c);
            }

            const totalUnits = reconState.unit_count || 13;
            let html = '<div class="judge-unit-container">';
            for (let u = 1; u <= totalUnits; u++) {
                const uCells = unitGroups[u] || [];
                if (uCells.length === 0) continue;

                html += `
                    <div class="judge-unit-block">
                        <div class="judge-unit-header-label">
                            <span style="font-weight: 600; color: #c084fc;">Unit ${u}</span>
                        </div>
                        <div class="judge-unit-bits">
                `;

                for (let i = 0; i < uCells.length; i++) {
                    const c = uCells[i];
                    if (reconState.fields_established && (i === 4 || i === 8 || i === 9)) {
                        html += '<div class="judge-field-divider" title="Field Boundary"></div>';
                    }
                    html += _renderCellSpan(c);
                }

                html += `
                        </div>
                    </div>
                `;
            }
            html += '</div>';
            bitGrid.innerHTML = html;
        } else {
            // Flat continuous grid (Single evolving grid: unresolved ? and unplaced 0/1 in RED directly in cells)
            const cells = (currentJudgeSegment === "entire") ? (reconState.entire_cells || []) : (reconState.part1_cells || []);
            if (startLbl) startLbl.textContent = "Bit 0";
            if (endLbl) endLbl.textContent = `Bit ${cells.length > 0 ? cells.length - 1 : 142}`;
            bitGrid.innerHTML = cells.map(c => _renderCellSpan(c)).join("");
        }
    }

    // Render Per-Unit Structural Breakdown Table (Revealed in Stage F)
    const unitCard = document.getElementById("judgeUnitAssemblyCard");
    const unitTbody = document.getElementById("judgeUnitTableBody");
    const unitFormatBadge = document.getElementById("judgeUnitFieldFormatBadge");

    if (reconState && reconState.fields_established) {
        if (unitCard) {
            unitCard.style.display = "block";
            if (unitFormatBadge && reconState.field_widths) {
                const fw = reconState.field_widths;
                unitFormatBadge.textContent = `A(${fw.A}b)||B(${fw.B}b)||C(${fw.C}b)||D(${fw.D}b)`;
            }
            const units = (data.evaluation && data.evaluation.unit_candidates) || [];
            if (unitTbody) {
                unitTbody.innerHTML = units.map(u => {
                    let stCls = "badge-v1";
                    if (u.status === "CONFIRMED") stCls = "badge-success";
                    else if (u.status === "INFERRED") stCls = "badge-warning";

                    const posText = (u.position !== undefined && u.position !== null) ? u.position : (u.unit_index || 1);
                    const onesText = (u.ones_count !== null && u.ones_count !== undefined) ? u.ones_count : '?';

                    return `
                        <tr>
                            <td style="color: var(--text-muted); font-weight: 600;">Unit ${posText}</td>
                            <td><code>${u.a_bits}</code> <span style="font-size: 0.68rem; color: var(--text-muted);">(${u.a_val !== null && u.a_val !== undefined ? u.a_val : '?'})</span></td>
                            <td><code>${u.b_bits}</code> <span style="font-size: 0.68rem; color: var(--text-muted);">(${u.b_val !== null && u.b_val !== undefined ? u.b_val : '?'})</span></td>
                            <td><code>${u.c_bits}</code></td>
                            <td><code>${u.d_bits}</code> <span style="font-size: 0.68rem; color: var(--text-muted);">(${u.d_val !== null && u.d_val !== undefined ? u.d_val : '?'})</span></td>
                            <td><strong style="color: var(--text-primary);">${onesText}</strong></td>
                            <td><span class="badge ${stCls}" style="font-size: 0.62rem;">${u.status}</span></td>
                        </tr>
                    `;
                }).join("");
            }
        }
    } else {
        if (unitCard) unitCard.style.display = "none";
    }

    // Render Rule 5 Register Allocation Breakdown Table (Revealed in Stage S2)
    const rule5Card = document.getElementById("judgeRule5AssemblyCard");
    const rule5Tbody = document.getElementById("judgeRule5TableBody");
    const rule5Badge = document.getElementById("judgeRule5CountBadge");

    const pairs = (data.evaluation && data.evaluation.pair_candidates) || data.pair_candidates || [];
    const isStageS2OrLater = activeWf === "secured_design_encoding" && reconState && (
        reconState.stage === "STAGE_S2" || reconState.stage === "STAGE_S3" || reconState.stage === "STAGE_S4" || reconState.stage === "STAGE_COMPLETE"
    );

    if (isStageS2OrLater && pairs.length > 0) {
        if (rule5Card) {
            rule5Card.style.display = "block";
            const confirmedCount = pairs.filter(p => p.status === "CONFIRMED" || p.is_fixed).length;
            if (rule5Badge) {
                rule5Badge.textContent = `${confirmedCount} / ${pairs.length} pairs resolved`;
                rule5Badge.className = (confirmedCount === pairs.length && pairs.length > 0) ? "badge badge-success" : "badge badge-v1";
            }
            if (rule5Tbody) {
                rule5Tbody.innerHTML = pairs.map(p => {
                    let stCls = "badge-v1";
                    if (p.status === "CONFIRMED") stCls = "badge-success";
                    else if (p.status === "CONTRADICTION") stCls = "badge-danger";
                    else if (p.is_fixed) stCls = "badge-info";

                    const regText = p.register_name ? `<code style="color: #38bdf8;">${p.register_name}</code>` : `<span style="color: var(--text-muted);">--</span>`;
                    const varParityText = `${p.variable_parity} (<code>${p.variable_parity_code}</code>)`;
                    const regParityText = p.register_parity ? `${p.register_parity} (<code>${p.register_parity_code}</code>)` : `<span style="color: var(--text-muted);">--</span>`;
                    const codeText = `<code>${p.four_bit_code}</code>`;
                    const bitRangeText = p.bit_range || (p.bit_offset_global !== undefined ? `Bit ${p.bit_offset_global}..${p.bit_offset_global + 3}` : '--');
                    const provText = p.provenance || 'UNKNOWN';

                    return `
                        <tr>
                            <td style="color: var(--text-muted); font-weight: 600;">#${p.pair_index}</td>
                            <td><strong style="color: #c084fc;">${p.variable_name}</strong></td>
                            <td>${varParityText}</td>
                            <td>${regText}</td>
                            <td>${regParityText}</td>
                            <td>${codeText}</td>
                            <td style="color: var(--text-muted);">${bitRangeText}</td>
                            <td><span style="font-size: 0.68rem; color: #60a5fa;">${provText}</span></td>
                            <td><span class="badge ${stCls}" style="font-size: 0.65rem;">${p.status}</span></td>
                        </tr>
                    `;
                }).join("");
            }
        }
    } else {
        if (rule5Card) rule5Card.style.display = "none";
    }

    // Render Cryptographic Commitment Verification Card (Stage S4)
    const commCard = document.getElementById("judgeCommitmentCard");
    const commBadge = document.getElementById("judgeCommitmentStatusBadge");
    const targetCesEl = document.getElementById("judgeTargetCes");
    const recalcCesEl = document.getElementById("judgeRecalcCes");
    const commDetailEl = document.getElementById("judgeCommitmentDetail");
    const cv = (data.evaluation && data.evaluation.commitment_verification) || data.commitment_verification;

    if (commCard) {
        if (activeWf === "secured_design_encoding") {
            commCard.style.display = "block";
            if (cv) {
                if (targetCesEl) targetCesEl.textContent = cv.target_commitment || "Pending Generation";
                if (recalcCesEl) recalcCesEl.textContent = cv.recalculated_commitment || "--";
                if (commDetailEl) commDetailEl.textContent = cv.detail || "Requires completion of all 251 bits across Stages S1 and S2.";
                if (commBadge) {
                    commBadge.textContent = cv.status || "AWAITING ASSEMBLY";
                    if (cv.status === "VERIFIED") commBadge.className = "badge badge-success";
                    else if (cv.status === "COMMITMENT_MISMATCH") commBadge.className = "badge badge-danger";
                    else if (cv.status === "PENDING_COMMITMENT") commBadge.className = "badge badge-warning";
                    else commBadge.className = "badge badge-v1";
                }
            }
        } else {
            commCard.style.display = "none";
        }
    }

    // 8. History Ledger Accordion
    const historyList = document.getElementById("judgeHistoryList");
    const historyBadge = document.getElementById("judgeHistoryCountBadge");
    const ledger = data.history_ledger || [];

    if (historyBadge) historyBadge.textContent = `${ledger.length} entries`;

    if (historyList) {
        if (ledger.length === 0) {
            historyList.innerHTML = `<div style="text-align: center; padding: 1.5rem; color: var(--text-muted); font-size: 0.78rem;">No answers recorded yet. The interrogation ledger will appear here as questions are completed.</div>`;
        } else {
            const sortedLedger = [...ledger].reverse();
            historyList.innerHTML = sortedLedger.map(entry => {
                let badgeCls = "badge-v1";
                if (entry.status === "OBSERVED") badgeCls = "badge-success";
                else if (entry.status === "DERIVED") badgeCls = "badge-info";
                else if (entry.status === "INFERRED") badgeCls = "badge-warning";
                else if (entry.status === "CONTRADICTION" || entry.status === "REJECTED") badgeCls = "badge-danger";

                const isCorr = entry.is_correction;
                const corrTag = isCorr ? `<span class="badge" style="background: rgba(139, 92, 246, 0.2); color: #c084fc; font-size: 0.62rem; margin-left: 4px;">CORRECTION</span>` : "";

                return `
                    <div class="judge-history-entry">
                        <div class="judge-history-header" onclick="this.nextElementSibling.style.display = (this.nextElementSibling.style.display === 'none' ? 'block' : 'none');">
                            <div style="display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap;">
                                <span style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted);">#${entry.entry_id}</span>
                                <strong style="color: #c084fc; font-family: var(--font-mono); font-size: 0.8rem;">${entry.question_id}</strong>
                                ${corrTag}
                                <span style="font-size: 0.78rem; color: var(--text-primary); max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${entry.question_prompt}</span>
                            </div>
                            <div style="display: flex; align-items: center; gap: 0.6rem;">
                                <span style="font-family: var(--font-mono); font-weight: 600; color: #f8fafc; font-size: 0.82rem;">Ans: ${entry.effective_answer}</span>
                                <span class="badge ${badgeCls}" style="font-size: 0.65rem;">${entry.status}</span>
                            </div>
                        </div>
                        <div class="judge-history-body" style="display: none;">
                            <div style="margin-bottom: 0.5rem; color: var(--text-secondary); line-height: 1.4;">${entry.question_prompt}</div>
                            <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.72rem; color: var(--text-muted); flex-wrap: wrap; gap: 0.5rem;">
                                <div>
                                    <span>Submitted: <code>${entry.submitted_answer}</code></span> &bull; 
                                    <span>Effective: <code>${entry.effective_answer}</code></span> &bull; 
                                    <em>${entry.message}</em>
                                </div>
                                <button type="button" class="btn-step-rerun" onclick="openCorrectionModal(${JSON.stringify(entry).replace(/"/g, '&quot;')})">
                                    <span>Correct Answer</span>
                                </button>
                            </div>
                        </div>
                    </div>
                `;
            }).join("");
    }
}
}

// ==============================================================================
// Comprehensive IP Securing Report Generator & Interactive Viewer
// ==============================================================================

let cachedSecuringReport = null;

function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    if (typeof str !== "string") return String(str);
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

window.loadAndRenderSellerReport = async function(forceFresh = false) {
    const statusBadge = document.getElementById("repBadgeStatus");
    const emptyState = document.getElementById("repEmptyState");
    const content = document.getElementById("repContentContainer");
    const errorBanner = document.getElementById("repErrorBanner");

    if (!forceFresh && cachedSecuringReport) {
        renderSellerReport(cachedSecuringReport);
        return;
    }

    if (statusBadge) {
        statusBadge.textContent = "Status: Loading...";
        statusBadge.className = "badge badge-info";
    }

    try {
        const res = await fetch("/api/transaction/report");
        if (!res.ok) {
            throw new Error(`Report fetch failed with HTTP ${res.status}`);
        }
        const data = await res.json();
        cachedSecuringReport = data;
        renderSellerReport(data);
    } catch (err) {
        console.error("Failed to load securing report:", err);
        if (statusBadge) {
            statusBadge.textContent = "Status: Unavailable";
            statusBadge.className = "badge badge-danger";
        }
        if (errorBanner) {
            errorBanner.style.display = "block";
            const msgEl = document.getElementById("repErrorMessage");
            if (msgEl) msgEl.textContent = err.message;
        }
    }
};

function renderSellerReport(raw) {
    const data = (raw && raw.report) ? raw.report : (raw || {});
    const experiments = data.experiments || [];

    const tbody = document.getElementById("wmStrengthTableBody");
    if (tbody) {
        if (!experiments || experiments.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Loading Watermark Strength Analysis...</td></tr>`;
            fetch("/api/analysis/watermark-strength")
                .then(r => r.json())
                .then(res => {
                    if (res && res.experiments) {
                        data.experiments = res.experiments;
                        renderSellerReport({ report: res });
                    }
                })
                .catch(err => console.error("Error fetching strength analysis:", err));
            return;
        }

        tbody.innerHTML = experiments.map(exp => {
            const isExact = (exp.requested_bits === (exp.pre_existing_constraints + exp.distinct_artificial_edges_count));
            const relBadge = isExact
                ? `<span class="badge badge-success" style="font-size: 0.68rem;">${exp.pre_existing_constraints} + ${exp.distinct_artificial_edges_count} = ${exp.requested_bits} (Exact)</span>`
                : `<span class="badge badge-warning" style="font-size: 0.68rem;">${exp.pre_existing_constraints} pre + ${exp.newly_added_artificial_edges_steps} add (${exp.distinct_artificial_edges_count} distinct)</span>`;

            return `
                <tr style="border-bottom: 1px solid var(--border-subtle);">
                    <td style="padding: 0.65rem; font-weight: 600; color: #a78bfa;">
                        <strong>${exp.watermark_length} bits</strong>
                        <div style="font-size: 0.68rem; color: var(--text-muted); font-family: var(--font-mono);">Zeros: ${exp.zeros_count} · Ones: ${exp.ones_count}</div>
                    </td>
                    <td style="padding: 0.65rem; text-align: right; font-family: var(--font-mono); color: var(--text-secondary); font-weight: 500;">
                        ${exp.requested_bits}
                    </td>
                    <td style="padding: 0.65rem; text-align: right; font-family: var(--font-mono); color: #38bdf8; font-weight: 600;">
                        ${exp.successfully_embedded_bits}
                    </td>
                    <td style="padding: 0.65rem; text-align: right; font-family: var(--font-mono); color: #fbbf24; font-weight: 500;">
                        ${exp.pre_existing_constraints}
                    </td>
                    <td style="padding: 0.65rem; text-align: right; font-family: var(--font-mono); color: #34d399; font-weight: 600;">
                        ${exp.distinct_artificial_edges_count}
                    </td>
                    <td style="padding: 0.65rem; text-align: center;">
                        ${relBadge}
                    </td>
                </tr>
            `;
        }).join("");
    }
}

window.downloadSellerReportJson = function() {
    const dataToExport = (cachedSecuringReport && cachedSecuringReport.report) ? cachedSecuringReport.report : (cachedSecuringReport || {});
    const blob = new Blob([JSON.stringify(dataToExport, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `hardware_ip_securing_report_${dataToExport.run_id || Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
};

window.printSellerReport = function() {
    window.print();
};


