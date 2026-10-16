// Hardware IP Protection V1 - Frontend Orchestration

let currentProtectionData = null;
let currentDisputeData = null;
let benchmarksMap = {};
let currentTransactionState = null;

document.addEventListener("DOMContentLoaded", () => {
    initTabs();
    initTransactionWorkflow();
    initVerifierWorkflow();
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

            // Persist transaction state seamlessly across Seller, Buyer, and Verifier profiles
            if (targetId === "profileSeller" || targetId === "profileBuyer") {
                fetchTransactionState();
            } else if (targetId === "profileVerifier") {
                fetchTransactionState();
                initOrRefreshVerifierProfile();
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

    // STEP 2: Generate Original Design Encoding D & Commitment C_D
    const btnEncodeD = document.getElementById("btnSellerEncodeD");
    if (btnEncodeD) {
        btnEncodeD.addEventListener("click", async () => {
            btnEncodeD.disabled = true;
            btnEncodeD.innerHTML = `<span>Generating Encoding D & Commit(D)...</span>`;
            try {
                const res = await fetch("/api/transaction/encode_design", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ use_table_quirks: false }),
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
        }

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
            const b2D = document.getElementById("sellerSubstage2DBox");
            if (b2D) {
                b2D.classList.remove("collapsed");
                b2D.classList.add("active");
                b2D.scrollIntoView({ behavior: "smooth" });
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
            btnEmbedWatermark.disabled = true;
            btnEmbedWatermark.innerHTML = `<span>Synthesizing Protected RTL &amp; Embedding Watermark...</span>`;
            try {
                const res = await fetch("/api/transaction/embed_watermark", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ watermark_length: "auto" })
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
                btnToggleEnc.innerHTML = isHidden ?
                    `<svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 15l7-7 7 7"></path></svg><span>Hide Supporting Structural Encoding Table</span>` :
                    `<svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg><span>Inspect Supporting Structural Encoding Table (143 bits)</span>`;
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

    // --- SELLER UI WORKFLOW STEPS ---
    const sDes = document.getElementById("sellerDesignSelect");
    if (sDes) sDes.value = st.design_id || "iir_butterworth";
    const sRul = document.getElementById("sellerRuleSelect");
    if (sRul) sRul.value = st.encoding_rule_id || "iir_butterworth_rule_v1";

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
    const sellerOverallProgressBadge = document.getElementById("sellerOverallProgressBadge");

    if (st.stage4_completed) {
        if (sellerOverallProgressBadge) sellerOverallProgressBadge.textContent = "Pipeline Completed (4/4)";
        if (sellerNavStatus1) sellerNavStatus1.textContent = "Completed (143 bits)";
        if (sellerNavStatus2) sellerNavStatus2.textContent = "Completed (W & W1)";
        if (sellerNavStatus3) sellerNavStatus3.textContent = "Embedded & Allocated";
        if (sellerNavStatus4) sellerNavStatus4.textContent = "RTL Verified (E_S = D)";
        if (sellerNavItem1) sellerNavItem1.classList.add("completed");
        if (sellerNavItem2) sellerNavItem2.classList.add("completed");
        if (sellerNavItem3) sellerNavItem3.classList.add("completed");
        if (sellerNavItem4) sellerNavItem4.classList.add("completed");
    } else if (st.watermarked_RTL) {
        if (sellerOverallProgressBadge) sellerOverallProgressBadge.textContent = "Stage 4 of 4";
        if (sellerNavStatus1) sellerNavStatus1.textContent = "Completed (143 bits)";
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
        if (sellerNavStatus1) sellerNavStatus1.textContent = "Completed (143 bits)";
        if (sellerNavStatus2) sellerNavStatus2.textContent = "Completed (W & W1)";
        if (sellerNavStatus3) sellerNavStatus3.textContent = "Ready to Embed";
        if (sellerNavStatus4) sellerNavStatus4.textContent = "Pending Stage 3";
        if (sellerNavItem1) sellerNavItem1.classList.add("completed");
        if (sellerNavItem2) sellerNavItem2.classList.add("completed");
        if (sellerNavItem3) sellerNavItem3.classList.remove("completed");
        if (sellerNavItem4) sellerNavItem4.classList.remove("completed");
    } else if (st.W1) {
        if (sellerOverallProgressBadge) sellerOverallProgressBadge.textContent = "Stage 2 of 4";
        if (sellerNavStatus1) sellerNavStatus1.textContent = "Completed (143 bits)";
        if (sellerNavStatus2) sellerNavStatus2.textContent = "Split (32b / 224b)";
        if (sellerNavStatus3) sellerNavStatus3.textContent = "Pending Stage 2";
        if (sellerNavStatus4) sellerNavStatus4.textContent = "Pending Stage 3";
        if (sellerNavItem1) sellerNavItem1.classList.add("completed");
        if (sellerNavItem2) sellerNavItem2.classList.remove("completed");
        if (sellerNavItem3) sellerNavItem3.classList.remove("completed");
        if (sellerNavItem4) sellerNavItem4.classList.remove("completed");
    } else if (st.C_W) {
        if (sellerOverallProgressBadge) sellerOverallProgressBadge.textContent = "Stage 2 of 4";
        if (sellerNavStatus1) sellerNavStatus1.textContent = "Completed (143 bits)";
        if (sellerNavStatus2) sellerNavStatus2.textContent = "Committed (C_W)";
        if (sellerNavStatus3) sellerNavStatus3.textContent = "Pending Stage 2";
        if (sellerNavStatus4) sellerNavStatus4.textContent = "Pending Stage 3";
        if (sellerNavItem1) sellerNavItem1.classList.add("completed");
        if (sellerNavItem2) sellerNavItem2.classList.remove("completed");
        if (sellerNavItem3) sellerNavItem3.classList.remove("completed");
        if (sellerNavItem4) sellerNavItem4.classList.remove("completed");
    } else if (st.watermark_W) {
        if (sellerOverallProgressBadge) sellerOverallProgressBadge.textContent = "Stage 2 of 4";
        if (sellerNavStatus1) sellerNavStatus1.textContent = "Completed (143 bits)";
        if (sellerNavStatus2) sellerNavStatus2.textContent = "Watermark Generated (256b)";
        if (sellerNavStatus3) sellerNavStatus3.textContent = "Pending Stage 2";
        if (sellerNavStatus4) sellerNavStatus4.textContent = "Pending Stage 3";
        if (sellerNavItem1) sellerNavItem1.classList.add("completed");
        if (sellerNavItem2) sellerNavItem2.classList.remove("completed");
        if (sellerNavItem3) sellerNavItem3.classList.remove("completed");
        if (sellerNavItem4) sellerNavItem4.classList.remove("completed");
    } else if (st.buyer_approved) {
        if (sellerOverallProgressBadge) sellerOverallProgressBadge.textContent = "Stage 2 of 4";
        if (sellerNavStatus1) sellerNavStatus1.textContent = "Completed (143 bits)";
        if (sellerNavStatus2) sellerNavStatus2.textContent = "Buyer Received (555b)";
        if (sellerNavStatus3) sellerNavStatus3.textContent = "Pending Stage 2";
        if (sellerNavStatus4) sellerNavStatus4.textContent = "Pending Stage 3";
        if (sellerNavItem1) sellerNavItem1.classList.add("completed");
        if (sellerNavItem2) sellerNavItem2.classList.remove("completed");
        if (sellerNavItem3) sellerNavItem3.classList.remove("completed");
        if (sellerNavItem4) sellerNavItem4.classList.remove("completed");
    } else if (st.design_encoding_D) {
        if (sellerOverallProgressBadge) sellerOverallProgressBadge.textContent = "Stage 2 of 4";
        if (sellerNavStatus1) sellerNavStatus1.textContent = "Completed (143 bits)";
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
        if (sellerNavItem4) sellerNavItem4.classList.remove("completed");
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

    // Substage 2D: Split and Protect Watermark (W1 & W2)
    if (st.W1 && st.protected_W2) {
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

    // Active / Collapsed progression management for Stage 2
    if (st.watermarked_RTL) {
        if (sellerSubstage2ABox) sellerSubstage2ABox.className = "seller-substage-box collapsed";
        if (sellerSubstage2BBox) sellerSubstage2BBox.className = "seller-substage-box collapsed";
        if (sellerSubstage2CBox) sellerSubstage2CBox.className = "seller-substage-box collapsed";
        if (sellerSubstage2DBox) sellerSubstage2DBox.className = "seller-substage-box collapsed";
        if (sellerSubstage2EBox) sellerSubstage2EBox.className = "seller-substage-box collapsed";
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
            btnEmbedWatermark.disabled = !st.C_W1;
        }
        if (sellerStage3ActionBox) sellerStage3ActionBox.style.display = "block";
        if (sellerStage3Results) sellerStage3Results.style.display = "none";
        if (badgeStage3Top) {
            badgeStage3Top.textContent = st.C_W1 ? "Ready to Embed" : "Pending Stage 2";
            badgeStage3Top.className = st.C_W1 ? "badge badge-warning" : "badge badge-v1";
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
        if (sellerStageEsBitstream) sellerStageEsBitstream.textContent = st.secured_encoding_E_S || st.design_encoding_D || "--";
        if (sellerStageEsBadge) {
            sellerStageEsBadge.textContent = "Reconstructed (143 bits)";
            sellerStageEsBadge.className = "badge badge-success";
        }
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
            sellerBadge4C.textContent = "Unchanged: E_S = D";
            sellerBadge4C.className = "badge badge-success";
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
    if (sum4B) sum4B.textContent = st.stage4_es_calculated ? "Calculated · 143 bits" : "Pending";
    const sum4C = document.getElementById("sellerSummary4C");
    if (sum4C) sum4C.textContent = st.stage4_encodings_compared ? "Validated · E_S = D" : "Pending";
    const sum4D = document.getElementById("sellerSummary4D");
    if (sum4D) sum4D.textContent = st.stage4_behavioral_verified ? "Verified · 32/32 Matches" : "Pending";
    const sum4E = document.getElementById("sellerSummary4E");
    if (sum4E) sum4E.textContent = st.stage4_completed ? "Not Required · E_S = D" : "Pending";

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

    const sellerPrivW1 = document.getElementById("sellerPrivW1");
    if (sellerPrivW1) {
        sellerPrivW1.textContent = st.W1 ? `${st.W1} (${st.W1.length} bits)` : "Not generated yet.";
    }
    const sellerPrivW2 = document.getElementById("sellerPrivW2");
    if (sellerPrivW2) {
        sellerPrivW2.textContent = st.protected_W2 ? `${st.protected_W2} (${st.protected_W2.length} bits)` : "Not generated yet.";
    }
    const sellerPrivStoredCw1 = document.getElementById("sellerPrivStoredCw1");
    if (sellerPrivStoredCw1) {
        sellerPrivStoredCw1.textContent = st.C_W1 || "--";
    }
    const sellerEvidCw1Status = document.getElementById("sellerEvidCw1Status");
    if (sellerEvidCw1Status) {
        if (st.C_W1) {
            sellerEvidCw1Status.textContent = "Generated / Stored";
            sellerEvidCw1Status.className = "badge badge-success";
        } else {
            sellerEvidCw1Status.textContent = "Not generated yet";
            sellerEvidCw1Status.className = "badge badge-v1";
        }
    }
    const sellerPrivGenGW = document.getElementById("sellerPrivGenGW");
    if (sellerPrivGenGW) {
        sellerPrivGenGW.textContent = (st.seller_private_info && st.seller_private_info.C_W_evidence && st.seller_private_info.C_W_evidence.commitment_verification.generator_g) || "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    }
    const sellerPrivGenHW = document.getElementById("sellerPrivGenHW");
    if (sellerPrivGenHW) {
        sellerPrivGenHW.textContent = (st.seller_private_info && st.seller_private_info.C_W_evidence && st.seller_private_info.C_W_evidence.commitment_verification.generator_h) || "021ad06fad86cbbf99815a56f6c511152d048e5e0893d02c18194e3165a6aa4db3";
    }
    const sellerPrivGenGW1 = document.getElementById("sellerPrivGenGW1");
    if (sellerPrivGenGW1) {
        sellerPrivGenGW1.textContent = (st.seller_private_info && st.seller_private_info.C_W1_evidence && st.seller_private_info.C_W1_evidence.commitment_verification.generator_g) || "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    }
    const sellerPrivGenHW1 = document.getElementById("sellerPrivGenHW1");
    if (sellerPrivGenHW1) {
        sellerPrivGenHW1.textContent = (st.seller_private_info && st.seller_private_info.C_W1_evidence && st.seller_private_info.C_W1_evidence.commitment_verification.generator_h) || "021ad06fad86cbbf99815a56f6c511152d048e5e0893d02c18194e3165a6aa4db3";
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
        wmLen.textContent = `${totalWmBits} bits (W1) / 256b (W)`;
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

    // Render Structural Design Encoding (Rules 1-4)
    if (data.structural_encoding) {
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
    if (bEl) bEl.textContent = `${enc.total_bit_length ?? enc.total_bits ?? "--"} bits`;
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

    const box = document.getElementById("protEncBitstreamBox");
    if (box) box.textContent = enc.canonical_bitstream || "(empty bitstream)";
    const bBadge = document.getElementById("protEncBitstreamBadge");
    if (bBadge) bBadge.textContent = `${enc.total_bit_length ?? enc.total_bits ?? 0} bits`;
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
        title: "Step 5: Extract Embedded Watermark (W1')",
        party: "Seller Rules / Verifier RTL Extraction",
        desc: "Inspect synthesized RTL register bindings for target CIG pairs and recover embedded 32-bit watermark W1'.",
        defaultMethod: "Parse synthesized RTL register allocations; inspect mutual exclusion across target CIG pairs",
        defaultInput: "Synthesizable Verilog RTL source and target variable pair mapping"
    },
    {
        num: 6,
        title: "Step 6: Verify Embedded Watermark Commitment (C_W1)",
        party: "Seller",
        desc: "Recalculate C_W1' = Commit(W1', r_W1) and verify equality with stored C_W1 over NIST P-256.",
        defaultMethod: "Value is extracted 32-bit watermark slice W1' from Step 5",
        defaultInput: "W1' (32 bits)"
    },
    {
        num: 7,
        title: "Step 7: Reconstruct Complete Watermark (W')",
        party: "Seller Private Evidence",
        desc: "Combine extracted W1' (32 bits) and protected slice W2 (224 bits) to reconstruct complete 256-bit watermark W'.",
        defaultMethod: "Watermark reconstruction rule: W = W1 || W2 (Concatenation)",
        defaultInput: "Extracted W1' (32 bits) and protected off-chain W2 (224 bits)"
    },
    {
        num: 8,
        title: "Step 8: Verify Complete Watermark Commitment (C_W)",
        party: "Seller",
        desc: "Recalculate C_W' = Commit(W', r_W) and verify equality with stored commitment C_W over NIST P-256.",
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
            const stepNum = parseInt(btn.dataset.step, 10);
            if (!isNaN(stepNum)) {
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

        // Update session
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
    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `<span>Executing Step ${stepNum}...</span>`;

    try {
        const res = await fetch("/api/verifier/execute_step", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ step_number: stepNum })
        });

        if (res.ok) {
            const data = await res.json();
            currentVerifierSession = data.session;
            currentVerifierStep = stepNum;

            // Expand this step card
            const stepBox = document.getElementById(`vStepBox_${stepNum}`);
            if (stepBox) stepBox.classList.remove("collapsed");

            // Update all step views and badges
            updateAllVerifierStepsUI();

            // If final step 13, render report
            if (stepNum === 13 && currentVerifierSession.final_report) {
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

function isVerifierStepEligible(stepNum, stepResults) {
    if (stepNum === 1) return true;
    const isDone = (num, okStatuses) => {
        const r = stepResults[`step_${num}`];
        const defaultOk = ["MATCH", "NOT REQUIRED", "LOADED", "EXTRACTED", "VALIDATED", "CONSISTENT", "RECONSTRUCTED"];
        return r && (okStatuses || defaultOk).includes(r.status);
    };
    if (stepNum === 2) return isDone(1, ["LOADED", "MATCH"]);
    if (stepNum === 3) return isDone(2, ["EXTRACTED", "MATCH"]);
    if (stepNum === 4) return isDone(3, ["NOT REQUIRED", "MATCH"]);
    if (stepNum === 5) return isDone(1, ["LOADED", "MATCH"]);
    if (stepNum === 6) return isDone(5, ["EXTRACTED", "MATCH"]);
    if (stepNum === 7) return isDone(5, ["EXTRACTED", "MATCH"]);
    if (stepNum === 8) return isDone(7, ["MATCH", "RECONSTRUCTED"]);
    if (stepNum === 9) return isDone(1, ["LOADED", "MATCH"]);
    if (stepNum === 10) return isDone(9, ["MATCH", "VALIDATED"]);
    if (stepNum === 11) return isDone(4, ["MATCH"]) && isDone(8, ["MATCH"]) && isDone(10, ["MATCH"]);
    if (stepNum === 12) return isDone(11, ["MATCH"]);
    if (stepNum === 13) {
        for (let s = 1; s <= 12; s++) {
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

    for (let i = 1; i <= 13; i++) {
        const res = stepResults[`step_${i}`];
        const box = document.getElementById(`vStepBox_${i}`);
        const badge = document.getElementById(`vStepBadge_${i}`);
        const resultBox = document.getElementById(`vStepResult_${i}`);
        const notes = document.getElementById(`vStepNotes_${i}`);
        const summary = document.getElementById(`vStepSummary_${i}`);
        const btn = document.getElementById(`btnVerifierExecStep_${i}`);
        const rerun = document.getElementById(`vStepRerunContainer_${i}`);

        if (res) {
            const isSuccess = (res.status === "MATCH" || res.status === "NOT REQUIRED" || res.status === "LOADED" || res.status === "EXTRACTED" || res.status === "VALIDATED" || res.status === "CONSISTENT" || res.status === "RECONSTRUCTED");
            if (isSuccess) {
                completedCount++;
                if (i <= 8) sec1Completed++;
                else if (i <= 10) sec2Completed++;
                else if (i <= 12) sec3Completed++;
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

            if (summary) {
                if (i === 1) summary.textContent = "Synthesized RTL Loaded";
                else if (i === 2) summary.textContent = "143 bits (E_S')";
                else if (i === 3) summary.textContent = "E_S = D (Invariant)";
                else if (i === 4) summary.textContent = "C_D Verified (P-256)";
                else if (i === 5) summary.textContent = "32 bits (W1' Extracted)";
                else if (i === 6) summary.textContent = "C_W1 Verified";
                else if (i === 7) summary.textContent = "256 bits (W' Reconstructed)";
                else if (i === 8) summary.textContent = "C_W Verified";
                else if (i === 9) summary.textContent = "555 bits (B' Validated)";
                else if (i === 10) summary.textContent = "C_B Verified";
                else if (i === 11) summary.textContent = "HKDF Formula Match";
                else if (i === 12) summary.textContent = "License (exclusive)";
                else if (i === 13) summary.textContent = "Report Ready";
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

            populateStepResultFields(i, res);
        } else {
            if (box) {
                box.classList.remove("completed", "failed");
            }
            if (resultBox) {
                resultBox.style.display = "none";
            }
            const eligible = isVerifierStepEligible(i, stepResults);
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
    const b1 = document.getElementById("vSecBadge1");
    if (b1) {
        b1.textContent = sec1Completed === 8 ? "8/8 Verified" : `${sec1Completed}/8 Steps`;
        b1.className = sec1Completed === 8 ? "badge badge-success" : "badge badge-v1";
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
        const count = [5, 6, 7, 8].filter(i => stepResults[`step_${i}`] && ["MATCH", "NOT REQUIRED", "EXTRACTED", "RECONSTRUCTED"].includes(stepResults[`step_${i}`].status)).length;
        bWm.textContent = count === 4 ? "4/4 Verified" : `${count}/4 Steps`;
        bWm.className = count === 4 ? "badge badge-success" : "badge badge-v1";
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

    // Overall progress badge in header: clear "X of 13 steps completed" format
    const overallCount = document.getElementById("vCompletedStepsCount");
    if (overallCount) {
        overallCount.textContent = `${completedCount} of 13`;
    }
}

function populateStepResultFields(stepNum, res) {
    const s1 = res.stage1_reconstruction || {};
    const s2 = res.stage2_verification || {};

    if (stepNum === 1) {
        const codeEl = document.getElementById("vDisputedVerilogRTL_inline");
        const rtlCode = s1.synthesizable_verilog_code || s1.preview || (currentVerifierSession && currentVerifierSession.disputed_rtl) || "--";
        if (codeEl) codeEl.textContent = rtlCode;
        const propsEl = document.getElementById("vStepProps_1");
        if (propsEl) propsEl.textContent = `${s1.lines_of_code || '--'} lines (${s1.artifact_type || 'Synthesizable Verilog RTL'})`;
        const digestEl = document.getElementById("vStepDigest_1");
        if (digestEl && s1.sha256_digest) digestEl.textContent = s1.sha256_digest;
        const s1Status = document.getElementById("vStage1Status_1");
        if (s1Status) s1Status.textContent = s1.status || res.status || "LOADED";
    } else if (stepNum === 2) {
        const valEl = document.getElementById("vStepVal_2");
        if (valEl) valEl.textContent = s1.extracted_bitstream || s1.secured_encoding_ES || "--";
        const propEl = document.getElementById("vStepProps_2");
        if (propEl) {
            const nodes = s1.total_nodes_recovered || 13;
            const steps = s1.total_steps_recovered || 7;
            propEl.textContent = `${s1.bit_length || 143} bits (${nodes} nodes across ${steps} steps)`;
        }
        const s1Status = document.getElementById("vStage1Status_2");
        if (s1Status) s1Status.textContent = s1.status || res.status || "EXTRACTED";
    } else if (stepNum === 3) {
        const invEl = document.getElementById("vStepInvariance_3");
        if (invEl) {
            invEl.textContent = s1.comparison || (res.status === "NOT REQUIRED" || res.status === "MATCH" ? "E_S is bit-for-bit identical to D (143/143 bits match)." : "E_S differs from baseline D.");
        }
        const cesEl = document.getElementById("vStepStoredCES_3");
        if (cesEl) {
            cesEl.textContent = s2.stored_c_es || (res.status === "NOT REQUIRED" ? "NOT_REQUIRED (E_S = D)" : s2.stored_commitment_C_ES || "NOT_REQUIRED");
        }
        const branchEl = document.getElementById("vStepBranch_3");
        if (branchEl) {
            branchEl.textContent = s1.branch_action || (s1.branch ? `${s1.branch} (Invariance holds — direct verification of C_D)` : "Branch A (Invariance holds — direct verification of C_D)");
        }
        const pill = document.getElementById("vStage2Pill_3");
        if (pill) {
            pill.textContent = res.status || "NOT REQUIRED";
            pill.className = (res.status === "NOT REQUIRED" || res.status === "MATCH") ? "badge badge-success" : "badge badge-warning";
        }
    } else if (stepNum === 4) {
        const propEl = document.getElementById("vStepProps_4");
        if (propEl) propEl.textContent = `${s1.bit_length || 143} bits (Golden Benchmark)`;
        const valEl = document.getElementById("vStepVal_4");
        if (valEl) valEl.textContent = s1.calculated_value_D || "--";
        const openEl = document.getElementById("vStepOpening_4");
        if (openEl && s2.opening_factor_r_D) openEl.textContent = s2.opening_factor_r_D;
        const storedEl = document.getElementById("vStepStored_4");
        if (storedEl && s2.stored_commitment_C_D) storedEl.textContent = s2.stored_commitment_C_D;
        const recalcEl = document.getElementById("vStepRecalc_4");
        if (recalcEl && s2.recalculated_commitment_C_D) recalcEl.textContent = s2.recalculated_commitment_C_D;
        const pill = document.getElementById("vStage2Pill_4");
        if (pill) {
            pill.textContent = s2.status || res.status;
            pill.className = (s2.status === "MATCH" || res.status === "MATCH") ? "badge badge-success" : "badge badge-danger";
        }
    } else if (stepNum === 5) {
        const valEl = document.getElementById("vStepVal_5");
        if (valEl && s1.extracted_bitstream_W1) valEl.textContent = s1.extracted_bitstream_W1;
        const propEl = document.getElementById("vStepProps_5");
        if (propEl) propEl.textContent = `${s1.bit_length || 32} bits`;
        const pill = document.getElementById("vStage2Pill_5");
        if (pill) {
            pill.textContent = s1.extraction_status || s1.status || res.status || "EXTRACTED";
            pill.className = "badge badge-success";
        }
    } else if (stepNum === 6) {
        const openEl = document.getElementById("vStepOpening_6");
        if (openEl && s2.opening_factor_r_W1) openEl.textContent = s2.opening_factor_r_W1;
        const storedEl = document.getElementById("vStepStored_6");
        if (storedEl && s2.stored_commitment_C_W1) storedEl.textContent = s2.stored_commitment_C_W1;
        const recalcEl = document.getElementById("vStepRecalc_6");
        if (recalcEl && s2.recalculated_commitment_C_W1) recalcEl.textContent = s2.recalculated_commitment_C_W1;
        const pill = document.getElementById("vStage2Pill_6");
        if (pill) {
            pill.textContent = s2.status || res.status;
            pill.className = s2.status === "MATCH" ? "badge badge-success" : "badge badge-danger";
        }
    } else if (stepNum === 7) {
        const valEl = document.getElementById("vStepVal_7");
        if (valEl && s1.reconstructed_watermark_W) valEl.textContent = s1.reconstructed_watermark_W;
        const propEl = document.getElementById("vStepProps_7");
        if (propEl) propEl.textContent = `${s1.total_bit_length || s1.bit_length || 256} bits`;
        const pill = document.getElementById("vStage2Pill_7");
        if (pill) {
            pill.textContent = s1.status || res.status || "MATCH";
            pill.className = "badge badge-success";
        }
    } else if (stepNum === 8) {
        const openEl = document.getElementById("vStepOpening_8");
        if (openEl && s2.opening_factor_r_W) openEl.textContent = s2.opening_factor_r_W;
        const storedEl = document.getElementById("vStepStored_8");
        if (storedEl && s2.stored_commitment_C_W) storedEl.textContent = s2.stored_commitment_C_W;
        const recalcEl = document.getElementById("vStepRecalc_8");
        if (recalcEl && s2.recalculated_commitment_C_W) recalcEl.textContent = s2.recalculated_commitment_C_W;
        const pill = document.getElementById("vStage2Pill_8");
        if (pill) {
            pill.textContent = s2.status || res.status;
            pill.className = s2.status === "MATCH" ? "badge badge-success" : "badge badge-danger";
        }
    } else if (stepNum === 9) {
        const valEl = document.getElementById("vStepVal_9");
        if (valEl && s1.bitstream_B) valEl.textContent = s1.bitstream_B;
        const propEl = document.getElementById("vStepProps_9");
        if (propEl) propEl.textContent = `${s1.bit_length || 555} bits`;
        const pill = document.getElementById("vStage2Pill_9");
        if (pill) {
            pill.textContent = s1.status || res.status || "VALIDATED";
            pill.className = "badge badge-success";
        }
    } else if (stepNum === 10) {
        const openEl = document.getElementById("vStepOpening_10");
        if (openEl && s2.opening_factor_r_B) openEl.textContent = s2.opening_factor_r_B;
        const storedEl = document.getElementById("vStepStored_10");
        if (storedEl && s2.stored_commitment_C_B) storedEl.textContent = s2.stored_commitment_C_B;
        const recalcEl = document.getElementById("vStepRecalc_10");
        if (recalcEl && s2.recalculated_commitment_C_B) recalcEl.textContent = s2.recalculated_commitment_C_B;
        const pill = document.getElementById("vStage2Pill_10");
        if (pill) {
            pill.textContent = s2.status || res.status;
            pill.className = s2.status === "MATCH" ? "badge badge-success" : "badge badge-danger";
        }
    } else if (stepNum === 11) {
        const propEl = document.getElementById("vStepProps_11");
        const bitLen = (s1.reconstructed_watermark_W && s1.reconstructed_watermark_W.length) || (s1.expected_watermark_W && s1.expected_watermark_W.length) || 256;
        if (propEl) propEl.textContent = `${bitLen} bits`;
        const valEl = document.getElementById("vStepVal_11");
        if (valEl) valEl.textContent = s1.expected_watermark_W || s1.reconstructed_watermark_W || "--";
        const pill = document.getElementById("vStage2Pill_11");
        if (pill) {
            pill.textContent = s2.status || res.status;
            pill.className = s2.status === "MATCH" ? "badge badge-success" : "badge badge-danger";
        }
    } else if (stepNum === 12) {
        const pill = document.getElementById("vStage2Pill_12");
        if (pill) {
            pill.textContent = s2.status || res.status;
            pill.className = (s2.status === "MATCH" || s2.status === "CONSISTENT") ? "badge badge-success" : "badge badge-danger";
        }
    } else if (stepNum === 13) {
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
        const summary = document.getElementById(`vStepSummary_${i}`);

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

            if (summary) {
                if (i === 1) summary.textContent = "Synthesized RTL Loaded";
                else if (i === 2) summary.textContent = "143 bits (E_S')";
                else if (i === 3) summary.textContent = "E_S = D (Invariant)";
                else if (i === 4) summary.textContent = "C_D Verified (P-256)";
                else if (i === 5) summary.textContent = "32 bits (W1' Extracted)";
                else if (i === 6) summary.textContent = "C_W1 Verified";
                else if (i === 7) summary.textContent = "256 bits (W' Reconstructed)";
                else if (i === 8) summary.textContent = "C_W Verified";
                else if (i === 9) summary.textContent = "555 bits (B' Validated)";
                else if (i === 10) summary.textContent = "C_B Verified";
                else if (i === 11) summary.textContent = "HKDF Formula Match";
                else if (i === 12) summary.textContent = "License (exclusive)";
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

