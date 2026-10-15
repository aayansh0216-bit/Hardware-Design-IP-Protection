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

    // STEP 4: Continue Watermark Workflow
    const btnContinueWm = document.getElementById("btnSellerContinueWatermark");
    if (btnContinueWm) {
        btnContinueWm.addEventListener("click", async () => {
            btnContinueWm.disabled = true;
            btnContinueWm.innerHTML = `<span>Embedding Watermark into RTL...</span>`;
            try {
                const res = await fetch("/api/transaction/continue_watermark", {
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
                    if (data.state.pipeline_result) {
                        currentProtectionData = data.state.pipeline_result;
                        renderProtectionResults(data.state.pipeline_result);
                        syncToDisputeTab(data.state.pipeline_result);
                    }
                } else {
                    const err = await res.json();
                    alert(`Watermark embedding failed: ${err.detail || "Server error"}`);
                }
            } catch (err) {
                console.error("Failed to continue watermark workflow:", err);
                alert("Network error executing watermark workflow.");
            } finally {
                btnContinueWm.disabled = false;
                btnContinueWm.innerHTML = `
                    <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
                    </svg>
                    <span>Continue Existing Watermark Workflow</span>`;
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

    if (st.design_encoding_D) {
        if (badgeStep2) {
            badgeStep2.textContent = `Generated (${st.design_encoding_D.length} bits)`;
            badgeStep2.className = "badge badge-success";
        }
        if (sellerSummaryBox) sellerSummaryBox.style.display = "block";
        if (sellerDLength) sellerDLength.textContent = `${st.design_encoding_D.length} bits`;
        if (sellerCD) sellerCD.textContent = st.C_D || "--";
        if (btnReqBuyer && st.buyer_request_status === "Not Requested") {
            btnReqBuyer.disabled = false;
        }

        if (st.design_encoding_details) {
            renderStructuralEncodingTab1(st.design_encoding_details);
            const resultsArea = document.getElementById("protectionResults");
            if (resultsArea && resultsArea.style.display === "none" && !st.watermark_W) {
                resultsArea.style.display = "block";
                const encTabBtn = document.querySelector('[data-view="viewStructuralEncoding"]');
                if (encTabBtn) encTabBtn.click();
            }
        }
    } else {
        if (badgeStep2) {
            badgeStep2.textContent = "Ready to Generate";
            badgeStep2.className = "badge badge-warning";
        }
        if (sellerSummaryBox) sellerSummaryBox.style.display = "none";
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
        if (sellerCB) sellerCB.textContent = st.C_B || "--";
    }

    if (btnReqBuyer) {
        btnReqBuyer.disabled = (st.buyer_request_status !== "Not Requested" || !st.design_encoding_D);
    }

    const btnContinueWm = document.getElementById("btnSellerContinueWatermark");
    const sellerStep4Badge = document.getElementById("sellerStep4Badge");

    if (btnContinueWm) {
        btnContinueWm.disabled = !st.buyer_approved;
    }

    if (sellerStep4Badge) {
        if (st.watermark_W) {
            sellerStep4Badge.textContent = "Protected & Embedded";
            sellerStep4Badge.className = "badge badge-success";
        } else if (st.buyer_approved) {
            sellerStep4Badge.textContent = "Ready to Embed";
            sellerStep4Badge.className = "badge badge-warning";
        } else {
            sellerStep4Badge.textContent = "Awaiting Buyer";
            sellerStep4Badge.className = "badge badge-v1";
        }
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

    // Stepper pill clicks
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
            if (currentVerifierSession.final_report) {
                renderFinalReport(currentVerifierSession.final_report);
            }
        }
    } catch (err) {
        console.warn("Failed to refresh verifier profile state:", err);
    }
}

function renderVerifierStep(stepNum) {
    const meta = VERIFIER_STEPS_META.find(m => m.num === stepNum) || VERIFIER_STEPS_META[0];

    const badgeNum = document.getElementById("vStepBadgeNum");
    if (badgeNum) badgeNum.textContent = meta.num;

    const titleEl = document.getElementById("vStepHeaderTitle");
    if (titleEl) titleEl.textContent = meta.title;

    const descEl = document.getElementById("vStepHeaderDesc");
    if (descEl) descEl.textContent = meta.desc;

    const partyEl = document.getElementById("vStepPartyBadge");
    if (partyEl) partyEl.textContent = `Party: ${meta.party}`;

    const btnExec = document.getElementById("btnVerifierExecStep");
    if (btnExec) btnExec.textContent = `Execute Step ${stepNum}`;

    // Update stepper pill active states
    document.querySelectorAll("#verifierStepper .step-tracker-pill").forEach(pill => {
        const pNum = parseInt(pill.dataset.step, 10);
        pill.classList.remove("active");
        if (pNum === stepNum) pill.classList.add("active");

        if (currentVerifierSession && currentVerifierSession.step_results) {
            const stepRes = currentVerifierSession.step_results[`step_${pNum}`];
            if (stepRes) {
                if (stepRes.status === "MATCH" || stepRes.status === "NOT REQUIRED" || stepRes.status === "LOADED" || stepRes.status === "EXTRACTED" || stepRes.status === "VALIDATED") {
                    pill.classList.add("completed");
                    pill.classList.remove("failed");
                } else if (stepRes.status === "MISMATCH" || stepRes.status === "BLOCKED") {
                    pill.classList.add("failed");
                    pill.classList.remove("completed");
                }
            }
        }
    });

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

