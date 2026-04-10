async function checkURL() {
    const input   = document.getElementById("urlInput");
    const btn     = document.getElementById("checkBtn");
    const loader  = document.getElementById("loader");
    const result  = document.getElementById("result");

    const url = input.value.trim();

    if (!url) {
        result.innerHTML = '<div class="error-msg">⚠️ Please enter a URL first.</div>';
        return;
    }

    // Loading state
    btn.disabled = true;
    loader.classList.remove("hidden");
    result.innerHTML = "";

    try {
        const response = await fetch("/check", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.error || "Server error");
        }

        const data = await response.json();

        // Verdict styling
        const verdictClass = data.verdict.toLowerCase(); // 'phishing' | 'suspicious' | 'legitimate'

        const verdictIcons = {
            phishing:   "🚨",
            suspicious: "⚠️",
            legitimate: "✅"
        };

        const icon = verdictIcons[verdictClass] || "🔍";
        const maxScore = 20; // max possible score

        // Build detail rows
        let detailRows = "";
        for (const [key, val] of Object.entries(data.details)) {
            detailRows += `
                <div class="detail-row">
                    <span class="detail-key">${escapeHTML(key)}</span>
                    <span class="detail-val">${escapeHTML(val)}</span>
                </div>`;
        }

        result.innerHTML = `
            <div class="result-card">
                <div class="verdict-banner ${verdictClass}">
                    <span class="verdict-label">${icon} ${escapeHTML(data.verdict)}</span>
                    <span class="verdict-score">Risk Score: ${data.score} / ${maxScore}</span>
                </div>
                <div class="details-section">
                    ${detailRows}
                </div>
            </div>`;

    } catch (err) {
        result.innerHTML = `<div class="error-msg">❌ Error: ${escapeHTML(err.message)}</div>`;
    } finally {
        btn.disabled = false;
        loader.classList.add("hidden");
    }
}

// Prevent XSS from URL content being rendered as HTML
function escapeHTML(str) {
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

// Allow Enter key to trigger check
document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("urlInput").addEventListener("keydown", (e) => {
        if (e.key === "Enter") checkURL();
    });
});
