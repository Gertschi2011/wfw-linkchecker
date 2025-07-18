async function checkUrl() {
  const url = document.getElementById("urlInput").value;
  const resultDiv = document.getElementById("result");
  resultDiv.innerHTML = "⏳ Wird geprüft...";
  resultDiv.className = "output";

  const apiKey = "AIzaSyA0HyrC4HxtnXd11ZkJvxPVT3Q-qAdHsDQ"; // geschützt durch w-f-w.at
  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;

  const body = {
    client: {
      clientId: "wfw-checker",
      clientVersion: "1.0.0"
    },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }]
    }
  };

  const heuristics = [];
  try {
    const parsedUrl = new URL(url.includes("://") ? url : "http://" + url);
    const host = parsedUrl.hostname;

    if (url.includes("@")) heuristics.push("⚠️ Die URL enthält ein '@' – Spoofing-Verdacht.");
    if ([".cc", ".tk", ".ml", ".gq", ".xyz", ".top"].some(tld => host.endsWith(tld)))
      heuristics.push("⚠️ Verdächtige Domainendung.");
    if (host.length < 10 || host.includes("android")) heuristics.push("⚠️ Ungewöhnlich kurze oder technisch klingende Domain.");
  } catch (e) {
    heuristics.push("⚠️ Ungültige URL – bitte überprüfen.");
  }

  let heuristicWarnings = heuristics.map(w => `<li>${w}</li>`).join("");

  try {
    const res = await fetch(endpoint, {
      method: "POST",
      body: JSON.stringify(body),
      headers: { "Content-Type": "application/json" }
    });

    const data = await res.json();
    if (data && data.matches) {
      resultDiv.innerHTML = `<strong>🚫 Gefährlich:</strong> Die Seite ist als Bedrohung gemeldet.<ul>${heuristicWarnings}</ul>`;
      resultDiv.classList.add("danger");
    } else if (heuristics.length > 0) {
      resultDiv.innerHTML = `<strong>⚠️ Verdächtig:</strong> Keine Google-Warnung, aber Anzeichen für Phishing.<ul>${heuristicWarnings}</ul>`;
      resultDiv.classList.add("warning");
    } else {
      resultDiv.innerHTML = "✅ Die URL scheint sicher zu sein.";
      resultDiv.classList.add("safe");
    }
  } catch (e) {
    resultDiv.innerHTML = "❌ Fehler bei der API-Anfrage.";
    resultDiv.classList.add("warning");
  }
}
function openTab(tabId) {
  document.querySelectorAll(".tab-content").forEach(tab => tab.classList.remove("active"));
  document.querySelectorAll(".tab-button").forEach(btn => btn.classList.remove("active"));
  document.getElementById(tabId).classList.add("active");
  document.querySelector(`.tab-button[onclick="openTab('${tabId}')"]`).classList.add("active");
}

function checkEmail() {
  const input = document.getElementById("emailInput").value.trim();
  const result = document.getElementById("emailResult");
  result.innerHTML = ""; // Reset

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const suspiciousTLDs = [".xyz", ".tk", ".top", ".click", ".support"];
  const blacklist = [
    "bamf-sicherheit.com", "paypal-konto-check.com",
    "post-verifikation.net", "sicher-konto-check24.com"
  ];

  if (!emailRegex.test(input)) {
    result.innerHTML = "❌ Ungültiges E-Mail-Format.";
    result.style.color = "red";
    return;
  }

  const domain = input.split("@")[1];
  const tld = domain.substring(domain.lastIndexOf("."));

  if (blacklist.includes(domain)) {
    result.innerHTML = "🔴 Diese E-Mail-Domain ist **hochverdächtig** (Phishing-Muster erkannt).";
    result.style.color = "red";
  } else if (suspiciousTLDs.includes(tld)) {
    result.innerHTML = "🟡 Vorsicht: Diese Domain-Endung ist ungewöhnlich. Bitte genau prüfen.";
    result.style.color = "orange";
  } else {
    result.innerHTML = "🟢 Diese E-Mail-Adresse wirkt unauffällig.";
    result.style.color = "green";
  }
}