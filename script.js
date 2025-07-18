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

async function checkEmail() {
  const input = document.getElementById("emailInput").value.trim();
  const result = document.getElementById("emailResult");
  result.className = "output"; // Reset Klassen
  result.innerHTML = ""; // Reset Inhalt

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const suspiciousTLDs = [".xyz", ".tk", ".top", ".click", ".support"];
  const blacklist = [
    "bamf-sicherheit.com", "paypal-konto-check.com", "post-verifikation.net",
    "sicher-konto-check24.com", "bamf-support.cc", "post-check.tk",
    "paypal-check.tk", "konto-verifizierung.info", "securelogin.xyz",
    "amazon-login.click", "banned.de", "fakeemail.org"
  ];

  if (!emailRegex.test(input)) {
    result.innerHTML = "❌ Ungültiges E-Mail-Format.";
    result.classList.add("danger");
    return;
  }

  const domain = input.split("@")[1];
  const tld = domain.substring(domain.lastIndexOf("."));
  const explanations = [];

  // Google Safe Browsing Prüfung
  const apiKey = "AIzaSyA0HyrC4HxtnXd11ZkJvxPVT3Q-qAdHsDQ";
  const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
  const threatCheckBody = {
    client: {
      clientId: "wfw-emailchecker",
      clientVersion: "1.0.0"
    },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url: "http://" + domain }]
    }
  };

  try {
    const res = await fetch(apiUrl, {
      method: "POST",
      body: JSON.stringify(threatCheckBody),
      headers: { "Content-Type": "application/json" }
    });
    const data = await res.json();
    if (data && data.matches) {
      result.innerHTML = "🔴 Diese E-Mail-Domain wurde von Google als gefährlich gemeldet.";
      result.classList.add("danger");
      return;
    }
  } catch (e) {
    explanations.push("⚠️ Google-Prüfung konnte nicht durchgeführt werden.");
  }

  if (blacklist.some(bad => domain.includes(bad))) {
    result.innerHTML = "🔴 Diese E-Mail-Domain ist <strong>hochverdächtig</strong> (Phishing-Muster erkannt).";
    result.classList.add("danger");
    return;
  }

  if (suspiciousTLDs.includes(tld)) {
    explanations.push("⚠️ Diese Domainendung ist ungewöhnlich oder oft in Phishing-Adressen verwendet.");
  }

  if (domain.length < 5 || domain.includes("login") || domain.includes("bank")) {
    explanations.push("⚠️ Die Domain wirkt technisch oder zu allgemein. Vorsicht!");
  }

  if (domain.match(/(verif|secure|login|konto|support|check)/)) {
    explanations.push("⚠️ Die Domain enthält verdächtige Begriffe wie 'login', 'secure' oder 'verif'.");
  }

  if (domain.match(/(gmail\.com|gmx\.de|outlook\.com)$/) && input.toLowerCase().includes("polizei")) {
    explanations.push("⚠️ Achtung: Behörden wie Polizei verwenden keine kostenlosen E-Mail-Dienste wie Gmail.");
  }

  if (explanations.length > 0) {
    result.innerHTML = "<strong>⚠️ Verdächtig:</strong><ul><li>" + explanations.join("</li><li>") + "</li></ul>";
    result.classList.add("warning");
  } else {
    result.innerHTML = "✅ Die E-Mail-Adresse sieht unauffällig aus.";
    result.classList.add("safe");
  }
}