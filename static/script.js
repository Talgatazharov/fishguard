/**
 * PhishGuard AI — Frontend logic
 * URL scanning, result display, animations
 */

(function () {
  "use strict";

  const CIRCUMFERENCE = 2 * Math.PI * 52; // risk ring radius = 52

  const STATUS_CONFIG = {
    Safe: {
      icon: "✅",
      label: "Safe",
      class: "status-safe",
      color: "#00ff88",
    },
    Suspicious: {
      icon: "⚠",
      label: "Suspicious",
      class: "status-suspicious",
      color: "#ffd700",
    },
    Phishing: {
      icon: "❌",
      label: "Phishing",
      class: "status-phishing",
      color: "#ff3366",
    },
  };

  const FEATURE_LABELS = {
    url_length: { format: (v) => `${v} симв.` },
    has_https: { format: (v) => (v ? "Да ✓" : "Нет ✗"), alert: (v) => !v },
    has_ip_address: { format: (v) => (v ? "Обнаружен" : "Нет"), alert: (v) => v },
    at_symbol: { format: (v) => (v ? "Да" : "Нет"), alert: (v) => v },
    dash_count: { format: (v) => v, warn: (v) => v > 4 },
    dot_count: { format: (v) => v, warn: (v) => v > 5 },
    suspicious_word_count: { format: (v) => v, alert: (v) => v > 0 },
    subdomain_count: { format: (v) => v, warn: (v) => v > 3 },
    is_shortened: { format: (v) => (v ? "Да" : "Нет"), warn: (v) => v },
    special_char_count: { format: (v) => v, warn: (v) => v > 5 },
    digit_count: { format: (v) => v },
  };

  // DOM elements
  const urlInput = document.getElementById("url-input");
  const scanBtn = document.getElementById("scan-btn");
  const resultSection = document.getElementById("result");
  const statusCard = document.getElementById("status-card");
  const statusIcon = document.getElementById("status-icon");
  const statusText = document.getElementById("status-text");
  const riskValue = document.getElementById("risk-value");
  const riskCircle = document.getElementById("risk-circle");
  const explanationList = document.getElementById("explanation-list");
  const featureGrid = document.getElementById("feature-grid");
  const navToggle = document.getElementById("nav-toggle");
  const navLinks = document.getElementById("nav-links");

  // --- Particle background ---
  function initParticles() {
    const canvas = document.getElementById("particle-canvas");
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    let particles = [];
    let animationId;

    function resize() {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    }

    function createParticles() {
      const count = Math.min(80, Math.floor(window.innerWidth / 20));
      particles = [];
      for (let i = 0; i < count; i++) {
        particles.push({
          x: Math.random() * canvas.width,
          y: Math.random() * canvas.height,
          vx: (Math.random() - 0.5) * 0.5,
          vy: (Math.random() - 0.5) * 0.5,
          r: Math.random() * 2 + 0.5,
        });
      }
    }

    function draw() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      particles.forEach((p, i) => {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
        if (p.y < 0 || p.y > canvas.height) p.vy *= -1;

        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(0, 212, 255, 0.5)";
        ctx.fill();

        for (let j = i + 1; j < particles.length; j++) {
          const q = particles[j];
          const dist = Math.hypot(p.x - q.x, p.y - q.y);
          if (dist < 120) {
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(q.x, q.y);
            ctx.strokeStyle = `rgba(0, 212, 255, ${0.15 * (1 - dist / 120)})`;
            ctx.stroke();
          }
        }
      });

      animationId = requestAnimationFrame(draw);
    }

    resize();
    createParticles();
    draw();

    window.addEventListener("resize", () => {
      resize();
      createParticles();
    });

    return () => cancelAnimationFrame(animationId);
  }

  // --- Animated counters for ML metrics ---
  function animateCounters() {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;

          entry.target.querySelectorAll("[data-count]").forEach((el) => {
            const target = parseFloat(el.dataset.count);
            const decimals = parseInt(el.dataset.decimal || "2", 10);
            const duration = 1500;
            const start = performance.now();

            function tick(now) {
              const progress = Math.min((now - start) / duration, 1);
              const eased = 1 - Math.pow(1 - progress, 3);
              const current = target * eased;
              el.textContent =
                target < 1
                  ? current.toFixed(decimals)
                  : current.toFixed(decimals === 4 ? 4 : 2);
              if (progress < 1) requestAnimationFrame(tick);
            }

            requestAnimationFrame(tick);
          });

          observer.unobserve(entry.target);
        });
      },
      { threshold: 0.3 }
    );

    document.querySelectorAll(".models").forEach((section) => {
      observer.observe(section);
    });
  }

  // --- Update risk ring ---
  function setRiskRing(percent, color) {
    const offset = CIRCUMFERENCE - (percent / 100) * CIRCUMFERENCE;
    riskCircle.style.strokeDashoffset = offset;
    riskCircle.style.stroke = color;
    riskValue.textContent = `${percent}%`;
    riskValue.style.color = color;
  }

  // --- Display scan result ---
  function showResult(data) {
    const config = STATUS_CONFIG[data.status] || STATUS_CONFIG.Suspicious;

    resultSection.hidden = false;
    statusCard.className = `result-card glass ${config.class}`;
    statusIcon.textContent = config.icon;
    statusText.textContent = config.label;

    setRiskRing(data.risk, config.color);

    explanationList.innerHTML = "";
    const items = data.explanation || [];
    if (items.length === 0) {
      const li = document.createElement("li");
      li.className = "explanation-item explanation-item--neutral";
      li.innerHTML =
        '<span class="explanation-item__icon" aria-hidden="true">ℹ</span>' +
        '<span class="explanation-item__text">Нет дополнительных пояснений.</span>';
      explanationList.appendChild(li);
    } else {
      items.forEach((text, index) => {
        const li = document.createElement("li");
        const severity =
          data.status === "Phishing"
            ? "danger"
            : data.status === "Suspicious"
              ? "warn"
              : "ok";
        const icon =
          severity === "danger" ? "⚠" : severity === "warn" ? "◆" : "✓";
        li.className = `explanation-item explanation-item--${severity}`;
        li.innerHTML =
          `<span class="explanation-item__num">${index + 1}</span>` +
          `<span class="explanation-item__icon" aria-hidden="true">${icon}</span>` +
          `<span class="explanation-item__text"></span>`;
        li.querySelector(".explanation-item__text").textContent = text;
        explanationList.appendChild(li);
      });
    }

    updateFeatureCards(data.features || {});
    resultSection.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function updateFeatureCards(features) {
    featureGrid.querySelectorAll(".feature-card").forEach((card) => {
      const key = card.dataset.feature;
      const meta = FEATURE_LABELS[key];
      const valueEl = card.querySelector(".feature-card__value");
      const raw = features[key];

      if (raw === undefined) {
        valueEl.textContent = "—";
        card.classList.remove("alert", "warn", "ok");
        return;
      }

      valueEl.textContent = meta ? meta.format(raw) : String(raw);
      card.classList.remove("alert", "warn", "ok");

      if (meta?.alert?.(raw)) card.classList.add("alert");
      else if (meta?.warn?.(raw)) card.classList.add("warn");
      else if (key === "has_https" && raw) card.classList.add("ok");
    });
  }

  // --- API call ---
  async function scanUrl(url) {
    const response = await fetch("/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Ошибка сервера");
    }

    return data;
  }

  function setLoading(loading) {
    scanBtn.disabled = loading;
    scanBtn.classList.toggle("loading", loading);
    scanBtn.querySelector(".btn__loader").hidden = !loading;
  }

  async function handleScan() {
    const url = urlInput.value.trim();
    if (!url) {
      urlInput.focus();
      urlInput.style.borderColor = "#ff3366";
      setTimeout(() => {
        urlInput.style.borderColor = "";
      }, 1500);
      return;
    }

    setLoading(true);

    try {
      const data = await scanUrl(url);
      showResult(data);
    } catch (err) {
      alert(err.message || "Не удалось выполнить проверку. Запустите Flask-сервер.");
    } finally {
      setLoading(false);
    }
  }

  // --- Navbar mobile ---
  navToggle?.addEventListener("click", () => {
    navLinks.classList.toggle("open");
  });

  navLinks?.querySelectorAll("a").forEach((link) => {
    link.addEventListener("click", () => navLinks.classList.remove("open"));
  });

  // --- Events ---
  scanBtn.addEventListener("click", handleScan);
  urlInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") handleScan();
  });

  // Demo examples on double-click input
  urlInput.addEventListener("dblclick", () => {
    const demos = [
      "https://secure-login-verify-bank-account.com/update",
      "https://github.com",
      "http://192.168.1.1/paypal@evil.com/login",
    ];
    urlInput.value = demos[Math.floor(Math.random() * demos.length)];
  });

  // Init
  initParticles();
  animateCounters();

  // Set initial risk ring state
  riskCircle.style.strokeDasharray = CIRCUMFERENCE;
  riskCircle.style.strokeDashoffset = CIRCUMFERENCE;
})();
