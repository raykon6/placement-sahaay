// Placement Sahaay progressive enhancements. The application is fully usable
// without JavaScript; nothing here makes a security decision.
(function () {
  "use strict";

  // Bar widths come from data attributes (inline styles are blocked by CSP).
  function sizeBars() {
    document.querySelectorAll("[data-pct]").forEach(function (el) {
      var pct = Math.max(0, Math.min(100, parseFloat(el.getAttribute("data-pct")) || 0));
      requestAnimationFrame(function () { el.style.width = pct + "%"; });
    });
  }

  // Mobile navigation toggle and dropdown menus (native <details>, enhanced).
  function navToggle() {
    var btn = document.getElementById("nav-toggle");
    var nav = document.getElementById("primary-nav");
    var menus = Array.prototype.slice.call(document.querySelectorAll(".nav details.menu"));
    menus.forEach(function (m) {
      m.addEventListener("toggle", function () {
        if (m.open) menus.forEach(function (o) { if (o !== m) o.open = false; });
      });
    });
    document.addEventListener("click", function (e) {
      menus.forEach(function (m) { if (m.open && !m.contains(e.target)) m.open = false; });
      if (nav && btn && nav.classList.contains("open") && !nav.contains(e.target) && !btn.contains(e.target)) setOpen(false);
    });
    document.addEventListener("keydown", function (e) {
      if (e.key !== "Escape") return;
      menus.forEach(function (m) { if (m.open) { m.open = false; m.querySelector("summary").focus(); } });
      if (nav && nav.classList.contains("open")) { setOpen(false); btn.focus(); }
    });
    function setOpen(open) {
      nav.classList.toggle("open", open);
      btn.setAttribute("aria-expanded", String(open));
    }
    if (btn && nav) btn.addEventListener("click", function () { setOpen(!nav.classList.contains("open")); });
  }

  // Confirmation for consequential actions.
  function confirmForms() {
    document.querySelectorAll("form[data-confirm]").forEach(function (form) {
      form.addEventListener("submit", function (e) {
        if (!window.confirm(form.getAttribute("data-confirm"))) e.preventDefault();
      });
    });
  }

  // Acceptance deadline countdowns.
  function countdowns() {
    var els = document.querySelectorAll("[data-deadline]");
    if (!els.length) return;
    function tick() {
      var now = Date.now();
      els.forEach(function (el) {
        var t = Date.parse(el.getAttribute("data-deadline"));
        if (isNaN(t)) return;
        var s = Math.floor((t - now) / 1000);
        if (s <= 0) { el.textContent = "Past deadline"; el.classList.add("urgent"); return; }
        var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
        el.textContent = h + " h " + String(m).padStart(2, "0") + " min left";
        el.classList.toggle("urgent", s < 6 * 3600);
      });
    }
    tick();
    setInterval(tick, 30000);
  }

  // Show / hide password.
  function passwordToggles() {
    document.querySelectorAll("[data-pw-toggle]").forEach(function (btn) {
      var input = document.getElementById(btn.getAttribute("data-pw-toggle"));
      if (!input) return;
      btn.hidden = false;
      btn.addEventListener("click", function () {
        var show = input.type === "password";
        input.type = show ? "text" : "password";
        btn.textContent = show ? "Hide" : "Show";
        btn.setAttribute("aria-pressed", String(show));
      });
    });
  }

  // Dismissible notices.
  function dismissers() {
    document.querySelectorAll("[data-dismiss]").forEach(function (btn) {
      btn.hidden = false;
      btn.addEventListener("click", function () {
        var box = btn.closest(".flash");
        if (box) box.remove();
        var main = document.getElementById("main");
        if (main) main.focus();
      });
    });
  }

  // Conditional form sections: [data-show-when="name=value1,value2"].
  function conditionals() {
    var targets = document.querySelectorAll("[data-show-when]");
    if (!targets.length) return;
    function update() {
      targets.forEach(function (el) {
        var spec = el.getAttribute("data-show-when").split("=");
        var name = spec[0], values = spec[1].split(",");
        var checked = document.querySelector('[name="' + name + '"]:checked') || document.querySelector('select[name="' + name + '"]');
        var value = checked ? checked.value : "";
        var show = values.indexOf(value) !== -1;
        el.hidden = !show;
        el.querySelectorAll("input, select, textarea").forEach(function (i) { i.disabled = !show; });
      });
    }
    document.addEventListener("change", update);
    update();
  }

  document.addEventListener("DOMContentLoaded", function () {
    var printBtn = document.getElementById("print-btn");
    if (printBtn) { printBtn.hidden = false; printBtn.addEventListener("click", function () { window.print(); }); }
    sizeBars(); navToggle(); confirmForms(); countdowns(); passwordToggles(); dismissers(); conditionals();
    var summary = document.querySelector(".error-summary");
    if (summary) summary.focus();
  });
})();
