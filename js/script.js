/**    
 * botGuard.js
 * NBEP Vanguard Seal -- Automated Threat Detection and Deflection
 * Form: NBEP-VS-GUARD-001 | Version 1.2 | March 2026
 *
 * Detects non-human clients using layered signal analysis:
 *   Layer 1 -- User agent string inspection
 *   Layer 2 -- Automation framework globals (Playwright, Puppeteer, Selenium, CDP)
 *   Layer 3 -- Navigator API consistency checks
 *   Layer 4 -- WebGL and canvas rendering fingerprinting
 *   Layer 5 -- Behavioral entropy (mouse, touch, keyboard presence)
 *   Layer 6 -- Stealth-deletion detection (property erased by anti-detect plugin)
 *   Layer 7 -- Timing and environment consistency
 *
 * Trusted crawlers (Googlebot, Bingbot, DuckDuckBot, etc.) are explicitly
 * whitelisted by user agent prefix and are never scored or deflected.
 *
 * A weighted scoring system accumulates evidence across all layers.
 * Clients that exceed the threshold are deflected: the DOM is cleared,
 * all event handlers are removed, and the page is replaced with a
 * static decoy shell that returns no meaningful content.
 *
 * NOTE: No CDN delivery. Load this as the first synchronous script in <head>.
 * It must execute before any content is rendered.
 */

(function () {
  "use strict";

  const SCORE_THRESHOLD = 55;
  const DEBUG_MODE      = false;

  const TRUSTED_UA_PREFIXES = [
    "Googlebot",
    "Googlebot-Image",
    "Googlebot-News",
    "Googlebot-Video",
    "Bingbot",
    "bingbot",
    "Slurp", 
    "DuckDuckBot",
    "Baiduspider",
    "YandexBot",
    "Sogou",
    "Exabot",
    "facebot",
    "ia_archiver",
    "AhrefsBot", 
    "SemrushBot",
    "MJ12bot",
    "DotBot",
    "archive.org_bot",
    "CCBot",
    "LinkedInBot",
    "Twitterbot",
    "facebookexternalhit",
    "Applebot",
    "PetalBot",
    "UptimeRobot",
    "Pingdom",
    "StatusCake"
  ];

  const MALICIOUS_UA_PATTERNS = [
    /HeadlessChrome/i,
    /PhantomJS/i,
    /SlimerJS/i,
    /NightmareJS/i,
    /electron/i,
    /python-requests/i,
    /python-urllib/i,
    /python-httpx/i,
    /aiohttp/i,
    /scrapy/i,
    /mechanize/i,
    /libwww-perl/i,
    /curl\//i,
    /wget\//i,
    /java\/[0-9]/i,
    /Go-http-client/i,
    /okhttp/i,
    /node-fetch/i,
    /axios\//i,
    /got\//i,
    /undici/i,
    /pycurl/i,
    /Wget/i,
    /HTTrack/i,
    /DataForSeoBot/i,
    /MegaIndex/i,
    /serpstatbot/i,
    /PetalBot(?!.*Applebot)/i, // PetalBot
    /zgrab/i,
    /masscan/i,
    /nmap/i,
    /sqlmap/i,
  ];


  function log(msg, value) {
    if (DEBUG_MODE) {
      console.log("[botGuard] " + msg, value !== undefined ? value : "");
    }
  }

  function safeGet(fn) {
    try { return fn(); } catch (e) { return null; }
  }


  var score   = 0;
  var signals = [];

  function addSignal(name, points) {
    score += points;
    signals.push({ name: name, points: points });
    log("Signal: " + name, "+" + points);
  }


  var ua = navigator.userAgent || "";

  for (var i = 0; i < TRUSTED_UA_PREFIXES.length; i++) {
    if (ua.indexOf(TRUSTED_UA_PREFIXES[i]) !== -1) {
      log("Trusted crawler detected, exiting early", TRUSTED_UA_PREFIXES[i]);
      return; 
    }
  }


  for (var p = 0; p < MALICIOUS_UA_PATTERNS.length; p++) {
    if (MALICIOUS_UA_PATTERNS[p].test(ua)) {
      addSignal("ua_known_malicious_pattern", 60); 
      break;
    }
  }

  if (!ua || ua.trim().length === 0) {
    addSignal("ua_empty", 50);
  }

  if (ua.length > 0 && ua.length < 20) {
    addSignal("ua_implausibly_short", 30);
  }
  if (/Chrome/i.test(ua) && !/Mozilla\/5\.0/.test(ua)) {
    addSignal("ua_malformed_chrome_claim", 25);
  }

  var webdriverPresent = "webdriver" in navigator;
  var webdriverValue   = safeGet(function () { return navigator.webdriver; });

  if (webdriverPresent && webdriverValue === true) {
    addSignal("navigator_webdriver_true", 50);
  }

  if (webdriverPresent && (webdriverValue === undefined || webdriverValue === false)) {
    addSignal("navigator_webdriver_stealth_deleted_or_spoofed", 30);
  }

  if (safeGet(function () { return !!window.__playwright; })) {
    addSignal("playwright_global_detected", 70);
  }
  if (safeGet(function () { return !!window.__playwright__binding__; })) {
    addSignal("playwright_binding_detected", 70);
  }
  if (safeGet(function () { return !!window.__pwInitScripts; })) {
    addSignal("playwright_init_scripts_detected", 70);
  }

  if (safeGet(function () { return !!window.__puppeteer_evaluation_script__; })) {
    addSignal("puppeteer_global_detected", 70);
  }

  if (safeGet(function () { return !!window._selenium; })) {
    addSignal("selenium_global_detected", 60);
  }
  if (safeGet(function () { return !!window._Selenium_IDE_Recorder; })) {
    addSignal("selenium_ide_global_detected", 60);
  }
  if (safeGet(function () {
    var keys = Object.keys(document);
    for (var i = 0; i < keys.length; i++) {
      if (/\$cdc_[a-zA-Z0-9]+_/.test(keys[i])) return true;
    }
    return false;
  })) {
    addSignal("chromedriver_cdc_variable_detected", 65);
  }

  var cdpDetected = false;
  try {
    var err = new Error();
    Object.defineProperty(err, "stack", {
      get: function () {
        cdpDetected = true;
        return "";
      }
    });
    console.log(err); 
  } catch (e) { /* ignore */ }
  if (cdpDetected) {
    addSignal("cdp_error_stack_artifact", 55);
  }

  var pluginCount = safeGet(function () { return navigator.plugins.length; });
  if (pluginCount === 0) {
    addSignal("plugins_empty", 20);
  } else if (pluginCount !== null) {
    var firstPlugin = safeGet(function () { return navigator.plugins[0]; });
    if (firstPlugin !== null && typeof firstPlugin !== "object") {
      addSignal("plugins_spoofed_non_object_entries", 40);
    }
  }

  var hasChrome        = safeGet(function () { return !!window.chrome; });
  var hasChromeRuntime = safeGet(function () { return !!(window.chrome && window.chrome.runtime); });
  if (/Chrome/i.test(ua) && !hasChrome) {
    addSignal("ua_claims_chrome_but_window_chrome_absent", 35);
  }
  if (hasChrome && !hasChromeRuntime) {
    addSignal("window_chrome_exists_but_runtime_absent", 20);
  }

  var langs = safeGet(function () { return navigator.languages; });
  if (!langs || langs.length === 0) {
    addSignal("navigator_languages_empty", 25);
  }

  var cores = safeGet(function () { return navigator.hardwareConcurrency; });
  if (cores !== null && cores < 2) {
    addSignal("hardware_concurrency_suspiciously_low", 15);
  }

  var mem = safeGet(function () { return navigator.deviceMemory; });
  if (mem !== null && mem !== undefined && mem < 1) {
    addSignal("device_memory_suspiciously_low", 15);
  }

  if (navigator.permissions && navigator.permissions.query) {
    safeGet(function () {
      navigator.permissions.query({ name: "notifications" }).then(function (result) {
        if (result.state === "denied") {
          addSignal("notifications_permission_denied_without_prompt", 20);
          evaluateVerdict();
        }
      });
    });
  }

  var canvasSuspicious = false;
  safeGet(function () {
    var c   = document.createElement("canvas");
    var ctx = c.getContext("2d");
    if (!ctx) { canvasSuspicious = true; return; }
    ctx.textBaseline = "top";
    ctx.font         = "14px Arial";
    ctx.fillStyle    = "#f60";
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle    = "#069";
    ctx.fillText("NBEP Security Check 2026 @", 2, 15);
    ctx.fillStyle    = "rgba(102,204,0,0.7)";
    ctx.fillText("NBEP Security Check 2026 @", 4, 17);
    var dataUrl = c.toDataURL();
    if (!dataUrl || dataUrl.length < 500 || dataUrl === "data:,") {
      canvasSuspicious = true;
    }
  });
  if (canvasSuspicious) {
    addSignal("canvas_blank_or_minimal_output", 25);
  }

  var webglSuspicious = false;
  safeGet(function () {
    var canvas   = document.createElement("canvas");
    var gl       = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
    if (!gl) { webglSuspicious = true; return; }
    var ext      = gl.getExtension("WEBGL_debug_renderer_info");
    if (!ext) return;
    var renderer = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || "";
    var vendor   = gl.getParameter(ext.UNMASKED_VENDOR_WEBGL)   || "";
    if (
      /SwiftShader/i.test(renderer) ||
      /llvmpipe/i.test(renderer)    ||
      /softpipe/i.test(renderer)    ||
      /Mesa/i.test(renderer)        ||
      /VMware/i.test(renderer)      ||
      /VirtualBox/i.test(renderer)
    ) {
      webglSuspicious = true;
    }
    if (/Brian Paul/i.test(vendor)) {
      webglSuspicious = true;
    }
  });
  if (webglSuspicious) {
    addSignal("webgl_software_renderer_detected", 30);
  }

  safeGet(function () {
    var AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (!AudioCtx) {
      addSignal("audio_context_api_absent", 10);
      return;
    }
    var ctx      = new AudioCtx();
    var osc      = ctx.createOscillator();
    var analyser = ctx.createAnalyser();
    var gain     = ctx.createGain();
    var proc     = ctx.createScriptProcessor(4096, 1, 1);

    gain.gain.value = 0;

    osc.connect(analyser);
    analyser.connect(gain);
    gain.connect(proc);
    proc.connect(ctx.destination);
    osc.start(0);

    proc.onaudioprocess = function (e) {
      var data = e.inputBuffer.getChannelData(0);
      var sum  = 0;
      for (var i = 0; i < data.length; i++) { sum += Math.abs(data[i]); }
      // completely flat audio output is unusual in a real browser
      if (sum === 0) {
        addSignal("audio_context_flat_output", 15);
        evaluateVerdict();
      }
      proc.disconnect();
      osc.stop();
      safeGet(function () { ctx.close(); });
    };
  });

  var humanSignals = {
    mouseMove  : false,
    mouseClick : false,
    keydown    : false,
    touchStart : false,
    scroll     : false
  };

  function markHuman(type) {
    humanSignals[type] = true;
  }
  document.addEventListener("mousemove",  function () { markHuman("mouseMove");  }, { passive: true, once: true });
  document.addEventListener("click",      function () { markHuman("mouseClick"); }, { passive: true, once: true });
  document.addEventListener("keydown",    function () { markHuman("keydown");    }, { passive: true, once: true });
  document.addEventListener("touchstart", function () { markHuman("touchStart"); }, { passive: true, once: true });
  document.addEventListener("scroll",     function () { markHuman("scroll");     }, { passive: true, once: true });

  setTimeout(function () {
    var humanSignalCount = Object.keys(humanSignals).filter(function (k) {
      return humanSignals[k];
    }).length;

    if (humanSignalCount === 0) {
      addSignal("no_human_input_signals_in_observation_window", 20);
    }

    evaluateVerdict();
  }, 4000);

  var t1 = Date.now();
  var t2 = Date.now();
  if (t1 === t2) {
    addSignal("date_now_returns_identical_successive_values", 10);
  }

  var p1 = performance.now();
  var p2 = performance.now();
  if (p1 === p2) {
    addSignal("performance_now_returns_zero_delta", 10);
  }

  if (screen.width === 0 || screen.height === 0) {
    addSignal("screen_dimensions_zero", 40);
  }
  if (window.outerWidth === 0 && window.outerHeight === 0) {
    addSignal("outer_window_dimensions_zero", 25);
  }

  var mimeCount = safeGet(function () { return navigator.mimeTypes.length; });
  if (mimeCount === 0) {
    addSignal("mime_types_empty", 15);
  }

  safeGet(function () {
    if (!window.Worker) return;
    var blob   = new Blob([
      "self.postMessage(navigator.userAgent);"
    ], { type: "application/javascript" });
    var url    = URL.createObjectURL(blob);
    var worker = new Worker(url);
    worker.onmessage = function (e) {
      var workerUA = e.data || "";
      if (workerUA !== navigator.userAgent) {
        addSignal("worker_ua_differs_from_main_thread_ua", 35);
        evaluateVerdict();
      }
      worker.terminate();
      URL.revokeObjectURL(url);
    };
  });

  var deflected = false;

  function evaluateVerdict() {
    if (deflected) return;
    log("Current score", score);
    if (score >= SCORE_THRESHOLD) {
      deflect();
    }
  }

  function deflect() {
    deflected = true;

    log("DEFLECTING -- score exceeded threshold", score);
    log("Signals", signals);

    safeGet(function () {
      if (navigator.sendBeacon) {
        navigator.sendBeacon("/api/guard-event", JSON.stringify({
          score   : score,
          signals : signals.map(function (s) { return s.name; }),
          ua      : ua,
          ts      : Date.now()
        }));
      }
    });

    safeGet(function () {
      window.onload    = null;
      window.onerror   = null;
      document.onclick = null;
    });

    safeGet(function () {
      document.open();
      document.write([
        "<!DOCTYPE html>",
        "<html lang=\"en\">",
        "<head>",
        "  <meta charset=\"UTF-8\">",
        "  <meta name=\"robots\" content=\"noindex, nofollow\">",
        "  <title>403 Forbidden</title>",
        "  <style>",
        "    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }",
        "    html, body {",
        "      height: 100%; background: #0a0f1e; color: #cccccc;",
        "      font-family: 'Segoe UI', Arial, sans-serif; font-size: 15px;",
        "      display: flex; align-items: center; justify-content: center;",
        "    }",
        "    .shell {",
        "      text-align: center; padding: 40px; max-width: 520px;",
        "      border: 1px solid #1e3060; border-radius: 4px;",
        "      background: #0d1533;",
        "    }",
        "    .code  { font-size: 64px; font-weight: 700; color: #c9a84c; letter-spacing: 4px; }",
        "    .title { font-size: 18px; margin: 12px 0 8px; color: #e0e0e0; }",
        "    .body  { font-size: 13px; color: #888; line-height: 1.6; }",
        "    .ref   { margin-top: 20px; font-size: 11px; color: #444; font-family: monospace; }",
        "  </style>",
        "</head>",
        "<body>",
        "  <div class=\"shell\">",
        "    <div class=\"code\">403</div>",
        "    <div class=\"title\">Access Denied</div>",
        "    <p class=\"body\">",
        "      This resource is restricted. Automated access is not permitted.",
        "      If you believe this is an error, contact the site administrator.",
        "    </p>",
        "    <p class=\"ref\">REF: NBEP-VS-GUARD-001 &nbsp;|&nbsp; " + new Date().toUTCString() + "</p>",
        "  </div>",
        "</body>",
        "</html>"
      ].join("\n"));
      document.close();
    });
  }

  evaluateVerdict();

})();
