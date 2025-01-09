export function initOnDocumentLoadScript(cmdArgs) {
  window.cumulativeLayoutShiftScore = 0;
  window.largestContentfulPaintScore = 0;
  window.resources = [];

  const resourceObserver = new PerformanceObserver((entryList) => {
    const entries = entryList.getEntriesByType("resource");
    const excludedInitiatorTypes = ["beacon", "fetch", "xmlhttprequest"];
    entries.forEach((entry) => {
      if (excludedInitiatorTypes.indexOf(entry.initiatorType) === -1) {
        window.resources.push({
          name: entry.name,
          initiatorType: entry.initiatorType,
          startTime: entry.startTime,
          responseEnd: entry.responseEnd,
          duration: entry.duration,
          transferSize: entry.transferSize || 0,
        });
      }
    });
  });

  const clsObserver = new PerformanceObserver((list) => {
    const entries = list.getEntries();
    for (const entry of entries) {
      if (!entry.hadRecentInput) {
        console.log("New observer entry for cls: " + entry.value);
        window.cumulativeLayoutShiftScore += entry.value;
      }
    }
  });

  const lcpObserver = new PerformanceObserver((list) => {
    const entries = list.getEntries();
    const lastEntry = entries[entries.length - 1];
    window.largestContentfulPaint = lastEntry.renderTime || lastEntry.loadTime;
  });
  clsObserver.observe({ type: "layout-shift", buffered: true });
  lcpObserver.observe({ type: "largest-contentful-paint", buffered: true });
  resourceObserver.observe({ type: "resource", buffered: true });

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") {
      clsObserver.takeRecords();
      lcpObserver.takeRecords();
      resourceObserver.takeRecords();
      resourceObserver.disconnect();
      clsObserver.disconnect();
      lcpObserver.disconnect();
      console.log("CLS:", window.cumulativeLayoutShiftScore);
      console.log("LCP:", window.largestContentfulPaint);
    }
  });

  function injectScript() {
    const middlewareScript = document.createElement("script");
    middlewareScript.src =
      "https://cdnjs.middleware.io/browser/libs/0.0.2/middleware-rum.min.js";
    middlewareScript.type = "text/javascript";
    document.head.appendChild(middlewareScript);

    middlewareScript.onload = () => {
      if (window.Middleware) {
        Middleware.track({
          serviceName: "tests",
          projectName: "tests",
          accountKey: "zhyuilyvgytmlwdjbmjnzhzoouwsvvjyipqn",
          target: "https://p2i13hg.middleware.io",
          defaultAttributes: {
            "app.version": "1.0.0",
          },
        });
        console.log("Middleware RUM tracking initialized.");
      } else {
        console.error("Middleware library not loaded.");
      }
    };
  }
  if (cmdArgs.collectRum) {
    if (document.head) {
      injectScript();
    } else {
      document.addEventListener("DOMContentLoaded", injectScript);
    }
  }
}

export function generateBrowserArgs(cmdArgs) {
  const browserArgs = ["--disable-dev-shm-usage", "--no-sandbox"];
  if (cmdArgs["proxy-server"]) {
    browserArgs.push(`--proxy-server=${cmdArgs["proxy-server"]}`);
  }

  if (cmdArgs["disableCors"]) {
    browserArgs.push("--disable-web-security");
  }

  if (cmdArgs["disableCsp"]) {
    browserArgs.push("--disable-features=IsolateOrigins,site-per-process");
    browserArgs.push("--allow-running-insecure-content");
  }

  if (cmdArgs.sslCertificate && cmdArgs.sslCertificatePrivateKey) {
    const formattedCertificate = certificate.replace(/\\n/g, "\n");
    const formattedPrivateKey = privateKey.replace(/\\n/g, "\n");
    browserArgs.push(`--ssl-client-certificate=${formattedCertificate}`);
    browserArgs.push(`--ssl-client-key=${formattedPrivateKey}`);
  }
  return browserArgs;
}
