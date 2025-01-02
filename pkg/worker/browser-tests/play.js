import fs from "fs";
import path from "path";
import { chromium } from "playwright";

// Function to take a screenshot after each step
async function takeScreenshot(page, stepName) {
  const screenshotPath = path.join("screenshots", `${stepName}.png`);
  await page.screenshot({ path: screenshotPath });
  console.log(`Screenshot for step '${stepName}' saved at ${screenshotPath}`);
}

// Capture Resources
async function captureResources(page) {
  const resourceTimingJson = await page.evaluate(() =>
    JSON.stringify(window.performance.getEntriesByType('resource'))
  )

  const resourceTiming = JSON.parse(resourceTimingJson)
  return resourceTiming;
}

// Capture JavaScript Errors
async function captureJSErrors(page) {
  const jsErrors = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") {
      jsErrors.push(msg.text());
    }
  });
  return jsErrors;
}

// Main browser function to run the test and capture reports
(async function browser() {
  // Load recording.json
  const recordingFile = fs.readFileSync(
    "/home/archish/code/synthetics-agent/pkg/worker/browser-tests/recording1.json",
    "utf8"
  );
  const recording = JSON.parse(recordingFile);

  // Create screenshots directory if it doesn't exist
  if (!fs.existsSync("screenshots")) {
    fs.mkdirSync("screenshots", { recursive: true });
  }

  // Launch browser with Playwright (using Chromium)
  const browser = await chromium.launch({
    headless: false,
    args: ["--remote-debugging-port=9222"],
  });
  const page = await browser.newPage();

  let report = {
    steps: [],
    webVitals: null,
    resources: null,
    jsErrors: [],
  };

  // Inject Middleware tracking script
  await page.addScriptTag({
    url: "https://cdnjs.middleware.io/browser/libs/0.0.2/middleware-rum.min.js",
  });
  await page.evaluate(() => {
    if (window.Middleware) {
      Middleware.track({
        serviceName: "Beta Frontend",
        projectName: "Beta Frontend",
        accountKey: "alzasaumkqafytzqfwprazolqijvpnmrunjc",
        target: "https://kbuin.beta.env.middleware.io",
        defaultAttributes: {
          "app.version": "1.0.0",
        },
      });
    }
  });

  // Loop through each step and execute it
  for (let i = 0; i < recording.steps.length; i++) {
    const step = recording.steps[i];
    console.log(`Executing step: ${step.name}`);

    let err = null;
    if (step.type === "navigate") {
      await page.goto(step.url);
    } else if (step.type === "click") {
      await page.click(step.selectors[2]);
    } else if (step.type === "input") {
      await page.fill(step.selector, step.value);
    }

    // Take screenshot after each step
    if (!err) {
      const stepName = `step_${i + 1}`;
      await takeScreenshot(page, stepName);
    }

    // Add step result to the report
    const stepReport = {
      step: step.name,
      status: err ? "failed" : "completed",
      error: err ? err.message : undefined,
    };
    report.steps.push(stepReport);
  }

  // Capture Web Vitals using playAudit (Lighthouse)
  // Extract Web Vitals from Lighthouse report

  const cummulativeLayoutShift = await page.evaluate(() => {
    return new Promise((resolve) => {
      let CLS = 0

      new PerformanceObserver((l) => {
        const entries = l.getEntries()

        entries.forEach(entry => {
          if (!entry.hadRecentInput) {
            CLS += entry.value
          }
        })

        resolve(CLS.toString())
      }).observe({
        type: 'layout-shift',
        buffered: true
      })
    })
  }, '0')


  const largestContentfulPaint = await page.evaluate(() => {
    return new Promise((resolve) => {
      new PerformanceObserver((l) => {
        const entries = l.getEntries()
        // the last entry is the largest contentful paint
        const largestPaintEntry = entries.at(-1)
        resolve(largestPaintEntry.startTime)
      }).observe({
        type: 'largest-contentful-paint',
        buffered: true
      })
    })
  })
  const webVitals = {
    LCP: largestContentfulPaint,
    CLS: cummulativeLayoutShift,
  };

  // Capture Resources and JS Errors
  const resources = await captureResources(page);
  const jsErrors = await captureJSErrors(page);

  report.webVitals = webVitals;
  report.resources = resources;
  report.jsErrors = jsErrors;

  // Save the final report
  fs.writeFileSync("test-report-firefox.json", JSON.stringify(report, null, 2));

  console.log("Test report generated: test-report-firefox.json");

  // Close the browser
  await browser.close();
})();
