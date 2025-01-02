import { createRunner, PuppeteerRunnerExtension } from "@puppeteer/replay";
import puppeteer, { Browser } from "puppeteer";
import fs, { stat } from "fs";
import path from "path";
import commandLineArgs from "command-line-args";
import { type } from "os";

class Extension extends PuppeteerRunnerExtension {
  constructor(testId, browser, page, options, config) {
    super(browser, page, options);
    this.activeStep = null;
    this.testId = testId;
    this.testReport = {
      config,
      testId,
      steps: [],
      startTime: performance.now(),
      duration: 0,
    };
    this.stepCount = -1;
  }

  async captureResources(page) {
    const newResources = await page.evaluate(() => {
      const resources = window.resources;
      window.resources = []; // Clear after reading
      return resources;
    });

    return newResources;
  }

  async beforeAllSteps(flow) {
    await super.beforeAllSteps(flow);
    console.log("starting");
  }

  async beforeEachStep(step, flow) {
    await super.beforeEachStep(step, flow);
    console.log("before", step);
    this.stepCount += 1;
    step.result = {
      status: "SKIPPED",
      jsErrors: [],
      jsWarn: [],
      resources: [],
      webVitals: [],
      screenshotUrl: "",
      description: step.type,
      duration: 0,
    };
    step.result.startTime = performance.now();
    this.activeStep = step;
  }

  async captureWebVitals(page) {
    const vitals = await page.evaluate(() => {
      return [
        {
          cls: window.cumulativeLayoutShiftScore,
          lcp: window.largestContentfulPaintScore,
        },
      ];
    });
    return vitals;
  }

  async runStep(step, flow) {
    try {
      if (step.type === "navigate") {
        step.timeout = 60000;
      }
      await super.runStep(step, flow);
    } catch (e) {
      console.error("After Step error", e);
      this.activeStep.result.status = "FAILED";
      this.activeStep.result.error = e.message;
      this.activeStep.result.webVitals = [];
      this.activeStep.result.jsErrors = [];
      this.activeStep.result.jsWarn = [];
      this.activeStep.result.resources = [];
      await this.takeScreenshot(this.activeStep);
      this.testReport.steps.push(this.activeStep);
      const skippedSteps = flow.steps.slice(
        flow.steps.indexOf(this.activeStep) + 1,
        flow.steps.length
      );
      skippedSteps.forEach((step) => {
        step.result.status = "SKIPPED";
      });
      this.testReport.steps.push(...skippedSteps);
      this.testReport.duration = Math.round(
        performance.now() - this.testReport.startTime
      );
      this.testReport.failure = {
        message: e.message,
        code: e.name,
      };
      saveReport(this.testReport);
      console.log(JSON.stringify(this.testReport));
      process.exit(1);
    }
  }

  async afterEachStep(step, flow) {
    await super.afterEachStep(step, flow);
    console.log("after", step);
    await this.takeScreenshot(step);
    const endTime = performance.now();
    step.result.duration = Math.round(endTime - step.result.startTime);
    step.result.resources = await this.captureResources(this.page);
    let webVitals = [];
    if (step.type === "navigate") {
      webVitals = await this.captureWebVitals(this.page);
      console.log("Web Vitals:", webVitals);
    }
    step.result.rumContext = {
      sessionId: await this.page.evaluate(() => {
        return window.Middleware?.getSessionId();
      }),
    };
    step.result.jsErrors = [];
    step.result.jsWarn = [];
    step.result.webVitals = webVitals;
    step.result.status = "PASSED";
    step.result.description =
      step.title || `${step.type} ${step.url || step.key || step.value}`;
    await this.page.evaluate(() => {
      console.error("error");
    });
    await this.page.evaluate(() => {
      console.warn("warn");
    });
    this.testReport.steps.push(step);
  }

  async afterAllSteps(flow) {
    await super.afterAllSteps(flow);
    console.log("done");
    this.testReport.duration = Math.round(
      performance.now() - this.testReport.startTime
    );
    saveReport(this.testReport);
  }

  async takeScreenshot(step) {
    const screenshotDir = path.join("screenshots", this.testId);
    if (!fs.existsSync(screenshotDir)) {
      fs.mkdirSync(screenshotDir, { recursive: true });
    }

    const screenshotPath = path.join(
      screenshotDir,
      `${step.name || `step-${this.stepCount}`}_${Date.now()}.png`
    );
    await this.page.screenshot({ path: screenshotPath });
    step.result.screenshotUrl = screenshotPath;
    console.log(`Screenshot for step saved at ${screenshotPath}`);
  }
}

function calcJank(cmdArgs) {
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

function saveReport(data) {
  const reportPath = path.join("test-report.json");
  fs.writeFileSync(reportPath, JSON.stringify(data, null, 2));
  console.log("Test report generated:", reportPath);
}

(async function run() {
  const optionDefinitions = [
    { name: "browser", alias: "b", type: String },
    { name: "checkId", alias: "i", type: String },
    { name: "collectRum", type: Boolean },
    { name: "region", alias: "r", type: String },
  ];

  const cmdArgs = commandLineArgs(optionDefinitions);

  const browser = await puppeteer.launch({
    browser: cmdArgs.browser || "chrome",
    headless: false,
  });

  if (!cmdArgs.checkId) {
    console.error("Check ID is required");
    process.exit(1);
  }
  const testId = `${cmdArgs.checkId}-${
    cmdArgs.region || "default"
  }-${Date.now()}`;

  const page = await browser.newPage();
  const recordingFile = fs.readFileSync(
    "/home/archish/code/synthetics-agent/pkg/worker/browser-tests/recording1.json",
    "utf8"
  );
  const recording = JSON.parse(recordingFile);
  recording.testId = testId;
  recording.steps = recording.steps.map((step) => {
    step.result = {
      status: "SKIPPED",
      jsErrors: [],
      jsWarn: [],
      resources: [],
      webVitals: [],
      screenshotUrl: "",
      description: step.type,
      duration: 0,
    };

    return step;
  });
  await page.evaluateOnNewDocument(calcJank, cmdArgs);

  const userAgent = await page.evaluate(() => navigator.userAgent);

  const extension = new Extension(
    testId,
    browser,
    page,
    { timeout: 0 },
    {
      region: cmdArgs.region,
      device: {
        browser: cmdArgs.browser || "chrome",
        userAgent,
        isMobile: false,
      },
    }
  );
  const runner = await createRunner(recording, extension);
  await page.on("console", (msg) => {
    if (extension.activeStep === null) {
      return;
    }
    console.log(extension.activeStep);
    console.log(`[Console][${msg.type()}] ${msg.text()}`);
    if (msg.type() === "error") {
      extension.activeStep.result.jsErrors.push(msg.text());
    } else if (msg.type() === "warn") {
      extension.activeStep.result.jsWarn.push(msg.text());
    }
  });
  await runner.run();
  try {
  } catch (e) {
    console.error(e);
    extension.activeStep.result.status = "FAILED";
    extension.activeStep.result.error = e.message;
    extension.activeStep.result.webVitals = [];
    extension.activeStep.result.jsErrors = [];
    extension.activeStep.result.jsWarn = [];
    extension.activeStep.result.resources = [];
    await extension.takeScreenshot(extension.activeStep);
    extension.testReport.steps.push(extension.activeStep);
    const skippedSteps = recording.steps.slice(
      recording.steps.indexOf(extension.activeStep) + 1,
      recording.steps.length
    );
    skippedSteps.forEach((step) => {
      step.result.status = "SKIPPED";
    });
    extension.testReport.steps.push(...skippedSteps);
    extension.testReport.duration = Math.round(
      performance.now() - extension.testReport.startTime
    );
    extension.testReport.failure = {
      message: e.message,
      code: e.name,
    };
    saveReport(extension.testReport);
  } finally {
    await browser.close();
  }
})();
process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception:", err);
  process.exit(1);
});
