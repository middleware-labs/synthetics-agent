import fs from "fs"
import path from "path";
import { fileURLToPath } from "url";
import { FAILED, PASSED, SKIPPED } from "./constant.js";
import { PuppeteerRunnerExtension } from "@puppeteer/replay";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export class Extension extends PuppeteerRunnerExtension {
  constructor(
    logger,
    testId,
    browser,
    page,
    options,
    config,
    cmdArgs,
    screenshotsUrl
  ) {
    super(browser, page, options);
    this.logger = logger;
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
    this.cmdArgs = cmdArgs;
    this.screenshotsUrl = screenshotsUrl;
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
    this.logger.info("starting");
  }

  async beforeEachStep(step, flow) {
    await super.beforeEachStep(step, flow);
    this.logger.info("before", step);
    this.stepCount += 1;
    step.result = {
      status: SKIPPED,
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
      this.testReport.result.result = FAILED;
      this.activeStep.result.status = FAILED;
      this.activeStep.result.error = e.message;
      this.activeStep.result.webVitals = [];
      this.activeStep.result.jsErrors = [];
      this.activeStep.result.jsWarn = [];
      this.activeStep.result.resources = [];
      if (this.cmdArgs.screenshots && !this.cmdArgs["no-screenshots"]) {
        await this.takeScreenshot(this.activeStep);
      }
      this.testReport.steps.push(this.activeStep);
      const skippedSteps = flow.steps.slice(
        flow.steps.indexOf(this.activeStep) + 1,
        flow.steps.length
      );
      skippedSteps.forEach((step) => {
        step.result.status = SKIPPED;
      });
      this.testReport.steps.push(...skippedSteps);
      this.testReport.result.duration = Math.round(
        performance.now() - this.testReport.startTime
      );
      this.testReport.result.failure = {
        message: e.message,
        code: e.name,
      };
      console.log(JSON.stringify(this.testReport));
      process.exit(0);
    }
  }

  async afterEachStep(step, flow) {
    await super.afterEachStep(step, flow);
    this.logger.info("after", step);
    step.result.screenshotUrl = "";
    if (this.cmdArgs["screenshots"] && !this.cmdArgs["no-screenshots"]) {
      await this.takeScreenshot(step);
    }
    const endTime = performance.now();
    step.result.duration = Math.round(endTime - step.result.startTime);
    step.result.resources = await this.captureResources(this.page);
    let webVitals = [];
    if (step.type === "navigate") {
      webVitals = await this.captureWebVitals(this.page);
      this.logger.info("Web Vitals:", webVitals);
    }
    step.result.rumContext = {
      sessionId: await this.page.evaluate(() => {
        return window.Middleware?.getSessionId();
      }),
    };
    step.result.jsErrors = [];
    step.result.jsWarn = [];
    step.result.webVitals = webVitals;
    step.result.status = PASSED;
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
    this.logger.info("done");
    this.testReport.duration = Math.round(
      performance.now() - this.testReport.startTime
    );
    console.log(JSON.stringify(this.testReport));
  }

  async takeScreenshot(step) {
    const screenshotDir = path.join(__dirname, "screenshots", this.testId);
    if (!fs.existsSync(screenshotDir)) {
      fs.mkdirSync(screenshotDir, { recursive: true });
    }

    const screenshotPath = path.join(
      screenshotDir,
      `step-${this.stepCount}.png`
    );
    await this.page.screenshot({ path: screenshotPath });
    step.result.screenshotUrl = this.screenshotsUrl[this.stepCount];
    this.logger.info(`Screenshot for step saved at ${screenshotPath}`);
  }
}
