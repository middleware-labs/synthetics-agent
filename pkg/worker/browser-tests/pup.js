import { createRunner } from "@puppeteer/replay";
import commandLineArgs from "command-line-args";
import cookie from "cookie";
import fs from "fs";
import puppeteer from "puppeteer";
import {
  DEVICE_VIEWPORT_MAPPING,
  FAILED,
  SKIPPED
} from "./constant.js";
import { CustomLogger } from "./CustomLogger.js";
import { Extension } from "./Extension.js";
import { generateBrowserArgs, initOnDocumentLoadScript } from "./util.js";

(async function run() {
  const optionDefinitions = [
    { name: "debug", type: Boolean, defaultValue: false },
    { name: "browser", alias: "b", type: String },
    { name: "testId", alias: "i", type: String },
    { name: "recording", alias: "j", type: String },
    { name: "collectRum", type: Boolean },
    { name: "region", alias: "r", type: String },
    { name: "device", alias: "d", type: String },
    { name: "ignore-certificate-errors", type: Boolean },
    { name: "screenshots", alias: "s", type: Boolean, defaultValue: true },
    { name: "no-screenshots", type: Boolean },
    { name: "proxy-server", alias: "p", type: String },
    { name: "username", type: String },
    { name: "password", type: String },
    { name: "disableCors", type: Boolean },
    { name: "disableCsp", type: Boolean },
    { name: "headers", type: String },
    { name: "waitTimeout", type: Number, defaultValue: 0 },
    { name: "sslCertificatePrivateKey", type: String },
    { name: "sslCertificate", type: String },
    { name: "screenshotsUrl", type: String },
  ];

  const cmdArgs = commandLineArgs(optionDefinitions);
  const logger = new CustomLogger(cmdArgs);
  const testId = cmdArgs.testId;
  if (!testId) {
    logger.error("Test ID is required");
    process.exit(1);
  }
  logger.info(cmdArgs);

  const browserArgs = generateBrowserArgs(cmdArgs);
  const decidedBrowser = cmdArgs.browser || "chrome";
  const launchArgs = JSON.stringify({ stealth: true, args: browserArgs });

  const browser = await puppeteer.connect({
    browserWSEndpoint: `ws://localhost:3000/?launch=${launchArgs}`,    
    defaultViewport: null,
    acceptInsecureCerts: cmdArgs["ignore-certificate-errors"] || false,
  });

  const page = await browser.newPage();
  const recordingFile = fs.readFileSync(cmdArgs.recording, "utf8");
  const recording = JSON.parse(recordingFile);
  recording.testId = testId;
  recording.steps = recording.steps.map((step) => {
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

    return step;
  });

  if (cmdArgs["timezone"]) {
    await page.emulateTimezone(cmdArgs["timezone"]);
  }

  if (cmdArgs["language"]) {
    await page.setExtraHTTPHeaders({
      "Accept-Language": cmdArgs["language"],
    });
  }

  if (cmdArgs["username"] && cmdArgs["password"]) {
    await page.authenticate({
      username: cmdArgs["username"],
      password: cmdArgs["password"],
    });
  }

  if (cmdArgs["cookies"]) {
    const cookiesList = cmdArgs["cookies"].split(",");
    const kookies = cookiesList.map((kookie) => cookie.parse(kookie));
    await browser.setCookie(...kookies);
  }

  if (cmdArgs["disableCsp"]) {
    await page.setBypassCSP(true);
  }

  if (cmdArgs["headers"]) {
    try {
      const headers = JSON.parse(cmdArgs["headers"]);
      await page.setExtraHTTPHeaders(headers);
    } catch (e) {}
  }
  let screenshotsUrls = [];
  if (cmdArgs["screenshotsUrl"]) {
    screenshotsUrls = cmdArgs.screenshotsUrl.split(",");
  }

  await page.evaluateOnNewDocument(initOnDocumentLoadScript, cmdArgs);

  const userAgent = await page.evaluate(() => navigator.userAgent);

  const extension = new Extension(
    logger,
    testId,
    browser,
    page,
    { timeout: cmdArgs["waitTimeout"] },
    {
      region: cmdArgs.region,
      device: { ...DEVICE_VIEWPORT_MAPPING[decidedBrowser], userAgent },
    },
    cmdArgs,
    screenshotsUrls
  );
  const runner = await createRunner(recording, extension);
  await page.on("console", (msg) => {
    if (extension.activeStep === null) {
      return;
    }
    logger.info(extension.activeStep);
    logger.info(`[Console][${msg.type()}] ${msg.text()}`);
    if (msg.type() === "error") {
      extension.activeStep.result.jsErrors.push(msg.text());
    } else if (msg.type() === "warn") {
      extension.activeStep.result.jsWarn.push(msg.text());
    }
  });
  await runner.run();
  try {
  } catch (e) {
    logger.error(e);
    extension.activeStep.result.status = FAILED;
    extension.activeStep.result.error = e.message;
    extension.activeStep.result.webVitals = [];
    extension.activeStep.result.jsErrors = [];
    extension.activeStep.result.jsWarn = [];
    extension.activeStep.result.resources = [];
    if (cmdArgs.screenshots && !cmdArgs["no-screenshots"]) {
      await extension.takeScreenshot(extension.activeStep);
    }
    extension.testReport.steps.push(extension.activeStep);
    const skippedSteps = recording.steps.slice(
      recording.steps.indexOf(extension.activeStep) + 1,
      recording.steps.length
    );
    skippedSteps.forEach((step) => {
      step.result.status = SKIPPED;
    });
    extension.testReport.steps.push(...skippedSteps);
    extension.testReport.duration = Math.round(
      performance.now() - extension.testReport.startTime
    );
    extension.testReport.failure = {
      message: e.message,
      code: e.name,
    };
    console.log(JSON.stringify(extension.testReport));
  } finally {
    await browser.close();
  }
})();
process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception:", err);
  process.exit(1);
});
