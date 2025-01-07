export const BROWSER_EXECUTABLE_PATH_MAPPING = {
  chrome: "/usr/bin/google-chrome",
  edge: "/usr/bin/microsoft-edge",
  firefox: "/usr/bin/firefox",
};

export const DEVICE_VIEWPORT_MAPPING = {
  laptop: {
    width: "1440",
    height: "1100",
  },
  tablet: {
    width: "768",
    height: "1020",
  },
  mobile: {
    width: "320",
    height: "550",
    isMobile: true,
  },
};

export const SKIPPED = "SKIPPED";
export const PASSED = "PASSED";
export const FAILED = "FAILED";
