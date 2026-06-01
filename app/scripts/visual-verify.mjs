import { spawn } from "node:child_process";
import { access, mkdir, writeFile } from "node:fs/promises";
import { once } from "node:events";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

import { firefox } from "@playwright/test";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");
const outputDir = path.join(repoRoot, "visual-artifacts");
const previewUrl = "http://127.0.0.1:4173";
const distIndexPath = path.join(repoRoot, "dist", "index.html");
const layoutStorageKey = "files.workbench.layout.v1";
const viewports = [
  { width: 1366, height: 768 },
  { width: 1600, height: 900 },
  { width: 1920, height: 1080 },
];

await access(distIndexPath).catch(() => {
  throw new Error("Build output is missing. Run `npm run build` before `npm run test:visual`.");
});

await mkdir(outputDir, { recursive: true });

const server = spawn(
  process.platform === "win32" ? "cmd.exe" : "npm",
  process.platform === "win32"
    ? ["/d", "/s", "/c", "npm run preview -- --host 127.0.0.1 --port 4173"]
    : ["run", "preview", "--", "--host", "127.0.0.1", "--port", "4173"],
  {
    cwd: repoRoot,
    stdio: ["ignore", "pipe", "pipe"],
    env: process.env,
  },
);

let serverOutput = "";
server.stdout.on("data", (chunk) => {
  serverOutput += chunk.toString();
});
server.stderr.on("data", (chunk) => {
  serverOutput += chunk.toString();
});

const metrics = [];

try {
  await waitForPreview(previewUrl, server);

  const browser = await firefox.launch({
    headless: true,
  }).catch((error) => {
    throw new Error(`Firefox could not be launched. Run \`npx playwright install firefox\`.\n${String(error)}`);
  });

  try {
    for (const viewport of viewports) {
      const context = await browser.newContext({
        viewport,
        colorScheme: "dark",
        deviceScaleFactor: 1,
        reducedMotion: "reduce",
      });
      const page = await context.newPage();

      await page.goto(previewUrl, { waitUntil: "networkidle" });
      await page.locator("[data-testid='workbench-toolbar']").waitFor();
      await page.locator("[data-testid='browser-workbench']").waitFor();

      const baselineMetrics = await collectMetrics(page);
      assertViewportFit(baselineMetrics, viewport);
      await assertNoRowOverlap(page, "[data-testid='tree-entry-row']", `tree baseline ${viewport.width}x${viewport.height}`);
      await assertNoRowOverlap(
        page,
        "[data-testid='browser-list-row'], [data-testid='browser-deleted-row']",
        `browser baseline ${viewport.width}x${viewport.height}`,
      );

      const screenshotPath = path.join(outputDir, `workbench-${viewport.width}x${viewport.height}.png`);
      await page.screenshot({ path: screenshotPath, animations: "disabled" });

      let splitMetrics = null;
      let browserMetrics = null;
      let zoomMetrics = null;
      if (viewport.width === 1600) {
        splitMetrics = await exerciseSplitters(page);
        assertViewportFit(splitMetrics, viewport);
        browserMetrics = await exerciseBrowserInteractions(page);
        await assertNoRowOverlap(page, "[data-testid='tree-entry-row']", "tree after browser interactions");
        await assertNoRowOverlap(
          page,
          "[data-testid='browser-list-row'], [data-testid='browser-deleted-row']",
          "browser after interactions",
        );
        zoomMetrics = await exerciseZoom(page);
        await page.screenshot({
          path: path.join(outputDir, "workbench-1600x900-split.png"),
          animations: "disabled",
        });
      }

      metrics.push({
        viewport,
        baseline: baselineMetrics,
        split: splitMetrics,
        browser: browserMetrics,
        zoom: zoomMetrics,
      });

      await context.close();
    }
  } finally {
    await browser.close();
  }

  await writeFile(path.join(outputDir, "workbench-metrics.json"), JSON.stringify(metrics, null, 2), "utf8");
  process.stdout.write(`Visual verification screenshots saved to ${outputDir}\n`);
} catch (error) {
  const details = `${String(error)}\n\nPreview output:\n${serverOutput || "(no output)"}`;
  throw new Error(details);
} finally {
  await stopServer(server);
}

async function waitForPreview(url, serverProcess) {
  const deadline = Date.now() + 20_000;

  while (Date.now() < deadline) {
    if (serverProcess.exitCode != null) {
      throw new Error(`Preview server exited early with code ${serverProcess.exitCode}.`);
    }

    try {
      const response = await fetch(url);
      if (response.ok) {
        return;
      }
    } catch {
    }

    await delay(500);
  }

  throw new Error("Preview server did not become ready.");
}

async function collectMetrics(page) {
  return await page.evaluate((storageKey) => {
    const layout = window.localStorage.getItem(storageKey);
    return {
      title: document.title,
      innerWidth: window.innerWidth,
      innerHeight: window.innerHeight,
      bodyScrollWidth: document.body.scrollWidth,
      bodyScrollHeight: document.body.scrollHeight,
      documentScrollWidth: document.documentElement.scrollWidth,
      documentScrollHeight: document.documentElement.scrollHeight,
      separatorCount: document.querySelectorAll("[role='separator']").length,
      layout,
    };
  }, layoutStorageKey);
}

function assertViewportFit(metrics, viewport) {
  if (metrics.separatorCount < 2) {
    throw new Error(`Expected two splitters for ${viewport.width}x${viewport.height}, found ${metrics.separatorCount}.`);
  }

  if (metrics.bodyScrollWidth > viewport.width + 1 || metrics.documentScrollWidth > viewport.width + 1) {
    throw new Error(`Workbench overflowed horizontally at ${viewport.width}x${viewport.height}.`);
  }

  if (metrics.bodyScrollHeight > viewport.height + 1 || metrics.documentScrollHeight > viewport.height + 1) {
    throw new Error(`Workbench overflowed vertically at ${viewport.width}x${viewport.height}.`);
  }
}

async function exerciseSplitters(page) {
  const splitters = page.locator("[role='separator']");
  await dragSplitter(page, splitters.nth(0), 84, 0);
  await dragSplitter(page, splitters.nth(1), 0, -96);
  await delay(250);
  return await collectMetrics(page);
}

async function exerciseBrowserInteractions(page) {
  const sourceSelect =
    (await page.locator("[data-testid='source-select']").count()) > 0
      ? page.locator("[data-testid='source-select']")
      : page.locator("select").first();
  await sourceSelect.selectOption("vol-d");
  await page.locator("[data-testid='load-source']").click();
  await page.locator("[data-testid='browser-list-row']").first().waitFor();
  await page.locator("[data-testid='browser-list-row']").filter({ hasText: "evidence" }).first().dblclick();
  await page.locator("[data-testid='browser-status']").waitFor();
  await page.locator("[data-testid='browser-status']").waitFor({ state: "visible" });
  const initialStatus = (await page.locator("[data-testid='browser-status']").textContent())?.trim() ?? "";

  const evidenceTreeRow = page.locator("[data-testid='tree-entry-row']").filter({ hasText: "evidence" }).first();
  const treeRowCountBeforeExpand = await page.locator("[data-testid='tree-entry-row']").count();
  if (await evidenceTreeRow.count()) {
    await evidenceTreeRow.locator("[data-testid='tree-expand']").click();
    await delay(300);
    const treeRowCountAfterExpand = await page.locator("[data-testid='tree-entry-row']").count();
    if (treeRowCountAfterExpand < treeRowCountBeforeExpand) {
      throw new Error("Tree row count regressed after expanding the evidence node.");
    }
  }

  const treeBefore = await page.locator("[data-testid='source-tree']").evaluate((element) => {
    element.scrollTop = element.scrollHeight;
    element.dispatchEvent(new Event("scroll"));
    return {
      clientHeight: element.clientHeight,
      scrollHeight: element.scrollHeight,
      scrollTop: element.scrollTop,
      scrollable: element.scrollHeight > element.clientHeight,
    };
  });

  if (await page.locator("[data-testid='tree-load-more']").count()) {
    const treeLoadMore = page.locator("[data-testid='tree-load-more']").first();
    await treeLoadMore.click();
    await page.waitForFunction(
      () => document.querySelectorAll("[data-testid='tree-load-more']").length === 0,
    );
  }

  const loadMoreButton = page.locator("[data-testid='browser-list-load-more']");
  let afterLoadMoreStatus = initialStatus;
  if (await loadMoreButton.count()) {
    await loadMoreButton.first().click();
    await waitForLoadedCount(page, (loaded) => loaded > 256);
    afterLoadMoreStatus = (await page.locator("[data-testid='browser-status']").textContent())?.trim() ?? "";
  }

  const listMetrics = await page.locator("[data-testid='browser-list']").evaluate((element) => {
    element.scrollTop = element.scrollHeight;
    element.dispatchEvent(new Event("scroll"));
    const bottom = element.scrollTop;
    element.scrollTop = 0;
    element.dispatchEvent(new Event("scroll"));
    return {
      clientHeight: element.clientHeight,
      scrollHeight: element.scrollHeight,
      bottomScrollTop: bottom,
      resetScrollTop: element.scrollTop,
      scrollable: element.scrollHeight > element.clientHeight,
    };
  });

  return {
    initialStatus,
    afterLoadMoreStatus,
    tree: treeBefore,
    list: listMetrics,
  };
}

async function exerciseZoom(page) {
  const hasZoomTestId = (await page.locator("[data-testid='zoom-controls']").count()) > 0;
  const zoomLabel = hasZoomTestId
    ? page.locator("[data-testid='zoom-controls'] button").nth(1)
    : page.getByRole("button", { name: /\d+%/ }).first();
  const zoomIncreaseButton = hasZoomTestId
    ? page.locator("[data-testid='zoom-controls'] button").nth(2)
    : page.getByRole("button", { name: "+" }).first();

  await dispatchZoomKey(page, "=");
  await waitForZoomLabel(zoomLabel, "110%");

  await dispatchZoomKey(page, "-");
  await waitForZoomLabel(zoomLabel, "100%");

  await dispatchZoomWheel(page, -120);
  await waitForZoomLabel(zoomLabel, "110%");

  await dispatchZoomKey(page, "0");
  await waitForZoomLabel(zoomLabel, "100%");

  await zoomIncreaseButton.click();
  await waitForZoomLabel(zoomLabel, "110%");

  await page.reload({ waitUntil: "networkidle" });
  await page.locator("[data-testid='workbench-toolbar']").waitFor();
  const persistedZoomLabel =
    (await page.locator("[data-testid='zoom-controls']").count()) > 0
      ? page.locator("[data-testid='zoom-controls'] button").nth(1)
      : page.getByRole("button", { name: /\d+%/ }).first();
  await waitForZoomLabel(persistedZoomLabel, "110%");

  return {
    persistedZoom: (await persistedZoomLabel.textContent())?.trim() ?? "",
    storedZoom: await page.evaluate(() => window.localStorage.getItem("files.workbench.zoom.v1")),
  };
}

async function dispatchZoomKey(page, key) {
  await page.evaluate((pressedKey) => {
    window.dispatchEvent(
      new KeyboardEvent("keydown", {
        key: pressedKey,
        ctrlKey: true,
        bubbles: true,
        cancelable: true,
      }),
    );
  }, key);
}

async function dispatchZoomWheel(page, deltaY) {
  await page.evaluate((wheelDelta) => {
    window.dispatchEvent(
      new WheelEvent("wheel", {
        deltaY: wheelDelta,
        ctrlKey: true,
        bubbles: true,
        cancelable: true,
      }),
    );
  }, deltaY);
}

async function waitForZoomLabel(locator, expected) {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const value = (await locator.textContent())?.trim();
    if (value === expected) {
      return;
    }
    await delay(100);
  }
  throw new Error(`Zoom label did not reach ${expected}.`);
}

async function waitForLoadedCount(page, predicate) {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const status = (await page.locator("[data-testid='browser-status']").textContent())?.trim() ?? "";
    const match = status.match(/^(?:\d+\s+matching\s+•\s+)?(\d+)\/(\d+)\s+live(?:\s+•\s+(\d+)\/(\d+)\s+deleted)?$/);
    if (match) {
      const loaded = Number.parseInt(match[1], 10);
      const total = Number.parseInt(match[2], 10);
      if (predicate(loaded, total)) {
        return;
      }
    }
    await delay(100);
  }
  throw new Error("Browser status did not report the expected loaded-count change.");
}

async function assertNoRowOverlap(page, selector, label) {
  const rows = await page.locator(selector).evaluateAll((nodes) =>
    nodes
      .map((node) => {
        const rect = node.getBoundingClientRect();
        return {
          top: rect.top,
          bottom: rect.bottom,
          height: rect.height,
          width: rect.width,
          visible: rect.height > 0 && rect.bottom > 0 && rect.top < window.innerHeight,
          text: (node.textContent ?? "").trim().slice(0, 120),
        };
      })
      .filter((row) => row.visible)
      .sort((left, right) => left.top - right.top),
  );

  for (let index = 1; index < rows.length; index += 1) {
    const previous = rows[index - 1];
    const current = rows[index];
    if (current.top < previous.bottom - 1) {
      throw new Error(
        `${label} contains overlapping rows: "${previous.text}" overlaps "${current.text}" (${previous.bottom} > ${current.top}).`,
      );
    }
  }
}

async function dragSplitter(page, locator, deltaX, deltaY) {
  const box = await locator.boundingBox();
  if (!box) {
    throw new Error("Splitter bounding box was not available.");
  }

  const originX = box.x + box.width / 2;
  const originY = box.y + box.height / 2;
  await page.mouse.move(originX, originY);
  await page.mouse.down();
  await page.mouse.move(originX + deltaX, originY + deltaY, { steps: 12 });
  await page.mouse.up();
}

async function stopServer(serverProcess) {
  if (serverProcess.exitCode != null) {
    return;
  }

  if (process.platform === "win32") {
    const killer = spawn("taskkill", ["/pid", String(serverProcess.pid), "/t", "/f"], {
      stdio: "ignore",
      windowsHide: true,
    });
    await once(killer, "exit");
  } else {
    serverProcess.kill("SIGTERM");
    await Promise.race([once(serverProcess, "exit"), delay(1_500)]);
    if (serverProcess.exitCode == null) {
      serverProcess.kill("SIGKILL");
      await once(serverProcess, "exit");
    }
  }

  serverProcess.stdout?.destroy();
  serverProcess.stderr?.destroy();
}
