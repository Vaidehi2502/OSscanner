/**
 * api.js reads process.env.REACT_APP_API_KEY once at module import time, so
 * each test that needs a specific value sets the env var and reloads the
 * module fresh with jest.resetModules() + require() rather than importing
 * api.js normally at the top of this file.
 */

function mockFetchOnce(body, { ok = true, status = 200, headers = {} } = {}) {
  global.fetch = jest.fn().mockResolvedValue({
    ok,
    status,
    json: () => Promise.resolve(body),
    headers: { get: (name) => headers[name] ?? null },
    blob: () => Promise.resolve(new Blob([JSON.stringify(body)])),
  });
}

function loadApiWithKey(key) {
  jest.resetModules();
  if (key === undefined) {
    delete process.env.REACT_APP_API_KEY;
  } else {
    process.env.REACT_APP_API_KEY = key;
  }
  return require("./api");
}

afterEach(() => {
  delete process.env.REACT_APP_API_KEY;
  jest.resetModules();
  jest.restoreAllMocks();
});

test("runScan posts to /api/scan and returns the parsed JSON", async () => {
  const { runScan } = loadApiWithKey(undefined);
  mockFetchOnce({ risk_score: 42 });

  const result = await runScan();

  expect(global.fetch).toHaveBeenCalledWith("/api/scan", expect.objectContaining({ method: "POST" }));
  expect(result).toEqual({ risk_score: 42 });
});

test("listScans and getScan hit the expected paths", async () => {
  const { listScans, getScan } = loadApiWithKey(undefined);

  mockFetchOnce([{ id: 1 }]);
  await listScans();
  expect(global.fetch).toHaveBeenCalledWith("/api/scans", expect.anything());

  mockFetchOnce({ id: 5 });
  await getScan(5);
  expect(global.fetch).toHaveBeenCalledWith("/api/scans/5", expect.anything());
});

test("getMonitorStatus hits the expected path", async () => {
  const { getMonitorStatus } = loadApiWithKey(undefined);
  mockFetchOnce({ enabled: false, interval_seconds: 0 });

  const result = await getMonitorStatus();

  expect(global.fetch).toHaveBeenCalledWith("/api/monitor", expect.anything());
  expect(result).toEqual({ enabled: false, interval_seconds: 0 });
});

test("throws with the status code when the response is not ok", async () => {
  const { getScan } = loadApiWithKey(undefined);
  mockFetchOnce({}, { ok: false, status: 404 });

  await expect(getScan(999)).rejects.toThrow("404");
});

test("attaches X-API-Key when REACT_APP_API_KEY is configured", async () => {
  const { listScans } = loadApiWithKey("test-secret-123");
  mockFetchOnce([]);

  await listScans();

  const [, options] = global.fetch.mock.calls[0];
  expect(options.headers["X-API-Key"]).toBe("test-secret-123");
});

test("does not attach X-API-Key when not configured", async () => {
  const { listScans } = loadApiWithKey(undefined);
  mockFetchOnce([]);

  await listScans();

  const [, options] = global.fetch.mock.calls[0];
  expect(options.headers["X-API-Key"]).toBeUndefined();
});

test("downloadPdf fetches with the auth header and triggers a Blob download using the server's filename", async () => {
  const { downloadPdf } = loadApiWithKey("test-secret-123");

  const blob = new Blob(["pdf-bytes"]);
  global.fetch = jest.fn().mockResolvedValue({
    ok: true,
    blob: () => Promise.resolve(blob),
    headers: { get: (name) => (name === "Content-Disposition" ? 'attachment; filename="scan_5.pdf"' : null) },
  });

  const createObjectURL = jest.fn().mockReturnValue("blob:mock-url");
  const revokeObjectURL = jest.fn();
  window.URL.createObjectURL = createObjectURL;
  window.URL.revokeObjectURL = revokeObjectURL;
  const clickSpy = jest.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

  await downloadPdf(5);

  expect(global.fetch).toHaveBeenCalledWith("/api/scans/5/pdf", { headers: { "X-API-Key": "test-secret-123" } });
  expect(createObjectURL).toHaveBeenCalledWith(blob);
  expect(clickSpy).toHaveBeenCalledTimes(1);
  expect(revokeObjectURL).toHaveBeenCalledWith("blob:mock-url");
});

test("downloadPdf falls back to a default filename when Content-Disposition is missing", async () => {
  const { downloadPdf } = loadApiWithKey(undefined);

  const blob = new Blob(["pdf-bytes"]);
  global.fetch = jest.fn().mockResolvedValue({
    ok: true,
    blob: () => Promise.resolve(blob),
    headers: { get: () => null },
  });
  window.URL.createObjectURL = jest.fn().mockReturnValue("blob:mock-url");
  window.URL.revokeObjectURL = jest.fn();
  const clickSpy = jest.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

  await downloadPdf(5);

  expect(clickSpy).toHaveBeenCalledTimes(1);
});

test("downloadPdf throws when the response is not ok", async () => {
  const { downloadPdf } = loadApiWithKey(undefined);
  global.fetch = jest.fn().mockResolvedValue({ ok: false, status: 401 });

  await expect(downloadPdf(5)).rejects.toThrow("401");
});
