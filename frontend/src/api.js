const BASE_URL = "/api";

async function request(path, options) {
  const res = await fetch(`${BASE_URL}${path}`, options);
  if (!res.ok) {
    throw new Error(`Request to ${path} failed with status ${res.status}`);
  }
  return res.json();
}

export function runScan() {
  return request("/scan", { method: "POST" });
}

export function listScans() {
  return request("/scans");
}

export function getScan(scanId) {
  return request(`/scans/${scanId}`);
}

export function pdfUrl(scanId) {
  return `${BASE_URL}/scans/${scanId}/pdf`;
}
