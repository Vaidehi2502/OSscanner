const BASE_URL = "/api";
const API_KEY = process.env.REACT_APP_API_KEY;

function authHeaders() {
  return API_KEY ? { "X-API-Key": API_KEY } : {};
}

async function request(path, options = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers: { ...authHeaders(), ...(options.headers || {}) },
  });
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

// A plain <a href> can't carry the X-API-Key header, so the PDF is fetched
// here (with the header) and handed to the browser as a Blob download
// instead of linking directly to the API URL.
export async function downloadPdf(scanId) {
  const res = await fetch(`${BASE_URL}/scans/${scanId}/pdf`, { headers: authHeaders() });
  if (!res.ok) {
    throw new Error(`Request to /scans/${scanId}/pdf failed with status ${res.status}`);
  }

  const blob = await res.blob();
  const disposition = res.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename="?([^"]+)"?/);
  const filename = match ? match[1] : `scan_${scanId}.pdf`;

  const url = window.URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
}
