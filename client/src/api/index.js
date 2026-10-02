// The origin generiek's backend is reachable at, when the client is deployed on a different origin
// than the API (e.g. a separate static host). Empty means relative /api/... paths, which work when the
// dev server proxies /api (see vite.config.mjs) or when client and API share an origin in production.
const API_BASE = import.meta.env.VITE_API_BASE_URL || "";

function validateResponse(res) {
    if (!res.ok) {
        throw res;
    }
    return res.json();
}

function fetchJson(path, options = {}) {
    options.headers = {
        Accept: "application/json",
        "Content-Type": "application/json",
        ...options.headers
    };
    return fetch(`${API_BASE}${path}`, options).then(validateResponse);
}

export function studentDetails(correlationID) {
    return fetchJson(`/api/student-details?correlationID=${encodeURIComponent(correlationID)}`);
}

export function submitStudentDetails(form) {
    return fetchJson("/api/student-details", {method: "POST", body: JSON.stringify(form)});
}

// Not fetched with JS - handed to the browser as a plain download link so it can stream the PDF
// straight to disk using the filename from the Content-Disposition header.
export function customAgreementUrl(correlationID) {
    return `${API_BASE}/api/leerovereenkomst?correlationID=${encodeURIComponent(correlationID)}`;
}
