export function getParameterByName(name, windowLocationSearch = window.location.search) {
    const urlSearchParams = new URLSearchParams(windowLocationSearch);
    return urlSearchParams.get(name);
}
