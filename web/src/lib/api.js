// The relay, from the browser. One place for the fetch shape and the errors.

export class ApiError extends Error {
  constructor(status, code, message) {
    super(message)
    this.status = status
    this.code = code
  }
}

async function call(path, { method = 'GET', body } = {}) {
  const res = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  })

  const text = await res.text()
  let payload = null
  try {
    payload = text ? JSON.parse(text) : null
  } catch {
    throw new ApiError(res.status, 'bad_response', 'the relay sent something that was not JSON')
  }

  if (!res.ok) {
    throw new ApiError(res.status, payload?.error ?? 'error', payload?.message ?? res.statusText)
  }
  return payload
}

export const api = {
  me: () => call('/api/auth/me'),
  logout: () => call('/api/auth/logout', { method: 'POST' }),
  signets: () => call('/api/signets'),
  pairCode: () => call('/api/pair-code', { method: 'POST' }),
  claim: (requestId) => call('/api/claim', { method: 'POST', body: { request_id: requestId } }),
  approve: (requestId, signature) =>
    call('/api/approve', { method: 'POST', body: { request_id: requestId, signature } }),
  decline: (requestId) => call('/api/decline', { method: 'POST', body: { request_id: requestId } }),
  phones: () => call('/api/phones'),
  registerPhone: (phone) => call('/api/phones', { method: 'POST', body: phone }),
  forgetPhone: (deviceId) => call('/api/phones', { method: 'DELETE', body: { device_id: deviceId } }),
}
