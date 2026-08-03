public enum DTLS13CookieError: Error, Sendable, Equatable {
  case invalidConfiguration
  case malformedCookie
  case authenticationFailed
  case expired
  case cryptographicFailure
}
