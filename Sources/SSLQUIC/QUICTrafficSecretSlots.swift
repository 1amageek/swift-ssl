package struct QUICTrafficSecretSlots: ~Copyable, Sendable {
  private var readZeroRTT: QUICTrafficSecretEvent?
  private var writeZeroRTT: QUICTrafficSecretEvent?
  private var readHandshake: QUICTrafficSecretEvent?
  private var writeHandshake: QUICTrafficSecretEvent?
  private var readOneRTT: QUICTrafficSecretEvent?
  private var writeOneRTT: QUICTrafficSecretEvent?

  package init() {
    readZeroRTT = nil
    writeZeroRTT = nil
    readHandshake = nil
    writeHandshake = nil
    readOneRTT = nil
    writeOneRTT = nil
  }

  package mutating func insert(
    _ event: consuming QUICTrafficSecretEvent
  ) throws(QUICTLSStepOutputError) {
    let direction = event.direction
    let level = event.level

    guard !contains(direction: direction, level: level) else {
      throw .duplicateTrafficSecretStorage(
        direction: direction,
        level: level
      )
    }

    switch (direction, level) {
    case (.read, .zeroRTT):
      readZeroRTT = consume event
    case (.write, .zeroRTT):
      writeZeroRTT = consume event
    case (.read, .handshake):
      readHandshake = consume event
    case (.write, .handshake):
      writeHandshake = consume event
    case (.read, .oneRTT):
      readOneRTT = consume event
    case (.write, .oneRTT):
      writeOneRTT = consume event
    }
  }

  package borrowing func contains(
    direction: QUICSecretDirection,
    level: QUICTrafficSecretLevel
  ) -> Bool {
    switch (direction, level) {
    case (.read, .zeroRTT):
      readZeroRTT != nil
    case (.write, .zeroRTT):
      writeZeroRTT != nil
    case (.read, .handshake):
      readHandshake != nil
    case (.write, .handshake):
      writeHandshake != nil
    case (.read, .oneRTT):
      readOneRTT != nil
    case (.write, .oneRTT):
      writeOneRTT != nil
    }
  }

  package mutating func take(
    direction: QUICSecretDirection,
    level: QUICTrafficSecretLevel
  ) -> QUICTrafficSecretEvent? {
    switch (direction, level) {
    case (.read, .zeroRTT):
      readZeroRTT.take()
    case (.write, .zeroRTT):
      writeZeroRTT.take()
    case (.read, .handshake):
      readHandshake.take()
    case (.write, .handshake):
      writeHandshake.take()
    case (.read, .oneRTT):
      readOneRTT.take()
    case (.write, .oneRTT):
      writeOneRTT.take()
    }
  }
}
