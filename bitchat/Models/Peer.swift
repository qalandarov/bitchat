//
// Peer.swift
// BitLogger
//
// This is free and unencumbered software released into the public domain.
// For more information, see <https://unlicense.org>
//

import Foundation
import struct CryptoKit.SHA256

struct Peer: Equatable, Hashable {
    let id: String
    
    static let empty = Peer(str: "")
}

extension Peer {
    var data: Data? {
        id.data(using: .utf8)
    }
    
    /// Returns true if `id` starts with "`nostr`"
    var isNostr: Bool {
        id.hasPrefix("nostr")
    }
    
    /// Returns true if `id` starts with "`nostr:`"
    var isNostrColon: Bool {
        id.hasPrefix("nostr:")
    }
    
    /// Returns true if `id` starts with "`nostr_`"
    var isNostrUnderscore: Bool {
        id.hasPrefix("nostr_")
    }
}

// MARK: - Validation

extension Peer {
    private enum Constants {
        static let maxIDLength = 64
        static let hexIDLength = 16 // 8 bytes = 16 hex chars
    }
    
    /// Validates a peer ID from any source (short 16-hex, full 64-hex, or internal alnum/-/_ up to 64)
    var isValid: Bool {
        // Accept short routing IDs (exact 16-hex) or Full Noise key hex (exact 64-hex)
        if isShort || isNoiseKeyHex {
            return true
        }
        
        // If length equals short or full but isn't valid hex, reject
        if id.count == Constants.hexIDLength || id.count == Constants.maxIDLength {
            return false
        }
        
        // Internal format: alphanumeric + dash/underscore up to 63 (not 16 or 64)
        let validCharset = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_"))
        return !id.isEmpty &&
                id.count < Constants.maxIDLength &&
                id.rangeOfCharacter(from: validCharset.inverted) == nil
    }
    
    /// Short routing IDs (exact 16-hex)
    var isShort: Bool {
        id.count == Constants.hexIDLength && Data(hexString: id) != nil
    }
    
    /// Full Noise key hex (exact 64-hex)
    var isNoiseKeyHex: Bool {
        noiseKey != nil
    }
    
    /// Full Noise key (exact 64-hex) as Data
    var noiseKey: Data? {
        guard id.count == Constants.maxIDLength else { return nil }
        return Data(hexString: id)
    }
}

// MARK: - ExpressibleByStringLiteral

extension Peer: ExpressibleByStringLiteral {
    init(stringLiteral value: String) {
        self.init(str: value)
    }
}

// MARK: - ExpressibleByStringInterpolation

extension Peer: ExpressibleByStringInterpolation {
    init(extendedGraphemeClusterLiteral value: String) {
        self.init(str: value)
    }
}

// MARK: - Codable

extension Peer: Codable {
    init(from decoder: any Decoder) throws {
        id = try decoder.singleValueContainer().decode(String.self)
    }
    
    func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(id)
    }
}

// MARK: - Convenience Inits

extension Peer {
    init(str: String) {
        id = str.lowercased()
    }
    
    init(str: String.SubSequence) {
        self.init(str: String(str))
    }
    
    init?(data: Data) {
        guard let str = String(data: data, encoding: .utf8) else {
            return nil
        }
        self.init(str: str)
    }
}

// MARK: - Noise Public Key Helpers

extension Peer {
    /// Derive the stable 16-hex peer ID from a Noise static public key
    init(publicKey: Data) {
        let digest = SHA256.hash(data: publicKey)
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        self.init(str: hex.prefix(16))
    }
    
    /// Returns a 16-hex short peer ID derived from a 64-hex Noise public key if needed
    func toShort() -> Peer {
        if id.count == Constants.maxIDLength, let data = Data(hexString: id) {
            return Peer(publicKey: data)
        }
        return self
    }
}
