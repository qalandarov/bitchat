//
// String+Sanitization.swift
// BitLogger
//
// This is free and unencumbered software released into the public domain.
// For more information, see <https://unlicense.org>
//

import Foundation

extension String {
    /// Sanitize strings to remove potentially sensitive data
    func sanitized() -> String {
        let key = self as NSString
        
        // Check cache first
        if let cached = Self.queue.sync(execute: { Self.cache.object(forKey: key) }) {
            return cached as String
        }
        
        var sanitized = self
        
        // Remove full fingerprints (keep first 8 chars for debugging)
        sanitized = sanitized.replacing("[a-fA-F0-9]{64}") { match, nsString in
            let fingerprint = nsString.substring(with: match.range)
            return String(fingerprint.prefix(8)) + "..."
        }
        
        // Remove base64 encoded data that might be keys
        sanitized = sanitized.replacing("[A-Za-z0-9+/]{40,}={0,2}") { (_, _) in
            "<base64-data>"
        }
        
        // Remove potential passwords (assuming they're in quotes or after "password:")
        sanitized = sanitized.replacing(#"password["\s:=]+["']?[^"'\s]+["']?"#) { (_, _) in
            "password: <redacted>"
        }
        
        // Truncate peer IDs to first 8 characters
        sanitized = sanitized.replacing(#"peerID: ([a-zA-Z0-9]{8})[a-zA-Z0-9]+"#) { match, nsString in
            if let peerID = match.group(1, in: nsString) {
                return "peerID: \(peerID)..."
            }
            return nsString.substring(with: match.range) // fallback if no capture
        }
        
        // Cache the result
        Self.queue.sync {
            Self.cache.setObject(sanitized as NSString, forKey: key)
        }
        
        return sanitized
    }
}

// MARK: - Cache Helpers

private extension String {
    static let queue = DispatchQueue(label: "chat.bitchat.securelogger.cache", attributes: .concurrent)

    static let cache: NSCache<NSString, NSString> = {
        let cache = NSCache<NSString, NSString>()
        cache.countLimit = 100 // Keep last 100 sanitized strings
        return cache
    }()
}

// MARK: - Regex Helper

private extension String {
    func replacing(_ pattern: String, with replacement: (NSTextCheckingResult, NSString) -> String) -> String {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return self }
        let nsString = self as NSString
        let range = NSRange(location: 0, length: nsString.length)
        let matches = regex.matches(in: self, range: range)
        guard !matches.isEmpty else { return self }
        var result = ""
        var lastIndex = 0
        for match in matches {
            let range = match.range
            if range.location > lastIndex {
                result += nsString.substring(with: NSRange(location: lastIndex, length: range.location - lastIndex))
            }
            result += replacement(match, nsString)
            lastIndex = range.location + range.length
        }
        if lastIndex < nsString.length {
            result += nsString.substring(from: lastIndex)
        }
        return result
    }
}

private extension NSTextCheckingResult {
    func group(_ index: Int, in nsString: NSString) -> String? {
        let range = self.range(at: index)
        return range.location != NSNotFound ? nsString.substring(with: range) : nil
    }
}
