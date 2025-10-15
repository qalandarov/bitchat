//
// RateLimiterService.swift
// bitchat
//
// This is free and unencumbered software released into the public domain.
// For more information, see <https://unlicense.org>
//

import Foundation

/// Encapsulates spam‑resilience logic previously embedded directly in ``ChatViewModel``.
///
/// This service implements per‑sender and per‑content token buckets to limit the
/// rate of incoming messages. It also manages a small least‑recently‑used (LRU)
/// cache keyed by normalized message content to detect and suppress near‑duplicate
/// messages that arrive within a short time window. By extracting this logic
/// into a dedicated type we reduce the size and complexity of ``ChatViewModel``
/// and make the throttling logic easier to reason about and test in isolation.
final class RateLimiterService {
    /// Simple token bucket implementation for rate limiting.
    /// Maintains a fixed capacity and refills tokens at a constant rate.
    private struct TokenBucket {
        var capacity: Double
        var tokens: Double
        var refillPerSec: Double
        var lastRefill: Date

        mutating func allow(cost: Double = 1.0, now: Date = Date()) -> Bool {
            let dt = now.timeIntervalSince(lastRefill)
            if dt > 0 {
                tokens = min(capacity, tokens + dt * refillPerSec)
                lastRefill = now
            }
            if tokens >= cost {
                tokens -= cost
                return true
            }
            return false
        }
    }

    // Per‑sender and per‑content buckets keyed by normalized identifiers.
    private var rateBucketsBySender: [String: TokenBucket] = [:]
    private var rateBucketsByContent: [String: TokenBucket] = [:]

    private let senderBucketCapacity: Double
    private let senderBucketRefill: Double
    private let contentBucketCapacity: Double
    private let contentBucketRefill: Double

    // Persistent recent content map (LRU) to suppress near duplicates
    private var contentLRUMap: [String: Date] = [:]
    private var contentLRUOrder: [String] = []
    private let contentLRUCap: Int

    /// Regex used to simplify HTTP/HTTPS URLs by stripping query and fragment.
    /// This is compiled once on initialization for efficiency.
    private let simplifyHTTPURL: NSRegularExpression

    /// Initialize a new rate limiter service with configurable bucket and LRU sizes.
    ///
    /// - Parameters:
    ///   - senderBucketCapacity: Maximum tokens in the per‑sender bucket. Defaults to ``TransportConfig.uiSenderRateBucketCapacity``.
    ///   - senderBucketRefill: Tokens refilled per second for the per‑sender bucket. Defaults to ``TransportConfig.uiSenderRateBucketRefillPerSec``.
    ///   - contentBucketCapacity: Maximum tokens in the per‑content bucket. Defaults to ``TransportConfig.uiContentRateBucketCapacity``.
    ///   - contentBucketRefill: Tokens refilled per second for the per‑content bucket. Defaults to ``TransportConfig.uiContentRateBucketRefillPerSec``.
    ///   - contentLRUCap: Maximum number of recent content keys to track for duplicate suppression. Defaults to ``TransportConfig.contentLRUCap``.
    init(
        senderBucketCapacity: Double = TransportConfig.uiSenderRateBucketCapacity,
        senderBucketRefill: Double = TransportConfig.uiSenderRateBucketRefillPerSec,
        contentBucketCapacity: Double = TransportConfig.uiContentRateBucketCapacity,
        contentBucketRefill: Double = TransportConfig.uiContentRateBucketRefillPerSec,
        contentLRUCap: Int = TransportConfig.contentLRUCap
    ) {
        self.senderBucketCapacity = senderBucketCapacity
        self.senderBucketRefill = senderBucketRefill
        self.contentBucketCapacity = contentBucketCapacity
        self.contentBucketRefill = contentBucketRefill
        self.contentLRUCap = contentLRUCap
        // Precompile URL simplification regex (case‑insensitive). Matches the full URL
        // including any query and fragment components.
        self.simplifyHTTPURL = try! NSRegularExpression(
            pattern: "https?://[^\\s?#]+(?:[?#][^\\s]*)?",
            options: [.caseInsensitive]
        )
    }

    /// Normalize message content into a short key for rate limiting and duplicate detection.
    ///
    /// This method lowercases the input, strips query/fragment components from HTTP/S
    /// URLs, collapses consecutive whitespace into single spaces, trims leading/trailing
    /// whitespace and newlines, and truncates to a fixed prefix length (see
    /// ``TransportConfig.contentKeyPrefixLength``). The resulting prefix is hashed
    /// using a fast DJB2 hash and formatted as a hexadecimal string.
    ///
    /// - Parameter content: Raw message text to normalize.
    /// - Returns: A normalized hash key (e.g. "h:0abc1234…").
    func normalizedContentKey(_ content: String) -> String {
        // Lowercase to make comparisons case‑insensitive
        let lowered = content.lowercased()
        let ns = lowered as NSString
        let range = NSRange(location: 0, length: ns.length)
        var simplified = ""
        var last = 0
        // Replace each URL match with its simplified form (without query/fragment)
        for m in simplifyHTTPURL.matches(in: lowered, options: [], range: range) {
            if m.range.location > last {
                simplified += ns.substring(with: NSRange(location: last, length: m.range.location - last))
            }
            let url = ns.substring(with: m.range)
            if let q = url.firstIndex(where: { $0 == "?" || $0 == "#" }) {
                simplified += String(url[..<q])
            } else {
                simplified += url
            }
            last = m.range.location + m.range.length
        }
        if last < ns.length { simplified += ns.substring(with: NSRange(location: last, length: ns.length - last)) }
        let trimmed = simplified.trimmingCharacters(in: .whitespacesAndNewlines)
        // Collapse any runs of whitespace to single spaces
        let collapsed = trimmed.replacingOccurrences(of: "\\s+", with: " ", options: .regularExpression)
        // Truncate to the configured prefix length
        let prefix = String(collapsed.prefix(TransportConfig.contentKeyPrefixLength))
        // Compute DJB2 hash of the prefix
        let h = prefix.djb2()
        return String(format: "h:%016llx", h)
    }

    /// Attempt to consume one token for the given sender and content keys.
    ///
    /// Each key uses its own token bucket. If either bucket is empty the call
    /// returns ``false`` and no state is mutated. Otherwise the tokens are
    /// decremented and ``true`` is returned.
    ///
    /// - Parameters:
    ///   - senderKey: Normalized sender identifier (e.g. from ``ChatViewModel.normalizedSenderKey(for:)``).
    ///   - contentKey: Normalized content identifier returned from ``normalizedContentKey(_:)``.
    ///   - now: Timestamp used to update refill state. Defaults to ``Date()``.
    /// - Returns: `true` if both buckets allowed the operation; `false` if either bucket ran empty.
    func allow(senderKey: String, contentKey: String, now: Date = Date()) -> Bool {
        var sBucket = rateBucketsBySender[senderKey] ?? TokenBucket(
            capacity: senderBucketCapacity,
            tokens: senderBucketCapacity,
            refillPerSec: senderBucketRefill,
            lastRefill: now
        )
        let senderAllowed = sBucket.allow(now: now)
        rateBucketsBySender[senderKey] = sBucket
        var cBucket = rateBucketsByContent[contentKey] ?? TokenBucket(
            capacity: contentBucketCapacity,
            tokens: contentBucketCapacity,
            refillPerSec: contentBucketRefill,
            lastRefill: now
        )
        let contentAllowed = cBucket.allow(now: now)
        rateBucketsByContent[contentKey] = cBucket
        return senderAllowed && contentAllowed
    }

    /// Record the most recent timestamp for a normalized content key.
    ///
    /// The service maintains a simple LRU to bound memory usage. When the
    /// capacity is exceeded the oldest keys are evicted. This map enables
    /// duplicate detection within a small time window (see
    /// ``isRecentDuplicate(contentKey:timestamp:within:)``).
    ///
    /// - Parameters:
    ///   - key: The normalized content key to record.
    ///   - timestamp: The timestamp associated with the message.
    func recordContentKey(_ key: String, timestamp: Date) {
        if contentLRUMap[key] == nil { contentLRUOrder.append(key) }
        contentLRUMap[key] = timestamp
        if contentLRUOrder.count > contentLRUCap {
            let overflow = contentLRUOrder.count - contentLRUCap
            for _ in 0..<overflow {
                if let victim = contentLRUOrder.first {
                    contentLRUOrder.removeFirst()
                    contentLRUMap.removeValue(forKey: victim)
                }
            }
        }
    }

    /// Check if a message with the given key and timestamp is considered a recent duplicate.
    ///
    /// A duplicate is defined as any message whose normalized content key has been
    /// recorded within ``within`` seconds of the provided timestamp. This helper
    /// is used when flushing batched messages to avoid showing near‑identical
    /// messages multiple times.
    ///
    /// - Parameters:
    ///   - contentKey: Normalized content key produced via ``normalizedContentKey(_:)``.
    ///   - timestamp: Timestamp of the candidate message.
    ///   - within: Time interval (in seconds) to consider as duplicate. Defaults to 1.0.
    /// - Returns: `true` if a recent duplicate exists; otherwise `false`.
    func isRecentDuplicate(contentKey: String, timestamp: Date, within: TimeInterval = 1.0) -> Bool {
        if let ts = contentLRUMap[contentKey] {
            return abs(ts.timeIntervalSince(timestamp)) < within
        }
        return false
    }
}
