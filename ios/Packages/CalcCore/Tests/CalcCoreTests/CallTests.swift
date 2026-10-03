import Foundation
import Testing
@testable import CalcCore

@MainActor
struct CallTests {
    /// Alice and Bob with an accepted conversation in both directions.
    func pair() async throws -> (FakeRelay, MessengerService, MessengerService) {
        let relay = FakeRelay()
        let t = MessengerTests()
        let alice = try t.makeService(relay)
        let bob = try t.makeService(relay)
        try await alice.register()
        try await bob.register()
        try await alice.addContact(id: bob.accountID!, name: "Bob", verifiedInPerson: true)
        try await alice.send("hi", to: bob.accountID!)
        await bob.sync()
        try bob.rename(alice.accountID!, to: "Alice")
        await alice.sync() // delivered receipt
        return (relay, alice, bob)
    }

    @Test func signalingArrivesInOrderAndOpaque() async throws {
        let (relay, alice, bob) = try await pair()
        var got: [(String, CallSignal)] = []
        bob.onCallSignal = { from, signal, age in
            #expect(age < 60)
            got.append((from, signal))
        }
        let id = UInt64.max - 7 // beyond 2^53: must survive JSON
        let offer = CallSignal(kind: .offer, callID: id, opaque: Data("sdp-offer-bytes".utf8), video: true)
        let ice = CallSignal(kind: .ice, callID: id, candidates: [Data("cand1".utf8), Data("cand2".utf8)])
        try await alice.sendCallSignal(offer, to: bob.accountID!)
        try await alice.sendCallSignal(ice, to: bob.accountID!)

        let queued = relay.queues[bob.accountID!] ?? []
        #expect(queued.count == 2)
        for env in queued {
            #expect(env.data.range(of: Data("sdp-offer-bytes".utf8)) == nil)
            #expect(env.data.range(of: Data("offer".utf8)) == nil)
        }

        #expect(await bob.sync() == 0) // signaling is not a chat message
        #expect(got.map(\.0) == [alice.accountID!, alice.accountID!])
        #expect(got.map(\.1) == [offer, ice])
        #expect(got.first?.1.callIDValue == id)
        // No delivery receipts or chat entries for signaling.
        #expect(relay.queues[alice.accountID!, default: []].isEmpty)
        #expect(bob.messages(with: alice.accountID!).count == 1)
    }

    @Test func requestsAndStrangersCannotRing() async throws {
        let relay = FakeRelay()
        let t = MessengerTests()
        let alice = try t.makeService(relay)
        let bob = try t.makeService(relay)
        let carol = try t.makeService(relay)
        for s in [alice, bob, carol] { try await s.register() }
        var rang = 0
        bob.onCallSignal = { _, _, _ in rang += 1 }

        // A stranger: the call doesn't even create a contact.
        try await carol.addContact(id: bob.accountID!, name: "Bob", verifiedInPerson: false)
        try await carol.sendCallSignal(CallSignal(kind: .offer, callID: 1, opaque: Data([1])), to: bob.accountID!)
        await bob.sync()
        #expect(rang == 0)
        #expect(bob.contact(carol.accountID!) == nil)

        // A message request rings only once Bob accepts it.
        try await alice.addContact(id: bob.accountID!, name: "Bob", verifiedInPerson: false)
        try await alice.send("hello", to: bob.accountID!)
        try await alice.sendCallSignal(CallSignal(kind: .offer, callID: 2, opaque: Data([2])), to: bob.accountID!)
        await bob.sync()
        #expect(rang == 0)
        #expect(bob.contact(alice.accountID!)?.isRequest == true)

        try bob.rename(alice.accountID!, to: "Alice")
        try await alice.sendCallSignal(CallSignal(kind: .offer, callID: 3, opaque: Data([3])), to: bob.accountID!)
        await bob.sync()
        #expect(rang == 1)
    }

    @Test func callLog() async throws {
        let (relay, alice, bob) = try await pair()
        await bob.markRead(alice.accountID!)
        relay.queues[alice.accountID!] = []
        bob.recordCall(with: alice.accountID!, outgoing: false, info: CallInfo(video: false, outcome: .missed))
        alice.recordCall(with: bob.accountID!, outgoing: true, info: CallInfo(video: true, outcome: .answered, duration: 42))

        #expect(bob.contact(alice.accountID!)?.unread == 1)
        #expect(bob.contact(alice.accountID!)?.lastPreview == "📞 Пропущенный звонок")
        #expect(alice.contact(bob.accountID!)?.lastPreview == "📞 Исходящий видеозвонок")
        #expect(alice.messages(with: bob.accountID!).last?.call?.duration == 42)

        // Reading the chat clears the badge but sends no receipt for a call entry.
        await bob.markRead(alice.accountID!)
        #expect(bob.contact(alice.accountID!)?.unread == 0)
        #expect(relay.queues[alice.accountID!, default: []].isEmpty)
        #expect(bob.messages(with: alice.accountID!).allSatisfy { $0.status == .read })
    }

    @Test func turnCredentialsAreCached() async throws {
        let (relay, alice, _) = try await pair()
        // Each client prefetched once during sync; later calls use the cache.
        #expect(relay.turnRequests == 2)
        let c = try await alice.turnCredentials()
        await alice.sync()
        #expect(try await alice.turnCredentials() == c)
        #expect(relay.turnRequests == 2)
    }
}
