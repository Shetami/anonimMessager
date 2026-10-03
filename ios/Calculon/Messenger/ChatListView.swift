import CalcCore
import SwiftUI

struct MessengerRootView: View {
    @Environment(Session.self) private var session
    @Environment(MessengerService.self) private var service
    @Environment(CallService.self) private var calls

    var body: some View {
        ZStack {
            NavigationStack {
                ChatListView()
                    .navigationDestination(for: String.self) { ChatView(contactID: $0) }
            }
            .tint(.orange)
            if let call = calls.current, call.isVisible {
                CallScreen(call: call).transition(.opacity)
            }
        }
        .animation(.default, value: calls.current?.isVisible)
    }
}

struct ChatListView: View {
    @Environment(Session.self) private var session
    @Environment(MessengerService.self) private var service
    @State private var showAdd = false
    @State private var showMyID = false
    @State private var showSettings = false

    var body: some View {
        List {
            if service.state?.registered != true {
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        ProgressView()
                        Text("Регистрация анонимного ящика…").foregroundStyle(.secondary)
                    }
                    if let error = session.registrationError {
                        Text(error).font(.caption).foregroundStyle(.red)
                    }
                }
            }
            ForEach(service.contacts) { c in
                NavigationLink(value: c.id) { ContactRow(contact: c) }
            }
            .onDelete { idx in
                for i in idx { try? service.deleteContact(service.contacts[i].id) }
            }
        }
        .overlay {
            if service.contacts.isEmpty && service.state?.registered == true {
                ContentUnavailableView {
                    Label("Нет чатов", systemImage: "bubble.left.and.bubble.right")
                } description: {
                    Text("Покажите свой QR-код собеседнику или добавьте контакт по ID.")
                } actions: {
                    Button("Добавить контакт") { showAdd = true }.buttonStyle(.borderedProminent)
                }
            }
        }
        .navigationTitle("Чаты")
        .toolbar {
            ToolbarItem(placement: .topBarLeading) {
                Button { session.lock() } label: { Image(systemName: "lock.fill") }
                    .accessibilityLabel("Заблокировать")
            }
            ToolbarItemGroup(placement: .topBarTrailing) {
                Button { showMyID = true } label: { Image(systemName: "qrcode") }
                Button { showAdd = true } label: { Image(systemName: "square.and.pencil") }
                Button { showSettings = true } label: { Image(systemName: "gearshape") }
            }
        }
        .refreshable { await service.sync() }
        .sheet(isPresented: $showAdd) { AddContactView() }
        .sheet(isPresented: $showMyID) { MyIDView() }
        .sheet(isPresented: $showSettings) { SettingsView() }
    }
}

struct ContactRow: View {
    let contact: Contact

    var body: some View {
        HStack(spacing: 12) {
            Circle()
                .fill(Color(hue: Double(contact.id.unicodeScalars.reduce(0) { ($0 * 31 + Int($1.value)) % 360 }) / 360,
                             saturation: 0.5, brightness: 0.6))
                .frame(width: 44, height: 44)
                .overlay(Text(contact.name.prefix(1).uppercased()).font(.headline).foregroundStyle(.white))
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(contact.name).font(.headline)
                    if contact.verified {
                        Image(systemName: "checkmark.seal.fill").font(.caption).foregroundStyle(.green)
                    }
                    if contact.isRequest {
                        Text("новый").font(.caption2).padding(.horizontal, 6).padding(.vertical, 1)
                            .background(.orange.opacity(0.3), in: Capsule())
                    }
                }
                Text(contact.lastPreview ?? " ").font(.subheadline).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 4) {
                Text(contact.lastActivity, style: .time).font(.caption).foregroundStyle(.secondary)
                if contact.unread > 0 {
                    Text("\(contact.unread)").font(.caption2.bold()).padding(.horizontal, 7).padding(.vertical, 2)
                        .background(.orange, in: Capsule()).foregroundStyle(.black)
                }
            }
        }
    }
}
