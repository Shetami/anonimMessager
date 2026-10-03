import CalcCore
import SwiftUI

struct ChatView: View {
    let contactID: String
    @Environment(MessengerService.self) private var service
    @State private var draft = ""
    @State private var messages: [ChatMessage] = []
    @State private var sendError: String?
    @State private var showInfo = false

    private var contact: Contact? { service.contact(contactID) }

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 6) {
                    if let c = contact, c.isRequest {
                        RequestBanner(contact: c)
                    }
                    ForEach(messages) { m in
                        Bubble(message: m).id(m.id)
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
            }
            .scrollDismissesKeyboard(.interactively)
            .defaultScrollAnchor(.bottom)
            .onChange(of: messages.last?.id) { _, id in
                if let id { withAnimation { proxy.scrollTo(id, anchor: .bottom) } }
            }
        }
        .safeAreaInset(edge: .bottom) { composer }
        .navigationTitle(contact?.name ?? "")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button { showInfo = true } label: {
                    if let t = contact?.disappearAfter {
                        Label(DisappearOption.label(t), systemImage: "timer")
                    } else {
                        Image(systemName: "info.circle")
                    }
                }
            }
        }
        .sheet(isPresented: $showInfo) { ContactInfoView(contactID: contactID) }
        .task(id: contactID) {
            // Refresh while the chat is open; also expires disappearing messages.
            while !Task.isCancelled {
                messages = service.messages(with: contactID)
                service.markRead(contactID)
                try? await Task.sleep(for: .seconds(1))
            }
        }
        .alert("Не отправлено", isPresented: .constant(sendError != nil)) {
            Button("OK") { sendError = nil }
        } message: { Text(sendError ?? "") }
    }

    private var composer: some View {
        HStack(alignment: .bottom, spacing: 8) {
            TextField("Сообщение", text: $draft, axis: .vertical)
                .lineLimit(1...6)
                // No autocorrect / predictive learning: the system keyboard
                // otherwise remembers words you type.
                .autocorrectionDisabled()
                .textInputAutocapitalization(.sentences)
                .textContentType(.none)
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(Color(white: 0.15), in: RoundedRectangle(cornerRadius: 18))
            Button {
                let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !text.isEmpty else { return }
                draft = ""
                Task {
                    do {
                        try await service.send(text, to: contactID)
                    } catch {
                        sendError = "Проверьте соединение с сервером."
                    }
                    messages = service.messages(with: contactID)
                }
            } label: {
                Image(systemName: "arrow.up.circle.fill").font(.system(size: 32))
            }
            .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(.bar)
    }
}

struct Bubble: View {
    let message: ChatMessage

    var body: some View {
        HStack {
            if message.outgoing { Spacer(minLength: 48) }
            VStack(alignment: message.outgoing ? .trailing : .leading, spacing: 2) {
                Text(message.body)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(message.outgoing ? Color.orange : Color(white: 0.2),
                                in: RoundedRectangle(cornerRadius: 16))
                    .foregroundStyle(message.outgoing ? .black : .white)
                    .contextMenu {
                        Button("Скопировать", systemImage: "doc.on.doc") { SecurePasteboard.copy(message.body) }
                    }
                HStack(spacing: 4) {
                    if message.expiresAt != nil { Image(systemName: "timer") }
                    Text(message.sentAt, style: .time)
                    if message.outgoing { statusIcon }
                }
                .font(.caption2)
                .foregroundStyle(.secondary)
            }
            if !message.outgoing { Spacer(minLength: 48) }
        }
    }

    @ViewBuilder private var statusIcon: some View {
        switch message.status {
        case .sending: Image(systemName: "clock")
        case .sent: Image(systemName: "checkmark")
        case .failed: Image(systemName: "exclamationmark.circle").foregroundStyle(.red)
        case .received: EmptyView()
        }
    }
}

struct RequestBanner: View {
    let contact: Contact
    @Environment(MessengerService.self) private var service
    @State private var name = ""

    var body: some View {
        VStack(spacing: 8) {
            Text("Новый контакт написал вам первым. Сверьте его ID лично, прежде чем доверять.")
                .font(.footnote).multilineTextAlignment(.center)
            Text(AccountID.grouped(contact.id)).font(.caption.monospaced()).foregroundStyle(.secondary)
            HStack {
                TextField("Имя контакта", text: $name).textFieldStyle(.roundedBorder).autocorrectionDisabled()
                Button("Сохранить") { try? service.rename(contact.id, to: name) }
                    .disabled(name.isEmpty)
            }
        }
        .padding()
        .background(Color(white: 0.12), in: RoundedRectangle(cornerRadius: 12))
    }
}

enum DisappearOption {
    static let values: [TimeInterval?] = [nil, 30, 300, 3600, 86400, 604800]

    static func label(_ t: TimeInterval?) -> String {
        switch t {
        case nil: return "Выкл."
        case 30?: return "30 с"
        case 300?: return "5 мин"
        case 3600?: return "1 ч"
        case 86400?: return "1 д"
        case 604800?: return "1 нед"
        case let s?: return "\(Int(s)) с"
        }
    }
}
