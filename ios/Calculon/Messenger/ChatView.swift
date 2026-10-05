import CalcCore
import PhotosUI
import QuickLook
import SwiftUI

struct ChatView: View {
    let contactID: String
    @Environment(MessengerService.self) private var service
    @Environment(CallService.self) private var calls
    @State private var draft = ""
    @State private var messages: [ChatMessage] = []
    @State private var sendError: String?
    @State private var showInfo = false
    @State private var pending: [OutgoingAttachment] = []
    @State private var preparing = false
    @State private var showPhotoPicker = false
    @State private var showFileImporter = false
    @State private var photoItems: [PhotosPickerItem] = []
    @State private var viewing: AttachmentPointer?
    @State private var previewURL: URL?
    @State private var deleteError: String?

    private var contact: Contact? { service.contact(contactID) }

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 6) {
                    if let c = contact, c.isRequest {
                        RequestBanner(contact: c)
                    }
                    ForEach(messages) { m in
                        Group {
                            if let info = m.call {
                                CallLogRow(message: m, info: info)
                            } else if let change = m.timerChange {
                                TimerNoticeRow(message: m, change: change)
                            } else {
                                Bubble(message: m, open: open)
                            }
                        }
                        .id(m.id)
                        .contextMenu { deleteMenu(m) }
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
            ToolbarItemGroup(placement: .topBarTrailing) {
                // Message requests can't be called until accepted (the peer's
                // side ignores them the same way).
                if let c = contact, !c.isRequest {
                    Button { Task { await calls.call(contactID, video: true) } } label: { Image(systemName: "video") }
                        .accessibilityLabel("Видеозвонок")
                        .disabled(calls.current != nil)
                    Button { Task { await calls.call(contactID, video: false) } } label: { Image(systemName: "phone") }
                        .accessibilityLabel("Звонок")
                        .disabled(calls.current != nil)
                }
                Button { showInfo = true } label: {
                    if let t = contact?.disappearAfter {
                        Label(DisappearTimer.label(t), systemImage: "timer")
                    } else {
                        Image(systemName: "info.circle")
                    }
                }
            }
        }
        .sheet(isPresented: $showInfo) { ContactInfoView(contactID: contactID) }
        .photosPicker(isPresented: $showPhotoPicker, selection: $photoItems,
                      maxSelectionCount: max(1, MessengerService.maxAttachments - pending.count),
                      matching: .any(of: [.images, .videos]), preferredItemEncoding: .compatible)
        .onChange(of: photoItems) { _, items in
            guard !items.isEmpty else { return }
            photoItems = []
            addAttachments { try await items.asyncMap(AttachmentPreparer.prepare) }
        }
        .fileImporter(isPresented: $showFileImporter, allowedContentTypes: [.item], allowsMultipleSelection: true) { result in
            guard case .success(let urls) = result else { return }
            addAttachments { try urls.map(AttachmentPreparer.prepare(fileAt:)) }
        }
        .quickLookPreview($previewURL)
        .onChange(of: previewURL) { _, url in
            if url == nil { TempFiles.removeAll() }
        }
        .overlay {
            if let viewing {
                PhotoViewer(pointer: viewing) { self.viewing = nil }
                    .transition(.opacity)
            }
        }
        .onDisappear { TempFiles.removeAll() }
        .task(id: contactID) {
            // Refresh while the chat is open; also expires disappearing messages.
            while !Task.isCancelled {
                await service.markRead(contactID)
                messages = service.messages(with: contactID)
                try? await Task.sleep(for: .seconds(1))
            }
        }
        .alert("Не отправлено", isPresented: .constant(sendError != nil)) {
            Button("OK") { sendError = nil }
        } message: { Text(sendError ?? "") }
        .alert("Не удалено", isPresented: .constant(deleteError != nil)) {
            Button("OK") { deleteError = nil }
        } message: { Text(deleteError ?? "") }
    }

    @ViewBuilder private func deleteMenu(_ m: ChatMessage) -> some View {
        if !m.body.isEmpty {
            Button("Скопировать", systemImage: "doc.on.doc") { SecurePasteboard.copy(m.body) }
        }
        Button("Удалить у меня", systemImage: "trash", role: .destructive) {
            service.deleteMessages([m.id], in: contactID)
            messages = service.messages(with: contactID)
        }
        // Only your own messages; call log and notices are local anyway.
        if m.outgoing, m.call == nil, m.timerChange == nil {
            Button("Удалить у всех", systemImage: "trash.fill", role: .destructive) {
                Task {
                    do {
                        try await service.deleteForEveryone([m.id], in: contactID)
                    } catch {
                        deleteError = "Не удалось отправить собеседнику запрос на удаление. Проверьте соединение с сервером."
                    }
                    messages = service.messages(with: contactID)
                }
            }
        }
    }

    private var canSend: Bool {
        !preparing && (!draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || !pending.isEmpty)
    }

    private var composer: some View {
        VStack(spacing: 0) {
            if !pending.isEmpty || preparing {
                HStack {
                    PendingAttachmentsStrip(items: $pending)
                    if preparing { ProgressView().padding(.horizontal, 12).padding(.top, 10) }
                }
            }
            composerRow
        }
        .background(.bar)
    }

    private var composerRow: some View {
        HStack(alignment: .bottom, spacing: 8) {
            Menu {
                Button("Фото и видео", systemImage: "photo.on.rectangle") { showPhotoPicker = true }
                Button("Файл", systemImage: "doc") { showFileImporter = true }
            } label: {
                Image(systemName: "paperclip").font(.system(size: 22)).frame(width: 32, height: 36)
            }
            .disabled(pending.count >= MessengerService.maxAttachments || preparing)
            TextField("Сообщение", text: $draft, axis: .vertical)
                .lineLimit(1...6)
                // No autocorrect / predictive learning: the system keyboard
                // otherwise remembers words you type.
                .autocorrectionDisabled()
                .textInputAutocapitalization(.sentences)
                .textContentType(.none)
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(Theme.surface, in: RoundedRectangle(cornerRadius: 18))
            Button {
                let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
                let attachments = pending
                guard !text.isEmpty || !attachments.isEmpty else { return }
                draft = ""
                pending = []
                Task {
                    do {
                        try await service.send(text, attachments: attachments, to: contactID)
                    } catch RelayError.tooLarge {
                        sendError = "Сервер не принял файл: он слишком большой."
                    } catch RelayError.storageFull {
                        sendError = "На сервере закончилось место для файлов."
                    } catch {
                        sendError = "Проверьте соединение с сервером."
                    }
                    messages = service.messages(with: contactID)
                }
                // Show the message (with its "sending" clock) right away.
                Task { messages = service.messages(with: contactID) }
            } label: {
                Image(systemName: "arrow.up.circle.fill").font(.system(size: 32))
            }
            .disabled(!canSend)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    /// Prepares picked items off the composer, keeping at most the limit.
    private func addAttachments(_ load: @escaping () async throws -> [OutgoingAttachment]) {
        preparing = true
        Task {
            defer { preparing = false }
            do {
                let new = try await load()
                let room = MessengerService.maxAttachments - pending.count
                if new.count > room {
                    sendError = "Можно приложить не больше \(MessengerService.maxAttachments) файлов."
                }
                pending += new.prefix(max(0, room))
            } catch {
                sendError = error.localizedDescription
            }
        }
    }

    /// Photos open in the shielded in-chat viewer; videos and documents in
    /// QuickLook from a temporary decrypted copy.
    private func open(_ p: AttachmentPointer) {
        if p.isImage {
            withAnimation { viewing = p }
            return
        }
        Task {
            guard let data = try? await service.attachmentData(p),
                  let url = try? TempFiles.write(data, name: p.name) else { return }
            previewURL = url
        }
    }
}

struct Bubble: View {
    let message: ChatMessage
    var open: (AttachmentPointer) -> Void = { _ in }

    var body: some View {
        HStack {
            if message.outgoing { Spacer(minLength: 48) }
            VStack(alignment: message.outgoing ? .trailing : .leading, spacing: 2) {
                if message.attachments?.isEmpty == false {
                    AttachmentList(message: message, open: open)
                }
                if !message.body.isEmpty {
                    Text(message.body)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                        .background(message.outgoing ? AnyShapeStyle(Theme.gradient) : AnyShapeStyle(Theme.surface),
                                    in: RoundedRectangle(cornerRadius: 16))
                        .foregroundStyle(message.outgoing ? Theme.textOnAccent : .primary)
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
        case .delivered: doubleCheck
        case .read: doubleCheck.foregroundStyle(.tint)
        case .failed: Image(systemName: "exclamationmark.circle").foregroundStyle(.red)
        case .received: EmptyView()
        }
    }

    private var doubleCheck: some View {
        ZStack(alignment: .leading) {
            Image(systemName: "checkmark")
            Image(systemName: "checkmark").padding(.leading, 5)
        }
    }
}

struct TimerNoticeRow: View {
    let message: ChatMessage
    let change: TimerChange

    var body: some View {
        Label(change.label(outgoing: message.outgoing), systemImage: "timer")
            .font(.caption)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(Theme.pill, in: Capsule())
            .frame(maxWidth: .infinity)
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
        .background(Theme.surface, in: RoundedRectangle(cornerRadius: 12))
    }
}

extension Sequence {
    func asyncMap<T>(_ transform: (Element) async throws -> T) async rethrows -> [T] {
        var out: [T] = []
        for element in self { out.append(try await transform(element)) }
        return out
    }
}
