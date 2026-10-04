import CalcCore
import SwiftUI

struct AddContactView: View {
    @Environment(MessengerService.self) private var service
    @Environment(\.dismiss) private var dismiss
    @State private var idText = ""
    @State private var name = ""
    @State private var scannedID: String?
    @State private var showScanner = false
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Button { showScanner = true } label: {
                        Label("Сканировать QR-код собеседника", systemImage: "qrcode.viewfinder")
                    }
                } footer: {
                    Text("Сканирование при личной встрече — самый надёжный способ: ID однозначно привязан к ключу шифрования собеседника.")
                }
                Section("Или введите ID") {
                    TextField("abcd efgh …", text: $idText, axis: .vertical)
                        .font(.body.monospaced())
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    TextField("Имя (видно только вам)", text: $name)
                        .autocorrectionDisabled()
                }
                if let error {
                    Section { Text(error).foregroundStyle(.red) }
                }
            }
            .navigationTitle("Новый контакт")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Отмена") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    if busy { ProgressView() } else {
                        Button("Добавить") { add() }.disabled(AccountID.normalize(idText) == nil)
                    }
                }
            }
            .fullScreenCover(isPresented: $showScanner) {
                QRScannerView { code in
                    showScanner = false
                    if let id = AccountID.normalize(code) {
                        idText = id
                        scannedID = id
                    } else {
                        error = "Это не QR-код контакта."
                    }
                } onCancel: {
                    showScanner = false
                }
                .ignoresSafeArea()
            }
        }
    }

    private func add() {
        busy = true
        error = nil
        // Only "verified" if the ID being added is exactly the one scanned.
        let verified = scannedID != nil && AccountID.normalize(idText) == scannedID
        Task {
            defer { busy = false }
            do {
                try await service.addContact(id: idText, name: name, verifiedInPerson: verified)
                dismiss()
            } catch MessengerError.keyMismatch, MessengerError.badSignature {
                error = "Сервер вернул ключи, не соответствующие этому ID. Возможна атака — контакт не добавлен."
            } catch MessengerError.cannotAddSelf {
                error = "Это ваш собственный ID."
            } catch RelayError.notFound {
                error = "Такой ID не найден."
            } catch {
                self.error = "Не удалось связаться с сервером."
            }
        }
    }
}

struct MyIDView: View {
    @Environment(MessengerService.self) private var service
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                if let id = service.accountID {
                    QRCodeImage(text: "calc:" + id)
                        .frame(width: 240, height: 240)
                        .padding(16)
                        .background(.white, in: RoundedRectangle(cornerRadius: 16))
                    Text(AccountID.grouped(id))
                        .font(.title3.monospaced())
                        .multilineTextAlignment(.center)
                    Button("Скопировать ID", systemImage: "doc.on.doc") { SecurePasteboard.copy(id) }
                    Text("ID не содержит номера телефона или других данных о вас. Он вычисляется из вашего ключа шифрования, поэтому сервер не может подменить ключ незаметно.")
                        .font(.footnote).foregroundStyle(.secondary).multilineTextAlignment(.center)
                } else {
                    ProgressView("Создание ключей…")
                }
            }
            .padding()
            .navigationTitle("Мой ID")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Готово") { dismiss() } } }
        }
    }
}

struct ContactInfoView: View {
    let contactID: String
    @Environment(MessengerService.self) private var service
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var confirmDelete = false
    @State private var confirmClear = false
    @State private var clearError: String?

    var body: some View {
        NavigationStack {
            Form {
                if let c = service.contact(contactID) {
                    Section("Имя") {
                        TextField("Имя", text: $name).autocorrectionDisabled()
                            .onSubmit { try? service.rename(contactID, to: name) }
                    }
                    Section {
                        Picker("Исчезающие сообщения", selection: Binding(
                            get: { c.disappearAfter },
                            set: { v in Task { try? await service.setDisappearing(v, for: contactID) } }
                        )) {
                            ForEach(DisappearTimer.options, id: \.self) { v in
                                Text(DisappearTimer.label(v)).tag(v)
                            }
                        }
                    } footer: {
                        Text("Таймер применяется у обоих собеседников. Ваши сообщения исчезают через это время после отправки, входящие — после прочтения.")
                    }
                    Section {
                        LabeledContent("ID") {
                            Text(AccountID.grouped(c.id)).font(.caption.monospaced())
                        }
                        LabeledContent("Проверен лично", value: c.verified ? "Да" : "Нет")
                    } footer: {
                        Text("Если вы не сканировали QR-код при встрече, сверьте ID голосом или лично.")
                    }
                    Section {
                        Button("Очистить переписку", role: .destructive) { confirmClear = true }
                        Button("Удалить чат и контакт", role: .destructive) { confirmDelete = true }
                    }
                }
            }
            .onAppear { name = service.contact(contactID)?.name ?? "" }
            .navigationTitle("Контакт")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Готово") {
                        if !name.isEmpty { try? service.rename(contactID, to: name) }
                        dismiss()
                    }
                }
            }
            .confirmationDialog("Очистить переписку без возможности восстановления? Контакт останется.",
                                isPresented: $confirmClear, titleVisibility: .visible) {
                Button("Только у меня", role: .destructive) { clear(forEveryone: false) }
                Button("У меня и у собеседника", role: .destructive) { clear(forEveryone: true) }
            }
            .alert("Не удалено", isPresented: .constant(clearError != nil)) {
                Button("OK") { clearError = nil }
            } message: { Text(clearError ?? "") }
            .confirmationDialog("Удалить переписку без возможности восстановления?", isPresented: $confirmDelete,
                                titleVisibility: .visible) {
                Button("Удалить", role: .destructive) {
                    try? service.deleteContact(contactID)
                    dismiss()
                }
            }
        }
    }

    private func clear(forEveryone: Bool) {
        Task {
            do {
                try await service.clearChat(contactID, forEveryone: forEveryone)
                dismiss()
            } catch {
                clearError = "Не удалось отправить собеседнику запрос на очистку. Проверьте соединение с сервером."
            }
        }
    }
}
