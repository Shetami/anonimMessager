import CalcCore
import SwiftUI

struct SettingsView: View {
    @Environment(Session.self) private var session
    @Environment(\.dismiss) private var dismiss
    @State private var codeSheet: CodeSheet?
    @State private var confirmWipe = false
    @State private var notice: String?

    enum CodeSheet: Identifiable {
        case change, decoy
        var id: Self { self }
    }

    var body: some View {
        @Bindable var session = session
        NavigationStack {
            Form {
                Section {
                    Picker("Автоблокировка", selection: $session.autoLockSeconds) {
                        Text("Сразу").tag(TimeInterval(0))
                        Text("30 секунд").tag(TimeInterval(30))
                        Text("1 минута").tag(TimeInterval(60))
                        Text("5 минут").tag(TimeInterval(300))
                    }
                } footer: {
                    Text("Через это время в фоне приложение снова станет ежедневником.")
                }

                Section {
                    Button("Изменить секретный код") { codeSheet = .change }
                    if session.canManageDecoy {
                        Button("Задать ложный код") { codeSheet = .decoy }
                        Button("Отключить ложный код", role: .destructive) {
                            try? session.removeDecoyCode()
                            notice = "Ложный код отключён."
                        }
                    }
                } header: {
                    Text("Коды")
                } footer: {
                    if session.canManageDecoy {
                        Text("Ложный код открывает второй, полностью отдельный профиль. Если вас вынуждают разблокировать приложение — введите его. Доказать существование основного профиля по данным на устройстве невозможно. Чтобы профиль выглядел правдоподобно, заведите в нём пару безобидных чатов.")
                    }
                }

                Section {
                    if JailbreakCheck.isSuspicious {
                        Label("Устройство похоже на взломанное (jailbreak). Защита данных не гарантируется.",
                              systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.yellow)
                    }
                    Button("Уничтожить все данные", role: .destructive) { confirmWipe = true }
                } footer: {
                    Text("Удаляет ящик на сервере и мгновенно уничтожает ключи на устройстве (оба профиля). Восстановление невозможно.")
                }
            }
            .navigationTitle("Настройки")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Готово") { dismiss() } } }
            .sheet(item: $codeSheet) { kind in
                CodeEntryView(title: kind == .change ? "Новый секретный код" : "Ложный код") { code in
                    do {
                        if kind == .change { try session.changeCode(code) } else { try session.setDecoyCode(code) }
                        notice = "Код сохранён."
                        return nil
                    } catch VaultError.codeInUse {
                        return "Этот код уже используется."
                    } catch VaultError.codeTooShort {
                        return "Минимум \(Vault.minimumCodeLength) символа."
                    } catch {
                        return "Ошибка сохранения."
                    }
                }
            }
            .confirmationDialog("Все данные будут уничтожены безвозвратно.", isPresented: $confirmWipe,
                                titleVisibility: .visible) {
                Button("Уничтожить", role: .destructive) {
                    Task { await session.wipeEverything() }
                }
            }
            .alert(notice ?? "", isPresented: .constant(notice != nil)) { Button("OK") { notice = nil } }
        }
    }
}

/// Code entry. The code is what you will type as a new task in the planner.
/// Saving runs PBKDF2, which takes about a second.
struct CodeEntryView: View {
    let title: String
    let save: (String) -> String?
    @Environment(\.dismiss) private var dismiss
    @State private var code = ""
    @State private var confirm = ""
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField("Код", text: $code)
                    SecureField("Повторите", text: $confirm)
                } footer: {
                    Text("Любой текст от \(Vault.minimumCodeLength) символов — ровно то, что будете вводить как новую задачу в ежедневнике. Регистр не важен. Лучше фраза, которая выглядит как обычная задача, но которую вы никогда не напишете случайно: например «Забрать 7 коробок у Лены».")
                }
                if let error { Section { Text(error).foregroundStyle(.red) } }
            }
            .autocorrectionDisabled()
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Отмена") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Сохранить") {
                        guard code == confirm else { error = "Коды не совпадают."; return }
                        if let e = save(TodoStore.code(from: code)) { error = e } else { dismiss() }
                    }
                    .disabled(code.isEmpty)
                }
            }
        }
    }
}
