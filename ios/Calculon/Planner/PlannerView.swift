import CalcCore
import SwiftUI

/// The disguise: an ordinary daily planner. Every new task is quietly checked
/// against the vault (see `AppModel.submitDraft`).
struct PlannerView: View {
    @Environment(AppModel.self) private var model
    @State private var selectedDay = Calendar.current.startOfDay(for: Date())
    @FocusState private var inputFocused: Bool

    private let calendar = Calendar.current
    static let locale = Locale(identifier: "ru_RU")

    var body: some View {
        NavigationStack {
            List {
                setupBanner
                let tasks = model.planner.items(on: selectedDay).sorted { $0.created < $1.created }
                let open = tasks.filter { !$0.done }
                let done = tasks.filter(\.done)
                if !open.isEmpty {
                    Section { ForEach(open) { TaskRow(task: $0, day: selectedDay) } }
                }
                if !done.isEmpty {
                    Section("Выполнено") { ForEach(done) { TaskRow(task: $0, day: selectedDay) } }
                }
            }
            .listStyle(.insetGrouped)
            .overlay {
                if model.planner.items(on: selectedDay).isEmpty && model.setupStep == nil {
                    ContentUnavailableView("Нет задач", systemImage: "checklist",
                                           description: Text("Добавьте задачу на этот день"))
                }
            }
            .safeAreaInset(edge: .top, spacing: 0) {
                WeekStrip(selectedDay: $selectedDay)
            }
            .safeAreaInset(edge: .bottom, spacing: 0) { inputBar }
            .navigationTitle(title)
            // Inline: a large title lives inside the list's scroll area and the
            // top-inset week strip would cover it.
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                if !calendar.isDateInToday(selectedDay) {
                    ToolbarItem(placement: .topBarTrailing) {
                        Button("Сегодня") {
                            withAnimation { selectedDay = calendar.startOfDay(for: Date()) }
                        }
                    }
                }
            }
        }
    }

    private var title: String {
        if calendar.isDateInToday(selectedDay) { return "Сегодня" }
        if calendar.isDateInTomorrow(selectedDay) { return "Завтра" }
        if calendar.isDateInYesterday(selectedDay) { return "Вчера" }
        return selectedDay.formatted(.dateTime.day().month(.wide).locale(Self.locale))
    }

    private var inputBar: some View {
        @Bindable var model = model
        return HStack(spacing: 10) {
            Image(systemName: "plus.circle.fill")
                .font(.title2)
                .foregroundStyle(.tint)
            // No autocorrection: the keyboard must not learn (and later
            // suggest) a code typed here.
            TextField("Новая задача", text: $model.draft)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.sentences)
                .submitLabel(.done)
                .focused($inputFocused)
                .onSubmit {
                    model.submitDraft(on: selectedDay)
                    inputFocused = true // keep the keyboard up for the next task
                }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(.bar)
    }

    @ViewBuilder
    private var setupBanner: some View {
        if let step = model.setupStep {
            Section {
                VStack(alignment: .leading, spacing: 6) {
                    Text(step == .choose
                         ? "Придумайте секретный код (от \(Vault.minimumCodeLength) символов) и введите его как новую задачу. Подойдёт любая фраза, например «Купить 3 лимона»."
                         : "Повторите код ещё раз как новую задачу.")
                        .font(.footnote)
                    if let msg = model.setupMessage {
                        Text(msg).font(.footnote.bold()).foregroundStyle(.red)
                    }
                    Text("Эта подсказка больше никогда не появится. Потом мессенджер открывается, если добавить задачу с этим текстом.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 4)
            }
        }
    }
}

private struct TaskRow: View {
    @Environment(AppModel.self) private var model
    let task: TodoItem
    let day: Date

    var body: some View {
        Button {
            UIImpactFeedbackGenerator(style: .light).impactOccurred()
            withAnimation { model.planner.toggle(task.id) }
        } label: {
            HStack(spacing: 12) {
                Image(systemName: task.done ? "checkmark.circle.fill" : "circle")
                    .font(.title3)
                    .foregroundStyle(task.done ? AnyShapeStyle(.tint) : AnyShapeStyle(.secondary))
                Text(task.title)
                    .strikethrough(task.done)
                    .foregroundStyle(task.done ? .secondary : .primary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .swipeActions(edge: .trailing) {
            Button("Удалить", systemImage: "trash", role: .destructive) {
                withAnimation { model.planner.remove(task.id) }
            }
            Button("На завтра", systemImage: "arrow.turn.up.right") {
                withAnimation { model.planner.move(task.id, to: shifted(1)) }
            }
            .tint(Theme.accent)
        }
        .contextMenu {
            Button("Перенести на завтра", systemImage: "arrow.turn.up.right") {
                model.planner.move(task.id, to: shifted(1))
            }
            Button("Удалить", systemImage: "trash", role: .destructive) {
                model.planner.remove(task.id)
            }
        }
    }

    private func shifted(_ days: Int) -> Date {
        Calendar.current.date(byAdding: .day, value: days, to: day) ?? day
    }
}

/// One week of days; swipe sideways to change the week.
private struct WeekStrip: View {
    @Environment(AppModel.self) private var model
    @Binding var selectedDay: Date
    private let calendar = Calendar.current

    private var days: [Date] {
        let start = calendar.dateInterval(of: .weekOfYear, for: selectedDay)?.start ?? selectedDay
        return (0..<7).compactMap { calendar.date(byAdding: .day, value: $0, to: start) }
    }

    var body: some View {
        HStack(spacing: 4) {
            ForEach(days, id: \.self) { day in
                let selected = calendar.isDate(day, inSameDayAs: selectedDay)
                let today = calendar.isDateInToday(day)
                Button {
                    withAnimation(.snappy) { selectedDay = day }
                } label: {
                    VStack(spacing: 4) {
                        Text(day.formatted(.dateTime.weekday(.abbreviated).locale(PlannerView.locale)).capitalized)
                            .font(.caption2)
                            .foregroundStyle(selected ? AnyShapeStyle(Theme.onAccent.opacity(0.85)) : AnyShapeStyle(.secondary))
                        Text(day.formatted(.dateTime.day()))
                            .font(.body.weight(today || selected ? .semibold : .regular))
                            .foregroundStyle(selected ? AnyShapeStyle(Theme.onAccent) : today ? AnyShapeStyle(.tint) : AnyShapeStyle(.primary))
                        Circle()
                            .frame(width: 5, height: 5)
                            .foregroundStyle(selected ? AnyShapeStyle(Theme.onAccent) : AnyShapeStyle(.tint))
                            .opacity(model.planner.hasOpenItems(on: day) ? 1 : 0)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                    .background {
                        if selected { RoundedRectangle(cornerRadius: 12).fill(Theme.gradient) }
                    }
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 12)
        .padding(.bottom, 8)
        .background(.bar)
        .gesture(DragGesture(minimumDistance: 30).onEnded { v in
            guard abs(v.translation.width) > 60 else { return }
            let weeks = v.translation.width < 0 ? 1 : -1
            withAnimation(.snappy) {
                selectedDay = calendar.date(byAdding: .weekOfYear, value: weeks, to: selectedDay) ?? selectedDay
            }
        })
    }
}
