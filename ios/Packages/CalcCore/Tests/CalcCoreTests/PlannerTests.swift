import Foundation
import Testing
@testable import CalcCore

struct TodoStoreTests {
    let today = Calendar.current.startOfDay(for: Date())
    var tomorrow: Date { Calendar.current.date(byAdding: .day, value: 1, to: today)! }

    func fileText(_ url: URL) -> String {
        (try? String(contentsOf: url, encoding: .utf8)) ?? ""
    }

    @Test func persistsAcrossReloads() throws {
        let url = tempDir().appendingPathComponent("tasks.json")
        var store = TodoStore(fileURL: url)
        let newMilk = store.add("  Купить молоко ", on: today)
        let milk = try #require(newMilk)
        store.add("Позвонить маме", on: tomorrow)
        store.toggle(milk.id)

        let reloaded = TodoStore(fileURL: url)
        #expect(reloaded.items.count == 2)
        #expect(reloaded.items(on: today).map(\.title) == ["Купить молоко"])
        #expect(reloaded.items(on: today).first?.done == true)
        #expect(!reloaded.hasOpenItems(on: today))
        #expect(reloaded.hasOpenItems(on: tomorrow))
    }

    @Test func emptyTitleIsIgnored() {
        var store = TodoStore(fileURL: nil)
        #expect(store.add("   \n", on: today) == nil)
        #expect(store.items.isEmpty)
    }

    @Test func heldTaskNeverReachesDisk() throws {
        let url = tempDir().appendingPathComponent("tasks.json")
        var store = TodoStore(fileURL: url)
        let newCode = store.add("секрет 7391", on: today, held: true)
        let code = try #require(newCode)
        // Other edits while the code is being checked must not flush it either.
        store.add("Обычная задача", on: today)
        store.toggle(code.id)
        #expect(store.items.count == 2)
        #expect(!fileText(url).contains("7391"))

        store.discard(code.id)
        #expect(store.items.map(\.title) == ["Обычная задача"])
        #expect(!fileText(url).contains("7391"))
        #expect(TodoStore(fileURL: url).items.count == 1)
    }

    @Test func releasedTaskIsSaved() throws {
        let url = tempDir().appendingPathComponent("tasks.json")
        var store = TodoStore(fileURL: url)
        let newTask = store.add("Сходить в зал", on: today, held: true)
        let task = try #require(newTask)
        store.release(task.id)
        #expect(TodoStore(fileURL: url).items.map(\.title) == ["Сходить в зал"])
        // Release/discard of an already resolved task is a no-op.
        store.discard(task.id)
        #expect(store.items.count == 1)
    }

    @Test func moveToAnotherDay() throws {
        var store = TodoStore(fileURL: nil)
        let newTask = store.add("Отчёт", on: today)
        let task = try #require(newTask)
        store.move(task.id, to: tomorrow.addingTimeInterval(3600))
        #expect(store.items(on: today).isEmpty)
        #expect(store.items(on: tomorrow).count == 1)
        store.remove(task.id)
        #expect(store.items.isEmpty)
    }

    @Test func normalizeMatchesTypedCode() {
        // Decomposed "й" (и + combining breve) as some input methods produce it.
        #expect(TodoStore.normalize(" мой код\n") == TodoStore.normalize("мои\u{0306} код"))
        // The task field auto-capitalizes; the settings field doesn't.
        #expect(TodoStore.code(from: "Купить 3 Лимона ") == TodoStore.code(from: "купить 3 лимона"))
    }
}
