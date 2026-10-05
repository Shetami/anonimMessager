import SwiftUI

/// One palette for the planner and the messenger, taken from the app icon:
/// a warm amber gradient with white marks. Everything else is system colors,
/// so both halves follow light/dark mode the same way.
enum Theme {
    /// Matches the AccentColor asset (deeper in light mode for contrast on white).
    static let accent = Color.accentColor

    /// The icon's own gradient, top to bottom.
    static let gradient = LinearGradient(colors: [Color(red: 1, green: 0.8, blue: 0.376),
                                                  Color(red: 1, green: 0.639, blue: 0)],
                                         startPoint: .top, endPoint: .bottom)

    /// Marks drawn on the amber (the icon's checkmark).
    static let onAccent = Color.white
    /// Running text on the amber: white is unreadable there.
    static let textOnAccent = Color.black.opacity(0.85)

    /// Incoming bubbles, input fields, document tiles.
    static let surface = Color(.secondarySystemBackground)
    /// Small service pills in the chat (timer changes, call log).
    static let pill = Color(.tertiarySystemFill)
}

/// Round initial in the icon's style; used for contacts and calls.
struct Avatar: View {
    let name: String
    var size: CGFloat = 44

    var body: some View {
        Circle()
            .fill(Theme.gradient)
            .frame(width: size, height: size)
            .overlay(Text(name.prefix(1).uppercased())
                .font(.system(size: size * 0.42, weight: .bold, design: .rounded))
                .foregroundStyle(Theme.onAccent))
    }
}
