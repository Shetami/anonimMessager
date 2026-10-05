import AVFoundation
import CalcCore
import ImageIO
import PhotosUI
import SwiftUI
import UniformTypeIdentifiers

enum AttachmentError: LocalizedError {
    case unreadable
    case tooLarge(String)

    var errorDescription: String? {
        switch self {
        case .unreadable: return "Не удалось прочитать файл."
        case .tooLarge(let name):
            return "«\(name)» больше \(ByteCountFormatter.string(fromByteCount: Int64(MessengerService.maxAttachmentSize), countStyle: .file))."
        }
    }
}

// MARK: - Preparing picked files

/// Turns picked photos, videos and files into attachments. Photos are
/// re-encoded and videos re-exported so EXIF/GPS and other metadata never
/// leave the device.
enum AttachmentPreparer {
    static let maxImagePixels = 4096
    static let thumbnailPixels = 240

    static func prepare(_ item: PhotosPickerItem) async throws -> OutgoingAttachment {
        if item.supportedContentTypes.contains(where: { $0.conforms(to: .movie) }) {
            guard let movie = try await item.loadTransferable(type: PickedMovie.self) else { throw AttachmentError.unreadable }
            defer { try? FileManager.default.removeItem(at: movie.url) }
            return try await video(at: movie.url)
        }
        guard let data = try await item.loadTransferable(type: Data.self) else { throw AttachmentError.unreadable }
        return try image(data)
    }

    static func prepare(fileAt url: URL) throws -> OutgoingAttachment {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
        guard size <= MessengerService.maxAttachmentSize else { throw AttachmentError.tooLarge(url.lastPathComponent) }
        let data = try Data(contentsOf: url)
        let mime = UTType(filenameExtension: url.pathExtension)?.preferredMIMEType ?? "application/octet-stream"
        return OutgoingAttachment(data: data, name: url.lastPathComponent, mime: mime)
    }

    static func image(_ data: Data) throws -> OutgoingAttachment {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil),
              let full = downsample(source, maxPixels: maxImagePixels),
              let jpeg = UIImage(cgImage: full).jpegData(compressionQuality: 0.85)
        else { throw AttachmentError.unreadable }
        return OutgoingAttachment(
            data: jpeg, name: "photo-\(shortID()).jpg", mime: "image/jpeg",
            thumbnail: downsample(source, maxPixels: thumbnailPixels).flatMap(thumbnailJPEG),
            width: full.width, height: full.height)
    }

    static func video(at url: URL) async throws -> OutgoingAttachment {
        let asset = AVURLAsset(url: url)
        guard let export = AVAssetExportSession(asset: asset, presetName: AVAssetExportPresetHighestQuality) else {
            throw AttachmentError.unreadable
        }
        let out = TempFiles.makeURL(name: "video-\(shortID()).mp4")
        defer { try? FileManager.default.removeItem(at: out) }
        export.outputURL = out
        export.outputFileType = .mp4
        export.shouldOptimizeForNetworkUse = true
        // Drops location, device model and other identifying metadata.
        export.metadataItemFilter = .forSharing()
        await export.export()
        guard export.status == .completed else { throw AttachmentError.unreadable }

        let size = (try? out.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
        guard size <= MessengerService.maxAttachmentSize else { throw AttachmentError.tooLarge("Видео") }
        let data = try Data(contentsOf: out)

        let generator = AVAssetImageGenerator(asset: asset)
        generator.appliesPreferredTrackTransform = true
        generator.maximumSize = CGSize(width: thumbnailPixels, height: thumbnailPixels)
        let frame = try? await generator.image(at: .zero).image
        return OutgoingAttachment(
            data: data, name: out.lastPathComponent, mime: "video/mp4",
            thumbnail: frame.flatMap(thumbnailJPEG), width: frame?.width, height: frame?.height)
    }

    static func downsample(_ source: CGImageSource, maxPixels: Int) -> CGImage? {
        let options: [CFString: Any] = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceCreateThumbnailWithTransform: true,
            kCGImageSourceThumbnailMaxPixelSize: maxPixels,
        ]
        return CGImageSourceCreateThumbnailAtIndex(source, 0, options as CFDictionary)
    }

    private static func thumbnailJPEG(_ image: CGImage) -> Data? {
        UIImage(cgImage: image).jpegData(compressionQuality: 0.5)
    }

    private static func shortID() -> String { String(UUID().uuidString.prefix(8)).lowercased() }
}

/// A picked video, copied out of the Photos library into a temporary file.
struct PickedMovie: Transferable {
    let url: URL

    static var transferRepresentation: some TransferRepresentation {
        FileRepresentation(contentType: .movie) { SentTransferredFile($0.url) } importing: { received in
            let url = TempFiles.makeURL(name: "import-\(UUID().uuidString).\(received.file.pathExtension)")
            try FileManager.default.copyItem(at: received.file, to: url)
            return Self(url: url)
        }
    }
}

/// Decrypted copies for QuickLook / video playback, and transient copies
/// while picking. Removed when the viewer closes, on lock and at launch.
enum TempFiles {
    static var directory: URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("open", isDirectory: true)
    }

    static func makeURL(name: String) -> URL {
        let dir = directory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let base = (name as NSString).lastPathComponent
        return dir.appendingPathComponent(base.isEmpty || base.hasPrefix(".") ? "file" : base)
    }

    static func write(_ data: Data, name: String) throws -> URL {
        let url = makeURL(name: name)
        try data.write(to: url, options: [.atomic, .completeFileProtection])
        return url
    }

    static func removeAll() {
        try? FileManager.default.removeItem(at: directory)
    }
}

// MARK: - Composer

struct PendingAttachmentsStrip: View {
    @Binding var items: [OutgoingAttachment]

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(items.indices, id: \.self) { i in
                    ZStack(alignment: .topTrailing) {
                        AttachmentThumb(thumbnail: items[i].thumbnail, mime: items[i].mime, name: items[i].name)
                            .frame(width: 64, height: 64)
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                        Button {
                            items.remove(at: i)
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .symbolRenderingMode(.palette)
                                .foregroundStyle(.white, .black.opacity(0.7))
                        }
                        .offset(x: 6, y: -6)
                    }
                }
            }
            .padding(.horizontal, 12)
            .padding(.top, 10)
        }
    }
}

/// Thumbnail if there is one, otherwise a document icon with the name.
struct AttachmentThumb: View {
    let thumbnail: Data?
    let mime: String
    let name: String

    var body: some View {
        if let thumbnail, let image = UIImage(data: thumbnail) {
            Image(uiImage: image).resizable().scaledToFill()
                .overlay {
                    if mime.hasPrefix("video/") {
                        Image(systemName: "play.circle.fill").font(.title2).foregroundStyle(.white)
                    }
                }
        } else {
            VStack(spacing: 4) {
                Image(systemName: "doc.fill").font(.title3)
                Text(name).font(.system(size: 9)).lineLimit(2).multilineTextAlignment(.center)
            }
            .padding(4)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Theme.surface)
        }
    }
}

// MARK: - In a message

struct AttachmentList: View {
    let message: ChatMessage
    let open: (AttachmentPointer) -> Void

    private var media: [AttachmentPointer] { (message.attachments ?? []).filter { $0.isImage || $0.isVideo } }
    private var documents: [AttachmentPointer] { (message.attachments ?? []).filter { !$0.isImage && !$0.isVideo } }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            if !media.isEmpty {
                let single = media.count == 1
                LazyVGrid(columns: Array(repeating: GridItem(.fixed(single ? 220 : 108), spacing: 4), count: single ? 1 : 2),
                          spacing: 4) {
                    ForEach(media) { p in
                        MediaTile(pointer: p, open: open)
                            .frame(width: single ? 220 : 108, height: single ? 220 : 108)
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                    }
                }
            }
            ForEach(documents) { p in
                DocumentRow(pointer: p, outgoing: message.outgoing, open: open)
            }
        }
    }
}

private struct MediaTile: View {
    let pointer: AttachmentPointer
    let open: (AttachmentPointer) -> Void
    @Environment(MessengerService.self) private var service
    @State private var image: UIImage?

    var body: some View {
        let downloaded = service.isDownloaded(pointer) && !service.downloading.contains(pointer.id)
        Button {
            if downloaded { open(pointer) } else { Task { await service.download(pointer) } }
        } label: {
            ZStack {
                Color(.systemGray2)
                if let image {
                    Image(uiImage: image).resizable().scaledToFill()
                } else if let t = pointer.thumbnail, let thumb = UIImage(data: t) {
                    Image(uiImage: thumb).resizable().scaledToFill().blur(radius: downloaded ? 0 : 6)
                }
                DownloadState(pointer: pointer, downloaded: downloaded)
                if downloaded && pointer.isVideo {
                    Image(systemName: "play.circle.fill").font(.largeTitle).foregroundStyle(.white)
                }
            }
        }
        .buttonStyle(.plain)
        .task(id: downloaded) {
            guard downloaded, pointer.isImage, image == nil,
                  let data = try? await service.attachmentData(pointer),
                  let source = CGImageSourceCreateWithData(data as CFData, nil),
                  let cg = AttachmentPreparer.downsample(source, maxPixels: 600)
            else { return }
            image = UIImage(cgImage: cg)
        }
    }
}

private struct DocumentRow: View {
    let pointer: AttachmentPointer
    let outgoing: Bool
    let open: (AttachmentPointer) -> Void
    @Environment(MessengerService.self) private var service

    var body: some View {
        let downloaded = service.isDownloaded(pointer) && !service.downloading.contains(pointer.id)
        Button {
            if downloaded { open(pointer) } else { Task { await service.download(pointer) } }
        } label: {
            HStack(spacing: 10) {
                ZStack {
                    Circle().fill(outgoing ? AnyShapeStyle(Color.black.opacity(0.2)) : AnyShapeStyle(Theme.gradient))
                    if downloaded {
                        Image(systemName: "doc.fill").foregroundStyle(Theme.onAccent)
                    } else {
                        DownloadState(pointer: pointer, downloaded: false)
                    }
                }
                .frame(width: 40, height: 40)
                VStack(alignment: .leading, spacing: 2) {
                    Text(pointer.name).font(.subheadline).lineLimit(1).truncationMode(.middle)
                    Text(ByteCountFormatter.string(fromByteCount: Int64(pointer.size), countStyle: .file))
                        .font(.caption).opacity(0.7)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .frame(maxWidth: 260, alignment: .leading)
            .background(outgoing ? AnyShapeStyle(Theme.gradient) : AnyShapeStyle(Theme.surface),
                        in: RoundedRectangle(cornerRadius: 16))
            .foregroundStyle(outgoing ? Theme.textOnAccent : .primary)
        }
        .buttonStyle(.plain)
    }
}

/// Spinner while downloading, a retry/download arrow otherwise.
private struct DownloadState: View {
    let pointer: AttachmentPointer
    let downloaded: Bool
    @Environment(MessengerService.self) private var service

    var body: some View {
        if service.downloading.contains(pointer.id) {
            ProgressView().tint(.white)
        } else if !downloaded {
            Image(systemName: service.failedDownloads.contains(pointer.id) ? "arrow.clockwise.circle.fill" : "arrow.down.circle.fill")
                .font(.title)
                .foregroundStyle(.white)
        }
    }
}

// MARK: - Viewer

/// Full-screen photo viewer. Drawn inside the chat (not as a separate
/// presentation) so it stays under the screenshot shield.
struct PhotoViewer: View {
    let pointer: AttachmentPointer
    let close: () -> Void
    @Environment(MessengerService.self) private var service
    @State private var image: UIImage?
    @State private var scale: CGFloat = 1

    var body: some View {
        ZStack(alignment: .topTrailing) {
            Color.black.ignoresSafeArea()
            if let image {
                Image(uiImage: image)
                    .resizable()
                    .scaledToFit()
                    .scaleEffect(scale)
                    .gesture(MagnifyGesture()
                        .onChanged { scale = max(1, $0.magnification) }
                        .onEnded { _ in withAnimation { scale = 1 } })
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            Button(action: close) {
                Image(systemName: "xmark.circle.fill").font(.title).foregroundStyle(.white.opacity(0.8))
            }
            .padding()
        }
        .task {
            guard let data = try? await service.attachmentData(pointer),
                  let source = CGImageSourceCreateWithData(data as CFData, nil),
                  let cg = AttachmentPreparer.downsample(source, maxPixels: AttachmentPreparer.maxImagePixels)
            else { return }
            image = UIImage(cgImage: cg)
        }
    }
}
