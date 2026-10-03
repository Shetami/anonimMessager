#!/usr/bin/env bash
# Generates the Xcode project and installs libsignal.
# Requires: Xcode (license accepted), Homebrew.
#   ./bootstrap.sh                     use the pinned libsignal (.libsignal-version)
#   ./bootstrap.sh --update-signal     re-pin libsignal and RingRTC to the versions Signal-iOS currently ships
set -euo pipefail
cd "$(dirname "$0")"

command -v xcodegen >/dev/null || brew install xcodegen
command -v pod >/dev/null || brew install cocoapods

# pin <pod name> <checksum env var> <output file> <tag key> <checksum key>
pin() {
  local tag sum
  tag=$(grep -E "^pod '$1'" <<<"$podfile" | grep -Eo "v[0-9]+\.[0-9]+\.[0-9]+" | head -1)
  sum=$(grep -E "^ENV\['$2'\]" <<<"$podfile" | grep -Eo "[0-9a-f]{64}" | head -1)
  [[ -n "$tag" && -n "$sum" ]] || { echo "Could not parse $1 from the Signal-iOS Podfile" >&2; exit 1; }
  printf '%s=%s\n%s=%s\n' "$4" "$tag" "$5" "$sum" > "$3"
  echo "Pinned $1 $tag"
}

if [[ "${1:-}" == "--update-signal" || "${1:-}" == "--update-libsignal" ]]; then
  podfile=$(curl -fsSL https://raw.githubusercontent.com/signalapp/Signal-iOS/main/Podfile)
  pin LibSignalClient LIBSIGNAL_FFI_PREBUILD_CHECKSUM .libsignal-version LIBSIGNAL_TAG LIBSIGNAL_FFI_PREBUILD_CHECKSUM
  pin SignalRingRTC RINGRTC_PREBUILD_CHECKSUM .ringrtc-version RINGRTC_TAG RINGRTC_PREBUILD_CHECKSUM
  echo "Re-check Calculon/Crypto/SignalEngine.swift and Calculon/Calls/CallService.swift against the new APIs."
fi

xcodegen generate
pod install
echo "Done. Open Calculon.xcworkspace"
