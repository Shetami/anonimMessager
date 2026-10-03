#!/usr/bin/env bash
# Generates the Xcode project and installs libsignal.
# Requires: Xcode (license accepted), Homebrew.
#   ./bootstrap.sh                     use the pinned libsignal (.libsignal-version)
#   ./bootstrap.sh --update-libsignal  re-pin to the version Signal-iOS currently ships
set -euo pipefail
cd "$(dirname "$0")"

command -v xcodegen >/dev/null || brew install xcodegen
command -v pod >/dev/null || brew install cocoapods

if [[ "${1:-}" == "--update-libsignal" ]]; then
  podfile=$(curl -fsSL https://raw.githubusercontent.com/signalapp/Signal-iOS/main/Podfile)
  tag=$(grep -E "^pod 'LibSignalClient'" <<<"$podfile" | grep -Eo "v[0-9]+\.[0-9]+\.[0-9]+" | head -1)
  sum=$(grep -E "^ENV\['LIBSIGNAL_FFI_PREBUILD_CHECKSUM'\]" <<<"$podfile" | grep -Eo "[0-9a-f]{64}" | head -1)
  [[ -n "$tag" && -n "$sum" ]] || { echo "Could not parse Signal-iOS Podfile" >&2; exit 1; }
  printf 'LIBSIGNAL_TAG=%s\nLIBSIGNAL_FFI_PREBUILD_CHECKSUM=%s\n' "$tag" "$sum" > .libsignal-version
  echo "Pinned libsignal $tag — re-check Calculon/Crypto/SignalEngine.swift against its API."
fi

xcodegen generate
pod install
echo "Done. Open Calculon.xcworkspace"
