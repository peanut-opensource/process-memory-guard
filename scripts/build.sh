#!/bin/zsh
set -euo pipefail

project_dir="${0:A:h:h}"
build_dir="$project_dir/work/build"
app_dir="$project_dir/outputs/Process Memory Guard.app"
binary="$app_dir/Contents/MacOS/ProcessMemoryGuard"
source_stage="$build_dir/Process-Memory-Guard-source"
version="2.1.1"

mkdir -p "$build_dir" "$project_dir/outputs" "$app_dir/Contents/MacOS" "$app_dir/Contents/Resources"

source_files=("$project_dir"/Sources/**/*.swift(N))
if (( ${#source_files[@]} == 0 )); then
  print -u2 "No Swift source files found under Sources"
  exit 1
fi

xcrun swiftc \
  -swift-version 5 \
  -O \
  -framework AppKit \
  -framework Security \
  -framework ServiceManagement \
  -framework UserNotifications \
  "${source_files[@]}" \
  -o "$binary"

/usr/libexec/PlistBuddy -c "Clear dict" "$app_dir/Contents/Info.plist" 2>/dev/null || true
/usr/libexec/PlistBuddy -c "Add :CFBundleDevelopmentRegion string zh_CN" "$app_dir/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Add :CFBundleDisplayName string Process Memory Guard" "$app_dir/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Add :CFBundleExecutable string ProcessMemoryGuard" "$app_dir/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Add :CFBundleIdentifier string com.peanutopensource.ProcessMemoryGuard" "$app_dir/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Add :CFBundleInfoDictionaryVersion string 6.0" "$app_dir/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Add :CFBundleName string ProcessMemoryGuard" "$app_dir/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Add :CFBundlePackageType string APPL" "$app_dir/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Add :CFBundleShortVersionString string $version" "$app_dir/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Add :CFBundleVersion string 210" "$app_dir/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Add :LSMinimumSystemVersion string 13.0" "$app_dir/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Add :LSUIElement bool true" "$app_dir/Contents/Info.plist"

ditto "$project_dir/LICENSE" "$app_dir/Contents/Resources/LICENSE"
codesign --force --sign - --identifier com.peanutopensource.ProcessMemoryGuard "$app_dir"
"$binary" --self-test
print "version=$version"

ditto -c -k --sequesterRsrc --keepParent "$app_dir" "$project_dir/outputs/Process-Memory-Guard.app.zip"
mkdir -p "$source_stage"
ditto "$project_dir/Sources" "$source_stage/Sources"
ditto "$project_dir/scripts" "$source_stage/scripts"
ditto "$project_dir/docs" "$source_stage/docs"
ditto "$project_dir/AGENTS.md" "$source_stage/AGENTS.md"
ditto "$project_dir/README.md" "$source_stage/README.md"
ditto "$project_dir/LICENSE" "$source_stage/LICENSE"
ditto -c -k --sequesterRsrc --keepParent "$source_stage" "$project_dir/outputs/Process-Memory-Guard-source.zip"

(cd "$project_dir/outputs" && shasum -a 256 "Process-Memory-Guard.app.zip" "Process-Memory-Guard-source.zip" > "SHA256SUMS")
print "sha256=outputs/SHA256SUMS"
