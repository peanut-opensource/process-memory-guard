import AppKit
import Darwin
import Security
import ServiceManagement
import SwiftUI
import UserNotifications

private enum Constants {
    static let appName = "Process Memory Guard"
    static let defaultPath = "/Library/Apple/System/Library/PrivateFrameworks/RemotePairing.framework/Versions/A/XPCServices/remotepairingd.xpc/Contents/MacOS/remotepairingd"
    static let defaultIdentifier = "com.apple.CoreDevice.remotepairingd"
    static let openAIEndpoint = URL(string: "https://api.openai.com/v1/responses")!
    static let notificationCategory = "PROCESS_MEMORY_ALERT"
    static let setThresholdAction = "SET_THRESHOLD"
    static let reminderCooldown: TimeInterval = 30 * 60
    static let gib = UInt64(1_073_741_824)
}

private struct AppGroup: Codable, Identifiable, Hashable { var id: UUID; var name: String }
private struct ProcessRule: Codable, Identifiable, Hashable {
    var id: UUID; var groupID: UUID; var name: String; var executablePath: String
    var signingIdentifier: String; var signingRequirement: String; var thresholdBytes: UInt64; var enabled: Bool
}
private struct SavedConfiguration: Codable { var groups: [AppGroup]; var rules: [ProcessRule] }
private struct ProcessSample { let pid: pid_t; let footprint: UInt64 }
private enum RuleScan { case notRunning, running([ProcessSample]), invalid(String) }
private struct RuleRuntime {
    var memoryBytes: UInt64 = 0; var pids: [pid_t] = []; var error: String?
    var aboveThreshold = false; var samples: [UInt64] = []; var lastNotification: Date?
    var aiSummary: AIAnalysis?; var aiInFlight = false
}

private enum CodeIdentity {
    static func inspect(path: String) -> Result<(identifier: String, requirement: String), Error> {
        let url = URL(fileURLWithPath: path) as CFURL
        var code: SecStaticCode?
        var status = SecStaticCodeCreateWithPath(url, SecCSFlags(), &code)
        guard status == errSecSuccess, let code else { return .failure(error("无法读取代码签名", status)) }
        var requirement: SecRequirement?
        status = SecCodeCopyDesignatedRequirement(code, SecCSFlags(), &requirement)
        guard status == errSecSuccess, let requirement else { return .failure(error("目标没有可用的指定签名要求", status)) }
        var requirementText: CFString?
        status = SecRequirementCopyString(requirement, SecCSFlags(), &requirementText)
        guard status == errSecSuccess, let requirementText else { return .failure(error("无法读取签名要求", status)) }
        var information: CFDictionary?
        status = SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information)
        let dictionary = information as? [String: Any]
        let identifier = dictionary?[kSecCodeInfoIdentifier as String] as? String ?? URL(fileURLWithPath: path).lastPathComponent
        return .success((identifier, requirementText as String))
    }

    static func validate(_ rule: ProcessRule) -> String? {
        var code: SecStaticCode?
        var status = SecStaticCodeCreateWithPath(URL(fileURLWithPath: rule.executablePath) as CFURL, SecCSFlags(), &code)
        guard status == errSecSuccess, let code else { return "无法读取可执行文件签名" }
        var requirement: SecRequirement?
        status = SecRequirementCreateWithString(rule.signingRequirement as CFString, SecCSFlags(), &requirement)
        guard status == errSecSuccess, let requirement else { return "保存的签名规则无效" }
        status = SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures), requirement)
        return status == errSecSuccess ? nil : "当前文件不再满足保存的签名身份"
    }

    private static func error(_ message: String, _ status: OSStatus) -> NSError {
        NSError(domain: "ProcessMemoryGuard.CodeIdentity", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "\(message)（OSStatus \(status)）"])
    }
}

private enum ProcessInspector {
    static func scan(rules: [ProcessRule]) -> [UUID: RuleScan] {
        let enabled = rules.filter(\.enabled)
        var result = Dictionary(uniqueKeysWithValues: enabled.map { ($0.id, RuleScan.notRunning) })
        let byPath = Dictionary(grouping: enabled, by: \.executablePath)
        let estimated = proc_listallpids(nil, 0)
        guard estimated > 0 else { return Dictionary(uniqueKeysWithValues: enabled.map { ($0.id, .invalid("无法读取本机进程表")) }) }
        var pids = [pid_t](repeating: 0, count: Int(estimated) + 64)
        let count = pids.withUnsafeMutableBytes { proc_listallpids($0.baseAddress, Int32($0.count)) }
        guard count >= 0 else { return Dictionary(uniqueKeysWithValues: enabled.map { ($0.id, .invalid("读取本机进程表失败")) }) }
        var samplesByRule: [UUID: [ProcessSample]] = [:]
        var validated = Set<UUID>()
        for pid in pids.prefix(Int(count)) where pid > 0 {
            guard let path = executablePath(pid), let candidates = byPath[path], let footprint = physicalFootprint(pid) else { continue }
            for rule in candidates {
                if !validated.contains(rule.id) {
                    validated.insert(rule.id)
                    if let message = CodeIdentity.validate(rule) { result[rule.id] = .invalid(message); continue }
                }
                if case .invalid = result[rule.id] { continue }
                samplesByRule[rule.id, default: []].append(ProcessSample(pid: pid, footprint: footprint))
            }
        }
        for (id, samples) in samplesByRule { result[id] = .running(samples) }
        return result
    }

    static func physicalFootprint(_ pid: pid_t) -> UInt64? {
        var usage = rusage_info_v4()
        let value = withUnsafeMutablePointer(to: &usage) { pointer -> Int32 in
            UnsafeMutableRawPointer(pointer).withMemoryRebound(to: rusage_info_t?.self, capacity: 1) { proc_pid_rusage(pid, RUSAGE_INFO_V4, $0) }
        }
        return value == 0 ? usage.ri_phys_footprint : nil
    }

    private static func executablePath(_ pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let length = buffer.withUnsafeMutableBufferPointer { proc_pidpath(pid, $0.baseAddress, UInt32($0.count)) }
        return length > 0 ? String(cString: buffer) : nil
    }
}

private final class Preferences {
    private let defaults = UserDefaults.standard
    private enum Key {
        static let configuration = "groupedConfigurationV2"; static let enabled = "monitoringEnabledV2"
        static let interval = "monitorIntervalSecondsV2"; static let aiEnabled = "aiAnalysisEnabledV2"; static let aiModel = "aiModelV2"
    }
    init() { defaults.register(defaults: [Key.enabled: true, Key.interval: 60.0, Key.aiEnabled: false, Key.aiModel: "gpt-5.6"]) }
    var enabled: Bool { get { defaults.bool(forKey: Key.enabled) } set { defaults.set(newValue, forKey: Key.enabled) } }
    var interval: TimeInterval { get { max(15, defaults.double(forKey: Key.interval)) } set { defaults.set(max(15, newValue), forKey: Key.interval) } }
    var aiEnabled: Bool { get { defaults.bool(forKey: Key.aiEnabled) } set { defaults.set(newValue, forKey: Key.aiEnabled) } }
    var aiModel: String {
        get { defaults.string(forKey: Key.aiModel).flatMap { $0.isEmpty ? nil : $0 } ?? "gpt-5.6" }
        set { defaults.set(newValue.trimmingCharacters(in: .whitespacesAndNewlines), forKey: Key.aiModel) }
    }
    func load() -> SavedConfiguration {
        if let data = defaults.data(forKey: Key.configuration), let value = try? JSONDecoder().decode(SavedConfiguration.self, from: data) { return value }
        let group = AppGroup(id: UUID(), name: "Apple 设备通信")
        let identity = try? CodeIdentity.inspect(path: Constants.defaultPath).get()
        let rule = ProcessRule(id: UUID(), groupID: group.id, name: "remotepairingd", executablePath: Constants.defaultPath,
                               signingIdentifier: identity?.identifier ?? Constants.defaultIdentifier,
                               signingRequirement: identity?.requirement ?? "anchor apple and identifier \"\(Constants.defaultIdentifier)\"",
                               thresholdBytes: Constants.gib, enabled: true)
        return SavedConfiguration(groups: [group], rules: [rule])
    }
    func save(_ value: SavedConfiguration) { if let data = try? JSONEncoder().encode(value) { defaults.set(data, forKey: Key.configuration) } }
}

private enum APIKeyStore {
    private static let service = "com.local.RemotePairingGuard.openai"; private static let account = "api-key"
    static func load() -> String? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                    kSecAttrAccount as String: account, kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
    static func save(_ key: String) -> OSStatus {
        let base: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
        SecItemDelete(base as CFDictionary); var item = base; item[kSecValueData as String] = Data(key.utf8); item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        return SecItemAdd(item as CFDictionary, nil)
    }
}

private struct AIAnalysis {
    let verdict: String; let summary: String; let recommendation: String
    var label: String { ["abnormal": "确认异常", "likely_abnormal": "很可能异常", "likely_normal": "可能正常"][verdict] ?? "无法确定" }
}

private enum AIAnalyzer {
    static func analyze(rule: ProcessRule, group: String, model: String, apiKey: String, samples: [UInt64], interval: TimeInterval,
                        completion: @escaping (Result<AIAnalysis, Error>) -> Void) {
        let evidence: [String: Any] = ["application_group": group, "process": rule.name, "signing_identifier": rule.signingIdentifier,
            "signature_verified": true, "metric": "macOS ri_phys_footprint", "threshold_mb": Double(rule.thresholdBytes) / 1_048_576,
            "sample_interval_seconds": interval, "samples_mb_oldest_to_newest": samples.map { Double($0) / 1_048_576 }]
        let evidenceData = try! JSONSerialization.data(withJSONObject: evidence, options: [.sortedKeys])
        let schema: [String: Any] = ["type": "object", "properties": ["verdict": ["type": "string", "enum": ["abnormal", "likely_abnormal", "uncertain", "likely_normal"]],
            "summary": ["type": "string", "maxLength": 180], "recommendation": ["type": "string", "maxLength": 180]],
            "required": ["verdict", "summary", "recommendation"], "additionalProperties": false]
        let body: [String: Any] = ["model": model, "store": false, "max_output_tokens": 300,
            "input": [["role": "developer", "content": [["type": "input_text", "text": "You provide a conservative second opinion on macOS process memory anomalies. Use only the supplied physical-footprint trend and identity. Never override the local rule. State uncertainty when evidence is insufficient. Answer in Simplified Chinese."]]],
                      ["role": "user", "content": [["type": "input_text", "text": String(data: evidenceData, encoding: .utf8)!]]]],
            "text": ["format": ["type": "json_schema", "name": "process_memory_assessment", "strict": true, "schema": schema]]]
        var request = URLRequest(url: Constants.openAIEndpoint); request.httpMethod = "POST"; request.timeoutInterval = 25
        request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization"); request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        do { request.httpBody = try JSONSerialization.data(withJSONObject: body) } catch { completion(.failure(error)); return }
        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error { completion(.failure(error)); return }
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode), let data else {
                completion(.failure(NSError(domain: "ProcessMemoryGuard.AI", code: (response as? HTTPURLResponse)?.statusCode ?? -1, userInfo: [NSLocalizedDescriptionKey: "模型 API 请求失败"]))); return
            }
            do {
                let root = try JSONSerialization.jsonObject(with: data) as? [String: Any]
                let items = (root?["output"] as? [[String: Any]])?.compactMap { $0["content"] as? [[String: Any]] }.flatMap { $0 }
                guard let text = items?.first(where: { $0["type"] as? String == "output_text" })?["text"] as? String,
                      let json = text.data(using: .utf8), let value = try JSONSerialization.jsonObject(with: json) as? [String: Any],
                      let verdict = value["verdict"] as? String, let summary = value["summary"] as? String, let recommendation = value["recommendation"] as? String else {
                    throw NSError(domain: "ProcessMemoryGuard.AI", code: 2, userInfo: [NSLocalizedDescriptionKey: "无法解析模型响应"])
                }
                completion(.success(AIAnalysis(verdict: verdict, summary: summary, recommendation: recommendation)))
            } catch { completion(.failure(error)) }
        }.resume()
    }
}

private final class MonitorStore: NSObject, ObservableObject, UNUserNotificationCenterDelegate {
    @Published private(set) var groups: [AppGroup]; @Published private(set) var rules: [ProcessRule]
    @Published private(set) var runtime: [UUID: RuleRuntime] = [:]
    @Published var monitoringEnabled: Bool { didSet { preferences.enabled = monitoringEnabled; reschedule() } }
    @Published var interval: TimeInterval { didSet { preferences.interval = interval; reschedule() } }
    @Published var aiEnabled: Bool { didSet { preferences.aiEnabled = aiEnabled } }
    private let preferences = Preferences(); private let queue = DispatchQueue(label: "com.local.ProcessMemoryGuard.monitor", qos: .utility)
    private var timer: DispatchSourceTimer?
    override init() {
        let saved = preferences.load(); groups = saved.groups; rules = saved.rules
        monitoringEnabled = preferences.enabled; interval = preferences.interval; aiEnabled = preferences.aiEnabled
        super.init(); configureNotifications(); reschedule()
    }
    var abnormalCount: Int { runtime.values.filter(\.aboveThreshold).count }
    func rules(in groupID: UUID?) -> [ProcessRule] { groupID.map { id in rules.filter { $0.groupID == id } } ?? [] }
    func rule(_ id: UUID?) -> ProcessRule? { id.flatMap { wanted in rules.first { $0.id == wanted } } }
    func state(_ id: UUID) -> RuleRuntime { runtime[id] ?? RuleRuntime() }
    func updateGroupName(_ id: UUID, _ name: String) { guard let index = groups.firstIndex(where: { $0.id == id }) else { return }; groups[index].name = name; persist() }
    func addGroup() -> UUID { let group = AppGroup(id: UUID(), name: "新分组"); groups.append(group); persist(); return group.id }
    func deleteGroup(_ id: UUID) { guard groups.count > 1 else { return }; groups.removeAll { $0.id == id }; rules.removeAll { $0.groupID == id }; persist() }
    func updateRule(_ id: UUID, _ change: (inout ProcessRule) -> Void) { guard let index = rules.firstIndex(where: { $0.id == id }) else { return }; change(&rules[index]); persist() }
    func deleteRule(_ id: UUID) { rules.removeAll { $0.id == id }; runtime[id] = nil; persist() }
    func addExecutable(to groupID: UUID) {
        let panel = NSOpenPanel(); panel.title = "选择要监视的应用或可执行文件"; panel.canChooseFiles = true; panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false; panel.treatsFilePackagesAsDirectories = false
        guard panel.runModal() == .OK, var url = panel.url else { return }
        if url.pathExtension.lowercased() == "app", let executable = Bundle(url: url)?.executableURL { url = executable }
        switch CodeIdentity.inspect(path: url.path) {
        case .failure(let error): showAlert("无法添加进程", error.localizedDescription)
        case .success(let identity):
            rules.append(ProcessRule(id: UUID(), groupID: groupID, name: url.deletingPathExtension().lastPathComponent, executablePath: url.path,
                                     signingIdentifier: identity.identifier, signingRequirement: identity.requirement, thresholdBytes: Constants.gib, enabled: true))
            persist(); checkNow()
        }
    }
    func setThreshold(ruleID: UUID, text: String) -> Bool {
        guard let bytes = parseMemory(text), bytes >= 64 * 1_048_576 else { return false }
        updateRule(ruleID) { $0.thresholdBytes = bytes }
        if var state = runtime[ruleID] { state.aboveThreshold = state.memoryBytes >= bytes; state.lastNotification = nil; runtime[ruleID] = state }
        return true
    }
    func checkNow() { queue.async { [weak self] in self?.performScan() } }
    private func reschedule() {
        timer?.cancel(); timer = nil; guard monitoringEnabled else { return }
        let source = DispatchSource.makeTimerSource(queue: queue); source.schedule(deadline: .now(), repeating: interval, leeway: .seconds(2))
        source.setEventHandler { [weak self] in self?.performScan() }; source.resume(); timer = source
    }
    private func performScan() { let snapshot = rules; let results = ProcessInspector.scan(rules: snapshot); DispatchQueue.main.async { [weak self] in self?.consume(results) } }
    private func consume(_ results: [UUID: RuleScan]) {
        for rule in rules where rule.enabled {
            var state = runtime[rule.id] ?? RuleRuntime()
            switch results[rule.id] ?? .notRunning {
            case .notRunning: state = RuleRuntime()
            case .invalid(let message): state.error = message; state.aboveThreshold = false
            case .running(let samples):
                let memory = samples.reduce(UInt64(0)) { $0 + $1.footprint }; state.memoryBytes = memory; state.pids = samples.map(\.pid); state.error = nil
                state.samples.append(memory); if state.samples.count > 10 { state.samples.removeFirst(state.samples.count - 10) }
                let abnormal = memory >= rule.thresholdBytes; let reminder = state.lastNotification.map { Date().timeIntervalSince($0) >= Constants.reminderCooldown } ?? true
                if abnormal && !state.aboveThreshold {
                    state.aiSummary = nil
                    if aiEnabled, let key = APIKeyStore.load() { state.aiInFlight = true; runtime[rule.id] = state; requestAI(rule: rule, state: state, apiKey: key) }
                    else { notify(rule: rule, state: state, analysis: nil); state.lastNotification = Date() }
                } else if abnormal && reminder && !state.aiInFlight { notify(rule: rule, state: state, analysis: state.aiSummary); state.lastNotification = Date() }
                state.aboveThreshold = abnormal
            }
            runtime[rule.id] = state
        }
        objectWillChange.send()
    }
    private func requestAI(rule: ProcessRule, state: RuleRuntime, apiKey: String) {
        let group = groups.first(where: { $0.id == rule.groupID })?.name ?? "未分组"
        AIAnalyzer.analyze(rule: rule, group: group, model: preferences.aiModel, apiKey: apiKey, samples: state.samples, interval: interval) { [weak self] result in
            DispatchQueue.main.async {
                guard let self, var current = self.runtime[rule.id] else { return }; current.aiInFlight = false
                guard current.aboveThreshold else { self.runtime[rule.id] = current; return }
                if case .success(let analysis) = result { current.aiSummary = analysis }
                self.notify(rule: rule, state: current, analysis: current.aiSummary); current.lastNotification = Date(); self.runtime[rule.id] = current
            }
        }
    }
    private func configureNotifications() {
        let action = UNTextInputNotificationAction(identifier: Constants.setThresholdAction, title: "直接设置新阈值…", options: [], textInputButtonTitle: "保存", textInputPlaceholder: "例如 1.5 GB 或 768 MB")
        UNUserNotificationCenter.current().setNotificationCategories([UNNotificationCategory(identifier: Constants.notificationCategory, actions: [action], intentIdentifiers: [], options: [])])
        UNUserNotificationCenter.current().delegate = self; UNUserNotificationCenter.current().requestAuthorization(options: [.alert]) { _, _ in }
    }
    private func notify(rule: ProcessRule, state: RuleRuntime, analysis: AIAnalysis?) {
        let content = UNMutableNotificationContent(); content.categoryIdentifier = Constants.notificationCategory; content.userInfo = ["ruleID": rule.id.uuidString]
        content.title = analysis.map { "\(rule.name) 内存异常 · AI：\($0.label)" } ?? "\(rule.name) 内存异常"
        content.body = "当前 \(formatBytes(state.memoryBytes))，阈值 \(formatBytes(rule.thresholdBytes))。" + (analysis.map { " \($0.summary) \($0.recommendation)" } ?? "")
        content.sound = nil; if #available(macOS 12.0, *) { content.interruptionLevel = .passive }
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "memory-\(rule.id)-\(Int(Date().timeIntervalSince1970))", content: content, trigger: nil))
    }
    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse, withCompletionHandler completionHandler: @escaping () -> Void) {
        defer { completionHandler() }
        guard response.actionIdentifier == Constants.setThresholdAction, let idText = response.notification.request.content.userInfo["ruleID"] as? String,
              let id = UUID(uuidString: idText), let input = response as? UNTextInputNotificationResponse else { return }
        DispatchQueue.main.async { [weak self] in guard let self else { return }; if !self.setThreshold(ruleID: id, text: input.userText) { self.postInfo("阈值格式无效", "请输入例如 1.5 GB、768 MB 或 2048 MB。") } }
    }
    func configureAI() {
        let alert = NSAlert(); alert.messageText = "配置可选 AI 二次分析"; alert.informativeText = "模型请求仅在某条进程规则首次越过阈值时发送；API Key 只保存在 macOS 钥匙串。"
        alert.addButton(withTitle: "保存"); alert.addButton(withTitle: "取消")
        let stack = NSStackView(); stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 8
        let model = NSTextField(string: preferences.aiModel); model.frame.size.width = 340
        let key = NSSecureTextField(string: ""); key.placeholderString = APIKeyStore.load() == nil ? "OpenAI API Key" : "已保存在钥匙串（留空则保持）"; key.frame.size.width = 340
        stack.addArrangedSubview(NSTextField(labelWithString: "模型")); stack.addArrangedSubview(model); stack.addArrangedSubview(NSTextField(labelWithString: "API Key")); stack.addArrangedSubview(key); alert.accessoryView = stack
        guard alert.runModal() == .alertFirstButtonReturn else { return }; preferences.aiModel = model.stringValue
        let value = key.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        if !value.isEmpty, APIKeyStore.save(value) != errSecSuccess { showAlert("无法保存 API Key", "macOS 钥匙串拒绝了写入。") }
        objectWillChange.send()
    }
    func toggleAI(_ enabled: Bool) { if enabled && APIKeyStore.load() == nil { configureAI() }; aiEnabled = enabled && APIKeyStore.load() != nil }
    func reveal(_ rule: ProcessRule) { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: rule.executablePath)]) }
    private func persist() { preferences.save(SavedConfiguration(groups: groups, rules: rules)); objectWillChange.send() }
    private func postInfo(_ title: String, _ body: String) { let content = UNMutableNotificationContent(); content.title = title; content.body = body; UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)) }
}

private func parseMemory(_ input: String) -> UInt64? {
    let normalized = input.lowercased().replacingOccurrences(of: " ", with: "").replacingOccurrences(of: "ib", with: "b")
    let unit: Double; let number: String
    if normalized.hasSuffix("gb") { unit = Double(Constants.gib); number = String(normalized.dropLast(2)) }
    else if normalized.hasSuffix("mb") { unit = 1_048_576; number = String(normalized.dropLast(2)) }
    else { unit = Double(Constants.gib); number = normalized }
    guard let value = Double(number), value.isFinite, value > 0 else { return nil }; return UInt64(value * unit)
}
private func showAlert(_ title: String, _ body: String) { let alert = NSAlert(); alert.messageText = title; alert.informativeText = body; alert.runModal() }
private func formatBytes(_ bytes: UInt64) -> String { let formatter = ByteCountFormatter(); formatter.allowedUnits = [.useMB, .useGB]; formatter.countStyle = .memory; return formatter.string(fromByteCount: Int64(bytes)) }

private struct DashboardView: View {
    @ObservedObject var store: MonitorStore; @State private var selectedGroup: UUID?; @State private var selectedRule: UUID?
    init(store: MonitorStore) { self.store = store; _selectedGroup = State(initialValue: store.groups.first?.id); _selectedRule = State(initialValue: store.rules.first?.id) }
    var body: some View {
        VStack(spacing: 0) {
            HStack { Toggle("监视", isOn: $store.monitoringEnabled).toggleStyle(.switch)
                Picker("间隔", selection: $store.interval) { Text("1 分钟").tag(60.0); Text("3 分钟").tag(180.0); Text("5 分钟").tag(300.0) }.frame(width: 180)
                Spacer(); Toggle("AI 二次分析", isOn: Binding(get: { store.aiEnabled }, set: { store.toggleAI($0) })).toggleStyle(.switch)
                Button("AI 配置…") { store.configureAI() }; Button("立即检查") { store.checkNow() } }.padding(12)
            Divider()
            HStack(spacing: 0) {
                VStack(alignment: .leading, spacing: 0) { Text("应用分组").font(.headline).padding(10)
                    if let id = selectedGroup {
                        TextField("分组名称", text: Binding(get: { store.groups.first(where: { $0.id == id })?.name ?? "" },
                                                           set: { store.updateGroupName(id, $0) }))
                            .textFieldStyle(.roundedBorder).padding(.horizontal, 8).padding(.bottom, 6)
                    }
                    List(selection: $selectedGroup) { ForEach(store.groups) { group in Text(group.name).tag(Optional(group.id)) } }
                    HStack { Button(action: { selectedGroup = store.addGroup() }) { Image(systemName: "plus") }
                        Button(action: { if let id = selectedGroup { store.deleteGroup(id); selectedGroup = store.groups.first?.id } }) { Image(systemName: "minus") }.disabled(store.groups.count <= 1) }.padding(8) }.frame(width: 180)
                Divider()
                VStack(alignment: .leading, spacing: 0) { Text("进程规则").font(.headline).padding(10)
                    List(selection: $selectedRule) { ForEach(store.rules(in: selectedGroup)) { rule in
                        HStack { Circle().fill(store.state(rule.id).aboveThreshold ? Color.orange : Color.green).frame(width: 8, height: 8)
                            VStack(alignment: .leading) { Text(rule.name); Text(formatBytes(store.state(rule.id).memoryBytes)).font(.caption).foregroundStyle(.secondary) } }.tag(Optional(rule.id)) } }
                    HStack { Button(action: { if let group = selectedGroup { store.addExecutable(to: group) } }) { Image(systemName: "plus") }
                        Button(action: { if let id = selectedRule { store.deleteRule(id); selectedRule = nil } }) { Image(systemName: "minus") }.disabled(selectedRule == nil) }.padding(8) }.frame(width: 250)
                Divider(); detail.frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }.frame(minWidth: 850, minHeight: 500)
    }
    @ViewBuilder private var detail: some View {
        if let id = selectedRule, let rule = store.rule(id) {
            Form {
                Section("进程设置") {
                    TextField("显示名称", text: Binding(get: { store.rule(id)?.name ?? "" }, set: { value in store.updateRule(id) { $0.name = value } }))
                    Picker("应用分组", selection: Binding(get: { store.rule(id)?.groupID ?? rule.groupID }, set: { value in store.updateRule(id) { $0.groupID = value }; selectedGroup = value })) { ForEach(store.groups) { Text($0.name).tag($0.id) } }
                    Toggle("启用此规则", isOn: Binding(get: { store.rule(id)?.enabled ?? false }, set: { value in store.updateRule(id) { $0.enabled = value } }))
                    HStack { TextField("阈值", value: Binding(get: { Double(store.rule(id)?.thresholdBytes ?? Constants.gib) / Double(Constants.gib) }, set: { value in store.updateRule(id) { $0.thresholdBytes = UInt64(max(0.0625, value) * Double(Constants.gib)) } }), format: .number.precision(.fractionLength(0...2))).frame(width: 100); Text("GB"); Text("直接输入，回车保存").foregroundStyle(.secondary) }
                }
                Section("实时状态") {
                    LabeledContent("当前 physical footprint", value: formatBytes(store.state(id).memoryBytes)); LabeledContent("阈值", value: formatBytes(rule.thresholdBytes))
                    LabeledContent("PID", value: store.state(id).pids.isEmpty ? "未运行" : store.state(id).pids.map(String.init).joined(separator: ", "))
                    if let error = store.state(id).error { Text(error).foregroundStyle(.red) }
                    if let ai = store.state(id).aiSummary { LabeledContent("AI 二次判断", value: ai.label); Text(ai.summary).foregroundStyle(.secondary) }
                }
                Section("身份校验") { LabeledContent("签名标识", value: rule.signingIdentifier); Text(rule.executablePath).font(.caption).textSelection(.enabled); Button("在 Finder 中显示") { store.reveal(rule) } }
            }.formStyle(.grouped).padding()
        } else { ContentUnavailableView("选择一条进程规则", systemImage: "memorychip", description: Text("每条规则都有独立阈值和签名身份。")) }
    }
}

private final class StatusController: NSObject, NSMenuDelegate {
    let store: MonitorStore; private let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength); private var window: NSWindow?
    init(store: MonitorStore) { self.store = store; super.init(); item.button?.image = NSImage(systemSymbolName: "memorychip", accessibilityDescription: Constants.appName); let menu = NSMenu(); menu.delegate = self; item.menu = menu }
    func menuWillOpen(_ menu: NSMenu) {
        menu.removeAllItems(); let status = NSMenuItem(title: store.abnormalCount > 0 ? "\(store.abnormalCount) 条规则异常" : "所有规则正常", action: nil, keyEquivalent: ""); status.isEnabled = false; menu.addItem(status)
        let open = NSMenuItem(title: "打开监视控制台…", action: #selector(openDashboard), keyEquivalent: "o"); open.target = self; menu.addItem(open)
        let check = NSMenuItem(title: "立即检查", action: #selector(checkNow), keyEquivalent: "r"); check.target = self; menu.addItem(check)
        if #available(macOS 13.0, *) { let login = NSMenuItem(title: "登录时启动", action: #selector(toggleLogin), keyEquivalent: ""); login.target = self; login.state = SMAppService.mainApp.status == .enabled ? .on : .off; menu.addItem(login) }
        menu.addItem(.separator()); let quit = NSMenuItem(title: "退出", action: #selector(quit), keyEquivalent: "q"); quit.target = self; menu.addItem(quit)
    }
    @objc private func openDashboard() { if window == nil { let host = NSHostingController(rootView: DashboardView(store: store)); let value = NSWindow(contentViewController: host); value.title = Constants.appName; value.setContentSize(NSSize(width: 920, height: 560)); value.styleMask = [.titled, .closable, .miniaturizable, .resizable]; window = value }; NSApp.activate(ignoringOtherApps: true); window?.makeKeyAndOrderFront(nil) }
    @objc private func checkNow() { store.checkNow() }
    @available(macOS 13.0, *) @objc private func toggleLogin() { do { if SMAppService.mainApp.status == .enabled { try SMAppService.mainApp.unregister() } else { try SMAppService.mainApp.register() } } catch { showAlert("无法更改登录项", error.localizedDescription) } }
    @objc private func quit() { NSApp.terminate(nil) }
}

private final class AppDelegate: NSObject, NSApplicationDelegate { private var status: StatusController?; func applicationDidFinishLaunching(_ notification: Notification) { status = StatusController(store: MonitorStore()) } }
private func runSelfTest() -> Int32 {
    let config = Preferences().load(); guard let rule = config.rules.first else { print("default_rule=missing"); return 1 }
    let identityOK = CodeIdentity.validate(rule) == nil; let footprint = ProcessInspector.physicalFootprint(getpid()) ?? 0; let scan = ProcessInspector.scan(rules: [rule])[rule.id]
    print("default_identity=\(identityOK ? "ok" : "failed")"); print("self_physical_footprint=\(footprint)")
    switch scan { case .running?: print("target_scan=running"); case .notRunning?: print("target_scan=not_running"); case .invalid(let error)?: print("target_scan=invalid:\(error)"); case nil: print("target_scan=missing") }
    return identityOK && footprint > 0 ? 0 : 1
}
if CommandLine.arguments.contains("--self-test") { exit(runSelfTest()) }
private let app = NSApplication.shared; private let delegate = AppDelegate()
app.delegate = delegate; app.setActivationPolicy(.accessory); app.run()
