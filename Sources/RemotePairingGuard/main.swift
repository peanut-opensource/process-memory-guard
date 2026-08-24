import AppKit
import Combine
import Darwin
import Foundation
import Security
import ServiceManagement
import SwiftUI
import UserNotifications

private enum Constants {
    static let appName = "Process Memory Guard"
    static let version = "2.1.0"
    static let defaultPath = "/Library/Apple/System/Library/PrivateFrameworks/RemotePairing.framework/Versions/A/XPCServices/remotepairingd.xpc/Contents/MacOS/remotepairingd"
    static let defaultIdentifier = "com.apple.CoreDevice.remotepairingd"
    static let openAIEndpoint = URL(string: "https://api.openai.com/v1/responses")!
    static let notificationCategory = "PROCESS_MEMORY_ALERT"
    static let viewDetailsAction = "VIEW_DETAILS"
    static let setThresholdAction = "SET_THRESHOLD"
    static let snoozeAction = "SNOOZE_ONE_HOUR"
    static let reminderCooldown: TimeInterval = 30 * 60
    static let snoozeDuration: TimeInterval = 60 * 60
    static let gib = UInt64(1_073_741_824)
    static let minimumThreshold = UInt64(64 * 1_048_576)
}

private struct AppGroup: Codable, Identifiable, Hashable {
    var id: UUID
    var name: String
    var aggregateThresholdBytes: UInt64?
}

private struct ProcessRule: Codable, Identifiable, Hashable {
    var id: UUID
    var groupID: UUID
    var name: String
    var executablePath: String
    var signingIdentifier: String
    var signingRequirement: String
    var thresholdBytes: UInt64
    var enabled: Bool
}

private struct SavedConfiguration: Codable {
    var groups: [AppGroup]
    var rules: [ProcessRule]
}

private struct ProcessSample {
    let pid: pid_t
    let footprint: UInt64
}

private enum RuleScan {
    case notRunning
    case running([ProcessSample])
    case invalid(String)
}

private enum MemoryPressureState: String {
    case unknown
    case normal
    case warning
    case critical

    var label: String {
        switch self {
        case .unknown: return "未知"
        case .normal: return "正常"
        case .warning: return "warning"
        case .critical: return "critical"
        }
    }
}

private enum AlertSeverity: Int {
    case normal = 0
    case warning = 1
    case critical = 2

    var label: String {
        switch self {
        case .normal: return "正常"
        case .warning: return "warning"
        case .critical: return "critical"
        }
    }
}

private enum RuleDisplayStatus {
    case notRunning
    case disabled
    case identityInvalid
    case normal
    case warning
    case critical

    var label: String {
        switch self {
        case .notRunning: return "未运行"
        case .disabled: return "已禁用"
        case .identityInvalid: return "身份失效"
        case .normal: return "正常"
        case .warning: return "warning"
        case .critical: return "critical"
        }
    }
}

private struct Incident {
    var startedAt: Date
    var peak: UInt64
    var severity: AlertSeverity
    var notificationCount: Int
    var snoozeUntil: Date?
}

private struct RuleRuntime {
    var memoryBytes: UInt64 = 0
    var pids: [pid_t] = []
    var error: String?
    var status: RuleDisplayStatus = .notRunning
    var samples: [UInt64] = []
    var peakBytes: UInt64 = 0
    var aboveThresholdSamples = 0
    var recoverySamples = 0
    var incident: Incident?
    var lastNotificationAt: Date?
    var aiSummary: AIAnalysis?
    var aiError: String?
    var aiInFlight = false
    var aiRequested = false
}

private struct GroupRuntime {
    var totalBytes: UInt64 = 0
    var memberContributions: [UUID: UInt64] = [:]
    var hasRunningMember = false
    var status: RuleDisplayStatus = .notRunning
    var samples: [UInt64] = []
    var peakBytes: UInt64 = 0
    var aboveThresholdSamples = 0
    var recoverySamples = 0
    var incident: Incident?
    var lastNotificationAt: Date?
    var aiSummary: AIAnalysis?
    var aiError: String?
    var aiInFlight = false
    var aiRequested = false
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
        static let configuration = "groupedConfigurationV2"
        static let enabled = "monitoringEnabledV2"
        static let interval = "monitorIntervalSecondsV2"
        static let aiEnabled = "aiAnalysisEnabledV2"
        static let aiModel = "aiModelV2"
    }

    init() {
        defaults.register(defaults: [Key.enabled: true, Key.interval: 60.0, Key.aiEnabled: false, Key.aiModel: "gpt-5.6"])
    }

    var enabled: Bool {
        get { defaults.bool(forKey: Key.enabled) }
        set { defaults.set(newValue, forKey: Key.enabled) }
    }

    var interval: TimeInterval {
        get { max(15, defaults.double(forKey: Key.interval)) }
        set { defaults.set(max(15, newValue), forKey: Key.interval) }
    }

    var aiEnabled: Bool {
        get { defaults.bool(forKey: Key.aiEnabled) }
        set { defaults.set(newValue, forKey: Key.aiEnabled) }
    }

    var aiModel: String {
        get { defaults.string(forKey: Key.aiModel).flatMap { $0.isEmpty ? nil : $0 } ?? "gpt-5.6" }
        set { defaults.set(newValue.trimmingCharacters(in: .whitespacesAndNewlines), forKey: Key.aiModel) }
    }

    func load() -> SavedConfiguration {
        if let data = defaults.data(forKey: Key.configuration), let value = try? JSONDecoder().decode(SavedConfiguration.self, from: data) {
            return value
        }
        let group = AppGroup(id: UUID(), name: "Apple 设备通信", aggregateThresholdBytes: nil)
        let identity = try? CodeIdentity.inspect(path: Constants.defaultPath).get()
        let rule = ProcessRule(id: UUID(), groupID: group.id, name: "remotepairingd", executablePath: Constants.defaultPath,
                               signingIdentifier: identity?.identifier ?? Constants.defaultIdentifier,
                               signingRequirement: identity?.requirement ?? "anchor apple and identifier \"\(Constants.defaultIdentifier)\"",
                               thresholdBytes: Constants.gib, enabled: true)
        return SavedConfiguration(groups: [group], rules: [rule])
    }

    func save(_ value: SavedConfiguration) {
        if let data = try? JSONEncoder().encode(value) { defaults.set(data, forKey: Key.configuration) }
    }
}

private enum APIKeyStore {
    private static let service = "com.local.RemotePairingGuard.openai"
    private static let account = "api-key"

    static func load() -> String? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                    kSecAttrAccount as String: account, kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func save(_ key: String) -> OSStatus {
        let base: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
        SecItemDelete(base as CFDictionary)
        var item = base
        item[kSecValueData as String] = Data(key.utf8)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        return SecItemAdd(item as CFDictionary, nil)
    }

    static func delete() -> OSStatus {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecItemNotFound ? errSecSuccess : status
    }
}

private struct AIAnalysis {
    let verdict: String
    let summary: String
    let recommendation: String

    var label: String {
        ["abnormal": "确认异常", "likely_abnormal": "很可能异常", "likely_normal": "可能正常"][verdict] ?? "无法确定"
    }
}

private enum AIAnalyzer {
    static func analyze(rule: ProcessRule, group: String, model: String, apiKey: String, samples: [UInt64], interval: TimeInterval,
                        aggregateThreshold: UInt64?, completion: @escaping (Result<AIAnalysis, Error>) -> Void) {
        let evidence: [String: Any] = [
            "application_group": group,
            "rule_id": rule.id.uuidString,
            "process": rule.name,
            "signing_identifier": rule.signingIdentifier,
            "signature_verified": true,
            "metric": "macOS ri_phys_footprint",
            "rule_threshold_mb": Double(rule.thresholdBytes) / 1_048_576,
            "aggregate_threshold_mb": aggregateThreshold.map { Double($0) / 1_048_576 } ?? NSNull(),
            "sample_interval_seconds": interval,
            "samples_mb_oldest_to_newest": samples.map { Double($0) / 1_048_576 }
        ]
        guard let evidenceData = try? JSONSerialization.data(withJSONObject: evidence, options: [.sortedKeys]) else {
            completion(.failure(NSError(domain: "ProcessMemoryGuard.AI", code: 1, userInfo: [NSLocalizedDescriptionKey: "无法准备模型请求"])))
            return
        }
        let schema: [String: Any] = ["type": "object", "properties": ["verdict": ["type": "string", "enum": ["abnormal", "likely_abnormal", "uncertain", "likely_normal"]],
            "summary": ["type": "string", "maxLength": 180], "recommendation": ["type": "string", "maxLength": 180]],
            "required": ["verdict", "summary", "recommendation"], "additionalProperties": false]
        let body: [String: Any] = ["model": model, "store": false, "max_output_tokens": 300,
            "input": [["role": "developer", "content": [["type": "input_text", "text": "You provide a conservative second opinion on macOS process memory anomalies. Use only the supplied physical-footprint trend and identity. Never override the local rule. State uncertainty when evidence is insufficient. Answer in Simplified Chinese."]]],
                      ["role": "user", "content": [["type": "input_text", "text": String(data: evidenceData, encoding: .utf8) ?? "{}"]]]],
            "text": ["format": ["type": "json_schema", "name": "process_memory_assessment", "strict": true, "schema": schema]]]
        post(body: body, apiKey: apiKey) { result in
            switch result {
            case .failure(let error): completion(.failure(error))
            case .success(let data):
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
            }
        }
    }

    static func testConnection(model: String, apiKey: String, completion: @escaping (Result<Void, Error>) -> Void) {
        let body: [String: Any] = ["model": model, "store": false, "max_output_tokens": 8,
                                   "input": "Return only OK to verify the Process Memory Guard connection."]
        post(body: body, apiKey: apiKey) { result in completion(result.map { _ in () }) }
    }

    private static func post(body: [String: Any], apiKey: String, completion: @escaping (Result<Data, Error>) -> Void) {
        var request = URLRequest(url: Constants.openAIEndpoint)
        request.httpMethod = "POST"
        request.timeoutInterval = 25
        request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        do { request.httpBody = try JSONSerialization.data(withJSONObject: body) }
        catch { completion(.failure(error)); return }
        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error { completion(.failure(error)); return }
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode), let data else {
                completion(.failure(NSError(domain: "ProcessMemoryGuard.AI", code: (response as? HTTPURLResponse)?.statusCode ?? -1,
                                             userInfo: [NSLocalizedDescriptionKey: "模型 API 请求失败"])))
                return
            }
            completion(.success(data))
        }.resume()
    }
}

private final class MonitorStore: NSObject, ObservableObject, UNUserNotificationCenterDelegate {
    @Published private(set) var groups: [AppGroup]
    @Published private(set) var rules: [ProcessRule]
    @Published private(set) var runtime: [UUID: RuleRuntime] = [:]
    @Published private(set) var groupRuntime: [UUID: GroupRuntime] = [:]
    @Published private(set) var memoryPressure: MemoryPressureState = .unknown
    @Published private(set) var feedback: String?
    @Published var monitoringEnabled: Bool { didSet { preferences.enabled = monitoringEnabled; reschedule() } }
    @Published var interval: TimeInterval { didSet { preferences.interval = interval; reschedule() } }
    @Published var aiEnabled: Bool { didSet { preferences.aiEnabled = aiEnabled } }

    var openRuleHandler: ((UUID) -> Void)?

    private let preferences = Preferences()
    private let queue = DispatchQueue(label: "com.local.ProcessMemoryGuard.monitor", qos: .utility)
    private var timer: DispatchSourceTimer?
    private var pressureSource: DispatchSourceMemoryPressure?

    override init() {
        let saved = preferences.load()
        groups = saved.groups
        rules = saved.rules
        monitoringEnabled = preferences.enabled
        interval = preferences.interval
        aiEnabled = preferences.aiEnabled
        super.init()
        configureNotifications()
        configureMemoryPressure()
        reschedule()
    }

    deinit {
        timer?.cancel()
        pressureSource?.cancel()
    }

    var activeIncidentCount: Int {
        runtime.values.filter { $0.incident != nil }.count + groupRuntime.values.filter { $0.incident != nil }.count
    }

    var highestSeverity: AlertSeverity {
        var value = AlertSeverity.normal
        for rule in rules where rule.enabled {
            if case .warning = displayStatus(rule) { value = maxSeverity(value, .warning) }
            if case .critical = displayStatus(rule) { value = .critical }
        }
        for group in groups {
            if case .warning = groupDisplayStatus(group) { value = maxSeverity(value, .warning) }
            if case .critical = groupDisplayStatus(group) { value = .critical }
        }
        return value
    }

    func rules(in groupID: UUID?) -> [ProcessRule] {
        groupID.map { id in rules.filter { $0.groupID == id } } ?? []
    }

    func rule(_ id: UUID?) -> ProcessRule? {
        id.flatMap { wanted in rules.first { $0.id == wanted } }
    }

    func group(_ id: UUID?) -> AppGroup? {
        id.flatMap { wanted in groups.first { $0.id == wanted } }
    }

    func state(_ id: UUID) -> RuleRuntime { runtime[id] ?? RuleRuntime() }
    func state(forGroup id: UUID) -> GroupRuntime { groupRuntime[id] ?? GroupRuntime() }

    func displayStatus(_ rule: ProcessRule) -> RuleDisplayStatus {
        guard monitoringEnabled else { return .disabled }
        guard rule.enabled else { return .disabled }
        let state = runtime[rule.id] ?? RuleRuntime()
        if state.error != nil { return .identityInvalid }
        guard state.status != .notRunning else { return .notRunning }
        let local: AlertSeverity = state.incident?.severity ?? .normal
        return displayStatus(local)
    }

    func groupDisplayStatus(_ group: AppGroup) -> RuleDisplayStatus {
        guard monitoringEnabled else { return .disabled }
        let state = groupRuntime[group.id] ?? GroupRuntime()
        guard state.hasRunningMember else { return .notRunning }
        let local: AlertSeverity = state.incident?.severity ?? .normal
        return displayStatus(local)
    }

    func trend(for samples: [UInt64]) -> String {
        guard let first = samples.first, let last = samples.last, samples.count >= 2 else { return "样本不足" }
        if last == first { return "→ 稳定" }
        let delta = Int64(last) - Int64(first)
        return delta > 0 ? "↑ +\(formatBytes(UInt64(delta)))" : "↓ -\(formatBytes(UInt64(-delta)))"
    }

    func updateGroupName(_ id: UUID, _ name: String) {
        guard let index = groups.firstIndex(where: { $0.id == id }) else { return }
        groups[index].name = name
        persist()
    }

    @discardableResult
    func addGroup() -> UUID {
        let group = AppGroup(id: UUID(), name: "新分组", aggregateThresholdBytes: nil)
        groups.append(group)
        persist()
        return group.id
    }

    func deleteGroup(_ id: UUID) {
        guard groups.count > 1 else { return }
        groups.removeAll { $0.id == id }
        rules.removeAll { $0.groupID == id }
        runtime = runtime.filter { entry in rules.contains { $0.id == entry.key } }
        groupRuntime[id] = nil
        persist()
    }

    func updateRule(_ id: UUID, _ change: (inout ProcessRule) -> Void) {
        guard let index = rules.firstIndex(where: { $0.id == id }) else { return }
        change(&rules[index])
        persist()
    }

    func deleteRule(_ id: UUID) {
        rules.removeAll { $0.id == id }
        runtime[id] = nil
        persist()
    }

    func addExecutable(to groupID: UUID) {
        let panel = NSOpenPanel()
        panel.title = "选择要监视的应用或可执行文件"
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.treatsFilePackagesAsDirectories = false
        guard panel.runModal() == .OK, var url = panel.url else { return }
        if url.pathExtension.lowercased() == "app", let executable = Bundle(url: url)?.executableURL { url = executable }
        switch CodeIdentity.inspect(path: url.path) {
        case .failure(let error): showAlert("无法添加进程", error.localizedDescription)
        case .success(let identity):
            rules.append(ProcessRule(id: UUID(), groupID: groupID, name: url.deletingPathExtension().lastPathComponent,
                                     executablePath: url.path, signingIdentifier: identity.identifier,
                                     signingRequirement: identity.requirement, thresholdBytes: Constants.gib, enabled: true))
            persist()
            checkNow()
        }
    }

    @discardableResult
    func setThreshold(ruleID: UUID, text: String, announce: Bool = true) -> Bool {
        guard let bytes = parseMemory(text), bytes >= Constants.minimumThreshold else { return false }
        updateRule(ruleID) { $0.thresholdBytes = bytes }
        resetRuleDecision(ruleID)
        if announce { postInfo("阈值已更新", "已将该规则阈值设为 \(formatBytes(bytes))。") }
        return true
    }

    @discardableResult
    func setGroupAggregateThreshold(_ groupID: UUID, text: String) -> Bool {
        guard let bytes = parseMemory(text), bytes >= Constants.minimumThreshold else { return false }
        guard let index = groups.firstIndex(where: { $0.id == groupID }) else { return false }
        groups[index].aggregateThresholdBytes = bytes
        resetGroupDecision(groupID)
        persist()
        postInfo("组阈值已更新", "已将该组总内存阈值设为 \(formatBytes(bytes))。")
        return true
    }

    func clearGroupAggregateThreshold(_ groupID: UUID) {
        guard let index = groups.firstIndex(where: { $0.id == groupID }) else { return }
        groups[index].aggregateThresholdBytes = nil
        resetGroupDecision(groupID)
        persist()
        postInfo("组阈值已清除", "该组将不再按总内存触发事件。")
    }

    func postInfoForUI(_ title: String, _ body: String) { postInfo(title, body) }

    func checkNow() {
        queue.async { [weak self] in
            guard let self, self.monitoringEnabled else { return }
            self.performScan()
        }
    }

    func snooze(ruleID: UUID, groupID: UUID? = nil) {
        let until = Date().addingTimeInterval(Constants.snoozeDuration)
        if let groupID, var state = groupRuntime[groupID], var incident = state.incident {
            incident.snoozeUntil = until
            state.incident = incident
            groupRuntime[groupID] = state
            postInfo("已暂停提醒", "该组事件将在 1 小时后恢复提醒。")
            return
        }
        guard var state = runtime[ruleID], var incident = state.incident else { return }
        incident.snoozeUntil = until
        state.incident = incident
        runtime[ruleID] = state
        postInfo("已暂停提醒", "该规则事件将在 1 小时后恢复提醒。")
    }

    func openRule(_ id: UUID) { openRuleHandler?(id) }

    func reveal(_ rule: ProcessRule) {
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: rule.executablePath)])
    }

    func configureAI() {
        let alert = NSAlert()
        alert.messageText = "配置可选 AI 二次分析"
        alert.informativeText = "AI 只在本地事件已触发且至少有 5 个样本时并行追加；本地告警不会等待 AI。关闭 AI 后不会自动联网。请求 payload 仅含组名、规则身份、阈值与最多 10 个内存样本；每个事件最多约 1 次模型调用，另有用户主动的连接测试。API Key 仅保存在 macOS 钥匙串。"
        alert.addButton(withTitle: "保存")
        alert.addButton(withTitle: "测试连接")
        alert.addButton(withTitle: "删除密钥")
        alert.addButton(withTitle: "取消")
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8
        let model = NSTextField(string: preferences.aiModel)
        model.frame.size.width = 340
        let key = NSSecureTextField(string: "")
        key.placeholderString = APIKeyStore.load() == nil ? "OpenAI API Key" : "已保存在钥匙串（留空则保持）"
        key.frame.size.width = 340
        stack.addArrangedSubview(NSTextField(labelWithString: "模型"))
        stack.addArrangedSubview(model)
        stack.addArrangedSubview(NSTextField(labelWithString: "API Key"))
        stack.addArrangedSubview(key)
        alert.accessoryView = stack
        let response = alert.runModal()
        let typedKey = key.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let effectiveKey = typedKey.isEmpty ? APIKeyStore.load() : typedKey
        switch response {
        case .alertFirstButtonReturn:
            preferences.aiModel = model.stringValue
            if !typedKey.isEmpty, APIKeyStore.save(typedKey) != errSecSuccess {
                showAlert("无法保存 API Key", "macOS 钥匙串拒绝了写入。")
            } else {
                postInfo("AI 配置已保存", effectiveKey == nil ? "尚未设置 API Key，AI 保持关闭。" : "AI 可在满足样本条件后追加分析。")
            }
            objectWillChange.send()
        case .alertSecondButtonReturn:
            guard let effectiveKey else { showAlert("无法测试连接", "请先输入或保存 API Key。"); return }
            AIAnalyzer.testConnection(model: model.stringValue.trimmingCharacters(in: .whitespacesAndNewlines), apiKey: effectiveKey) { result in
                DispatchQueue.main.async {
                    switch result {
                    case .success: showAlert("连接成功", "OpenAI Responses API 已返回成功响应。")
                    case .failure(let error): showAlert("连接失败", error.localizedDescription)
                    }
                }
            }
        case .alertThirdButtonReturn:
            let status = APIKeyStore.delete()
            postInfo(status == errSecSuccess ? "密钥已删除" : "删除密钥失败", status == errSecSuccess ? "AI 不会再使用已删除的钥匙串密钥。" : "macOS 钥匙串拒绝了删除操作。")
            if aiEnabled { aiEnabled = false }
        default:
            break
        }
    }

    func toggleAI(_ enabled: Bool) {
        if enabled && APIKeyStore.load() == nil { configureAI() }
        aiEnabled = enabled && APIKeyStore.load() != nil
        if enabled && !aiEnabled { postInfo("AI 未启用", "请先在 AI 配置中保存 API Key。") }
    }

    private func configureMemoryPressure() {
        let source = DispatchSource.makeMemoryPressureSource(eventMask: [.normal, .warning, .critical], queue: queue)
        source.setEventHandler { [weak self] in
            let flags = source.data
            let pressure: MemoryPressureState
            if flags.contains(.critical) { pressure = .critical }
            else if flags.contains(.warning) { pressure = .warning }
            else if flags.contains(.normal) { pressure = .normal }
            else { pressure = .unknown }
            DispatchQueue.main.async { [weak self] in self?.memoryPressure = pressure }
        }
        source.resume()
        pressureSource = source
    }

    private func reschedule() {
        timer?.cancel()
        timer = nil
        guard monitoringEnabled else { return }
        let source = DispatchSource.makeTimerSource(queue: queue)
        source.schedule(deadline: .now(), repeating: interval, leeway: .seconds(2))
        source.setEventHandler { [weak self] in self?.performScan() }
        source.resume()
        timer = source
    }

    private func performScan() {
        let snapshot = rules
        let results = ProcessInspector.scan(rules: snapshot)
        DispatchQueue.main.async { [weak self] in self?.consume(results) }
    }

    private func consume(_ results: [UUID: RuleScan]) {
        let now = Date()
        for rule in rules {
            guard rule.enabled else {
                runtime[rule.id] = RuleRuntime(status: .disabled)
                continue
            }
            var state = runtime[rule.id] ?? RuleRuntime()
            switch results[rule.id] ?? .notRunning {
            case .notRunning:
                state = RuleRuntime(status: .notRunning)
            case .invalid(let message):
                state = RuleRuntime(status: .identityInvalid)
                state.error = message
            case .running(let samples):
                updateRuleRuntime(&state, rule: rule, samples: samples, now: now)
            }
            runtime[rule.id] = state
            if case .running = results[rule.id] {
                maybeRequestAI(rule: rule, groupName: group(rule.groupID)?.name ?? "未分组", aggregateThreshold: group(rule.groupID)?.aggregateThresholdBytes,
                               samples: state.samples, ruleID: rule.id)
            }
        }
        updateGroupRuntime(now: now)
        objectWillChange.send()
    }

    private func updateRuleRuntime(_ state: inout RuleRuntime, rule: ProcessRule, samples: [ProcessSample], now: Date) {
        let memory = samples.reduce(UInt64(0)) { $0 &+ $1.footprint }
        state.memoryBytes = memory
        state.pids = samples.map(\.pid)
        state.error = nil
        state.status = .normal
        state.samples.append(memory)
        if state.samples.count > 10 { state.samples.removeFirst(state.samples.count - 10) }
        state.peakBytes = max(state.peakBytes, memory)
        let threshold = rule.thresholdBytes
        let atLeastDouble = memory >= threshold && memory / threshold >= 2
        if memory >= threshold {
            state.aboveThresholdSamples = min(2, state.aboveThresholdSamples + 1)
            state.recoverySamples = 0
        } else if belowRecovery(memory, threshold: threshold) {
            state.recoverySamples = min(2, state.recoverySamples + 1)
            state.aboveThresholdSamples = 0
        } else {
            state.aboveThresholdSamples = 0
            state.recoverySamples = 0
        }
        if let incident = state.incident {
            state.incident?.peak = max(incident.peak, memory)
            if atLeastDouble && incident.severity != .critical {
                state.incident?.severity = .critical
                sendRuleNotificationIfAllowed(rule: rule, groupName: group(rule.groupID)?.name ?? "未分组", state: &state, threshold: threshold, now: now, force: true)
            }
            if state.recoverySamples >= 2 {
                state.incident = nil
                state.lastNotificationAt = nil
                state.aiSummary = nil
                state.aiError = nil
                state.aiRequested = false
            } else {
                sendRuleReminderIfAllowed(rule: rule, groupName: group(rule.groupID)?.name ?? "未分组", state: &state, threshold: threshold, now: now)
            }
        } else if atLeastDouble || state.aboveThresholdSamples >= 2 {
            let severity: AlertSeverity = atLeastDouble ? .critical : .warning
            state.incident = Incident(startedAt: now, peak: memory, severity: severity, notificationCount: 0, snoozeUntil: nil)
            state.aiSummary = nil
            state.aiError = nil
            state.aiRequested = false
            sendRuleNotificationIfAllowed(rule: rule, groupName: group(rule.groupID)?.name ?? "未分组", state: &state, threshold: threshold, now: now)
        }
        if let incident = state.incident { state.status = incident.severity == .critical ? .critical : .warning }
    }

    private func updateGroupRuntime(now: Date) {
        for group in groups {
            let members = rules.filter { $0.groupID == group.id && $0.enabled }
            let contributions = Dictionary(uniqueKeysWithValues: members.map { ($0.id, runtime[$0.id]?.memoryBytes ?? 0) })
            let running = members.contains { runtime[$0.id]?.status == .normal || runtime[$0.id]?.status == .warning || runtime[$0.id]?.status == .critical }
            let total = contributions.values.reduce(UInt64(0), &+)
            var state = groupRuntime[group.id] ?? GroupRuntime()
            state.totalBytes = total
            state.memberContributions = contributions
            state.hasRunningMember = running
            guard running else {
                groupRuntime[group.id] = GroupRuntime(memberContributions: contributions)
                continue
            }
            state.status = .normal
            state.samples.append(total)
            if state.samples.count > 10 { state.samples.removeFirst(state.samples.count - 10) }
            state.peakBytes = max(state.peakBytes, total)
            guard let threshold = group.aggregateThresholdBytes else {
                state.incident = nil
                state.status = .normal
                groupRuntime[group.id] = state
                continue
            }
            let atLeastDouble = total >= threshold && total / threshold >= 2
            if total >= threshold {
                state.aboveThresholdSamples = min(2, state.aboveThresholdSamples + 1)
                state.recoverySamples = 0
            } else if belowRecovery(total, threshold: threshold) {
                state.recoverySamples = min(2, state.recoverySamples + 1)
                state.aboveThresholdSamples = 0
            } else {
                state.aboveThresholdSamples = 0
                state.recoverySamples = 0
            }
            let representative = members.max { (contributions[$0.id] ?? 0) < (contributions[$1.id] ?? 0) } ?? members[0]
            if let incident = state.incident {
                state.incident?.peak = max(incident.peak, total)
                if atLeastDouble && incident.severity != .critical {
                    state.incident?.severity = .critical
                    sendGroupNotificationIfAllowed(group: group, representative: representative, state: &state, threshold: threshold, now: now, force: true)
                }
                if state.recoverySamples >= 2 {
                    state.incident = nil
                    state.lastNotificationAt = nil
                    state.aiSummary = nil
                    state.aiError = nil
                    state.aiRequested = false
                } else {
                    sendGroupReminderIfAllowed(group: group, representative: representative, state: &state, threshold: threshold, now: now)
                }
            } else if atLeastDouble || state.aboveThresholdSamples >= 2 {
                let severity: AlertSeverity = atLeastDouble ? .critical : .warning
                state.incident = Incident(startedAt: now, peak: total, severity: severity, notificationCount: 0, snoozeUntil: nil)
                state.aiSummary = nil
                state.aiError = nil
                state.aiRequested = false
                sendGroupNotificationIfAllowed(group: group, representative: representative, state: &state, threshold: threshold, now: now)
            }
            if let incident = state.incident { state.status = incident.severity == .critical ? .critical : .warning }
            groupRuntime[group.id] = state
            maybeRequestAI(rule: representative, groupName: group.name, aggregateThreshold: threshold, samples: state.samples, ruleID: representative.id, groupID: group.id)
        }
    }

    private func maybeRequestAI(rule: ProcessRule, groupName: String, aggregateThreshold: UInt64?, samples: [UInt64], ruleID: UUID, groupID: UUID? = nil) {
        guard aiEnabled, samples.count >= 5, let key = APIKeyStore.load() else { return }
        if let groupID {
            guard var state = groupRuntime[groupID], state.incident != nil, !state.aiRequested, !state.aiInFlight else { return }
            state.aiRequested = true
            state.aiInFlight = true
            groupRuntime[groupID] = state
            requestAI(rule: rule, groupName: groupName, aggregateThreshold: aggregateThreshold, samples: samples, apiKey: key, groupID: groupID, ruleID: ruleID)
        } else {
            guard var state = runtime[ruleID], state.incident != nil, !state.aiRequested, !state.aiInFlight else { return }
            state.aiRequested = true
            state.aiInFlight = true
            runtime[ruleID] = state
            requestAI(rule: rule, groupName: groupName, aggregateThreshold: aggregateThreshold, samples: samples, apiKey: key, groupID: nil, ruleID: ruleID)
        }
    }

    private func requestAI(rule: ProcessRule, groupName: String, aggregateThreshold: UInt64?, samples: [UInt64], apiKey: String, groupID: UUID?, ruleID: UUID) {
        AIAnalyzer.analyze(rule: rule, group: groupName, model: preferences.aiModel, apiKey: apiKey, samples: samples, interval: interval,
                           aggregateThreshold: aggregateThreshold) { [weak self] result in
            DispatchQueue.main.async {
                guard let self else { return }
                if let groupID {
                    guard var state = self.groupRuntime[groupID] else { return }
                    state.aiInFlight = false
                    switch result {
                    case .success(let analysis): state.aiSummary = analysis; state.aiError = nil
                    case .failure(let error): state.aiError = error.localizedDescription
                    }
                    self.groupRuntime[groupID] = state
                } else {
                    guard var state = self.runtime[ruleID] else { return }
                    state.aiInFlight = false
                    switch result {
                    case .success(let analysis): state.aiSummary = analysis; state.aiError = nil
                    case .failure(let error): state.aiError = error.localizedDescription
                    }
                    self.runtime[ruleID] = state
                }
            }
        }
    }

    private func sendRuleNotificationIfAllowed(rule: ProcessRule, groupName: String, state: inout RuleRuntime, threshold: UInt64, now: Date, force: Bool = false) {
        guard var incident = state.incident else { return }
        guard canNotify(incident: incident, lastNotification: state.lastNotificationAt, now: now, force: force) else { return }
        notify(rule: rule, groupName: groupName, current: state.memoryBytes, peak: incident.peak, threshold: threshold, incident: incident, scope: "rule", groupID: rule.groupID)
        incident.notificationCount += 1
        state.lastNotificationAt = now
        state.incident = incident
    }

    private func sendRuleReminderIfAllowed(rule: ProcessRule, groupName: String, state: inout RuleRuntime, threshold: UInt64, now: Date) {
        guard let incident = state.incident, incident.notificationCount > 0 else { return }
        sendRuleNotificationIfAllowed(rule: rule, groupName: groupName, state: &state, threshold: threshold, now: now)
    }

    private func sendGroupNotificationIfAllowed(group: AppGroup, representative: ProcessRule, state: inout GroupRuntime, threshold: UInt64, now: Date, force: Bool = false) {
        guard var incident = state.incident else { return }
        guard canNotify(incident: incident, lastNotification: state.lastNotificationAt, now: now, force: force) else { return }
        notify(rule: representative, groupName: group.name, current: state.totalBytes, peak: incident.peak, threshold: threshold, incident: incident, scope: "group", groupID: group.id)
        incident.notificationCount += 1
        state.lastNotificationAt = now
        state.incident = incident
    }

    private func sendGroupReminderIfAllowed(group: AppGroup, representative: ProcessRule, state: inout GroupRuntime, threshold: UInt64, now: Date) {
        guard let incident = state.incident, incident.notificationCount > 0 else { return }
        sendGroupNotificationIfAllowed(group: group, representative: representative, state: &state, threshold: threshold, now: now)
    }

    private func canNotify(incident: Incident, lastNotification: Date?, now: Date, force: Bool = false) -> Bool {
        guard incident.notificationCount < 3 else { return false }
        if let snoozeUntil = incident.snoozeUntil, snoozeUntil > now { return false }
        if force { return true }
        if let lastNotification { return now.timeIntervalSince(lastNotification) >= Constants.reminderCooldown }
        return true
    }

    private func notify(rule: ProcessRule, groupName: String, current: UInt64, peak: UInt64, threshold: UInt64, incident: Incident, scope: String, groupID: UUID) {
        let content = UNMutableNotificationContent()
        content.categoryIdentifier = Constants.notificationCategory
        content.userInfo = ["ruleID": rule.id.uuidString, "groupID": groupID.uuidString, "scope": scope]
        let subject = scope == "group" ? "\(groupName) 总内存" : rule.name
        content.title = "\(subject) · \(incident.severity.label)"
        content.body = "当前 \(formatBytes(current))，峰值 \(formatBytes(peak))，阈值 \(formatBytes(threshold))。点击查看详情或暂停 1 小时。"
        content.sound = nil
        if #available(macOS 12.0, *) { content.interruptionLevel = .passive }
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "memory-\(scope)-\(rule.id)-\(Int(Date().timeIntervalSince1970))", content: content, trigger: nil))
    }

    private func configureNotifications() {
        let view = UNNotificationAction(identifier: Constants.viewDetailsAction, title: "查看详情", options: [.foreground])
        let setThreshold = UNTextInputNotificationAction(identifier: Constants.setThresholdAction, title: "直接设置该规则阈值…", options: [], textInputButtonTitle: "保存", textInputPlaceholder: "例如 1.5 GB 或 768 MB")
        let snooze = UNNotificationAction(identifier: Constants.snoozeAction, title: "暂停 1 小时", options: [])
        let category = UNNotificationCategory(identifier: Constants.notificationCategory, actions: [view, setThreshold, snooze], intentIdentifiers: [], options: [.customDismissAction])
        UNUserNotificationCenter.current().setNotificationCategories([category])
        UNUserNotificationCenter.current().delegate = self
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert]) { _, _ in }
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse, withCompletionHandler completionHandler: @escaping () -> Void) {
        defer { completionHandler() }
        let userInfo = response.notification.request.content.userInfo
        guard let idText = userInfo["ruleID"] as? String, let id = UUID(uuidString: idText) else { return }
        let groupID = (userInfo["groupID"] as? String).flatMap(UUID.init(uuidString:))
        switch response.actionIdentifier {
        case Constants.setThresholdAction:
            guard let input = response as? UNTextInputNotificationResponse else { return }
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                if !self.setThreshold(ruleID: id, text: input.userText) { self.postInfo("阈值格式无效", "请输入例如 1.5 GB、768 MB 或 2048 MB。") }
                self.openRule(id)
            }
        case Constants.snoozeAction:
            DispatchQueue.main.async { [weak self] in self?.snooze(ruleID: id, groupID: groupID); self?.openRule(id) }
        case Constants.viewDetailsAction, UNNotificationDefaultActionIdentifier:
            DispatchQueue.main.async { [weak self] in self?.openRule(id) }
        default:
            break
        }
    }

    private func resetRuleDecision(_ id: UUID) {
        guard var state = runtime[id] else { return }
        state.aboveThresholdSamples = 0
        state.recoverySamples = 0
        state.incident = nil
        state.lastNotificationAt = nil
        state.aiSummary = nil
        state.aiError = nil
        state.aiRequested = false
        state.aiInFlight = false
        runtime[id] = state
    }

    private func resetGroupDecision(_ id: UUID) {
        guard var state = groupRuntime[id] else { return }
        state.aboveThresholdSamples = 0
        state.recoverySamples = 0
        state.incident = nil
        state.lastNotificationAt = nil
        state.aiSummary = nil
        state.aiError = nil
        state.aiRequested = false
        state.aiInFlight = false
        groupRuntime[id] = state
    }

    private func persist() {
        preferences.save(SavedConfiguration(groups: groups, rules: rules))
        objectWillChange.send()
    }

    private func postInfo(_ title: String, _ body: String) {
        feedback = "\(title)：\(body)"
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
    }

    private func displayStatus(_ severity: AlertSeverity) -> RuleDisplayStatus {
        switch maxSeverity(severity, pressureSeverity) {
        case .normal: return .normal
        case .warning: return .warning
        case .critical: return .critical
        }
    }

    private var pressureSeverity: AlertSeverity {
        switch memoryPressure {
        case .critical: return .critical
        case .warning: return .warning
        case .unknown, .normal: return .normal
        }
    }

    private func maxSeverity(_ lhs: AlertSeverity, _ rhs: AlertSeverity) -> AlertSeverity { lhs.rawValue >= rhs.rawValue ? lhs : rhs }

    private func belowRecovery(_ memory: UInt64, threshold: UInt64) -> Bool {
        memory < (threshold / 100) * 85 + ((threshold % 100) * 85 / 100)
    }
}

private func parseMemory(_ input: String) -> UInt64? {
    let normalized = input.lowercased().replacingOccurrences(of: " ", with: "")
    let suffixes: [(String, Double)] = [("gib", pow(1024, 3)), ("gb", pow(1024, 3)), ("mib", pow(1024, 2)), ("mb", pow(1024, 2)),
                                         ("kib", pow(1024, 1)), ("kb", pow(1024, 1)), ("b", 1)]
    let match = suffixes.first { normalized.hasSuffix($0.0) }
    let number = match.map { String(normalized.dropLast($0.0.count)) } ?? normalized
    let multiplier = match?.1 ?? pow(1024, 3)
    guard let value = Double(number), value.isFinite, value > 0, value <= Double(UInt64.max) / multiplier else { return nil }
    return UInt64(value * multiplier)
}

private func showAlert(_ title: String, _ body: String) {
    let alert = NSAlert()
    alert.messageText = title
    alert.informativeText = body
    alert.runModal()
}

private func formatBytes(_ bytes: UInt64) -> String {
    let formatter = ByteCountFormatter()
    formatter.allowedUnits = [.useMB, .useGB]
    formatter.countStyle = .memory
    return formatter.string(fromByteCount: Int64(min(bytes, UInt64(Int64.max))))
}

private func statusColor(_ status: RuleDisplayStatus) -> Color {
    switch status {
    case .critical: return .red
    case .warning: return .orange
    case .normal: return .green
    case .identityInvalid: return .red
    case .disabled: return .gray
    case .notRunning: return .secondary
    }
}

private struct DashboardView: View {
    @ObservedObject var store: MonitorStore
    @State private var selectedGroup: UUID?
    @State private var selectedRule: UUID?
    @State private var groupThresholdInput: String

    init(store: MonitorStore, initialRuleID: UUID? = nil) {
        self.store = store
        let initialRule = initialRuleID.flatMap { store.rule($0) } ?? store.rules.first
        _selectedGroup = State(initialValue: initialRule?.groupID ?? store.groups.first?.id)
        _selectedRule = State(initialValue: initialRule?.id)
        _groupThresholdInput = State(initialValue: initialRule.flatMap { store.group($0.groupID)?.aggregateThresholdBytes }.map(formatBytes) ?? "")
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Toggle("监视", isOn: $store.monitoringEnabled).toggleStyle(.switch)
                Picker("间隔", selection: $store.interval) {
                    Text("1 分钟").tag(60.0)
                    Text("3 分钟").tag(180.0)
                    Text("5 分钟").tag(300.0)
                }.frame(width: 180)
                Spacer()
                Text("系统压力：\(store.memoryPressure.label)").foregroundStyle(.secondary)
                Toggle("AI 二次分析", isOn: Binding(get: { store.aiEnabled }, set: { store.toggleAI($0) })).toggleStyle(.switch)
                Button("AI 配置…") { store.configureAI() }
                Button("立即检查") { store.checkNow() }
            }.padding(12)
            if let feedback = store.feedback { Text(feedback).font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 12).padding(.bottom, 6) }
            Divider()
            HStack(spacing: 0) {
                VStack(alignment: .leading, spacing: 0) {
                    Text("应用分组").font(.headline).padding(10)
                    if let id = selectedGroup {
                        TextField("分组名称", text: Binding(get: { store.group(id)?.name ?? "" }, set: { store.updateGroupName(id, $0) }))
                            .textFieldStyle(.roundedBorder).padding(.horizontal, 8).padding(.bottom, 6)
                    }
                    List(selection: $selectedGroup) {
                        ForEach(store.groups) { group in
                            let status = store.groupDisplayStatus(group)
                            VStack(alignment: .leading, spacing: 2) {
                                HStack { Text(group.name); Spacer(); Circle().fill(statusColor(status)).frame(width: 7, height: 7) }
                                Text("总计 \(formatBytes(store.state(forGroup: group.id).totalBytes)) · \(status.label)").font(.caption).foregroundStyle(.secondary)
                            }.tag(Optional(group.id))
                        }
                    }
                    HStack {
                        Button(action: { selectedGroup = store.addGroup(); selectedRule = nil; groupThresholdInput = "" }) { Image(systemName: "plus") }
                        Button(action: { if let id = selectedGroup { store.deleteGroup(id); selectedGroup = store.groups.first?.id; selectedRule = nil } }) { Image(systemName: "minus") }.disabled(store.groups.count <= 1)
                    }.padding(8)
                }.frame(width: 210)
                Divider()
                VStack(alignment: .leading, spacing: 0) {
                    Text("进程规则").font(.headline).padding(10)
                    List(selection: $selectedRule) {
                        ForEach(store.rules(in: selectedGroup)) { rule in
                            let status = store.displayStatus(rule)
                            HStack {
                                Circle().fill(statusColor(status)).frame(width: 8, height: 8)
                                VStack(alignment: .leading) { Text(rule.name); Text("\(formatBytes(store.state(rule.id).memoryBytes)) · \(status.label)").font(.caption).foregroundStyle(.secondary) }
                            }.tag(Optional(rule.id))
                        }
                    }
                    HStack {
                        Button(action: { if let group = selectedGroup { store.addExecutable(to: group) } }) { Image(systemName: "plus") }
                        Button(action: { if let id = selectedRule { store.deleteRule(id); selectedRule = nil } }) { Image(systemName: "minus") }.disabled(selectedRule == nil)
                    }.padding(8)
                }.frame(width: 270)
                Divider()
                detail.frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(minWidth: 980, minHeight: 600)
        .onChange(of: selectedGroup) { _, id in
            selectedRule = store.rules(in: id).first?.id
            groupThresholdInput = id.flatMap { store.group($0)?.aggregateThresholdBytes }.map(formatBytes) ?? ""
        }
    }

    @ViewBuilder private var detail: some View {
        if let id = selectedRule, let rule = store.rule(id), rule.groupID == selectedGroup {
            ruleDetail(id: id, rule: rule)
        } else if let id = selectedGroup, let group = store.group(id) {
            groupDetail(id: id, group: group)
        } else {
            ContentUnavailableView("选择一条进程规则或应用分组", systemImage: "memorychip", description: Text("每条规则都有独立阈值；分组可选总内存阈值。"))
        }
    }

    private func ruleDetail(id: UUID, rule: ProcessRule) -> some View {
        let state = store.state(id)
        let status = store.displayStatus(rule)
        return Form {
            Section("进程设置") {
                TextField("显示名称", text: Binding(get: { store.rule(id)?.name ?? "" }, set: { newValue in store.updateRule(id) { $0.name = newValue } }))
                Picker("应用分组", selection: Binding(get: { store.rule(id)?.groupID ?? rule.groupID }, set: { value in store.updateRule(id) { $0.groupID = value }; selectedGroup = value })) {
                    ForEach(store.groups) { Text($0.name).tag($0.id) }
                }
                Toggle("启用此规则", isOn: Binding(get: { store.rule(id)?.enabled ?? false }, set: { value in store.updateRule(id) { $0.enabled = value } }))
                HStack {
                    TextField("阈值", value: Binding(get: { Double(store.rule(id)?.thresholdBytes ?? Constants.gib) / Double(Constants.gib) }, set: { value in store.updateRule(id) { $0.thresholdBytes = UInt64(max(0.0625, value) * Double(Constants.gib)) } }), format: .number.precision(.fractionLength(0...2))).frame(width: 100)
                    Text("GB")
                    Text("每条规则独立判定；需连续 2 次超限，达到 2 倍立即 critical").foregroundStyle(.secondary)
                }
            }
            Section("实时状态") {
                LabeledContent("状态", value: status.label)
                LabeledContent("当前 physical footprint", value: formatBytes(state.memoryBytes))
                LabeledContent("峰值", value: formatBytes(state.incident?.peak ?? state.peakBytes))
                LabeledContent("趋势", value: store.trend(for: state.samples))
                LabeledContent("PID", value: state.pids.isEmpty ? "未运行" : state.pids.map(String.init).joined(separator: ", "))
                if let incident = state.incident {
                    LabeledContent("事件开始", value: incident.startedAt.formatted(date: .abbreviated, time: .shortened))
                    LabeledContent("通知次数", value: "\(incident.notificationCount)/3")
                    if let until = incident.snoozeUntil, until > Date() { LabeledContent("暂停至", value: until.formatted(date: .abbreviated, time: .shortened)) }
                }
                if let error = state.error { Text(error).foregroundStyle(.red) }
                if let ai = state.aiSummary { LabeledContent("AI 二次判断", value: ai.label); Text(ai.summary).foregroundStyle(.secondary); Text(ai.recommendation).font(.caption).foregroundStyle(.secondary) }
                if let aiError = state.aiError { Text("AI：\(aiError)").font(.caption).foregroundStyle(.secondary) }
            }
            Section("身份校验") {
                LabeledContent("签名标识", value: rule.signingIdentifier)
                Text(rule.executablePath).font(.caption).textSelection(.enabled)
                Button("在 Finder 中显示") { store.reveal(rule) }
            }
        }.formStyle(.grouped).padding()
    }

    private func groupDetail(id: UUID, group: AppGroup) -> some View {
        let state = store.state(forGroup: id)
        let members = store.rules(in: id)
        return Form {
            Section("分组设置") {
                TextField("分组名称", text: Binding(get: { store.group(id)?.name ?? "" }, set: { store.updateGroupName(id, $0) }))
                HStack {
                    TextField("总内存阈值（可选）", text: $groupThresholdInput)
                    Button("保存") { if !store.setGroupAggregateThreshold(id, text: groupThresholdInput) { store.postInfoForUI("组阈值格式无效", "请输入例如 4 GB、2048 MB。") } }
                    Button("清除") { store.clearGroupAggregateThreshold(id); groupThresholdInput = "" }
                }
            }
            Section("分组总内存") {
                LabeledContent("状态", value: store.groupDisplayStatus(group).label)
                LabeledContent("当前总值", value: formatBytes(state.totalBytes))
                LabeledContent("峰值", value: formatBytes(state.incident?.peak ?? state.peakBytes))
                LabeledContent("趋势", value: store.trend(for: state.samples))
                if let threshold = group.aggregateThresholdBytes { LabeledContent("组阈值", value: formatBytes(threshold)) }
                if let incident = state.incident {
                    LabeledContent("事件开始", value: incident.startedAt.formatted(date: .abbreviated, time: .shortened))
                    LabeledContent("严重度", value: incident.severity.label)
                    LabeledContent("通知次数", value: "\(incident.notificationCount)/3")
                }
            }
            Section("成员贡献") {
                ForEach(members) { rule in
                    LabeledContent(rule.name, value: "\(formatBytes(state.memberContributions[rule.id] ?? 0)) · \(store.displayStatus(rule).label)")
                }
            }
            if let ai = state.aiSummary { Section("AI 追加") { Text(ai.summary); Text(ai.recommendation).font(.caption).foregroundStyle(.secondary) } }
            if let aiError = state.aiError { Text("AI：\(aiError)").font(.caption).foregroundStyle(.secondary) }
        }.formStyle(.grouped).padding()
    }
}

private final class StatusController: NSObject, NSMenuDelegate {
    let store: MonitorStore
    private let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private var window: NSWindow?
    private var observation: AnyCancellable?

    init(store: MonitorStore) {
        self.store = store
        super.init()
        store.openRuleHandler = { [weak self] id in self?.openDashboard(ruleID: id) }
        item.button?.image = NSImage(systemSymbolName: "memorychip", accessibilityDescription: Constants.appName)
        item.button?.image?.isTemplate = true
        let menu = NSMenu()
        menu.delegate = self
        item.menu = menu
        observation = store.objectWillChange.sink { [weak self] _ in DispatchQueue.main.async { self?.updateStatusItem() } }
        updateStatusItem()
    }

    func menuWillOpen(_ menu: NSMenu) {
        updateStatusItem()
        menu.removeAllItems()
        let statusTitle: String
        if !store.monitoringEnabled { statusTitle = "监视已禁用" }
        else if store.activeIncidentCount > 0 { statusTitle = "\(store.activeIncidentCount) 个事件 · \(store.highestSeverity.label)" }
        else { statusTitle = "所有规则正常 · 系统压力 \(store.memoryPressure.label)" }
        let status = NSMenuItem(title: statusTitle, action: nil, keyEquivalent: "")
        status.isEnabled = false
        menu.addItem(status)
        let open = NSMenuItem(title: "打开监视控制台…", action: #selector(openDashboardMenu), keyEquivalent: "o")
        open.target = self
        menu.addItem(open)
        let check = NSMenuItem(title: "立即检查", action: #selector(checkNow), keyEquivalent: "r")
        check.target = self
        menu.addItem(check)
        if #available(macOS 13.0, *) {
            let login = NSMenuItem(title: "登录时启动", action: #selector(toggleLogin), keyEquivalent: "")
            login.target = self
            login.state = SMAppService.mainApp.status == .enabled ? .on : .off
            menu.addItem(login)
        }
        menu.addItem(.separator())
        let quit = NSMenuItem(title: "退出", action: #selector(quit), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)
    }

    private func updateStatusItem() {
        let imageName: String
        if !store.monitoringEnabled { imageName = "pause.circle" }
        else {
            switch store.highestSeverity {
            case .critical: imageName = "exclamationmark.triangle.fill"
            case .warning: imageName = "memorychip.fill"
            case .normal: imageName = "memorychip"
            }
        }
        item.button?.image = NSImage(systemSymbolName: imageName, accessibilityDescription: Constants.appName)
        item.button?.image?.isTemplate = true
        let statusLabel = store.monitoringEnabled ? store.highestSeverity.label : "已禁用"
        item.button?.toolTip = "\(Constants.appName) · \(statusLabel)"
    }

    @objc private func openDashboardMenu() { openDashboard(ruleID: nil) }

    private func openDashboard(ruleID: UUID?) {
        let host = NSHostingController(rootView: DashboardView(store: store, initialRuleID: ruleID))
        if let window {
            window.contentViewController = host
        } else {
            let value = NSWindow(contentViewController: host)
            value.title = Constants.appName
            value.setContentSize(NSSize(width: 980, height: 600))
            value.styleMask = [.titled, .closable, .miniaturizable, .resizable]
            window = value
        }
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }

    @objc private func checkNow() { store.checkNow() }

    @available(macOS 13.0, *)
    @objc private func toggleLogin() {
        do {
            if SMAppService.mainApp.status == .enabled { try SMAppService.mainApp.unregister() }
            else { try SMAppService.mainApp.register() }
        } catch { showAlert("无法更改登录项", error.localizedDescription) }
    }

    @objc private func quit() { NSApp.terminate(nil) }
}

private final class AppDelegate: NSObject, NSApplicationDelegate {
    private var status: StatusController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        status = StatusController(store: MonitorStore())
    }
}

private func runSelfTest() -> Int32 {
    let config = Preferences().load()
    guard let rule = config.rules.first else { print("default_rule=missing"); return 1 }
    let identityOK = CodeIdentity.validate(rule) == nil
    let footprint = ProcessInspector.physicalFootprint(getpid()) ?? 0
    let scan = ProcessInspector.scan(rules: [rule])[rule.id]
    print("version=\(Constants.version)")
    print("default_identity=\(identityOK ? "ok" : "failed")")
    print("self_physical_footprint=\(footprint)")
    switch scan {
    case .running?: print("target_scan=running")
    case .notRunning?: print("target_scan=not_running")
    case .invalid(let error)?: print("target_scan=invalid:\(error)")
    case nil: print("target_scan=missing")
    }
    return identityOK && footprint > 0 ? 0 : 1
}

if CommandLine.arguments.contains("--self-test") { exit(runSelfTest()) }
private let app = NSApplication.shared
private let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
