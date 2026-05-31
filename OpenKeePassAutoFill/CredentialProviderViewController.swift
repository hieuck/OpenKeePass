import AuthenticationServices
import SecurityKit
import UIKit

final class CredentialProviderViewController: ASCredentialProviderViewController, UITableViewDataSource, UITableViewDelegate {
    private let store = AutoFillCredentialStore()
    private var records: [AutoFillCredentialRecord] = []
    private let reuseIdentifier = "CredentialCell"

    private lazy var tableView: UITableView = {
        let tableView = UITableView(frame: .zero, style: .insetGrouped)
        tableView.translatesAutoresizingMaskIntoConstraints = false
        tableView.dataSource = self
        tableView.delegate = self
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: reuseIdentifier)
        return tableView
    }()

    private lazy var emptyLabel: UILabel = {
        let label = UILabel()
        label.translatesAutoresizingMaskIntoConstraints = false
        label.text = "No matching credentials"
        label.textAlignment = .center
        label.textColor = .secondaryLabel
        label.numberOfLines = 0
        return label
    }()

    override func viewDidLoad() {
        super.viewDidLoad()
        configureListView()
    }

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        records = store.records(matching: serviceIdentifiers)
        configureListView()
        reloadCredentialList()
    }

    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        completeRequest(for: credentialIdentity)
    }

    override func prepareInterfaceToProvideCredential(for credentialIdentity: ASPasswordCredentialIdentity) {
        completeRequest(for: credentialIdentity)
    }

    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        records.count
    }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: reuseIdentifier)
        let record = records[indexPath.row]
        cell.textLabel?.text = record.title.isEmpty ? record.username : record.title
        cell.detailTextLabel?.text = record.serviceHost.map { "\(record.username) - \($0)" } ?? record.username
        cell.accessoryType = .disclosureIndicator
        return cell
    }

    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        completeRequest(recordIdentifier: records[indexPath.row].id)
    }

    private func completeRequest(for credentialIdentity: ASPasswordCredentialIdentity) {
        guard
            let recordIdentifier = credentialIdentity.recordIdentifier
        else {
            cancelMissingCredential()
            return
        }

        completeRequest(recordIdentifier: recordIdentifier)
    }

    private func completeRequest(recordIdentifier: String) {
        guard let credential = store.credential(recordIdentifier: recordIdentifier) else {
            cancelMissingCredential()
            return
        }
        extensionContext.completeRequest(withSelectedCredential: credential, completionHandler: nil)
    }

    private func configureListView() {
        guard tableView.superview == nil else {
            return
        }

        view.addSubview(tableView)
        view.addSubview(emptyLabel)

        NSLayoutConstraint.activate([
            tableView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            tableView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            tableView.topAnchor.constraint(equalTo: view.topAnchor),
            tableView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            emptyLabel.leadingAnchor.constraint(equalTo: view.layoutMarginsGuide.leadingAnchor),
            emptyLabel.trailingAnchor.constraint(equalTo: view.layoutMarginsGuide.trailingAnchor),
            emptyLabel.centerYAnchor.constraint(equalTo: view.centerYAnchor)
        ])
    }

    private func reloadCredentialList() {
        tableView.reloadData()
        tableView.isHidden = records.isEmpty
        emptyLabel.isHidden = !records.isEmpty
    }

    private func cancelMissingCredential() {
        extensionContext.cancelRequest(withError: NSError(
            domain: "dev.openkeepass.autofill",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: "Credential is no longer available."]
        ))
    }
}
