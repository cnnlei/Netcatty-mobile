import 'package:dartssh2/dartssh2.dart';

import '../../domain/models/host.dart';

/// Builds the client identities for [host] from the vault [keys].
///
/// Returns null when the host does not reference a usable private key, so the
/// caller can fall back to password authentication.
List<SSHKeyPair>? buildHostIdentities(
    HostProfile host, List<SshKeyProfile> keys) {
  final identity = keys.cast<SshKeyProfile?>().firstWhere(
        (value) => value?.id == host.identityFileId,
        orElse: () => null,
      );
  if (identity == null || identity.privateKey.isEmpty) return null;
  return SSHKeyPair.fromPem(
      identity.privateKey, normalizedPassphrase(identity));
}

/// Returns the key passphrase, or null when the key is not protected.
///
/// dartssh2 rejects any passphrase argument for an unencrypted key, so an empty
/// or whitespace-only stored value has to become null instead of `''`. The key
/// picker stores `''` when the user leaves the optional passphrase field empty,
/// and that value is also already persisted in existing vaults.
///
/// Whitespace-only values are treated as empty. A passphrase made only of
/// spaces cannot be entered reliably on a mobile keyboard, while a passphrase
/// that merely starts or ends with whitespace is preserved untouched.
String? normalizedPassphrase(SshKeyProfile key) {
  final passphrase = key.passphrase;
  if (passphrase == null) return null;
  return passphrase.trim().isEmpty ? null : passphrase;
}

/// Guesses the key type label from a PEM/OpenSSH private key body.
///
/// Returns null when the format is not recognised, so the caller can fall back
/// to a generic label. This is only used for display.
String? detectPrivateKeyType(String privateKey) {
  if (privateKey.contains('BEGIN OPENSSH PRIVATE KEY')) return 'OpenSSH';
  if (privateKey.contains('BEGIN RSA PRIVATE KEY')) return 'RSA';
  if (privateKey.contains('BEGIN EC PRIVATE KEY')) return 'ECDSA';
  if (privateKey.contains('BEGIN DSA PRIVATE KEY')) return 'DSA';
  if (privateKey.contains('BEGIN PRIVATE KEY')) return 'PKCS#8';
  return null;
}
