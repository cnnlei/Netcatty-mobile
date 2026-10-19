import 'package:flutter_test/flutter_test.dart';
import 'package:netcatty_mobile/domain/models/host.dart';
import 'package:netcatty_mobile/infrastructure/ssh/ssh_identity.dart';

/// Structurally valid unencrypted OpenSSH ed25519 key used only to prove that
/// the passphrase argument is normalised before it reaches dartssh2.
///
/// The container and private blob follow the OpenSSH PROTOCOL.key layout, so
/// dartssh2 really parses it, but every byte is deterministic filler: the key
/// authenticates nothing and is never used against a host.
const unencryptedTestKey = '''
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAREREREREREREREREREREREREREREREREREREREREREQAAAJASNFZ4EjRW
eAAAAAtzc2gtZWQyNTUxOQAAACAREREREREREREREREREREREREREREREREREREREREREQ
AAAEAzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMz
MzMzMzMzMzMzMzMzMzMzAAAADW5ldGNhdHR5LXRlc3QBAgMEBQY=
-----END OPENSSH PRIVATE KEY-----
''';

/// Deliberately unparsable material. Any test that reaches dartssh2 with this
/// key fails loudly, which proves the key was not supposed to be used.
const invalidTestKey = '''
-----BEGIN OPENSSH PRIVATE KEY-----
bm90LWEtcmVhbC1rZXktYm9keQ==
-----END OPENSSH PRIVATE KEY-----
''';

SshKeyProfile _key(Map<String, dynamic> data) => SshKeyProfile({
      'id': 'key-1',
      'label': 'test key',
      'privateKey': unencryptedTestKey,
      ...data,
    });

HostProfile _host({String? identityFileId = 'key-1'}) => HostProfile({
      'id': 'host-1',
      'label': 'demo',
      'hostname': 'example.com',
      'username': 'demo',
      'authMethod': 'key',
      if (identityFileId != null) 'identityFileId': identityFileId,
    });

void main() {
  group('normalizedPassphrase', () {
    test('turns the stored empty string into null', () {
      // Regression: the importer persisted '' when the user left the optional
      // passphrase field empty, which broke every unencrypted key with
      // "Passphrase is not required for unencrypted keys".
      expect(normalizedPassphrase(_key({'passphrase': ''})), isNull);
    });

    test('turns a missing passphrase into null', () {
      expect(normalizedPassphrase(_key({})), isNull);
    });

    test('turns whitespace-only passphrases into null', () {
      expect(normalizedPassphrase(_key({'passphrase': '   '})), isNull);
      expect(normalizedPassphrase(_key({'passphrase': '\n\t'})), isNull);
    });

    test('keeps a real passphrase untouched', () {
      expect(normalizedPassphrase(_key({'passphrase': 'secret'})), 'secret');
    });

    test('keeps inner and outer whitespace of a real passphrase', () {
      expect(
        normalizedPassphrase(_key({'passphrase': ' secret '})),
        ' secret ',
      );
    });
  });

  group('buildHostIdentities', () {
    test('parses an unencrypted key stored with an empty passphrase', () {
      // Before the fix this threw ArgumentError before authentication started.
      final identities = buildHostIdentities(
        _host(),
        [
          _key({'passphrase': ''})
        ],
      );

      expect(identities, hasLength(1));
      expect(identities!.single.type, 'ssh-ed25519');
    });

    test('parses an unencrypted key stored without a passphrase', () {
      final identities = buildHostIdentities(_host(), [_key({})]);

      expect(identities, hasLength(1));
      expect(identities!.single.type, 'ssh-ed25519');
    });

    test('still reports a real passphrase for an unencrypted key', () {
      // A passphrase the user actually typed must not be silently dropped: it
      // is a genuine mismatch that dartssh2 reports.
      expect(
        () => buildHostIdentities(
          _host(),
          [
            _key({'passphrase': 'secret'})
          ],
        ),
        throwsA(
          isA<ArgumentError>().having(
            (error) => error.message,
            'message',
            contains('Passphrase is not required'),
          ),
        ),
      );
    });

    test('returns null when the host has no key', () {
      expect(
        buildHostIdentities(_host(identityFileId: null), [_key({})]),
        isNull,
      );
    });

    test('returns null when the referenced key is missing', () {
      expect(buildHostIdentities(_host(), const []), isNull);
    });

    test('returns null when the referenced key has no material', () {
      final empty = SshKeyProfile({
        'id': 'key-1',
        'privateKey': '',
        'passphrase': '',
      });

      expect(buildHostIdentities(_host(), [empty]), isNull);
    });

    test('never parses a key the host does not reference', () {
      final other = SshKeyProfile({
        'id': 'key-2',
        'privateKey': invalidTestKey,
      });

      expect(buildHostIdentities(_host(), [_key({}), other]), hasLength(1));
    });
  });

  group('detectPrivateKeyType', () {
    test('detects the OpenSSH container', () {
      expect(detectPrivateKeyType(unencryptedTestKey), 'OpenSSH');
    });

    test('detects classic PEM containers', () {
      expect(detectPrivateKeyType('-----BEGIN RSA PRIVATE KEY-----'), 'RSA');
      expect(detectPrivateKeyType('-----BEGIN EC PRIVATE KEY-----'), 'ECDSA');
      expect(detectPrivateKeyType('-----BEGIN DSA PRIVATE KEY-----'), 'DSA');
    });

    test('detects PKCS#8 before the more specific OpenSSH check', () {
      expect(detectPrivateKeyType('-----BEGIN PRIVATE KEY-----'), 'PKCS#8');
    });

    test('returns null for unknown content', () {
      expect(detectPrivateKeyType('not a key'), isNull);
    });
  });
}
