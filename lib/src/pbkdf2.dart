import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'salt.dart';

/// @Describe: PBKDF2
///
/// @Author: LiWeNHuI
/// @Date: 2022/5/1

/// Instances of this type derive a key from a password, salt, and hash function
///
/// https://en.wikipedia.org/wiki/PBKDF2
class PBKDF2 {
  /// Creates instance capable of generating a key.
  ///
  /// [hashAlgorithm] defaults to [sha256].
  PBKDF2({Hash? hashAlgorithm}) {
    this.hashAlgorithm = hashAlgorithm ?? sha256;
  }

  Hash get hashAlgorithm => _hashAlgorithm;

  set hashAlgorithm(Hash algorithm) {
    _hashAlgorithm = algorithm;
    _blockSize = _hashAlgorithm.convert(<int>[1, 2, 3]).bytes.length;
  }

  late Hash _hashAlgorithm;
  late int _blockSize;

  /// Hashes a [password] with a given [salt].
  ///
  /// The length of this return value will be [keyLength].
  ///
  /// See [Salt.generateAsBase64String] for generating a random salt.
  ///
  /// See also [generateBase64Key], which base64 encodes the key returned from
  /// this method for storage.
  List<int> generateKey(
    String password,
    String salt,
    int rounds,
    int keyLength,
  ) {
    if (keyLength > (pow(2, 32) - 1) * _blockSize) {
      throw PBKDF2Exception('Derived key too long');
    }

    final int numberOfBlocks = (keyLength / _blockSize).ceil();
    final Hmac hmac = Hmac(hashAlgorithm, utf8.encode(password));
    final ByteData key = ByteData(keyLength);
    int offset = 0;

    final List<int> saltBytes = utf8.encode(salt);
    final int saltLength = saltBytes.length;
    final ByteData inputBuffer = ByteData(saltBytes.length + 4)
      ..buffer.asUint8List().setRange(0, saltBytes.length, saltBytes);

    for (int blockNumber = 1; blockNumber <= numberOfBlocks; blockNumber++) {
      inputBuffer
        ..setUint8(saltLength, blockNumber >> 24)
        ..setUint8(saltLength + 1, blockNumber >> 16)
        ..setUint8(saltLength + 2, blockNumber >> 8)
        ..setUint8(saltLength + 3, blockNumber);

      final Uint8List block =
          _XORDigestSink.generate(inputBuffer, hmac, rounds);
      int blockLength = _blockSize;
      if (offset + blockLength > keyLength) {
        blockLength = keyLength - offset;
      }
      key.buffer.asUint8List().setRange(offset, offset + blockLength, block);

      offset += blockLength;
    }

    return key.buffer.asUint8List();
  }

  /// Hashed a [password] with a given [salt] and base64 encodes the result.
  ///
  /// This method invokes [generateKey] and base64 encodes the result.
  String generateBase64Key(
    String password,
    String salt,
    int rounds,
    int keyLength,
  ) {
    const Base64Encoder converter = Base64Encoder();

    return converter.convert(generateKey(password, salt, rounds, keyLength));
  }
}

/// Thrown when [PBKDF2] throws an exception.
class PBKDF2Exception implements Exception {
  PBKDF2Exception(this.message);

  String message;

  @override
  String toString() => 'PBKDF2Exception: $message';
}

class _XORDigestSink extends Sink<Digest> {
  _XORDigestSink(ByteData inputBuffer, Hmac hmac) {
    lastDigest = Uint8List.fromList(
      hmac.convert(inputBuffer.buffer.asUint8List()).bytes,
    );
    bytes = ByteData(lastDigest.length)
      ..buffer.asUint8List().setRange(0, lastDigest.length, lastDigest);
  }

  static Uint8List generate(ByteData inputBuffer, Hmac hmac, int rounds) {
    final _XORDigestSink hashSink = _XORDigestSink(inputBuffer, hmac);

    // If rounds == 1, we have already run the first hash in the constructor
    // so this loop won't run.
    for (int round = 1; round < rounds; round++) {
      hmac.startChunkedConversion(hashSink)
        ..add(hashSink.lastDigest)
        ..close();
    }

    return hashSink.bytes.buffer.asUint8List();
  }

  late ByteData bytes;
  late Uint8List lastDigest;

  @override
  void add(Digest digest) {
    lastDigest = Uint8List.fromList(digest.bytes);
    for (int i = 0; i < digest.bytes.length; i++) {
      bytes.setUint8(i, bytes.getUint8(i) ^ lastDigest[i]);
    }
  }

  @override
  void close() {}
}
