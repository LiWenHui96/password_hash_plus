# password_hash_plus

[![pub package](https://img.shields.io/pub/v/password_hash_plus)](https://pub.dev/packages/password_hash_plus)

> This plugin is a null-safety version of [password_hash](https://pub.dev/packages/password_hash), you can use it if you
> need Flutter 2.x and above.

Implements PBKDF2 algorithm for securely hashing passwords.

## Preparing for use

### Version constraints

```yaml
  sdk: ">=2.17.0 <3.0.0"
  flutter: ">=3.0.0"
```

## Usage:

```dart
var generator = new PBKDF2();
var salt = Salt.generateAsBase64String();
var hash = generator.generateKey("mytopsecretpassword", salt, 1000, 32);
```
