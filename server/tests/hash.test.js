import test from 'node:test';
import assert from 'node:assert';
import argon2 from 'argon2';

test('Argon2id hashing stores correct parameters and verifies', async (t) => {
  const password = "my_secure_password";
  const saltHex = "1234567890abcdef1234567890abcdef";
  const saltBuf = Buffer.from(saltHex, 'hex');

  // 1. Generate hash
  const hash = await argon2.hash(password, {
    type: argon2.argon2id,
    salt: saltBuf
  });

  // 2. Ensure stored hash string starts with $argon2id$
  assert.ok(hash.startsWith('$argon2id$'), 'Hash should start with $argon2id$');

  // 3. Ensure hash verifies correctly
  const isMatch = await argon2.verify(hash, password);
  assert.strictEqual(isMatch, true, 'Hash should verify correctly');

  // 4. Ensure incorrect password fails verification
  const isMatchWrong = await argon2.verify(hash, 'wrong_password');
  assert.strictEqual(isMatchWrong, false, 'Hash should fail with wrong password');

  // 5. Ensure salt can be extracted from the encoded string
  const parts = hash.split('$');
  const extractedSaltBase64 = parts[4];
  const extractedSaltHex = Buffer.from(extractedSaltBase64, 'base64').toString('hex');
  assert.strictEqual(extractedSaltHex, saltHex, 'Extracted salt should match original salt');
});
