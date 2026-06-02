import test from 'node:test';
import assert from 'node:assert';
import argon2 from 'argon2';
import bcrypt from 'bcryptjs';

// Helper to extract KDF salt from Argon2id hash (mirroring the server endpoint logic)
function extractSalt(passwordHash) {
  if (passwordHash.startsWith("$argon2")) {
    const parts = passwordHash.split("$");
    if (parts.length >= 5) {
      const saltBase64 = parts[4];
      return Buffer.from(saltBase64, "base64").toString("hex");
    }
  }
  return null;
}

test('Argon2id Hashing and Verification', async () => {
  const authHash = "d3b07384d113edec49eaa6238ad5ff00";
  const clientSaltHex = "5f2b84a9e108cf1c28b9d3e5f410ac02";

  // 1. Generate Argon2id hash using the client-side derived authHash and KDF salt
  const hash = await argon2.hash(authHash, {
    type: argon2.argon2id,
    salt: Buffer.from(clientSaltHex, "hex")
  });

  // 2. Verify the hash format starts with $argon2id$
  assert.ok(hash.startsWith("$argon2id$"), `Hash should start with $argon2id$, got: ${hash}`);

  // 3. Verify correct authHash matches successfully
  const isMatch = await argon2.verify(hash, authHash);
  assert.strictEqual(isMatch, true, "Correct authHash should be verified successfully");

  // 4. Verify incorrect authHash fails to match
  const isWrongMatch = await argon2.verify(hash, "wrong_auth_hash_value");
  assert.strictEqual(isWrongMatch, false, "Incorrect authHash should fail verification");

  // 5. Verify the client-side KDF salt can be successfully extracted and matches original salt
  const extractedSaltHex = extractSalt(hash);
  assert.strictEqual(extractedSaltHex, clientSaltHex, "Extracted KDF salt should match the original input salt");
});

test('Legacy Bcrypt Verification Fallback', async () => {
  const authHash = "d3b07384d113edec49eaa6238ad5ff00";

  // 1. Generate legacy bcrypt hash (representing an existing DB record)
  const legacyHash = await bcrypt.hash(authHash, 10);

  // 2. Assert it does not start with $argon2
  assert.ok(!legacyHash.startsWith("$argon2"), "Legacy bcrypt hash should not start with $argon2");

  // 3. Verify legacy hash using bcrypt.compare (how the login fallback does it)
  const isMatch = await bcrypt.compare(authHash, legacyHash);
  assert.strictEqual(isMatch, true, "Legacy hash should be correctly verified by bcrypt fallback");

  // 4. Verify extracting salt from legacy hash returns null (triggering salt DB column fallback)
  const extractedSalt = extractSalt(legacyHash);
  assert.strictEqual(extractedSalt, null, "Extracting salt from bcrypt hash should return null");
});
