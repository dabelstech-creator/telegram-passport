import {
  constants as cryptoConstants,
  createCipheriv,
  createHash,
  generateKeyPairSync,
  publicEncrypt,
  randomBytes,
} from 'crypto';
import { TelegramPassport } from '../src/telegram-passport';
import { ErrorMessages } from '../src/constants';
import type {
  Credentials,
  EncryptedCredentials,
  EncryptedPassportElement,
  FileCredentials,
  PassportData,
  PassportFile,
  PersonalDetails,
  ResidentialAddress,
} from '../src/interfaces';

// ---------------------------------------------------------------------------
// Crypto helpers that mirror the Telegram Passport encryption spec so tests
// can build valid ciphertexts without depending on external fixtures.
// ---------------------------------------------------------------------------

/**
 * Encrypt `plainData` using the Telegram Passport AES-256-CBC scheme:
 *   - prepend N random padding bytes (N >= 32, first byte = N, total len % 16 == 0)
 *   - hash = SHA-256(paddedData)                 ← used for integrity + key derivation
 *   - digest = SHA-512(secret || hash)
 *   - key = digest[0:32], iv = digest[32:48]
 *   - encrypt paddedData with AES-256-CBC (no auto-padding)
 */
function telegramEncrypt(
  plainData: Buffer,
  secret: Buffer,
): { encryptedData: Buffer; hash: Buffer } {
  let paddingLength = 32;
  while ((paddingLength + plainData.length) % 16 !== 0) paddingLength++;

  const padding = randomBytes(paddingLength);
  padding[0] = paddingLength;
  const paddedData = Buffer.concat([padding, plainData]);

  const hash = createHash('sha256').update(paddedData).digest();
  const digest = createHash('sha512')
    .update(Buffer.concat([secret, hash]))
    .digest();
  const key = digest.slice(0, 32);
  const iv = digest.slice(32, 48);

  const cipher = createCipheriv('aes-256-cbc', key, iv);
  cipher.setAutoPadding(false);
  const encryptedData = Buffer.concat([cipher.update(paddedData), cipher.final()]);

  return { encryptedData, hash };
}

/**
 * Build a valid EncryptedCredentials object from a Credentials payload and an
 * RSA public key (for secret encryption). The private key counterpart is what
 * the TelegramPassport instance must hold.
 */
function buildEncryptedCredentials(
  credentials: Credentials,
  rsaPublicKeyPem: string,
): EncryptedCredentials {
  const secret = randomBytes(32);
  const { encryptedData, hash } = telegramEncrypt(
    Buffer.from(JSON.stringify(credentials)),
    secret,
  );
  const encryptedSecret = publicEncrypt(
    { key: rsaPublicKeyPem, padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING },
    secret,
  );
  return {
    data: encryptedData.toString('base64'),
    hash: hash.toString('base64'),
    secret: encryptedSecret.toString('base64'),
  };
}

/**
 * Convenience wrapper that builds a complete PassportData with encrypted
 * credentials and the supplied EncryptedPassportElement array.
 */
function buildPassportData(
  elements: EncryptedPassportElement[],
  credentials: Credentials,
  rsaPublicKeyPem: string,
): PassportData {
  return {
    data: elements,
    credentials: buildEncryptedCredentials(credentials, rsaPublicKeyPem),
  };
}

/** Stub PassportFile used as a stand-in for file metadata. */
const stubPassportFile = (): PassportFile => ({
  file_id: 'file-id-1',
  file_unique_id: 'unique-1',
  file_size: 1024,
  file_date: 1700000000,
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('TelegramPassport', () => {
  let privateKeyPem: string;
  let publicKeyPem: string;

  beforeAll(() => {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
    });
    privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
  });

  // -------------------------------------------------------------------------
  // constructor
  // -------------------------------------------------------------------------
  describe('constructor', () => {
    it('accepts a string private key without throwing', () => {
      expect(() => new TelegramPassport('any-string-key')).not.toThrow();
    });

    it('accepts a Buffer private key without throwing', () => {
      expect(() => new TelegramPassport(Buffer.from('any-buffer-key'))).not.toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // decryptData
  // -------------------------------------------------------------------------
  describe('decryptData', () => {
    // The private key is irrelevant for decryptData (no RSA involved).
    const tp = new TelegramPassport('irrelevant-key');

    it('decrypts correctly when all inputs are Buffers', () => {
      const secret = randomBytes(32);
      const plaintext = Buffer.from('{"hello":"world"}');
      const { encryptedData, hash } = telegramEncrypt(plaintext, secret);

      const result = tp.decryptData(encryptedData, secret, hash);

      expect(result.toString()).toBe('{"hello":"world"}');
    });

    it('decrypts correctly when all inputs are base64 strings', () => {
      const secret = randomBytes(32);
      const plaintext = Buffer.from('base64-input-test');
      const { encryptedData, hash } = telegramEncrypt(plaintext, secret);

      const result = tp.decryptData(
        encryptedData.toString('base64'),
        secret.toString('base64'),
        hash.toString('base64'),
      );

      expect(result.toString()).toBe('base64-input-test');
    });

    it('decrypts correctly with mixed Buffer and base64 string inputs', () => {
      const secret = randomBytes(32);
      const plaintext = Buffer.from('mixed-inputs');
      const { encryptedData, hash } = telegramEncrypt(plaintext, secret);

      const result = tp.decryptData(
        encryptedData,                     // Buffer
        secret.toString('base64'),         // string
        hash.toString('base64'),           // string
      );

      expect(result.toString()).toBe('mixed-inputs');
    });

    it('decrypts an empty JSON object', () => {
      const secret = randomBytes(32);
      const plaintext = Buffer.from('{}');
      const { encryptedData, hash } = telegramEncrypt(plaintext, secret);

      const result = tp.decryptData(encryptedData, secret, hash);

      expect(result.toString()).toBe('{}');
    });

    it('decrypts a large payload (> 256 bytes)', () => {
      const secret = randomBytes(32);
      const payload = 'A'.repeat(512);
      const plaintext = Buffer.from(payload);
      const { encryptedData, hash } = telegramEncrypt(plaintext, secret);

      const result = tp.decryptData(encryptedData, secret, hash);

      expect(result.toString()).toBe(payload);
    });

    it('returns a Buffer instance', () => {
      const secret = randomBytes(32);
      const plaintext = Buffer.from('buffer-check');
      const { encryptedData, hash } = telegramEncrypt(plaintext, secret);

      const result = tp.decryptData(encryptedData, secret, hash);

      expect(Buffer.isBuffer(result)).toBe(true);
    });

    it('throws ERR_DATA_INTEGRITY_CHECK_FAILED when hash is wrong', () => {
      const secret = randomBytes(32);
      const plaintext = Buffer.from('integrity-check');
      const { encryptedData } = telegramEncrypt(plaintext, secret);
      const wrongHash = randomBytes(32); // does not match SHA-256 of paddedData

      expect(() => tp.decryptData(encryptedData, secret, wrongHash)).toThrow(
        ErrorMessages.ERR_DATA_INTEGRITY_CHECK_FAILED,
      );
    });

    it('throws when the wrong secret is used (produces wrong hash check)', () => {
      const secret = randomBytes(32);
      const plaintext = Buffer.from('wrong-secret-test');
      const { encryptedData, hash } = telegramEncrypt(plaintext, secret);
      const wrongSecret = randomBytes(32);

      // Wrong secret → wrong key/iv → garbage decrypt → hash mismatch
      expect(() => tp.decryptData(encryptedData, wrongSecret, hash)).toThrow(
        ErrorMessages.ERR_DATA_INTEGRITY_CHECK_FAILED,
      );
    });
  });

  // -------------------------------------------------------------------------
  // decryptPassportCredentials
  // -------------------------------------------------------------------------
  describe('decryptPassportCredentials', () => {
    it('returns the parsed Credentials JSON including nonce', () => {
      const tp = new TelegramPassport(privateKeyPem);
      const credentials: Credentials = {
        nonce: 'test-nonce-abc',
        secure_data: {
          personal_details: {
            data: { data_hash: 'dh1', secret: 'sec1' },
          },
        },
      };

      const encCreds = buildEncryptedCredentials(credentials, publicKeyPem);
      const result = tp.decryptPassportCredentials(encCreds);

      expect(result.nonce).toBe('test-nonce-abc');
      expect(result.secure_data.personal_details?.data?.data_hash).toBe('dh1');
      expect(result.secure_data.personal_details?.data?.secret).toBe('sec1');
    });

    it('returns an empty secure_data when credentials carry none', () => {
      const tp = new TelegramPassport(privateKeyPem);
      const credentials: Credentials = { nonce: 'empty-nonce', secure_data: {} };

      const encCreds = buildEncryptedCredentials(credentials, publicKeyPem);
      const result = tp.decryptPassportCredentials(encCreds);

      expect(result.nonce).toBe('empty-nonce');
      expect(result.secure_data).toEqual({});
    });

    it('throws when decrypted with the wrong private key', () => {
      const { privateKey: wrongKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
      const wrongKeyPem = wrongKey.export({ type: 'pkcs8', format: 'pem' }) as string;

      const tp = new TelegramPassport(wrongKeyPem);
      const credentials: Credentials = { nonce: 'n', secure_data: {} };
      const encCreds = buildEncryptedCredentials(credentials, publicKeyPem);

      expect(() => tp.decryptPassportCredentials(encCreds)).toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // decryptPassportData
  // -------------------------------------------------------------------------
  describe('decryptPassportData', () => {
    // ------------------------------------------------------------------
    // phone_number / email – passed through without decryption
    // ------------------------------------------------------------------
    it('passes through phone_number without decryption', () => {
      const tp = new TelegramPassport(privateKeyPem);
      const credentials: Credentials = { nonce: 'nonce-phone', secure_data: {} };
      const element: EncryptedPassportElement = {
        type: 'phone_number',
        phone_number: '+15550001111',
        hash: 'elem-hash',
      };

      const pd = buildPassportData([element], credentials, publicKeyPem);
      const result = tp.decryptPassportData(pd);

      expect(result.nonce).toBe('nonce-phone');
      expect(result.phone_number).toBe('+15550001111');
    });

    it('passes through email without decryption', () => {
      const tp = new TelegramPassport(privateKeyPem);
      const credentials: Credentials = { nonce: 'nonce-email', secure_data: {} };
      const element: EncryptedPassportElement = {
        type: 'email',
        email: 'user@example.com',
        hash: 'elem-hash',
      };

      const pd = buildPassportData([element], credentials, publicKeyPem);
      const result = tp.decryptPassportData(pd);

      expect(result.email).toBe('user@example.com');
    });

    // ------------------------------------------------------------------
    // personal_details – element with an encrypted 'data' field
    // ------------------------------------------------------------------
    it('decrypts personal_details data field', () => {
      const tp = new TelegramPassport(privateKeyPem);
      const personalDetails: PersonalDetails = {
        first_name: 'Alice',
        last_name: 'Smith',
        birth_date: '01.01.1990',
        gender: 'female',
        country_code: 'US',
        residence_country_code: 'US',
      };

      const dataSecret = randomBytes(32);
      const { encryptedData: dataEnc, hash: dataHash } = telegramEncrypt(
        Buffer.from(JSON.stringify(personalDetails)),
        dataSecret,
      );

      const element: EncryptedPassportElement = {
        type: 'personal_details',
        data: dataEnc.toString('base64'),
        hash: 'elem-hash',
      };

      const credentials: Credentials = {
        nonce: 'nonce-pd',
        secure_data: {
          personal_details: {
            data: {
              data_hash: dataHash.toString('base64'),
              secret: dataSecret.toString('base64'),
            },
          },
        },
      };

      const pd = buildPassportData([element], credentials, publicKeyPem);
      const result = tp.decryptPassportData(pd);

      expect(result.nonce).toBe('nonce-pd');
      expect((result.personal_details as any).data.first_name).toBe('Alice');
      expect((result.personal_details as any).data.last_name).toBe('Smith');
      expect((result.personal_details as any).data.gender).toBe('female');
    });

    // ------------------------------------------------------------------
    // address – element with an encrypted 'data' field (ResidentialAddress)
    // ------------------------------------------------------------------
    it('decrypts address data field', () => {
      const tp = new TelegramPassport(privateKeyPem);
      const address: ResidentialAddress = {
        street_line1: '123 Main St',
        city: 'Springfield',
        country_code: 'US',
        post_code: '12345',
      };

      const dataSecret = randomBytes(32);
      const { encryptedData: dataEnc, hash: dataHash } = telegramEncrypt(
        Buffer.from(JSON.stringify(address)),
        dataSecret,
      );

      const element: EncryptedPassportElement = {
        type: 'address',
        data: dataEnc.toString('base64'),
        hash: 'elem-hash',
      };

      const credentials: Credentials = {
        nonce: 'nonce-addr',
        secure_data: {
          address: {
            data: {
              data_hash: dataHash.toString('base64'),
              secret: dataSecret.toString('base64'),
            },
          },
        },
      };

      const pd = buildPassportData([element], credentials, publicKeyPem);
      const result = tp.decryptPassportData(pd);

      expect((result.address as any).data.street_line1).toBe('123 Main St');
      expect((result.address as any).data.city).toBe('Springfield');
    });

    // ------------------------------------------------------------------
    // passport – element with front_side and selfie (single PassportFile)
    // ------------------------------------------------------------------
    it('merges file credentials into front_side and selfie for passport type', () => {
      const tp = new TelegramPassport(privateKeyPem);

      const frontSideFile = stubPassportFile();
      const selfieFile = { ...stubPassportFile(), file_id: 'selfie-id' };

      const frontSideCreds: FileCredentials = { file_hash: 'fh-front', secret: 'sec-front' };
      const selfieCreds: FileCredentials = { file_hash: 'fh-selfie', secret: 'sec-selfie' };

      const element: EncryptedPassportElement = {
        type: 'passport',
        front_side: frontSideFile,
        selfie: selfieFile,
        hash: 'elem-hash',
      };

      const credentials: Credentials = {
        nonce: 'nonce-passport',
        secure_data: {
          passport: {
            front_side: frontSideCreds,
            selfie: selfieCreds,
          },
        },
      };

      const pd = buildPassportData([element], credentials, publicKeyPem);
      const result = tp.decryptPassportData(pd);

      const passport = result.passport as any;
      expect(passport.front_side.file_id).toBe('file-id-1');
      expect(passport.front_side.file_hash).toBe('fh-front');
      expect(passport.front_side.secret).toBe('sec-front');
      expect(passport.selfie.file_id).toBe('selfie-id');
      expect(passport.selfie.file_hash).toBe('fh-selfie');
    });

    // ------------------------------------------------------------------
    // utility_bill – element with files array (Array<PassportFile>)
    // ------------------------------------------------------------------
    it('merges file credentials into each entry of the files array for utility_bill', () => {
      const tp = new TelegramPassport(privateKeyPem);

      const file1 = stubPassportFile();
      const file2 = { ...stubPassportFile(), file_id: 'file-id-2', file_unique_id: 'unique-2' };

      const fileCreds: FileCredentials[] = [
        { file_hash: 'hash-1', secret: 'secret-1' },
        { file_hash: 'hash-2', secret: 'secret-2' },
      ];

      const element: EncryptedPassportElement = {
        type: 'utility_bill',
        files: [file1, file2],
        hash: 'elem-hash',
      };

      const credentials: Credentials = {
        nonce: 'nonce-bill',
        secure_data: {
          utility_bill: {
            files: fileCreds,
          },
        },
      };

      const pd = buildPassportData([element], credentials, publicKeyPem);
      const result = tp.decryptPassportData(pd);

      const bill = result.utility_bill as any;
      expect(bill.files).toHaveLength(2);
      expect(bill.files[0].file_id).toBe('file-id-1');
      expect(bill.files[0].file_hash).toBe('hash-1');
      expect(bill.files[0].secret).toBe('secret-1');
      expect(bill.files[1].file_id).toBe('file-id-2');
      expect(bill.files[1].file_hash).toBe('hash-2');
      expect(bill.files[1].secret).toBe('secret-2');
    });

    // ------------------------------------------------------------------
    // translation array (on a bill-like element)
    // ------------------------------------------------------------------
    it('merges file credentials into the translation array', () => {
      const tp = new TelegramPassport(privateKeyPem);

      const translationFile = stubPassportFile();
      const translationCreds: FileCredentials[] = [
        { file_hash: 'th-1', secret: 'ts-1' },
      ];

      const element: EncryptedPassportElement = {
        type: 'bank_statement',
        files: [stubPassportFile()],
        translation: [translationFile],
        hash: 'elem-hash',
      };

      const credentials: Credentials = {
        nonce: 'nonce-bank',
        secure_data: {
          bank_statement: {
            files: [{ file_hash: 'fh-main', secret: 'fs-main' }],
            translation: translationCreds,
          },
        },
      };

      const pd = buildPassportData([element], credentials, publicKeyPem);
      const result = tp.decryptPassportData(pd);

      const stmt = result.bank_statement as any;
      expect(stmt.translation).toHaveLength(1);
      expect(stmt.translation[0].file_hash).toBe('th-1');
      expect(stmt.translation[0].secret).toBe('ts-1');
    });

    // ------------------------------------------------------------------
    // driver_license – combined: data + front_side + reverse_side + selfie
    // ------------------------------------------------------------------
    it('handles driver_license with data, front_side, reverse_side and selfie', () => {
      const tp = new TelegramPassport(privateKeyPem);

      const idData = { document_no: 'DL-123456', expiry_date: '31.12.2030' };
      const dataSecret = randomBytes(32);
      const { encryptedData: dataEnc, hash: dataHash } = telegramEncrypt(
        Buffer.from(JSON.stringify(idData)),
        dataSecret,
      );

      const frontSideFile = stubPassportFile();
      const reverseSideFile = { ...stubPassportFile(), file_id: 'rev-id' };
      const selfieFile = { ...stubPassportFile(), file_id: 'sel-id' };

      const element: EncryptedPassportElement = {
        type: 'driver_license',
        data: dataEnc.toString('base64'),
        front_side: frontSideFile,
        reverse_side: reverseSideFile,
        selfie: selfieFile,
        hash: 'elem-hash',
      };

      const credentials: Credentials = {
        nonce: 'nonce-dl',
        secure_data: {
          driver_license: {
            data: {
              data_hash: dataHash.toString('base64'),
              secret: dataSecret.toString('base64'),
            },
            front_side: { file_hash: 'fh-front', secret: 'sec-front' },
            reverse_side: { file_hash: 'fh-rev', secret: 'sec-rev' },
            selfie: { file_hash: 'fh-sel', secret: 'sec-sel' },
          },
        },
      };

      const pd = buildPassportData([element], credentials, publicKeyPem);
      const result = tp.decryptPassportData(pd);

      const dl = result.driver_license as any;
      expect(dl.data.document_no).toBe('DL-123456');
      expect(dl.data.expiry_date).toBe('31.12.2030');
      expect(dl.front_side.file_hash).toBe('fh-front');
      expect(dl.reverse_side.file_hash).toBe('fh-rev');
      expect(dl.selfie.file_hash).toBe('fh-sel');
    });

    // ------------------------------------------------------------------
    // Multiple elements in one PassportData
    // ------------------------------------------------------------------
    it('handles multiple elements including both encrypted and plain types', () => {
      const tp = new TelegramPassport(privateKeyPem);

      const personalDetails: PersonalDetails = {
        first_name: 'Bob',
        last_name: 'Jones',
        birth_date: '15.06.1985',
        gender: 'male',
        country_code: 'CA',
        residence_country_code: 'CA',
      };
      const dataSecret = randomBytes(32);
      const { encryptedData: dataEnc, hash: dataHash } = telegramEncrypt(
        Buffer.from(JSON.stringify(personalDetails)),
        dataSecret,
      );

      const elements: EncryptedPassportElement[] = [
        {
          type: 'personal_details',
          data: dataEnc.toString('base64'),
          hash: 'elem-hash-pd',
        },
        {
          type: 'phone_number',
          phone_number: '+12025550100',
          hash: 'elem-hash-phone',
        },
        {
          type: 'email',
          email: 'bob@example.com',
          hash: 'elem-hash-email',
        },
      ];

      const credentials: Credentials = {
        nonce: 'multi-nonce',
        secure_data: {
          personal_details: {
            data: {
              data_hash: dataHash.toString('base64'),
              secret: dataSecret.toString('base64'),
            },
          },
        },
      };

      const pd = buildPassportData(elements, credentials, publicKeyPem);
      const result = tp.decryptPassportData(pd);

      expect(result.nonce).toBe('multi-nonce');
      expect((result.personal_details as any).data.first_name).toBe('Bob');
      expect(result.phone_number).toBe('+12025550100');
      expect(result.email).toBe('bob@example.com');
    });

    // ------------------------------------------------------------------
    // nonce is always present in the returned fields
    // ------------------------------------------------------------------
    it('always includes the nonce from credentials in the returned fields', () => {
      const tp = new TelegramPassport(privateKeyPem);
      const credentials: Credentials = { nonce: 'unique-nonce-xyz', secure_data: {} };
      const pd = buildPassportData([], credentials, publicKeyPem);
      const result = tp.decryptPassportData(pd);

      expect(result.nonce).toBe('unique-nonce-xyz');
    });
  });
});
