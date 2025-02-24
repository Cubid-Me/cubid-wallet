// @ts-ignore
import * as CBOR from 'cbor-web';

// Custom error types for better error handling and debugging
class WebAuthnCryptoError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'WebAuthnCryptoError';
    }
}

class DatabaseError extends WebAuthnCryptoError {
    constructor(message: string) {
        super(message);
        this.name = 'DatabaseError';
    }
}

// Type definitions for our data structures
interface CredentialData {
    id: string;
    value: Uint8Array;
}

interface EncryptedData {
    id: string;
    encryptedData: ArrayBuffer;
    iv: Uint8Array;
    // Store the AES key that's protected by WebAuthn or password
    encryptedAesKey: ArrayBuffer;
    encryptionMethod: 'webauthn' | 'password';
    salt?: Uint8Array;
    ivForKeyEncryption?: Uint8Array;
    credentialId: any
}

interface WebAuthnCredential {
    credentialId: Uint8Array;
    publicKey: CryptoKey;
}

// Main WebAuthnCrypto class for handling WebAuthn-based encryption operations
export class WebAuthnCrypto {
    private credentialId: Uint8Array | null;
    private publicKey: CryptoKey | null;
    private db: IDBDatabase | null;
    private fallbackPasswordHash: string | null = null;
    constructor() {
        this.credentialId = null;
        this.publicKey = null;
        this.db = null;

        // Initialize database connection when class is instantiated
        this.initializeDatabase().catch((error) => {
            console.error('Failed to initialize database:', error);
            throw new DatabaseError('Database initialization failed');
        });
    }

    // Initialize IndexedDB for storing encrypted data and credentials
    private async initializeDatabase(): Promise<void> {
        try {
            this.db = await new Promise<IDBDatabase>((resolve, reject) => {
                const request = indexedDB.open('WebAuthnStorage', 1);

                request.onupgradeneeded = (event: IDBVersionChangeEvent) => {
                    const db = (event.target as IDBOpenDBRequest).result;

                    // Create object stores if they don't exist
                    if (!db.objectStoreNames.contains('encryptedData')) {
                        db.createObjectStore('encryptedData', { keyPath: 'id' });
                    }
                    if (!db.objectStoreNames.contains('credentialData')) {
                        db.createObjectStore('credentialData', { keyPath: 'id' });
                    }
                };

                request.onsuccess = () => resolve(request.result);
                request.onerror = () => reject(request.error);
            });

            console.log('IndexedDB initialized successfully');
        } catch (error) {
            throw new DatabaseError(`Failed to initialize IndexedDB: ${error.message}`);
        }
    }

    // Generate a new WebAuthn credential pair
    public async generateKeyPair(): Promise<any> {
        try {
            if (await this.isWebAuthnSupported()) {
                const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions = {
                    challenge: crypto.getRandomValues(new Uint8Array(32)),
                    rp: {
                        name: 'Hardware-Backed Device Share',
                        id: window.location.hostname
                    },
                    user: {
                        id: new TextEncoder().encode('cubid-wallet'),
                        name: 'cubid-wallet',
                        displayName: 'Cubid Wallet'
                    },
                    pubKeyCredParams: [
                        { type: 'public-key', alg: -7 }
                    ],
                    authenticatorSelection: {
                        authenticatorAttachment: 'platform',
                        requireResidentKey: false,
                        userVerification: 'required'
                    },
                    extensions: {
                        credProps: true
                    },
                    timeout: 60000,
                    attestation: 'none'
                };

                const credential = await navigator.credentials.create({
                    publicKey: publicKeyCredentialCreationOptions
                }) as PublicKeyCredential;

                const response = credential.response as AuthenticatorAttestationResponse;
                const attestationBuffer = new Uint8Array(response.attestationObject);
                const decodedAttestationObj = await CBOR.decodeFirst(attestationBuffer);
                const authData = new Uint8Array(decodedAttestationObj.authData);

                const flags = authData[32];
                const hasAttestedCredentialData = (flags & 0x40) === 0x40;

                if (!hasAttestedCredentialData) {
                    throw new Error('No attested credential data in authentication response');
                }

                let pointer = 37;
                const aaguid = authData.slice(pointer, pointer + 16);
                pointer += 16;

                const credentialIdLengthBytes = authData.slice(pointer, pointer + 2);
                const credentialIdLength = new DataView(credentialIdLengthBytes.buffer).getUint16(0, false);
                pointer += 2;

                if (pointer + credentialIdLength > authData.byteLength) {
                    throw new WebAuthnCryptoError('Invalid credential ID length in authenticator data');
                }

                this.credentialId = new Uint8Array(authData.slice(pointer, pointer + credentialIdLength));
                pointer += credentialIdLength;

                if (this.credentialId.length === 0) {
                    throw new WebAuthnCryptoError('Empty credential ID received from authenticator');
                }

                const publicKeyBytes = authData.slice(pointer);
                const publicKeyCBOR = await CBOR.decodeFirst(publicKeyBytes);

                if (!publicKeyCBOR.get(-2) || !publicKeyCBOR.get(-3)) {
                    throw new WebAuthnCryptoError('Invalid COSE key format: missing coordinates');
                }

                const toBase64Url = (buffer: ArrayBuffer): string => {
                    return btoa(String.fromCharCode(...new Uint8Array(buffer)))
                        .replace(/\+/g, '-')
                        .replace(/\//g, '_')
                        .replace(/=/g, '');
                };

                const jwk = {
                    kty: 'EC',
                    crv: 'P-256',
                    x: toBase64Url(publicKeyCBOR.get(-2)),
                    y: toBase64Url(publicKeyCBOR.get(-3)),
                    ext: true
                };

                this.publicKey = await crypto.subtle.importKey(
                    'jwk',
                    jwk,
                    {
                        name: 'ECDSA',
                        namedCurve: 'P-256'
                    },
                    true,
                    ['verify']
                );

                await this.storeInIndexedDB<CredentialData>('credentialData', {
                    id: 'credentialId',
                    value: this.credentialId
                });

                return {
                    type: 'webauthn',
                    credentialId: this.credentialId,
                    publicKey: this.publicKey
                };
            }

            return {
                type: 'password',
                message: 'WebAuthn is not supported. Using password-based encryption as fallback.'
            };

        } catch (error) {
            if (error instanceof WebAuthnCryptoError) {
                return {
                    type: 'password',
                    message: 'WebAuthn failed. Using password-based encryption as fallback.'
                };
            }
            throw error;
        }
    }

    private async isWebAuthnSupported(): Promise<boolean> {
        if (!window.isSecureContext) return false;
        if (!window.PublicKeyCredential) return false;
        return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    }

    private async deriveKeyFromPassword(password: string, salt: Uint8Array): Promise<CryptoKey> {
        const encoder = new TextEncoder();
        const passwordBuffer = encoder.encode(password);

        const importedKey = await crypto.subtle.importKey(
            'raw',
            passwordBuffer,
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );

        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            importedKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    // Encrypt data using AES-GCM and protect the key with WebAuthn or password
    public async encryptDeviceShare(deviceShare: string): Promise<boolean> {
        try {
            // Generate a random AES key for encrypting the device share
            const aesKey = await crypto.subtle.generateKey(
                {
                    name: 'AES-GCM',
                    length: 256
                },
                true,
                ['encrypt', 'decrypt']
            );

            // Generate a random initialization vector
            const iv = crypto.getRandomValues(new Uint8Array(12));

            // Encrypt the device share using AES-GCM
            const encryptedData = await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv
                },
                aesKey,
                new TextEncoder().encode(deviceShare)
            );

            // Export and store the AES key - it will be protected by WebAuthn or password
            let encryptedAesKey: ArrayBuffer;
            let encryptionMethod: 'webauthn' | 'password' = 'webauthn';
            let salt: Uint8Array | undefined;
            let ivForKeyEncryption: Uint8Array | undefined;

            if (this.publicKey) {
                // WebAuthn is available, export the AES key directly (Note: This is insecure and should be replaced with proper encryption)
                encryptedAesKey = await crypto.subtle.exportKey('raw', aesKey);
            } else {
                // Fallback to password-based encryption
                const password = prompt('Enter a password to encrypt your data:');
                if (!password) {
                    throw new WebAuthnCryptoError('Password is required for encryption');
                }

                // Generate salt and IV for key encryption
                salt = crypto.getRandomValues(new Uint8Array(16));
                ivForKeyEncryption = crypto.getRandomValues(new Uint8Array(12));

                // Derive key from password
                const derivedKey = await this.deriveKeyFromPassword(password, salt);

                // Encrypt the AES key with the derived key
                const exportedAesKey = await crypto.subtle.exportKey('raw', aesKey);
                encryptedAesKey = await crypto.subtle.encrypt(
                    {
                        name: 'AES-GCM',
                        iv: ivForKeyEncryption
                    },
                    derivedKey,
                    exportedAesKey
                );

                encryptionMethod = 'password';
            }

            // Store encrypted data in IndexedDB
            await this.storeInIndexedDB<EncryptedData>('encryptedData', {
                id: 'deviceShare',
                encryptedData,
                iv,
                encryptedAesKey,
                encryptionMethod,
                salt,
                ivForKeyEncryption,
                credentialId: this.credentialId
            });

            return true;
        } catch (error) {
            throw new WebAuthnCryptoError(`Failed to encrypt device share: ${error.message}`);
        }
    }

    // Decrypt data using WebAuthn authentication or password
    public async decryptDeviceShare(): Promise<string> {
        try {
            // Retrieve encrypted data from storage
            const encryptedStore = await this.getFromIndexedDB<EncryptedData>('encryptedData', 'deviceShare');
            if (!encryptedStore) {
                throw new WebAuthnCryptoError('No encrypted device share found');
            }

            let aesKey: CryptoKey;

            if (encryptedStore.encryptionMethod === 'webauthn') {
                // WebAuthn decryption path
                const credentialData = await this.getFromIndexedDB<CredentialData>('credentialData', 'credentialId');
                if (!credentialData) {
                    throw new WebAuthnCryptoError('No credential ID found');
                }

                // Create WebAuthn assertion options
                const assertionOptions: PublicKeyCredentialRequestOptions = {
                    challenge: crypto.getRandomValues(new Uint8Array(32)),
                    allowCredentials: [{
                        id: credentialData.value,
                        type: 'public-key',
                    }],
                    userVerification: 'required',
                    timeout: 60000
                };

                // Get authentication assertion
                const assertion = await navigator.credentials.get({
                    publicKey: assertionOptions
                }) as PublicKeyCredential;

                // Import the AES key (Note: This assumes the key is stored raw, which is insecure)
                aesKey = await crypto.subtle.importKey(
                    'raw',
                    encryptedStore.encryptedAesKey,
                    {
                        name: 'AES-GCM',
                        length: 256
                    },
                    false,
                    ['decrypt']
                );
            } else {
                // Password-based decryption path
                if (!encryptedStore.salt || !encryptedStore.ivForKeyEncryption) {
                    throw new WebAuthnCryptoError('Missing parameters for password-based decryption');
                }

                const password = prompt('Enter your password to decrypt the data:');
                if (!password) {
                    throw new WebAuthnCryptoError('Password is required for decryption');
                }

                // Derive key from password and salt
                const derivedKey = await this.deriveKeyFromPassword(password, encryptedStore.salt);

                // Decrypt the AES key
                const decryptedAesKey = await crypto.subtle.decrypt(
                    {
                        name: 'AES-GCM',
                        iv: encryptedStore.ivForKeyEncryption
                    },
                    derivedKey,
                    encryptedStore.encryptedAesKey
                );

                // Import the decrypted AES key
                aesKey = await crypto.subtle.importKey(
                    'raw',
                    decryptedAesKey,
                    {
                        name: 'AES-GCM',
                        length: 256
                    },
                    false,
                    ['decrypt']
                );
            }

            // Decrypt the data using AES-GCM
            const decryptedData = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: encryptedStore.iv
                },
                aesKey,
                encryptedStore.encryptedData
            );

            return new TextDecoder().decode(decryptedData);
        } catch (error) {
            throw new WebAuthnCryptoError(`Failed to decrypt device share: ${error.message}`);
        }
    }

    // Helper method to store data in IndexedDB
    private async storeInIndexedDB<T extends { id: string }>(
        storeName: string,
        data: T
    ): Promise<IDBValidKey> {
        if (!this.db) {
            throw new DatabaseError('Database not initialized');
        }

        return new Promise((resolve, reject) => {
            const transaction = this.db!.transaction(storeName, 'readwrite');
            const store = transaction.objectStore(storeName);
            const request = store.put(data);

            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    // Helper method to retrieve data from IndexedDB
    private async getFromIndexedDB<T>(
        storeName: string,
        key: string
    ): Promise<T | null> {
        if (!this.db) {
            throw new DatabaseError('Database not initialized');
        }

        return new Promise((resolve, reject) => {
            const transaction = this.db!.transaction(storeName, 'readonly');
            const store = transaction.objectStore(storeName);
            const request = store.get(key);

            request.onsuccess = () => resolve(request.result as T);
            request.onerror = () => reject(request.error);
        });
    }
    // ─── NEW METHODS BELOW ─────────────────────────────────────────────
    /**
     * Encrypts the given plain text string using a fresh AES key.
     * Depending on availability, the AES key is either "protected" via WebAuthn (if available)
     * or by a password-based mechanism. In the password path the user must enter the same password
     * that was used previously (if already set) otherwise decryption will fail.
     * 
     * This function both returns the resulting EncryptedData object and stores it in IndexedDB (with key 'encryptedString')
     * so that it can be retrieved later—even after a page reload.
     */
    public async encryptString(plainText: string): Promise<EncryptedData> {
        try {
            // Generate a new AES key for encrypting the string
            const aesKey = await crypto.subtle.generateKey(
                {
                    name: 'AES-GCM',
                    length: 256
                },
                true,
                ['encrypt', 'decrypt']
            );
            // Generate a random initialization vector for data encryption
            const iv = crypto.getRandomValues(new Uint8Array(12));
            // Encrypt the plain text string using AES-GCM
            const encryptedData = await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv
                },
                aesKey,
                new TextEncoder().encode(plainText)
            );
            let encryptedAesKey: ArrayBuffer;
            let encryptionMethod: 'webauthn' | 'password';
            let salt: Uint8Array | undefined;
            let ivForKeyEncryption: Uint8Array | undefined;
            if (this.publicKey) {
                // If WebAuthn is available, simply export the AES key.
                encryptedAesKey = await crypto.subtle.exportKey('raw', aesKey);
                encryptionMethod = 'webauthn';
            } else {
                // Fallback: prompt for a password to protect the AES key.
                const password = prompt('Enter a password to encrypt your string:');
                if (!password) {
                    throw new WebAuthnCryptoError('Password is required for encryption');
                }
                // Compute a hash of the entered password.
                const passwordHash = await this.hashPassword(password);
                if (this.fallbackPasswordHash) {
                    // If a fallback password was used before, enforce that it is reused.
                    if (this.fallbackPasswordHash !== passwordHash) {
                        throw new WebAuthnCryptoError('Incorrect password. Must use the same password as previously set.');
                    }
                } else {
                    // Store the hash for future comparisons.
                    this.fallbackPasswordHash = passwordHash;
                }
                // Generate salt and IV for encrypting the AES key.
                salt = crypto.getRandomValues(new Uint8Array(16));
                ivForKeyEncryption = crypto.getRandomValues(new Uint8Array(12));
                const derivedKey = await this.deriveKeyFromPassword(password, salt);
                const exportedAesKey = await crypto.subtle.exportKey('raw', aesKey);
                encryptedAesKey = await crypto.subtle.encrypt(
                    {
                        name: 'AES-GCM',
                        iv: ivForKeyEncryption
                    },
                    derivedKey,
                    exportedAesKey
                );
                encryptionMethod = 'password';
            }
            // Build the EncryptedData object and assign a fixed ID so it can be retrieved later.
            const encryptedDataObj: EncryptedData = {
                id: 'encryptedString',
                encryptedData,
                iv,
                encryptedAesKey,
                encryptionMethod,
                salt,
                ivForKeyEncryption,
                credentialId: this.credentialId
            };
            // Store the encrypted data in IndexedDB.
            await this.storeInIndexedDB<EncryptedData>('encryptedData', encryptedDataObj);
            // Return the encrypted data object.
            return encryptedDataObj;
        } catch (error) {
            throw new WebAuthnCryptoError(`Failed to encrypt string: ${error.message}`);
        }
    }
    /**
     * Decrypts the given EncryptedData object and returns the decrypted string.
     * If no parameter is provided, this function will attempt to retrieve the stored encrypted data (with key 'encryptedString')
     * from IndexedDB. If the data was protected using WebAuthn, a WebAuthn assertion is requested.
     * If password-based protection was used, the user must enter the same password as before.
     */
    public async decryptString(encrypted?: EncryptedData): Promise<string> {
        try {
            let encryptedDataObj: EncryptedData;
            if (!encrypted) {
                // Retrieve the encrypted data from IndexedDB using its fixed key.
                const storedData = await this.getFromIndexedDB<EncryptedData>('encryptedData', 'encryptedString');
                if (!storedData) {
                    throw new WebAuthnCryptoError('No encrypted string found in storage.');
                }
                encryptedDataObj = storedData;
            } else {
                encryptedDataObj = encrypted;
            }
            let aesKey: CryptoKey;
            if (encryptedDataObj.encryptionMethod === 'webauthn') {
                // WebAuthn decryption path.
                if (!encryptedDataObj.credentialId) {
                    throw new WebAuthnCryptoError('No credential ID available for WebAuthn decryption.');
                }
                const assertionOptions: PublicKeyCredentialRequestOptions = {
                    challenge: crypto.getRandomValues(new Uint8Array(32)),
                    allowCredentials: [{
                        id: encryptedDataObj.credentialId,
                        type: 'public-key'
                    }],
                    userVerification: 'required',
                    timeout: 60000
                };
                // Request a WebAuthn assertion.
                const assertion = await navigator.credentials.get({
                    publicKey: assertionOptions
                }) as PublicKeyCredential;
                // Import the AES key (assuming it was exported raw).
                aesKey = await crypto.subtle.importKey(
                    'raw',
                    encryptedDataObj.encryptedAesKey,
                    {
                        name: 'AES-GCM',
                        length: 256
                    },
                    false,
                    ['decrypt']
                );
            } else {
                // Password-based decryption path.
                if (!encryptedDataObj.salt || !encryptedDataObj.ivForKeyEncryption) {
                    throw new WebAuthnCryptoError('Missing parameters for password-based decryption');
                }
                const password = prompt('Enter your password to decrypt the string:');
                if (!password) {
                    throw new WebAuthnCryptoError('Password is required for decryption');
                }
                const passwordHash = await this.hashPassword(password);
                if (!this.fallbackPasswordHash) {
                    // If no fallback password was stored yet, then save it.
                    this.fallbackPasswordHash = passwordHash;
                } else {
                    // Enforce that the same password is used.
                    if (this.fallbackPasswordHash !== passwordHash) {
                        throw new WebAuthnCryptoError('Incorrect password. Must use the same password as previously set.');
                    }
                }
                const derivedKey = await this.deriveKeyFromPassword(password, encryptedDataObj.salt);
                const decryptedAesKey = await crypto.subtle.decrypt(
                    {
                        name: 'AES-GCM',
                        iv: encryptedDataObj.ivForKeyEncryption
                    },
                    derivedKey,
                    encryptedDataObj.encryptedAesKey
                );
                aesKey = await crypto.subtle.importKey(
                    'raw',
                    decryptedAesKey,
                    {
                        name: 'AES-GCM',
                        length: 256
                    },
                    false,
                    ['decrypt']
                );
            }
            // Decrypt the ciphertext using the imported AES key.
            const decryptedData = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: encryptedDataObj.iv
                },
                aesKey,
                encryptedDataObj.encryptedData
            );
            return new TextDecoder().decode(decryptedData);
        } catch (error) {
            throw new WebAuthnCryptoError(`Failed to decrypt string: ${error.message}`);
        }
    }
    /**
     * Helper method to hash a password using SHA-256.
     */
    private async hashPassword(password: string): Promise<string> {
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        // Convert buffer to hex string.
        return Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
}