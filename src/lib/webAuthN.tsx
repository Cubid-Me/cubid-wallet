// @ts-ignore
import * as CBOR from 'cbor-web';

// Shamir Secret Sharing Implementation
class ShamirSecretSharing {
    private static readonly PRIME = 2n ** 127n - 1n; // Mersenne prime for finite field arithmetic

    // Convert string to BigInt
    private static stringToBigInt(str: string): bigint {
        const encoder = new TextEncoder();
        const bytes = encoder.encode(str);
        let result = 0n;
        for (let i = 0; i < bytes.length; i++) {
            result = (result << 8n) + BigInt(bytes[i]);
        }
        return result;
    }

    // Convert BigInt back to string
    private static bigIntToString(num: bigint): string {
        if (num === 0n) return '';
        
        const bytes: number[] = [];
        let temp = num;
        while (temp > 0n) {
            bytes.unshift(Number(temp & 0xFFn));
            temp = temp >> 8n;
        }
        
        const decoder = new TextDecoder();
        return decoder.decode(new Uint8Array(bytes));
    }

    // Modular arithmetic for finite field
    private static mod(a: bigint, m: bigint): bigint {
        const result = a % m;
        return result < 0n ? result + m : result;
    }

    // Modular exponentiation
    private static modPow(base: bigint, exp: bigint, mod: bigint): bigint {
        let result = 1n;
        base = base % mod;
        while (exp > 0n) {
            if (exp % 2n === 1n) {
                result = (result * base) % mod;
            }
            exp = exp >> 1n;
            base = (base * base) % mod;
        }
        return result;
    }

    // Modular multiplicative inverse using extended Euclidean algorithm
    private static modInverse(a: bigint, m: bigint): bigint {
        if (m === 1n) return 0n;
        
        const m0 = m;
        let [x0, x1] = [0n, 1n];
        
        while (a > 1n) {
            const q = a / m;
            [a, m] = [m, a % m];
            [x0, x1] = [x1 - q * x0, x0];
        }
        
        return x1 < 0n ? x1 + m0 : x1;
    }

    // Generate random polynomial coefficients
    private static generateCoefficients(secret: bigint, threshold: number): bigint[] {
        const coefficients = [secret];
        for (let i = 1; i < threshold; i++) {
            // Generate random coefficient
            const randomBytes = crypto.getRandomValues(new Uint8Array(16));
            let coefficient = 0n;
            for (let j = 0; j < randomBytes.length; j++) {
                coefficient = (coefficient << 8n) + BigInt(randomBytes[j]);
            }
            coefficients.push(this.mod(coefficient, this.PRIME));
        }
        return coefficients;
    }

    // Evaluate polynomial at point x
    private static evaluatePolynomial(coefficients: bigint[], x: bigint): bigint {
        let result = 0n;
        let xPower = 1n;
        
        for (const coeff of coefficients) {
            result = this.mod(result + this.mod(coeff * xPower, this.PRIME), this.PRIME);
            xPower = this.mod(xPower * x, this.PRIME);
        }
        
        return result;
    }

    // Lagrange interpolation to reconstruct secret
    private static lagrangeInterpolation(shares: { x: bigint; y: bigint }[]): bigint {
        let secret = 0n;
        
        for (let i = 0; i < shares.length; i++) {
            let numerator = 1n;
            let denominator = 1n;
            
            for (let j = 0; j < shares.length; j++) {
                if (i !== j) {
                    numerator = this.mod(numerator * (-shares[j].x), this.PRIME);
                    denominator = this.mod(denominator * (shares[i].x - shares[j].x), this.PRIME);
                }
            }
            
            const lagrangeCoeff = this.mod(numerator * this.modInverse(denominator, this.PRIME), this.PRIME);
            secret = this.mod(secret + this.mod(shares[i].y * lagrangeCoeff, this.PRIME), this.PRIME);
        }
        
        return secret;
    }

    // Split secret into shares
    public static splitSecret(secret: string, totalShares: number, threshold: number): { x: number; y: string }[] {
        if (threshold > totalShares) {
            throw new Error('Threshold cannot be greater than total shares');
        }
        
        const secretBigInt = this.stringToBigInt(secret);
        const coefficients = this.generateCoefficients(secretBigInt, threshold);
        
        const shares: { x: number; y: string }[] = [];
        for (let i = 1; i <= totalShares; i++) {
            const x = BigInt(i);
            const y = this.evaluatePolynomial(coefficients, x);
            shares.push({
                x: i,
                y: y.toString()
            });
        }
        
        return shares;
    }

    // Combine shares to reconstruct secret
    public static combineShares(shares: { x: number; y: string }[]): string {
        if (shares.length < 2) {
            throw new Error('Need at least 2 shares to reconstruct secret');
        }
        
        const bigIntShares = shares.map(share => ({
            x: BigInt(share.x),
            y: BigInt(share.y)
        }));
        
        const secret = this.lagrangeInterpolation(bigIntShares);
        return this.bigIntToString(secret);
    }
}

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
    credentialId: any;
    // Shamir share information
    shamirScheme?: '1of2' | '2of3';
    shareIndex?: number;
    totalShares?: number;
    threshold?: number;
}

interface WebAuthnCredential {
    credentialId: Uint8Array;
    publicKey: CryptoKey;
}

interface ShamirShare {
    x: number;
    y: string;
}

interface ShamirKeyResult {
    appShare: ShamirShare;
    userShare: ShamirShare;
    deviceShare?: ShamirShare; // Only for 2-of-3 scheme
    publicAddress: string;
    scheme: '1of2' | '2of3';
}

// Main WebAuthnCrypto class for handling WebAuthn-based encryption operations with Shamir Secret Sharing
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
                const request = indexedDB.open('WebAuthnStorage', 2); // Increased version for schema changes

                request.onupgradeneeded = (event: IDBVersionChangeEvent) => {
                    const db = (event.target as IDBOpenDBRequest).result;

                    // Create object stores if they don't exist
                    if (!db.objectStoreNames.contains('encryptedData')) {
                        db.createObjectStore('encryptedData', { keyPath: 'id' });
                    }
                    if (!db.objectStoreNames.contains('credentialData')) {
                        db.createObjectStore('credentialData', { keyPath: 'id' });
                    }
                    if (!db.objectStoreNames.contains('shamirShares')) {
                        db.createObjectStore('shamirShares', { keyPath: 'id' });
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

    // Generate Shamir Secret Sharing for private keys
    public async generateShamirShares(privateKey: string, scheme: '1of2' | '2of3' = '2of3'): Promise<ShamirKeyResult> {
        try {
            let shares: ShamirShare[];
            let threshold: number;
            let totalShares: number;

            if (scheme === '1of2') {
                // 1-of-2: Either share can reconstruct the secret
                threshold = 1;
                totalShares = 2;
            } else {
                // 2-of-3: Need any 2 of 3 shares to reconstruct
                threshold = 2;
                totalShares = 3;
            }

            shares = ShamirSecretSharing.splitSecret(privateKey, totalShares, threshold);

            const result: ShamirKeyResult = {
                appShare: shares[0],      // Share 1: Stored on server
                userShare: shares[1],     // Share 2: Encrypted and stored locally
                scheme,
                publicAddress: '' // This should be derived from the private key
            };

            if (scheme === '2of3') {
                result.deviceShare = shares[2]; // Share 3: Encrypted and stored on device (for 2-of-3 only)
            }

            return result;
        } catch (error) {
            throw new WebAuthnCryptoError(`Failed to generate Shamir shares: ${error.message}`);
        }
    }

    // Reconstruct private key from Shamir shares
    public async reconstructPrivateKey(shares: ShamirShare[]): Promise<string> {
        try {
            if (shares.length < 1) {
                throw new WebAuthnCryptoError('Need at least 1 share to reconstruct key');
            }

            return ShamirSecretSharing.combineShares(shares);
        } catch (error) {
            throw new WebAuthnCryptoError(`Failed to reconstruct private key: ${error.message}`);
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

    // Encrypt Shamir share using AES-GCM and protect the key with WebAuthn or password
    public async encryptShamirShare(share: ShamirShare, shareId: string, scheme: '1of2' | '2of3'): Promise<boolean> {
        try {
            const shareString = JSON.stringify(share);
            
            // Generate a random AES key for encrypting the share
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

            // Encrypt the share using AES-GCM
            const encryptedData = await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv
                },
                aesKey,
                new TextEncoder().encode(shareString)
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
                const password = prompt('Enter a password to encrypt your share:');
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
                id: shareId,
                encryptedData,
                iv,
                encryptedAesKey,
                encryptionMethod,
                salt,
                ivForKeyEncryption,
                credentialId: this.credentialId,
                shamirScheme: scheme,
                shareIndex: share.x,
                totalShares: scheme === '1of2' ? 2 : 3,
                threshold: scheme === '1of2' ? 1 : 2
            });

            return true;
        } catch (error) {
            throw new WebAuthnCryptoError(`Failed to encrypt Shamir share: ${error.message}`);
        }
    }

    // Decrypt Shamir share using WebAuthn authentication or password
    public async decryptShamirShare(shareId: string): Promise<ShamirShare> {
        try {
            // Retrieve encrypted data from storage
            const encryptedStore = await this.getFromIndexedDB<EncryptedData>('encryptedData', shareId);
            if (!encryptedStore) {
                throw new WebAuthnCryptoError(`No encrypted share found with ID: ${shareId}`);
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

                const password = prompt('Enter your password to decrypt the share:');
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

            const shareString = new TextDecoder().decode(decryptedData);
            return JSON.parse(shareString) as ShamirShare;
        } catch (error) {
            throw new WebAuthnCryptoError(`Failed to decrypt Shamir share: ${error.message}`);
        }
    }

    // Legacy method for backward compatibility
    public async encryptDeviceShare(deviceShare: string): Promise<boolean> {
        try {
            // For backward compatibility, treat this as a simple string encryption
            return await this.encryptString(deviceShare, 'deviceShare');
        } catch (error) {
            throw new WebAuthnCryptoError(`Failed to encrypt device share: ${error.message}`);
        }
    }

    // Legacy method for backward compatibility
    public async decryptDeviceShare(): Promise<string> {
        try {
            return await this.decryptString(undefined, 'deviceShare');
        } catch (error) {
            throw new WebAuthnCryptoError(`Failed to decrypt device share: ${error.message}`);
        }
    }

    /**
     * Encrypts the given plain text string using a fresh AES key.
     * Depending on availability, the AES key is either "protected" via WebAuthn (if available)
     * or by a password-based mechanism.
     */
    public async encryptString(plainText: string, id: string = 'encryptedString'): Promise<boolean> {
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
            
            // Build the EncryptedData object and store it
            const encryptedDataObj: EncryptedData = {
                id: id,
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
            
            return true;
        } catch (error) {
            throw new WebAuthnCryptoError(`Failed to encrypt string: ${error.message}`);
        }
    }

    /**
     * Decrypts the given EncryptedData object and returns the decrypted string.
     * If no parameter is provided, this function will attempt to retrieve the stored encrypted data
     * from IndexedDB.
     */
    public async decryptString(encrypted?: EncryptedData, id: string = 'encryptedString'): Promise<string> {
        try {
            let encryptedDataObj: EncryptedData;
            
            if (!encrypted) {
                // Retrieve the encrypted data from IndexedDB using its ID.
                const storedData = await this.getFromIndexedDB<EncryptedData>('encryptedData', id);
                if (!storedData) {
                    throw new WebAuthnCryptoError(`No encrypted string found in storage with ID: ${id}`);
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

    // Get all stored shares for reconstruction
    public async getAllShamirShares(): Promise<{ id: string; share: ShamirShare; scheme: '1of2' | '2of3' }[]> {
        if (!this.db) {
            throw new DatabaseError('Database not initialized');
        }

        return new Promise((resolve, reject) => {
            const transaction = this.db!.transaction('encryptedData', 'readonly');
            const store = transaction.objectStore('encryptedData');
            const request = store.getAll();

            request.onsuccess = async () => {
                const allData = request.result as EncryptedData[];
                const shamirShares = allData.filter(data => data.shamirScheme);
                
                const shares = [];
                for (const encryptedShare of shamirShares) {
                    try {
                        const share = await this.decryptShamirShare(encryptedShare.id);
                        shares.push({
                            id: encryptedShare.id,
                            share,
                            scheme: encryptedShare.shamirScheme!
                        });
                    } catch (error) {
                        console.warn(`Failed to decrypt share ${encryptedShare.id}:`, error);
                    }
                }
                resolve(shares);
            };
            request.onerror = () => reject(request.error);
        });
    }
}

// Export the ShamirSecretSharing class for direct use if needed
export { ShamirSecretSharing };