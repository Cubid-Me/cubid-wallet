// Hooks-Based Internal Wallet Creation System
// File: hooks/useWalletCreation.tsx

import React, { useState, useEffect, useCallback, ReactNode, createContext, useContext, useMemo } from 'react';
import { WagmiProvider, createConfig, http } from 'wagmi';
import { celo, celoAlfajores, fuse, fuseSparknet } from 'wagmi/chains';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { usePublicClient, useBalance } from 'wagmi';
import { WebAuthnCrypto } from '../../index';
import { IdentitySDK, ClaimSDK } from '@goodsdks/citizen-sdk';
import { formatUnits, createWalletClient, http as viemHttp } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

// ============================================================================
// TYPES AND INTERFACES
// ============================================================================

export interface WalletProviderConfig {
  networks?: typeof celo[];
  defaultNetwork?: typeof celo;
  theme?: {
    mode?: 'light' | 'dark';
    variables?: Record<string, string>;
  };
}

interface InternalWallet {
  address: string;
  privateKey: string;
  created: boolean;
  verified: boolean;
}

interface WalletContextType {
  wallet: InternalWallet | null;
  isLoading: boolean;
  error: string | null;
  isInitialized: boolean;
  createWallet: (userId: string) => Promise<void>;
  loadExistingWallet: (userId: string) => Promise<void>;
  getBalance: (tokenAddress?: string) => any;
  clearError: () => void;
}

interface CitizenUbiProps {
  email?: string;
  phone?: string;
  environment?: 'production' | 'staging' | 'development';
  className?: string;
  theme?: 'light' | 'dark';
  showBalance?: boolean;
  showMultiTokenBalance?: boolean;
  customTokens?: Array<{
    address?: `0x${string}`;
    symbol: string;
    decimals: number;
    name: string;
  }>;
  onWalletCreated?: (address: string) => void;
  onVerificationComplete?: () => void;
  onClaimSuccess?: (amount: string, txHash: string) => void;
  onError?: (error: string) => void;
}

// ============================================================================
// STORAGE HOOKS
// ============================================================================

const useLocalStorage = <T,>(key: string, initialValue: T) => {
  const [storedValue, setStoredValue] = useState<T>(() => {
    try {
      const item = window.localStorage.getItem(key);
      return item ? JSON.parse(item) : initialValue;
    } catch (error) {
      console.error('Error reading from localStorage:', error);
      return initialValue;
    }
  });

  const setValue = (value: T | ((val: T) => T)) => {
    try {
      const valueToStore = value instanceof Function ? value(storedValue) : value;
      setStoredValue(valueToStore);
      window.localStorage.setItem(key, JSON.stringify(valueToStore));
    } catch (error) {
      console.error('Error saving to localStorage:', error);
    }
  };

  return [storedValue, setValue] as const;
};

const useEncryptedStorage = () => {
  const encrypt = async (text: string, password: string): Promise<{
    encrypted: string;
    iv: string;
    salt: string;
  }> => {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    const key = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      data
    );

    return {
      encrypted: Array.from(new Uint8Array(encrypted)).map(b => b.toString(16).padStart(2, '0')).join(''),
      iv: Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join(''),
      salt: Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('')
    };
  };

  const decrypt = async (encryptedData: {
    encrypted: string;
    iv: string;
    salt: string;
  }, password: string): Promise<string> => {
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    const encrypted = new Uint8Array(
      encryptedData.encrypted.match(/.{2}/g)!.map(byte => parseInt(byte, 16))
    );
    const iv = new Uint8Array(
      encryptedData.iv.match(/.{2}/g)!.map(byte => parseInt(byte, 16))
    );
    const salt = new Uint8Array(
      encryptedData.salt.match(/.{2}/g)!.map(byte => parseInt(byte, 16))
    );

    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    const key = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      encrypted
    );

    return decoder.decode(decrypted);
  };

  const storeEncrypted = async (key: string, data: any, userId: string) => {
    try {
      const encrypted = await encrypt(JSON.stringify(data), userId);
      localStorage.setItem(`cubid_${key}_${userId}`, JSON.stringify(encrypted));
    } catch (error) {
      console.error('Failed to store encrypted data:', error);
      throw error;
    }
  };

  const getEncrypted = async (key: string, userId: string) => {
    try {
      const stored = localStorage.getItem(`cubid_${key}_${userId}`);
      if (!stored) return null;

      const encrypted = JSON.parse(stored);
      const decrypted = await decrypt(encrypted, userId);
      return JSON.parse(decrypted);
    } catch (error) {
      console.error('Failed to retrieve encrypted data:', error);
      return null;
    }
  };

  return { storeEncrypted, getEncrypted };
};

// ============================================================================
// CRYPTO UTILITIES HOOKS
// ============================================================================

const useCryptoUtils = () => {
  const generatePrivateKey = (): string => {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return '0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  };

  const derivePublicAddress = (privateKey: string): string => {
    try {
      const account = privateKeyToAccount(privateKey as `0x${string}`);
      return account.address;
    } catch (error) {
      // Fallback to hash-based derivation if viem fails
      return deriveAddressFromHash(privateKey);
    }
  };

  const deriveAddressFromHash = async (privateKey: string): Promise<string> => {
    const msgBuffer = new TextEncoder().encode(privateKey);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return '0x' + hash.slice(0, 40);
  };

  return { generatePrivateKey, derivePublicAddress };
};

// ============================================================================
// WALLET CREATION HOOK
// ============================================================================

const useWalletCreation = () => {
  const [wallet, setWallet] = useState<InternalWallet | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isInitialized, setIsInitialized] = useState(false);

  const { generatePrivateKey, derivePublicAddress } = useCryptoUtils();
  const { storeEncrypted, getEncrypted } = useEncryptedStorage();
  const [webAuthn] = useState(() => new WebAuthnCrypto());

  // Load existing wallet with userId
  const loadExistingWallet = useCallback(async (userId: string) => {
    if (!userId || isInitialized) return;

    try {
      setIsLoading(true);
      const stored = await getEncrypted('wallet', userId);
      if (stored) {
        setWallet({
          address: stored.address,
          privateKey: stored.privateKey,
          created: true,
          verified: stored.verified || false
        });
      }
    } catch (error) {
      console.error('Failed to load existing wallet:', error);
      setError('Failed to load existing wallet');
    } finally {
      setIsLoading(false);
      setIsInitialized(true);
    }
  }, [getEncrypted, isInitialized]);

  const createWallet = async (userId: string): Promise<void> => {
    setIsLoading(true);
    setError(null);

    try {
      // Step 1: Generate WebAuthn credentials
      await webAuthn.generateKeyPair();

      // Step 2: Generate private key and derive address
      const privateKey = generatePrivateKey();
      const address = derivePublicAddress(privateKey);

      // Step 3: Create 1-of-2 Shamir shares
      const shamirResult = await webAuthn.generateShamirShares(privateKey, '1of2');

      // Step 4: Store user share locally (encrypted with WebAuthn)
      await webAuthn.encryptShamirShare(
        shamirResult.userShare,
        `userShare_${userId}`,
        '1of2'
      );

      // Step 5: Store app share in localStorage (encrypted)
      await storeEncrypted('appShare', shamirResult.appShare, userId);

      // Step 6: Store wallet metadata
      const walletData = {
        address,
        privateKey,
        verified: false,
        createdAt: Date.now(),
        scheme: '1of2'
      };

      await storeEncrypted('wallet', walletData, userId);

      // Step 7: Update state
      setWallet({
        address,
        privateKey,
        created: true,
        verified: false
      });

      console.log(`Internal wallet created for ${userId}: ${address}`);

    } catch (error) {
      console.error('Wallet creation failed:', error);
      setError(`Wallet creation failed: ${error?.message || 'Unknown error'}`);
      throw error;
    } finally {
      setIsLoading(false);
    }
  };

  const recoverWallet = async (userId: string): Promise<void> => {
    try {
      setIsLoading(true);

      // Get both shares
      const userShare = await webAuthn.decryptShamirShare(`userShare_${userId}`);
      const appShare = await getEncrypted('appShare', userId);

      if (!appShare) {
        throw new Error('App share not found');
      }

      // Reconstruct private key (1-of-2: either share works)
      const privateKey = await webAuthn.reconstructPrivateKey([userShare]);
      const address = derivePublicAddress(privateKey);

      setWallet({
        address,
        privateKey,
        created: true,
        verified: false // Would need to check verification status
      });

    } catch (error) {
      console.error('Wallet recovery failed:', error);
      setError(`Wallet recovery failed: ${error?.message || 'Unknown error'}`);
      throw error;
    } finally {
      setIsLoading(false);
    }
  };

  const clearError = () => setError(null);

  return {
    wallet,
    isLoading,
    error,
    isInitialized,
    createWallet,
    recoverWallet,
    loadExistingWallet,
    clearError
  };
};

// ============================================================================
// BALANCE HOOK
// ============================================================================

const useWalletBalance = (address?: string) => {
  const publicClient = usePublicClient();

  const { data: nativeBalance, isLoading: isNativeLoading, refetch: refetchNative } = useBalance({
    address: address as `0x${string}`,
    watch: true,
  });

  const { data: gDollarBalance, isLoading: isGDollarLoading, refetch: refetchGDollar } = useBalance({
    address: address as `0x${string}`,
    token: '0x62B8B11039FcfE5aB0C56E502b1C372A3d2a9c7A', // G$ token on Celo
    watch: true,
  });

  const formatBalance = (balance: bigint, decimals: number): string => {
    const formatted = formatUnits(balance, decimals);
    const num = parseFloat(formatted);

    if (num === 0) return '0';
    if (num < 0.001) return '<0.001';
    if (num < 1) return num.toFixed(3);
    if (num < 1000) return num.toFixed(2);
    if (num < 1000000) return `${(num / 1000).toFixed(1)}K`;
    return `${(num / 1000000).toFixed(1)}M`;
  };

  const getTokenBalance = (tokenAddress?: string) => {
    if (tokenAddress) {
      // For custom tokens, you'd need to implement custom balance fetching
      return { data: null, isLoading: false, refetch: () => { } };
    }
    return { data: gDollarBalance, isLoading: isGDollarLoading, refetch: refetchGDollar };
  };

  return {
    nativeBalance,
    gDollarBalance,
    isLoading: isNativeLoading || isGDollarLoading,
    formatBalance,
    getTokenBalance,
    refetch: () => {
      refetchNative();
      refetchGDollar();
    }
  };
};

// ============================================================================
// UBI CLAIM HOOK (Updated to use IdentitySDK directly)
// ============================================================================

const useUbiClaim = (wallet: InternalWallet | null, environment: string) => {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const publicClient = usePublicClient();

  // Helper function to create IdentitySDK instance
  const createIdentitySDK = useCallback(() => {
    if (!wallet || !publicClient) {
      return null;
    }

    try {
      // Create wallet client from private key
      const account = privateKeyToAccount(wallet.privateKey as `0x${string}`);
      const walletClient = createWalletClient({
        account,
        chain: celo,
        transport: viemHttp()
      });

      // Create IdentitySDK instance
      return new IdentitySDK(
        publicClient,
        walletClient,
        environment as 'production' | 'staging' | 'development'
      );
    } catch (error) {
      console.error('Failed to create IdentitySDK:', error);
      return null;
    }
  }, [wallet?.address, wallet?.privateKey, publicClient, environment]);

  const checkWalletState = useCallback(async () => {
    if (!wallet) {
      return {
        exists: false,
        isVerified: false,
        canClaim: false
      };
    }

    const identitySDK = createIdentitySDK();
    if (!identitySDK) {
      return {
        exists: true,
        address: wallet.address,
        isVerified: false,
        canClaim: false,
        error: 'Identity SDK not available'
      };
    }

    try {
      // Check if user is verified (whitelisted)
      const { isWhitelisted } = await identitySDK.getWhitelistedRoot(wallet.address as `0x${string}`);

      if (!isWhitelisted) {
        return {
          exists: true,
          address: wallet.address,
          isVerified: false,
          canClaim: false
        };
      }

      // Create wallet client for claiming
      const account = privateKeyToAccount(wallet.privateKey as `0x${string}`);
      const walletClient = createWalletClient({
        account,
        chain: celo,
        transport: viemHttp()
      });

      // Initialize claim SDK
      const claimSDK = await ClaimSDK.init({
        publicClient,
        walletClient,
        identitySDK,
        env: environment as any
      });

      const entitlement = await claimSDK.checkEntitlement();
      const claimAmount = Number(entitlement) / 1e18;

      if (entitlement === 0n) {
        const nextClaimTime = await claimSDK.nextClaimTime();
        return {
          exists: true,
          address: wallet.address,
          isVerified: true,
          canClaim: false,
          nextClaimTime
        };
      }

      return {
        exists: true,
        address: wallet.address,
        isVerified: true,
        canClaim: true,
        claimAmount: claimAmount.toFixed(2),
        claimSDK
      };

    } catch (error) {
      console.error('Wallet state check failed:', error);
      return {
        exists: !!wallet,
        isVerified: false,
        canClaim: false,
        error: error?.message || 'Unknown error'
      };
    }
  }, [wallet?.address, wallet?.privateKey, createIdentitySDK, publicClient, environment]);

  const startFaceVerification = useCallback(async () => {
    try {
      const identitySDK = createIdentitySDK();
      if (!identitySDK) {
        throw new Error('Identity SDK not initialized');
      }
      console.log({ identitySDK })
      const fvLink = await identitySDK.generateFVLink(
        false,
        window.location.href,
        42220
      );

      window.location.href = fvLink;

    } catch (error) {
      console.error('Face verification failed:', error);
      setError(error?.message || 'Face verification failed');
      throw error;
    }
  }, [createIdentitySDK]);

  const claimUbi = useCallback(async (claimSDK: any): Promise<{ amount: string; txHash: string }> => {
    setIsLoading(true);
    setError(null);

    try {
      const receipt = await claimSDK.claim();
      const amount = await claimSDK.checkEntitlement();
      const formattedAmount = (Number(amount) / 1e18).toFixed(2);

      return {
        amount: formattedAmount,
        txHash: receipt.transactionHash
      };

    } catch (error) {
      console.error('UBI claim failed:', error);
      setError(error?.message || 'UBI claim failed');
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const clearError = useCallback(() => setError(null), []);

  return useMemo(() => ({
    checkWalletState,
    startFaceVerification,
    claimUbi,
    isLoading,
    error,
    clearError
  }), [checkWalletState, startFaceVerification, claimUbi, isLoading, error, clearError]);
};

// ============================================================================
// WALLET CONTEXT
// ============================================================================

const WalletContext = createContext<WalletContextType | null>(null);

export const useWallet = () => {
  const context = useContext(WalletContext);
  if (!context) {
    throw new Error('useWallet must be used within a WalletProvider');
  }
  return context;
};

// ============================================================================
// WALLET PROVIDER COMPONENT
// ============================================================================

export const WalletProvider: React.FC<{
  config?: WalletProviderConfig;
  children: ReactNode;
}> = ({ config = {}, children }) => {
  const [queryClient] = useState(() => new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 30000,
        retry: 2,
        refetchOnWindowFocus: false,
      },
    },
  }));

  const [wagmiConfig] = useState(() => {
    const networks = config.networks || [celo, celoAlfajores, fuse, fuseSparknet];
    const transports = networks.reduce((acc, network) => {
      acc[network.id] = http();
      return acc;
    }, {} as Record<number, any>);

    return createConfig({
      chains: networks as any,
      transports,
    });
  });

  // Internal wallet management
  const walletCreation = useWalletCreation();

  const getBalance = (tokenAddress?: string) => {
    // This would be implemented to work with internal wallet
    return null;
  };

  const contextValue: WalletContextType = {
    wallet: walletCreation.wallet,
    isLoading: walletCreation.isLoading,
    error: walletCreation.error,
    isInitialized: walletCreation.isInitialized,
    createWallet: walletCreation.createWallet,
    loadExistingWallet: walletCreation.loadExistingWallet,
    getBalance,
    clearError: walletCreation.clearError,
  };

  return (
    <WagmiProvider config={wagmiConfig}>
      <QueryClientProvider client={queryClient}>
        <WalletContext.Provider value={contextValue}>
          {children}
        </WalletContext.Provider>
      </QueryClientProvider>
    </WagmiProvider>
  );
};

// ============================================================================
// BALANCE COMPONENTS
// ============================================================================

const BalanceDisplay: React.FC<{
  wallet: InternalWallet;
  showMultiToken?: boolean;
  customTokens?: Array<{
    address?: `0x${string}`;
    symbol: string;
    decimals: number;
    name: string;
  }>;
}> = ({ wallet, showMultiToken = false, customTokens }) => {
  const { nativeBalance, gDollarBalance, isLoading, formatBalance, refetch } = useWalletBalance(wallet.address);

  if (isLoading) {
    return (
      <div className="ui-balance-loading ui-bg-gray-50 ui-rounded-lg ui-p-4 ui-mb-4">
        <div className="ui-animate-pulse">
          <div className="ui-flex ui-justify-between ui-items-center ui-mb-2">
            <div className="ui-h-4 ui-bg-gray-300 ui-rounded ui-w-24"></div>
            <div className="ui-h-3 ui-bg-gray-300 ui-rounded ui-w-16"></div>
          </div>
          <div className="ui-h-6 ui-bg-gray-300 ui-rounded ui-w-32"></div>
        </div>
      </div>
    );
  }

  const defaultTokens = [
    {
      symbol: 'CELO',
      decimals: 18,
      name: 'Celo',
      balance: nativeBalance
    },
    {
      address: '0x62B8B11039FcfE5aB0C56E502b1C372A3d2a9c7A' as `0x${string}`,
      symbol: 'G$',
      decimals: 2,
      name: 'GoodDollar',
      balance: gDollarBalance
    },
  ];

  return (
    <div className="ui-balance-section ui-bg-gray-50 ui-rounded-lg ui-p-4 ui-mb-4">
      <div className="ui-flex ui-items-center ui-justify-between ui-mb-2">
        <h4 className="ui-text-sm ui-font-medium ui-text-gray-700">Your Balance</h4>
        <div className="ui-flex ui-items-center ui-text-xs ui-text-gray-500">
          <div className="ui-w-2 ui-h-2 ui-bg-green-400 ui-rounded-full ui-mr-1"></div>
          Internal Wallet
        </div>
      </div>

      {showMultiToken ? (
        <div className="ui-space-y-2">
          {defaultTokens.map((token, index) => (
            <div key={index} className="ui-flex ui-justify-between ui-items-center">
              <span className="ui-text-sm ui-text-gray-600">{token.name}:</span>
              <span className="ui-font-mono ui-font-semibold">
                {token.balance ? formatBalance(token.balance.value, token.balance.decimals) : '0'} {token.symbol}
              </span>
            </div>
          ))}
        </div>
      ) : (
        <div className="ui-text-right">
          <span className="ui-text-lg ui-font-mono ui-font-semibold">
            {gDollarBalance ? formatBalance(gDollarBalance.value, gDollarBalance.decimals) : '0'} G$
          </span>
        </div>
      )}

      <button
        onClick={refetch}
        className="ui-mt-2 ui-text-xs ui-text-blue-600 hover:ui-text-blue-800"
      >
        Refresh
      </button>
    </div>
  );
};

// ============================================================================
// ERROR BOUNDARY COMPONENT
// ============================================================================

class ErrorBoundary extends React.Component<
  { children: ReactNode; fallback?: ReactNode },
  { hasError: boolean; error?: Error }
> {
  constructor(props: { children: ReactNode; fallback?: ReactNode }) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: any) {
    console.error('ErrorBoundary caught an error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return this.props.fallback || (
        <div className="ui-p-4 ui-bg-red-50 ui-border ui-border-red-200 ui-rounded-lg">
          <h3 className="ui-text-lg ui-font-semibold ui-text-red-800 ui-mb-2">Something went wrong</h3>
          <p className="ui-text-red-600 ui-mb-4">
            {this.state.error?.message || 'An unexpected error occurred'}
          </p>
          <button
            onClick={() => this.setState({ hasError: false, error: undefined })}
            className="ui-px-4 ui-py-2 ui-bg-red-600 ui-text-white ui-rounded hover:ui-bg-red-700"
          >
            Try Again
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

// ============================================================================
// MAIN CITIZENUBI COMPONENT
// ============================================================================

export const CitizenUbi: React.FC<CitizenUbiProps> = ({
  email,
  phone,
  environment = 'production',
  className = '',
  theme = 'light',
  showBalance = true,
  showMultiTokenBalance = false,
  customTokens,
  onWalletCreated,
  onVerificationComplete,
  onClaimSuccess,
  onError
}) => {
  const userIdentifier = email || phone;

  if (!userIdentifier) {
    console.error('CitizenUbi: Either email or phone must be provided');
    return (
      <div className="ui-p-4 ui-bg-red-50 ui-border ui-border-red-200 ui-rounded-lg">
        <p className="ui-text-red-800">Error: Email or phone number required</p>
      </div>
    );
  }

  const {
    wallet,
    isLoading: walletLoading,
    error: walletError,
    isInitialized,
    createWallet,
    loadExistingWallet,
    clearError
  } = useWallet();

  const ubiClaim = useUbiClaim(wallet, environment);
  const [uiState, setUiState] = useState<any>({ type: 'loading' });
  const [isActionLoading, setIsActionLoading] = useState(false);

  // Initialize wallet loading
  useEffect(() => {
    if (!isInitialized && userIdentifier) {
      loadExistingWallet(userIdentifier);
    }
  }, [isInitialized, userIdentifier, loadExistingWallet]);

  // Determine current state with proper UBI functionality
  const determineState = useCallback(async () => {
    try {
      if (!isInitialized) {
        setUiState({ type: 'loading' });
        return;
      }

      if (!wallet) {
        setUiState({ type: 'create-wallet' });
        return;
      }

      // Check actual wallet state for UBI functionality
      const walletState = await ubiClaim.checkWalletState();

      if (walletState.error) {
        setUiState({
          type: 'error',
          message: walletState.error
        });
        return;
      }

      if (!walletState.isVerified) {
        setUiState({ type: 'verify' });
      } else if (walletState.canClaim) {
        setUiState({
          type: 'claim',
          data: {
            claimAmount: walletState.claimAmount,
            claimSDK: walletState.claimSDK
          }
        });
      } else {
        setUiState({
          type: 'timer',
          data: { nextClaimTime: walletState.nextClaimTime }
        });
      }

    } catch (error) {
      console.error('State determination error:', error);
      setUiState({
        type: 'error',
        message: error?.message || 'Unable to determine app state'
      });

      if (onError) {
        onError(error?.message || 'Unable to determine app state');
      }
    }
  }, [wallet?.address, wallet?.privateKey, isInitialized, ubiClaim.checkWalletState, onError]);

  useEffect(() => {
    determineState();
  }, [determineState]);

  // Event handlers
  const handleCreateWallet = useCallback(async () => {
    setIsActionLoading(true);
    clearError();

    try {
      await createWallet(userIdentifier);

      // The wallet should now be created, determineState will be called by useEffect
      // when wallet state changes, but let's also trigger onWalletCreated callback

    } catch (error) {
      setUiState({
        type: 'error',
        message: error?.message || 'Failed to create wallet'
      });

      if (onError) {
        onError(error?.message || 'Failed to create wallet');
      }
    } finally {
      setIsActionLoading(false);
    }
  }, [createWallet, userIdentifier, clearError, onError]);

  // Trigger callback when wallet is created
  useEffect(() => {
    if (wallet && onWalletCreated) {
      onWalletCreated(wallet.address);
    }
  }, [wallet?.address, onWalletCreated]);
  console.log({ ubiClaim })
  const handleVerify = useCallback(async () => {
    setIsActionLoading(true);
    try {
      await ubiClaim.startFaceVerification();

      if (onVerificationComplete) {
        onVerificationComplete();
      }

    } catch (error) {
      setUiState({
        type: 'error',
        message: error?.message || 'Verification failed'
      });

      if (onError) {
        onError(error?.message || 'Verification failed');
      }
    } finally {
      setIsActionLoading(false);
    }
  }, [ubiClaim.startFaceVerification, onVerificationComplete, onError]);

  const handleClaim = useCallback(async () => {
    setIsActionLoading(true);
    try {
      const result = await ubiClaim.claimUbi(uiState.data?.claimSDK);

      if (onClaimSuccess) {
        onClaimSuccess(result.amount, result.txHash);
      }

      await determineState();
    } catch (error) {
      setUiState({
        type: 'error',
        message: error?.message || 'Claim failed'
      });

      if (onError) {
        onError(error?.message || 'Claim failed');
      }
    } finally {
      setIsActionLoading(false);
    }
  }, [ubiClaim.claimUbi, uiState.data?.claimSDK, onClaimSuccess, onError, determineState]);

  const handleClearError = useCallback(() => {
    clearError();
    ubiClaim.clearError();
    determineState();
  }, [clearError, ubiClaim.clearError, determineState]);

  // UI Components
  const Button: React.FC<{
    onClick?: () => void;
    disabled?: boolean;
    variant?: 'primary' | 'secondary';
    children: React.ReactNode;
    className?: string;
  }> = ({ onClick, disabled, variant = 'primary', children, className = '' }) => {
    const baseClass = 'ui-px-6 ui-py-3 ui-rounded-lg ui-font-medium ui-transition-all ui-duration-200 disabled:ui-opacity-50 disabled:ui-cursor-not-allowed';
    const variants = {
      primary: 'ui-bg-blue-600 hover:ui-bg-blue-700 ui-text-white ui-shadow-lg hover:ui-shadow-xl',
      secondary: 'ui-bg-gray-200 hover:ui-bg-gray-300 ui-text-gray-800'
    };

    return (
      <button
        onClick={onClick}
        disabled={disabled}
        className={`${baseClass} ${variants[variant]} ${className}`}
      >
        {children}
      </button>
    );
  };

  const LoadingSpinner = () => (
    <div className="ui-flex ui-items-center ui-justify-center">
      <div className="ui-animate-spin ui-rounded-full ui-h-6 ui-w-6 ui-border-b-2 ui-border-current"></div>
    </div>
  );

  // Main content rendering
  const renderMainContent = () => {
    const isLoading = walletLoading || isActionLoading;
    const currentError = walletError || ubiClaim.error;

    if (currentError) {
      return (
        <div className="ui-text-center ui-space-y-4">
          <div className="ui-w-16 ui-h-16 ui-bg-red-100 ui-rounded-full ui-flex ui-items-center ui-justify-center ui-mx-auto">
            <svg className="ui-w-8 ui-h-8 ui-text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
            </svg>
          </div>
          <h3 className="ui-text-xl ui-font-semibold ui-text-red-600">Something went wrong</h3>
          <p className="ui-text-gray-600">{currentError}</p>
          <Button onClick={handleClearError} variant="secondary">
            Try Again
          </Button>
        </div>
      );
    }

    switch (uiState.type) {
      case 'loading':
        return (
          <div className="ui-text-center ui-py-8">
            <LoadingSpinner />
            <p className="ui-mt-4 ui-text-gray-600">Initializing...</p>
          </div>
        );

      case 'create-wallet':
        return (
          <div className="ui-text-center ui-space-y-4">
            <div className="ui-mb-6">
              <div className="ui-w-16 ui-h-16 ui-bg-blue-100 ui-rounded-full ui-flex ui-items-center ui-justify-center ui-mx-auto ui-mb-4">
                <svg className="ui-w-8 ui-h-8 ui-text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <h3 className="ui-text-xl ui-font-semibold ui-text-gray-900">Create Your Secure Wallet</h3>
              <p className="ui-text-gray-600 ui-mt-2">
                We'll create a secure internal wallet for <strong>{userIdentifier}</strong>
              </p>
            </div>

            <div className="ui-bg-blue-50 ui-p-4 ui-rounded-lg">
              <div className="ui-flex ui-items-start">
                <svg className="ui-w-5 ui-h-5 ui-text-blue-500 ui-mt-0.5 ui-mr-3" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                </svg>
                <div className="ui-text-left">
                  <p className="ui-text-sm ui-font-medium ui-text-blue-800">Internal Wallet Creation</p>
                  <p className="ui-text-sm ui-text-blue-600 ui-mt-1">
                    Your wallet is created internally with 1-of-2 Shamir sharing and biometric protection.
                  </p>
                </div>
              </div>
            </div>

            <Button onClick={handleCreateWallet} disabled={isLoading} className="ui-w-full">
              {isLoading ? (
                <div className="ui-flex ui-items-center ui-justify-center">
                  <LoadingSpinner />
                  <span className="ui-ml-2">Creating Internal Wallet...</span>
                </div>
              ) : (
                'Create Internal Wallet'
              )}
            </Button>
          </div>
        );

      case 'verify':
        return (
          <div className="ui-text-center ui-space-y-4">
            {showBalance && wallet && (
              <BalanceDisplay
                wallet={wallet}
                showMultiToken={showMultiTokenBalance}
                customTokens={customTokens}
              />
            )}
            <div className="ui-mb-6">
              <div className="ui-w-16 ui-h-16 ui-bg-green-100 ui-rounded-full ui-flex ui-items-center ui-justify-center ui-mx-auto ui-mb-4">
                <svg className="ui-w-8 ui-h-8 ui-text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <h3 className="ui-text-xl ui-font-semibold ui-text-gray-900">Verify Your Identity</h3>
              <p className="ui-text-gray-600 ui-mt-2">
                Complete face verification to start claiming your daily UBI
              </p>
            </div>

            <div className="ui-bg-green-50 ui-p-4 ui-rounded-lg">
              <div className="ui-flex ui-items-start">
                <svg className="ui-w-5 ui-h-5 ui-text-green-500 ui-mt-0.5 ui-mr-3" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                </svg>
                <div className="ui-text-left">
                  <p className="ui-text-sm ui-font-medium ui-text-green-800">Secure Verification Process</p>
                  <p className="ui-text-sm ui-text-green-600 ui-mt-1">
                    Your identity verification ensures secure UBI claiming and prevents fraud.
                  </p>
                </div>
              </div>
            </div>

            <Button onClick={handleVerify} disabled={isLoading} className="ui-w-full">
              {isLoading ? (
                <div className="ui-flex ui-items-center ui-justify-center">
                  <LoadingSpinner />
                  <span className="ui-ml-2">Redirecting to verification...</span>
                </div>
              ) : (
                'Verify My Identity'
              )}
            </Button>
          </div>
        );

      case 'claim':
        return (
          <div className="ui-text-center ui-space-y-4">
            {showBalance && wallet && (
              <BalanceDisplay
                wallet={wallet}
                showMultiToken={showMultiTokenBalance}
                customTokens={customTokens}
              />
            )}
            <div className="ui-mb-6">
              <div className="ui-w-16 ui-h-16 ui-bg-yellow-100 ui-rounded-full ui-flex ui-items-center ui-justify-center ui-mx-auto ui-mb-4">
                <svg className="ui-w-8 ui-h-8 ui-text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1" />
                </svg>
              </div>
              <h3 className="ui-text-xl ui-font-semibold ui-text-gray-900">Claim Your UBI</h3>
              <p className="ui-text-gray-600 ui-mt-2">
                Your daily Universal Basic Income is ready to claim
              </p>
            </div>

            <div className="ui-bg-yellow-50 ui-p-6 ui-rounded-lg">
              <div className="ui-text-center">
                <p className="ui-text-sm ui-text-yellow-700 ui-mb-2">Available to claim today:</p>
                <p className="ui-text-3xl ui-font-bold ui-text-yellow-800">{uiState.data?.claimAmount} G$</p>
              </div>
            </div>

            <Button onClick={handleClaim} disabled={isLoading} className="ui-w-full">
              {isLoading ? (
                <div className="ui-flex ui-items-center ui-justify-center">
                  <LoadingSpinner />
                  <span className="ui-ml-2">Claiming...</span>
                </div>
              ) : (
                `Claim ${uiState.data?.claimAmount} G$`
              )}
            </Button>
          </div>
        );

      case 'timer':
        const TimerView = () => {
          const [timeLeft, setTimeLeft] = useState<string>('');

          useEffect(() => {
            const updateTimer = () => {
              const now = new Date();
              const diff = uiState.data?.nextClaimTime?.getTime() - now.getTime();

              if (diff <= 0) {
                setTimeLeft('Ready to claim!');
                return;
              }

              const hours = Math.floor(diff / (1000 * 60 * 60));
              const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));

              setTimeLeft(`${hours}h ${minutes}m`);
            };

            updateTimer();
            const interval = setInterval(updateTimer, 60000);
            return () => clearInterval(interval);
          }, []);

          return (
            <div className="ui-text-center ui-space-y-4">
              {showBalance && wallet && (
                <BalanceDisplay
                  wallet={wallet}
                  showMultiToken={showMultiTokenBalance}
                  customTokens={customTokens}
                />
              )}
              <div className="ui-mb-6">
                <div className="ui-w-16 ui-h-16 ui-bg-gray-100 ui-rounded-full ui-flex ui-items-center ui-justify-center ui-mx-auto ui-mb-4">
                  <svg className="ui-w-8 ui-h-8 ui-text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <h3 className="ui-text-xl ui-font-semibold ui-text-gray-900">Already Claimed Today!</h3>
                <p className="ui-text-gray-600 ui-mt-2">
                  You've successfully claimed your UBI for today
                </p>
              </div>

              <div className="ui-bg-gray-50 ui-p-6 ui-rounded-lg">
                <div className="ui-text-center">
                  <p className="ui-text-sm ui-text-gray-600 ui-mb-2">Next claim available in:</p>
                  <p className="ui-text-2xl ui-font-bold ui-text-gray-800">{timeLeft}</p>
                </div>
              </div>

              <Button disabled variant="secondary" className="ui-w-full">
                Come back tomorrow for more UBI!
              </Button>
            </div>
          );
        };

        return <TimerView />;

      default:
        return <div>Unknown state</div>;
    }
  };

  const themeClasses = theme === 'dark'
    ? 'ui-bg-gray-900 ui-text-white'
    : 'ui-bg-white ui-text-gray-900';

  return (
    <div className="ui">
      <ErrorBoundary>
        <div className={`ui-citizen-ubi-internal ${themeClasses} ${className}`}>
          <div className="ui-max-w-md ui-mx-auto ui-p-6 ui-rounded-lg ui-shadow-lg">
            {renderMainContent()}

            {/* Manage Account Link */}
            <div className="ui-mt-6 ui-text-center">
              <button
                type="button"
                className="ui-text-blue-600 hover:ui-text-blue-800 ui-text-sm ui-underline ui-transition-colors"
                onClick={() => window.open('https://cubid.me/manage', '_blank')}
              >
                Manage / Recover Account
              </button>
            </div>
          </div>
        </div>
      </ErrorBoundary>
    </div>
  );
};

CitizenUbi.displayName = 'CitizenUbi';

export default CitizenUbi;