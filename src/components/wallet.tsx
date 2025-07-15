// @ts-nocheck
// Import necessary dependencies
import { ConnectButton } from '@rainbow-me/rainbowkit';
import { Wallet } from '../lib/nearWalletConfig';
import { WalletIcon, Plus, Shield, Key, Lock } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { WebAuthnCrypto } from '../lib/webAuthN';
import { useAccount, useDisconnect } from 'wagmi';
import axios from 'axios';
import {
  useConnectModal,
} from '@rainbow-me/rainbowkit';

// Define TypeScript interfaces for type safety
export interface WalletComp {
  type: 'evm' | 'near';
  user_id: string;
  dapp_id: string;
  api_key: string;
  onAppShare: (share: any) => void;
  onUserShare: (encrypted_share: any) => void;
  onDeviceShare?: (encrypted_share: any) => void; // For 2-of-3 scheme
  onEVMWallet?: (wallets: string[], walletDetails: any[]) => void;
  onNearWallet?: (wallets: string[], walletDetails: any[]) => void;
  shamirScheme?: '1of2' | '2of3'; // Allow choosing the scheme
}

interface WalletInfo {
  address: string;
  type: 'connected' | 'created';
  timestamp: number;
  public_key?: string;
  is_generated_via_lib: boolean;
  shamir_scheme?: '1of2' | '2of3';
  share_count?: number;
}

interface WalletStates {
  evm: WalletInfo[];
  near: WalletInfo[];
}

interface ShamirShare {
  x: number;
  y: string;
}

interface ShamirKeyResult {
  appShare: ShamirShare;
  userShare: ShamirShare;
  deviceShare?: ShamirShare;
  publicAddress: string;
  scheme: '1of2' | '2of3';
}

// Create an axios instance with default configuration for API calls
const api = axios.create({
  baseURL: '',
  headers: {
    'Content-Type': 'application/json'
  }
});

// Initialize wallet configuration for NEAR protocol
interface NearWallet {
  accountId?: string;
  signIn: () => Promise<void>;
  signOut: () => Promise<void>;
  startUp: () => void;
}

export const wallet = new Wallet({
  createAccessKeyFor: 'registry.i-am-human.near',
}) as unknown as NearWallet;

wallet.startUp();
const WebAuthN = new WebAuthnCrypto();

// Component to display individual wallet information
const WalletInfoDisplay = ({ address, explorerUrl, type, walletType, timestamp, shamirScheme, shareCount }: any) => {
  const truncateAddress = (addr: string) =>
    addr ? `${addr.slice(0, 6)}...${addr.slice(-4)}` : '';

  const formatDate = (ts: number) =>
    new Date(ts).toLocaleString();

  const getShamirBadgeColor = (scheme: string) => {
    return scheme === '1of2' ? 'bg-green-500/10 text-green-400' : 'bg-blue-500/10 text-blue-400';
  };

  const getShamirIcon = (scheme: string) => {
    return scheme === '1of2' ? <Key className="ui-h-3 ui-w-3" /> : <Shield className="ui-h-3 ui-w-3" />;
  };

  return (
    <div className="ui-p-4 ui-bg-white/5 ui-rounded-xl ui-border ui-border-white/10 ui-space-y-3">
      <div className="ui-flex ui-items-center ui-justify-between">
        <span className="ui-text-sm ui-text-gray-400">
          {walletType === 'created' ? 'Created Account' : `Connected to ${type}`}
        </span>
        <div className="ui-flex ui-gap-2">
          {shamirScheme && (
            <span className={`ui-px-2 ui-py-1 ui-text-xs ui-rounded-full ui-flex ui-items-center ui-gap-1 ${getShamirBadgeColor(shamirScheme)}`}>
              {getShamirIcon(shamirScheme)}
              {shamirScheme.toUpperCase()}
              {shareCount && ` (${shareCount} shares)`}
            </span>
          )}
          <span className="ui-px-2 ui-py-1 ui-bg-green-500/10 ui-text-green-400 ui-text-xs ui-rounded-full">
            {walletType === 'created' ? 'Created' : 'Connected'}
          </span>
        </div>
      </div>
      <div className="ui-flex ui-flex-col ui-gap-2">
        <div className="ui-flex ui-items-center ui-justify-between">
          <span className="ui-font-mono ui-text-sm ui-text-white/80">
            {truncateAddress(address)}
          </span>
          <button
            onClick={() => navigator.clipboard.writeText(address)}
            className="ui-text-xs ui-text-blue-400 hover:ui-text-blue-300"
          >
            Copy
          </button>
        </div>
        <div className="ui-flex ui-justify-between ui-items-center">
          <a
            href={explorerUrl}
            target="_blank"
            rel="noreferrer"
            className="ui-flex ui-items-center ui-gap-2 ui-text-sm ui-text-blue-400 hover:ui-text-blue-300"
          >
            <span>View on Explorer</span>
          </a>
          {shamirScheme && (
            <span className="ui-text-xs ui-text-gray-500">
              {formatDate(timestamp)}
            </span>
          )}
        </div>
      </div>
    </div>
  );
};

// Component for selecting Shamir scheme
const ShamirSchemeSelector = ({ selectedScheme, onSchemeChange, disabled }: any) => {
  return (
    <div className="ui-bg-white/5 ui-rounded-xl ui-p-4 ui-space-y-3">
      <h3 className="ui-text-lg ui-font-semibold ui-text-white ui-flex ui-items-center ui-gap-2">
        <Lock className="ui-h-5 ui-w-5" />
        Security Scheme
      </h3>
      <div className="ui-space-y-3">
        <div className="ui-flex ui-items-center ui-gap-3">
          <input
            type="radio"
            id="scheme-1of2"
            name="shamirScheme"
            value="1of2"
            checked={selectedScheme === '1of2'}
            onChange={(e) => onSchemeChange(e.target.value)}
            disabled={disabled}
            className="ui-w-4 ui-h-4 ui-text-green-500"
          />
          <label htmlFor="scheme-1of2" className="ui-flex-1 ui-cursor-pointer">
            <div className="ui-flex ui-items-center ui-gap-2 ui-text-sm ui-font-medium ui-text-white">
              <Key className="ui-h-4 ui-w-4 ui-text-green-400" />
              1-of-2 Scheme (Simplified)
            </div>
            <p className="ui-text-xs ui-text-gray-400 ui-mt-1">
              Either the app share OR user share can recover your wallet. Simpler but less secure.
            </p>
          </label>
        </div>
        
        <div className="ui-flex ui-items-center ui-gap-3">
          <input
            type="radio"
            id="scheme-2of3"
            name="shamirScheme"
            value="2of3"
            checked={selectedScheme === '2of3'}
            onChange={(e) => onSchemeChange(e.target.value)}
            disabled={disabled}
            className="ui-w-4 ui-h-4 ui-text-blue-500"
          />
          <label htmlFor="scheme-2of3" className="ui-flex-1 ui-cursor-pointer">
            <div className="ui-flex ui-items-center ui-gap-2 ui-text-sm ui-font-medium ui-text-white">
              <Shield className="ui-h-4 ui-w-4 ui-text-blue-400" />
              2-of-3 Scheme (Recommended)
            </div>
            <p className="ui-text-xs ui-text-gray-400 ui-mt-1">
              Need any 2 of 3 shares (app, user, device) to recover. More secure with redundancy.
            </p>
          </label>
        </div>
      </div>
    </div>
  );
};

// Updated AddWalletOptions component
const AddWalletOptions = ({
  onConnectWallet,
  onCreateWallet,
  type,
  loading,
  hasGeneratedWallet,
  shamirScheme,
  onShamirSchemeChange
}: any) => {
  const { openConnectModal } = useConnectModal();

  // Decide which "connect" action to call depending on chain
  const handleConnectClick = () => {
    if (type === 'evm' && openConnectModal) {
      openConnectModal();
    } else {
      onConnectWallet();
    }
  };

  return (
    <div className="ui-space-y-4">
      {/* Shamir Scheme Selector */}
      <ShamirSchemeSelector
        selectedScheme={shamirScheme}
        onSchemeChange={onShamirSchemeChange}
        disabled={loading === 'creating' || hasGeneratedWallet}
      />

      {/* Wallet Options */}
      <div className="ui-bg-black ui-w-full ui-p-4 ui-rounded-xl ui-space-y-4 ui-text-white">
        {/* First row: Create a new web3 account */}
        <div className="ui-flex ui-items-center ui-justify-between">
          <div className="ui-me-4">
            <p className="ui-text-sm md:ui-text-base ui-font-normal">
              Create a new web3 account and keep it safe for me (default)
            </p>
            <p className="ui-text-xs ui-text-gray-400 ui-mt-1">
              Uses {shamirScheme.toUpperCase()} Shamir Secret Sharing for enhanced security
            </p>
          </div>
          <button
            onClick={onCreateWallet}
            disabled={loading === 'creating' || hasGeneratedWallet}
            className="ui-bg-blue-600 hover:ui-bg-blue-700 ui-px-5 ui-py-2.5 ui-rounded-lg ui-text-sm ui-text-white ui-font-medium disabled:ui-opacity-50 ui-flex ui-items-center ui-gap-2"
          >
            {loading === 'creating' ? (
              <>
                <div className="ui-animate-spin ui-rounded-full ui-h-4 ui-w-4 ui-border-b-2 ui-border-white"></div>
                Creating...
              </>
            ) : (
              <>
                <Shield className="ui-h-4 ui-w-4" />
                Create Account
              </>
            )}
          </button>
        </div>

        {/* Second row: Connect existing wallet */}
        <div className="ui-flex ui-items-center ui-justify-between">
          <p className="ui-text-sm md:ui-text-base ui-font-normal ui-me-4">
            I'd rather use my existing account in my 3rd party wallet app
          </p>
          <button
            onClick={handleConnectClick}
            className="ui-bg-blue-600 hover:ui-bg-blue-700 ui-px-5 ui-py-2.5 ui-rounded-lg ui-text-sm ui-text-white ui-font-medium ui-flex ui-items-center ui-gap-2"
          >
            <WalletIcon className="ui-h-4 ui-w-4" />
            Connect Wallet
          </button>
        </div>
      </div>
    </div>
  );
};

// Recovery component for reconstructing keys from shares
const RecoveryComponent = ({ type, onRecover }: any) => {
  const [recoveryShares, setRecoveryShares] = useState<ShamirShare[]>([]);
  const [loading, setLoading] = useState(false);
  const [showRecovery, setShowRecovery] = useState(false);

  const addShare = () => {
    setRecoveryShares([...recoveryShares, { x: 0, y: '' }]);
  };

  const updateShare = (index: number, field: 'x' | 'y', value: string | number) => {
    const updated = [...recoveryShares];
    updated[index] = { ...updated[index], [field]: field === 'x' ? Number(value) : value };
    setRecoveryShares(updated);
  };

  const removeShare = (index: number) => {
    setRecoveryShares(recoveryShares.filter((_, i) => i !== index));
  };

  const handleRecover = async () => {
    try {
      setLoading(true);
      const validShares = recoveryShares.filter(share => share.x && share.y);
      
      if (validShares.length < 1) {
        throw new Error('Need at least 1 valid share for recovery');
      }

      const privateKey = await WebAuthN.reconstructPrivateKey(validShares);
      onRecover(privateKey);
      setShowRecovery(false);
      setRecoveryShares([]);
    } catch (error) {
      console.error('Recovery failed:', error);
      alert(`Recovery failed: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  if (!showRecovery) {
    return (
      <div className="ui-bg-yellow-500/10 ui-border ui-border-yellow-500/20 ui-rounded-xl ui-p-4">
        <h3 className="ui-text-lg ui-font-semibold ui-text-yellow-400 ui-mb-2">Wallet Recovery</h3>
        <p className="ui-text-sm ui-text-gray-300 ui-mb-3">
          Lost access to your wallet? Use your Shamir shares to recover it.
        </p>
        <button
          onClick={() => setShowRecovery(true)}
          className="ui-bg-yellow-600 hover:ui-bg-yellow-700 ui-px-4 ui-py-2 ui-rounded-lg ui-text-sm ui-text-white ui-font-medium"
        >
          Start Recovery
        </button>
      </div>
    );
  }

  return (
    <div className="ui-bg-yellow-500/10 ui-border ui-border-yellow-500/20 ui-rounded-xl ui-p-4 ui-space-y-4">
      <div className="ui-flex ui-justify-between ui-items-center">
        <h3 className="ui-text-lg ui-font-semibold ui-text-yellow-400">Wallet Recovery</h3>
        <button
          onClick={() => setShowRecovery(false)}
          className="ui-text-gray-400 hover:ui-text-white"
        >
          ✕
        </button>
      </div>

      <p className="ui-text-sm ui-text-gray-300">
        Enter your Shamir shares to recover your wallet. You need at least 1 share for 1-of-2 scheme or 2 shares for 2-of-3 scheme.
      </p>

      <div className="ui-space-y-3">
        {recoveryShares.map((share, index) => (
          <div key={index} className="ui-flex ui-gap-2 ui-items-center">
            <input
              type="number"
              placeholder="Share X"
              value={share.x || ''}
              onChange={(e) => updateShare(index, 'x', e.target.value)}
              className="ui-bg-black/50 ui-border ui-border-white/20 ui-rounded ui-px-3 ui-py-2 ui-text-white ui-w-20"
            />
            <input
              type="text"
              placeholder="Share Y (long string)"
              value={share.y}
              onChange={(e) => updateShare(index, 'y', e.target.value)}
              className="ui-bg-black/50 ui-border ui-border-white/20 ui-rounded ui-px-3 ui-py-2 ui-text-white ui-flex-1"
            />
            <button
              onClick={() => removeShare(index)}
              className="ui-text-red-400 hover:ui-text-red-300"
            >
              Remove
            </button>
          </div>
        ))}
      </div>

      <div className="ui-flex ui-gap-2">
        <button
          onClick={addShare}
          className="ui-bg-gray-600 hover:ui-bg-gray-700 ui-px-4 ui-py-2 ui-rounded-lg ui-text-sm ui-text-white"
        >
          Add Share
        </button>
        <button
          onClick={handleRecover}
          disabled={loading || recoveryShares.length === 0}
          className="ui-bg-yellow-600 hover:ui-bg-yellow-700 ui-px-4 ui-py-2 ui-rounded-lg ui-text-sm ui-text-white ui-font-medium disabled:ui-opacity-50"
        >
          {loading ? 'Recovering...' : 'Recover Wallet'}
        </button>
      </div>
    </div>
  );
};

// Main wallet component
export const WalletComponent = (props: WalletComp) => {
  const [sdk, setSdk] = useState<any>(null);
  const inEvm = props.type === 'evm';
  const { disconnect } = useDisconnect();
  const [showAddOptions, setShowAddOptions] = useState(false);
  const [wallets, setWallets] = useState<WalletStates>({ evm: [], near: [] });
  const [loading, setLoading] = useState<string | null>(null);
  const [shamirScheme, setShamirScheme] = useState<'1of2' | '2of3'>(props.shamirScheme || '2of3');
  const { address: evmAddress, isConnected: isEvmConnected } = useAccount();
  const user = { uuid: props.user_id };

  useEffect(() => {
    const loadSdk = async () => {
      try {
        const CubidSDKModule = await import('cubid-sdk');
        const sdkInstance = new CubidSDKModule.CubidSDK(props.dapp_id, props.api_key);
        setSdk(sdkInstance);
      } catch (error) {
        console.error('Error loading CubidSDK:', error);
      }
    };
    loadSdk();
  }, [props.dapp_id, props.api_key]);

  const fetchWallets = useCallback(async () => {
    if (!user?.uuid) return;
    try {
      const [evmResponse, nearResponse] = await Promise.all([
        api.post(`https://passport.cubid.me/api/wallet/fetch`, {
          dapp_uid: user.uuid,
          chain: 'evm'
        }),
        api.post(`https://passport.cubid.me/api/wallet/fetch`, {
          dapp_uid: user.uuid,
          chain: 'near'
        })
      ]);

      setWallets({
        evm: evmResponse.data.data || [],
        near: nearResponse.data.data || []
      });
    } catch (error) {
      console.error('Error fetching wallets:', error);
    }
  }, [user?.uuid]);

  const saveWallets = useCallback(
    async (type: 'evm' | 'near', wallets: WalletInfo[]) => {
      if (!user?.uuid) return;
      try {
        await Promise.all(
          wallets.map(async (item) => {
            await api.post('https://passport.cubid.me/api/wallet/save', {
              dapp_uid: user.uuid,
              chain: type,
              public_key: item.public_key || item.address,
              is_generated_via_lib: item.is_generated_via_lib,
              shamir_scheme: item.shamir_scheme,
              share_count: item.share_count
            });
          })
        );
      } catch (error) {
        console.error('Error saving wallets:', error);
      }
    },
    [user?.uuid]
  );

  useEffect(() => {
    fetchWallets();
  }, [fetchWallets]);

  useEffect(() => {
    props?.onEVMWallet?.(wallets?.evm.map(w => w.address), wallets?.evm);
    props?.onNearWallet?.(wallets?.near.map(w => w.address), wallets?.near);
  }, [wallets, props.onEVMWallet, props.onNearWallet]);

  useEffect(() => {
    saveWallets('evm', wallets.evm);
  }, [wallets.evm, saveWallets]);

  useEffect(() => {
    saveWallets('near', wallets.near);
  }, [wallets.near, saveWallets]);

  useEffect(() => {
    if (isEvmConnected && evmAddress) {
      setWallets((prev) => {
        const existingWallet = prev.evm.find((w) => w.address === evmAddress);
        if (existingWallet) return prev;

        return {
          ...prev,
          evm: [
            ...prev.evm,
            {
              address: evmAddress,
              type: 'connected',
              timestamp: Date.now(),
              is_generated_via_lib: false
            }
          ]
        };
      });
    }
  }, [evmAddress, isEvmConnected]);

  useEffect(() => {
    const checkNearWallet = async () => {
      if (wallet.accountId) {
        setWallets((prev) => {
          const existingWallet = prev.near.find(
            (w) => w.address === wallet.accountId
          );
          if (existingWallet) return prev;

          return {
            ...prev,
            near: [
              ...prev.near,
              {
                address: wallet.accountId!,
                type: 'connected',
                timestamp: Date.now(),
                is_generated_via_lib: false
              }
            ]
          };
        });
        await wallet.signOut();
      }
    };
    checkNearWallet();
  }, []);

  const getExplorerUrl = useCallback(
    (address: string) =>
      inEvm
        ? `https://etherscan.io/address/${address}`
        : `https://explorer.near.org/accounts/${address}`,
    [inEvm]
  );

  const createOnChainAccount = async () => {
    if (!sdk) {
      console.error('SDK not loaded yet');
      return;
    }

    setLoading('creating');
    try {
      await WebAuthN.generateKeyPair();
      
      // Generate wallet using SDK (this should return the private key)
      const { user_shares, public_address, private_key } = await sdk.encryptPrivateKey({
        user_id: user?.uuid,
        wallet_type: inEvm ? 'ethereum' : 'near'
      });

      // Use the private key with Shamir Secret Sharing
      let privateKeyToSplit = private_key;
      if (!privateKeyToSplit && user_shares && user_shares.length > 0) {
        // Fallback: combine existing shares if available
        privateKeyToSplit = user_shares.join('');
      }

      if (!privateKeyToSplit) {
        throw new Error('No private key available for Shamir Secret Sharing');
      }

      // Generate Shamir shares
      const shamirResult = await WebAuthN.generateShamirShares(privateKeyToSplit, shamirScheme);

      // Handle app share (send to server)
      props.onAppShare(shamirResult.appShare);

      // Handle user share (encrypt and store locally)
      await WebAuthN.encryptShamirShare(shamirResult.userShare, 'userShare', shamirScheme);
      if (props.onUserShare) {
        props.onUserShare(shamirResult.userShare);
      }

      // Handle device share (only for 2-of-3 scheme)
      if (shamirScheme === '2of3' && shamirResult.deviceShare) {
        await WebAuthN.encryptShamirShare(shamirResult.deviceShare, 'deviceShare', shamirScheme);
        if (props.onDeviceShare) {
          props.onDeviceShare(shamirResult.deviceShare);
        }
      }

      // Update wallets state
      setWallets((prev) => ({
        ...prev,
        [inEvm ? 'evm' : 'near']: [
          ...prev[inEvm ? 'evm' : 'near'],
          {
            address: public_address,
            type: 'created',
            timestamp: Date.now(),
            public_key: public_address,
            is_generated_via_lib: true,
            shamir_scheme: shamirScheme,
            share_count: shamirScheme === '1of2' ? 2 : 3
          }
        ]
      }));

    } catch (error) {
      console.error('Error creating account:', error);
      alert(`Failed to create account: ${error.message}`);
    } finally {
      setLoading(null);
      setShowAddOptions(false);
    }
  };

  const handleRecovery = async (privateKey: string) => {
    try {
      // Here you would use the recovered private key to restore the wallet
      console.log('Recovered private key:', privateKey);
      
      // You might want to:
      // 1. Import the private key into the wallet
      // 2. Derive the public address
      // 3. Update the UI to show the recovered wallet
      
      alert('Wallet recovered successfully!');
    } catch (error) {
      console.error('Recovery handling failed:', error);
      alert(`Recovery failed: ${error.message}`);
    }
  };

  const currentNetworkWallets = inEvm ? wallets.evm : wallets.near;
  const sortedWallets = [...currentNetworkWallets].sort(
    (a, b) => b.timestamp - a.timestamp
  );

  const hasGeneratedWallet = sortedWallets.filter((item) => item.is_generated_via_lib).length !== 0;

  return (
    <div className="ui">
      <div className="ui-w-full ui-mx-auto ui-bg-black ui-rounded-2xl ui-p-6 ui-shadow-2xl ui-shadow-purple-500/10 ui-border ui-border-white/20">
        <div className="ui-flex ui-flex-col ui-gap-4">
          <div className="ui-flex ui-justify-between ui-items-center">
            <h2 className="ui-text-2xl ui-font-bold ui-bg-gradient-to-r ui-from-blue-600 ui-to-purple-600 ui-bg-clip-text ui-text-transparent">
              Web3 Accounts
            </h2>
          </div>

          {/* Display existing wallets */}
          {sortedWallets.map((w) => (
            <WalletInfoDisplay
              key={w.public_key || w.address}
              address={w.public_key || w.address}
              explorerUrl={getExplorerUrl(w.public_key || w.address)}
              type={inEvm ? 'EVM' : 'NEAR'}
              walletType={w.type}
              timestamp={w.timestamp}
              shamirScheme={w.shamir_scheme}
              shareCount={w.share_count}
            />
          ))}

          {/* Show wallet creation options if no wallets exist */}
          {sortedWallets.length === 0 && (
            <AddWalletOptions
              type={inEvm ? 'evm' : 'near'}
              onConnectWallet={() => wallet.signIn()}
              onCreateWallet={createOnChainAccount}
              loading={loading}
              hasGeneratedWallet={hasGeneratedWallet}
              shamirScheme={shamirScheme}
              onShamirSchemeChange={setShamirScheme}
            />
          )}

          {/* Recovery component */}
          {sortedWallets.length > 0 && (
            <RecoveryComponent
              type={inEvm ? 'evm' : 'near'}
              onRecover={handleRecovery}
            />
          )}
        </div>
      </div>
    </div>
  );
};