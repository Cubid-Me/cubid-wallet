// @ts-nocheck
// Import necessary dependencies
import { ConnectButton } from '@rainbow-me/rainbowkit';
import { Wallet } from '../lib/nearWalletConfig';
import { WalletIcon, Plus } from 'lucide-react';
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
  onAppShare: (share: string) => void
  onUserShare: (encrypted_share: string) => void
  onEVMWallet?: (wallets: string[], walletDetails: any[]) => void
  onNearWallet?: (wallets: string[], walletDetails: any[]) => void
}

interface WalletInfo {
  address: string;
  type: 'connected' | 'created';
  timestamp: number;
  public_key?: string;
  is_generated_via_lib: boolean;
}

interface WalletStates {
  evm: WalletInfo[];
  near: WalletInfo[];
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
const WalletInfoDisplay = ({ address, explorerUrl, type, walletType, timestamp }: any) => {
  const truncateAddress = (addr: string) =>
    addr ? `${addr.slice(0, 6)}...${addr.slice(-4)}` : '';

  const formatDate = (ts: number) =>
    new Date(ts).toLocaleString();

  return (
    <div className="ui-p-4 ui-bg-white/5 ui-rounded-xl ui-border ui-border-white/10 ui-space-y-3">
      <div className="ui-flex ui-items-center ui-justify-between">
        <span className="ui-text-sm ui-text-gray-400">
          {walletType === 'created' ? 'Created Account' : `Connected to ${type}`}
        </span>
        <span className="ui-px-2 ui-py-1 ui-bg-green-500/10 ui-text-green-400 ui-text-xs ui-rounded-full">
          {walletType === 'created' ? 'Created' : 'Connected'}
        </span>
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
        <div className="ui-flex ui-justify-between">
          <a
            href={explorerUrl}
            target="_blank"
            rel="noreferrer"
            className="ui-flex ui-items-center ui-gap-2 ui-text-sm ui-text-blue-400 hover:ui-text-blue-300"
          >
            <span>View on Explorer</span>
          </a>
        </div>
      </div>
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// UPDATED AddWalletOptions COMPONENT TO MATCH THE IMAGE
// ─────────────────────────────────────────────────────────────────────────────
const AddWalletOptions = ({
  onConnectWallet,
  onCreateWallet,
  type,
  loading,
  hasGeneratedWallet
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
    <div className="ui-bg-black ui-w-full ui-p-4 ui-rounded-xl ui-space-y-4 ui-text-white">
      {/* First row: Create a new web3 account */}
      <div className="ui-flex ui-items-center ui-justify-between">
        <p className="ui-text-sm md:ui-text-base ui-font-normal ui-me-4">
          Create a new web3 account and keep it safe for me (default)
        </p>
        <button
          onClick={onCreateWallet}
          disabled={loading === 'creating' || hasGeneratedWallet}
          className="ui-bg-blue-600 hover:ui-bg-blue-700 ui-px-5 ui-py-2.5 ui-rounded-lg ui-text-sm ui-text-white ui-font-medium disabled:ui-opacity-50"
        >
          {loading === 'creating'
            ? 'Creating...'
            : 'Create Account'}
        </button>
      </div>

      {/* Second row: Connect existing wallet */}
      <div className="ui-flex ui-items-center ui-justify-between">
        <p className="ui-text-sm md:ui-text-base ui-font-normal ui-me-4">
          I’d rather use my existing account in my 3rd party wallet app
        </p>
        <button
          onClick={handleConnectClick}
          className="ui-bg-blue-600 hover:ui-bg-blue-700 ui-px-5 ui-py-2.5 ui-rounded-lg ui-text-sm ui-text-white ui-font-medium"
        >
          Connect Wallet
        </button>
      </div>
    </div>
  );
};
// ─────────────────────────────────────────────────────────────────────────────

// Main wallet component
export const WalletComponent = (props: WalletComp) => {
  const [sdk, setSdk] = useState<any>(null);
  const inEvm = props.type === 'evm';
  const { disconnect } = useDisconnect();
  const [showAddOptions, setShowAddOptions] = useState(false);
  const [wallets, setWallets] = useState<WalletStates>({ evm: [], near: [] });
  const [loading, setLoading] = useState<string | null>(null);
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
              is_generated_via_lib: item.is_generated_via_lib
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
    props?.onEVMWallet?.(wallets?.evm);
    props?.onNearWallet?.(wallets?.near);
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
      const { user_shares, public_address } = await sdk.encryptPrivateKey({
        user_id: user?.uuid,
        wallet_type: inEvm ? 'ethereum' : 'near'
      });
      props.onAppShare((user_shares as any)?.[0]);
      if (props.onUserShare) {
        const encryptedData = await WebAuthN.encryptString((user_shares as any)?.[1]);
        props.onUserShare(encryptedData)
      }
      await WebAuthN.encryptDeviceShare((user_shares as any)[1]);

      setWallets((prev) => ({
        ...prev,
        [inEvm ? 'evm' : 'near']: [
          ...prev[inEvm ? 'evm' : 'near'],
          {
            address: public_address,
            type: 'created',
            timestamp: Date.now(),
            public_key: public_address,
            is_generated_via_lib: true
          }
        ]
      }));
    } catch (error) {
      console.error('Error creating account:', error);
    } finally {
      setLoading(null);
      setShowAddOptions(false);
    }
  };

  const currentNetworkWallets = inEvm ? wallets.evm : wallets.near;
  const sortedWallets = [...currentNetworkWallets].sort(
    (a, b) => b.timestamp - a.timestamp
  );

  return (
    <div className="ui">
      <div className="ui-w-full ui-mx-auto ui-bg-black ui-rounded-2xl ui-p-6 ui-shadow-2xl ui-shadow-purple-500/10 ui-border ui-border-white/20">
        <div className="ui-flex ui-flex-col ui-gap-4">
          <div className="ui-flex ui-justify-between ui-items-center">
            <h2 className="ui-text-2xl ui-font-bold ui-bg-gradient-to-r ui-from-blue-600 ui-to-purple-600 ui-bg-clip-text ui-text-transparent">
              Web3 Accounts
            </h2>
            {/* {!showAddOptions && sortedWallets.length === 0 && (
              <button
                onClick={() => setShowAddOptions(true)}
                className="ui-flex ui-items-center ui-gap-2 ui-px-3 ui-py-1.5 ui-bg-white/5 hover:ui-bg-white/10 ui-rounded-lg ui-text-sm ui-text-white/80 ui-transition-all"
              >
                <Plus className="ui-h-4 ui-w-4" />
                Add Wallet
              </button>
            )} */}
          </div>

          {sortedWallets.map((w) => (
            <WalletInfoDisplay
              key={w.public_key || w.address}
              address={w.public_key || w.address}
              explorerUrl={getExplorerUrl(w.public_key || w.address)}
              type={inEvm ? 'EVM' : 'NEAR'}
              walletType={w.type}
              timestamp={w.timestamp}
            />
          ))}

          {/* Show the two big options only if user clicks "Add Wallet" or if no wallets exist */}
          {sortedWallets.length === 0 && (
            <AddWalletOptions
              type={inEvm ? 'evm' : 'near'}
              onConnectWallet={() => wallet.signIn()}
              onCreateWallet={createOnChainAccount}
              loading={loading}
              hasGeneratedWallet={
                sortedWallets.filter((item) => item.is_generated_via_lib).length !== 0
              }
            />
          )}
        </div>
      </div>
    </div>
  );
};
