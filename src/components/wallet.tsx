// @ts-nocheck
// Import necessary dependencies
import { ConnectButton } from '@rainbow-me/rainbowkit';
import { Wallet } from '../lib/nearWalletConfig';
import { WalletIcon, Plus } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { CubidSDK } from 'cubid-sdk';
import { WebAuthnCrypto } from '../lib/webAuthN';
import { useAccount, useDisconnect } from 'wagmi';
import axios from 'axios';

// Define TypeScript interfaces for type safety
export interface WalletComp {
    type: 'evm' | 'near';
    user_id: string;
    dapp_id: string;
    api_key: string;
    onAppShare: (share: string) => void
    onEVMWallet?: (wallets: string[]) => void
    onNearWallet?: (wallets: string[]) => void
}

interface WalletInfo {
    address: string;
    type: 'connected' | 'created';
    timestamp: number;
    public_key?: string;
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

// Initialize CubidSDK with environment variables
wallet.startUp();
const WebAuthN = new WebAuthnCrypto();

// Component to display individual wallet information
const WalletInfoDisplay = ({ address, explorerUrl, type, walletType, timestamp }: any) => {
    const truncateAddress = (addr: string) => addr ? `${addr?.slice?.(0, 6)}...${addr?.slice?.(-4)}` : '';
    const formatDate = (timestamp: number) => new Date(timestamp).toLocaleString();

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

// Component for wallet connection options
const AddWalletOptions = ({ onConnectWallet, onCreateWallet, type, loading }: any) => (
    <div className="ui-flex ui-flex-col ui-gap-4 ui-mt-4">
        {type === 'evm' ? (
            <div className="ui-group ui-relative">
                <ConnectButton />
            </div>
        ) : (
            <button
                onClick={onConnectWallet}
                className="ui-group ui-w-full ui-relative ui-overflow-hidden ui-rounded-2xl ui-bg-gradient-to-br ui-from-blue-500 ui-to-purple-600 ui-p-0.5 ui-transition-all ui-duration-500 hover:ui-scale-[1.01]"
            >
                <div className="ui-relative ui-flex ui-items-center ui-justify-between ui-rounded-2xl ui-bg-black ui-px-6 ui-py-4 ui-transition-all ui-duration-500 group-hover:ui-bg-opacity-90">
                    <span className="ui-text-lg ui-font-semibold ui-text-white">
                        Connect NEAR Wallet
                    </span>
                </div>
            </button>
        )}

        <button
            onClick={onCreateWallet}
            disabled={loading === 'creating'}
            className="ui-w-full ui-py-3 ui-bg-gradient-to-r ui-from-blue-600 ui-to-purple-600 hover:ui-from-blue-700 hover:ui-to-purple-700 ui-text-white ui-font-medium ui-rounded-xl ui-transition-all ui-duration-300 ui-transform hover:ui-scale-[1.02] disabled:ui-opacity-50 disabled:ui-cursor-not-allowed"
        >
            {loading === 'creating' ? 'Creating Account...' : 'Create New On-Chain Account'}
        </button>
    </div>
);

// Main wallet component
export const WalletComponent = (props: WalletComp) => {
    const sdk = new CubidSDK(props.dapp_id, props.api_key);
    const inEvm = props.type === 'evm';
    const { disconnect } = useDisconnect();
    const [showAddOptions, setShowAddOptions] = useState(false);
    const [wallets, setWallets] = useState<WalletStates>({ evm: [], near: [] });
    const [loading, setLoading] = useState<string | null>(null);
    const { address: evmAddress, isConnected: isEvmConnected } = useAccount();
    const user = { uuid: props.user_id };

    const fetchWallets = useCallback(async () => {
        if (!user?.uuid) return;
        try {
            const [evmResponse, nearResponse] = await Promise.all([
                api.post(`https://passport.cubid.me/api/wallet/fetch`, { dapp_uid: user.uuid, chain: 'evm' }),
                api.post(`https://passport.cubid.me/api/wallet/fetch`, { dapp_uid: user.uuid, chain: 'near' })
            ]);

            setWallets({
                evm: evmResponse.data.data || [],
                near: nearResponse.data.data || []
            });
        } catch (error) {
            console.error('Error fetching wallets:', error);
        }
    }, [user?.uuid]);

    const saveWallets = useCallback(async (type: 'evm' | 'near', wallets: WalletInfo[]) => {
        if (!user?.uuid) return;
        try {
            await Promise.all(wallets.map(async (item) => {
                await api.post('https://passport.cubid.me/api/wallet/save', {
                    dapp_uid: user.uuid,
                    chain: type,
                    public_key: item.public_key || item.address
                });
            }));
        } catch (error) {
            console.error('Error saving wallets:', error);
        }
    }, [user?.uuid]);

    useEffect(() => { fetchWallets(); }, [fetchWallets]);
    console.log({ props, wallets })
    useEffect(() => {
        props?.onEVMWallet?.(wallets?.evm)
        props?.onNearWallet?.(wallets?.near)
    }, [wallets, props.onEVMWallet, props.onNearWallet])

    useEffect(() => {
        saveWallets('evm', wallets.evm);
    }, [wallets.evm, saveWallets]);
    useEffect(() => {
        saveWallets('near', wallets.near);
    }, [wallets.near, saveWallets]);

    useEffect(() => {
        if (isEvmConnected && evmAddress) {
            setWallets(prev => {
                const existingWallet = prev.evm.find(w => w.address === evmAddress);
                if (existingWallet) return prev;

                return {
                    ...prev,
                    evm: [...prev.evm, {
                        address: evmAddress,
                        type: 'connected',
                        timestamp: Date.now()
                    }]
                };
            });
        }
    }, [evmAddress, isEvmConnected]);

    useEffect(() => {
        const checkNearWallet = async () => {
            if (wallet.accountId) {
                setWallets(prev => {
                    const existingWallet = prev.near.find(w => w.address === wallet.accountId);
                    if (existingWallet) return prev;

                    return {
                        ...prev,
                        near: [...prev.near, {
                            address: wallet.accountId!,
                            type: 'connected',
                            timestamp: Date.now()
                        }]
                    };
                });
                await wallet.signOut();
            }
        };
        checkNearWallet();
    }, []);

    const getExplorerUrl = useCallback((address: string) =>
        inEvm ? `https://etherscan.io/address/${address}`
            : `https://explorer.near.org/accounts/${address}`, [inEvm]);

    const createOnChainAccount = async () => {
        setLoading('creating');
        try {
            console.log('jere')
            const { user_shares, public_address } = await sdk.encryptPrivateKey({
                user_id: user?.uuid,
                wallet_type: inEvm ? "ethereum" : "near"
            });
            props.onAppShare((user_shares as any)?.[0])
            await WebAuthN.generateKeyPair();
            await WebAuthN.encryptDeviceShare((user_shares as any)[1]);

            setWallets(prev => ({
                ...prev,
                [inEvm ? 'evm' : 'near']: [
                    ...prev[inEvm ? 'evm' : 'near'],
                    {
                        address: public_address,
                        type: 'created',
                        timestamp: Date.now(),
                        public_key: public_address
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
    const sortedWallets = [...currentNetworkWallets].sort((a, b) => b.timestamp - a.timestamp);

    return (
        <div className="ui">
            <div className="ui-w-full ui-mx-auto ui-bg-black ui-rounded-2xl ui-p-6 ui-shadow-2xl ui-shadow-purple-500/10 ui-border ui-border-white/20">
                <div className="ui-flex ui-flex-col ui-gap-4">
                    <div className="ui-flex ui-justify-between ui-items-center">
                        <h2 className="ui-text-2xl ui-font-bold ui-bg-gradient-to-r ui-from-blue-600 ui-to-purple-600 ui-bg-clip-text ui-text-transparent">
                            {inEvm ? 'EVM Wallets' : 'NEAR Protocol'}
                        </h2>
                        <button
                            onClick={() => setShowAddOptions(true)}
                            className="ui-flex ui-items-center ui-gap-2 ui-px-3 ui-py-1.5 ui-bg-white/5 hover:ui-bg-white/10 ui-rounded-lg ui-text-sm ui-text-white/80 ui-transition-all"
                        >
                            <Plus className="ui-h-4 ui-w-4" />
                            Add Wallet
                        </button>
                    </div>

                    {sortedWallets.map(wallet => (
                        <WalletInfoDisplay
                            key={wallet.public_key || wallet.address}
                            address={wallet.public_key || wallet.address}
                            explorerUrl={getExplorerUrl(wallet.public_key || wallet.address)}
                            type={inEvm ? 'EVM' : 'NEAR'}
                            walletType={wallet.type}
                            timestamp={wallet.timestamp}
                        />
                    ))}

                    {(showAddOptions || sortedWallets.length === 0) && (
                        <AddWalletOptions
                            type={inEvm ? 'evm' : 'near'}
                            onConnectWallet={() => wallet.signIn()}
                            onCreateWallet={createOnChainAccount}
                            loading={loading}
                        />
                    )}
                </div>
            </div>
        </div>
    );
};