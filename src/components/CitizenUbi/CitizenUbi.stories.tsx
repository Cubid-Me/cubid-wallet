import type { Meta, StoryObj } from '@storybook/react';
import { CitizenUbi, WalletProvider, CitizenUbiProps } from './CitizenUbi';

const providerConfig = {
  reownProjectId: 'your-reown-project-id', // Get from https://cloud.reown.com
  metadata: {
    name: 'Internal Wallet dApp',
    description: 'dApp with internal wallet creation',
    url: 'https://mydapp.com',
    icons: ['https://mydapp.com/icon.png']
  }
};

const meta: Meta<typeof CitizenUbi> = {
  title: 'Components/CitizenUbi',
  component: CitizenUbi,
  parameters: {
    layout: 'centered',
  },
  decorators: [
    (Story) => (
      <WalletProvider>
        <Story />
      </WalletProvider>
    ),
  ],
};

export default meta;
type Story = StoryObj<typeof CitizenUbi>;

export const Default: Story = {
  args: {
    onCreateWallet: async () => alert('Wallet Created'),
    onFaceVerification: async () => alert('Face Verified'),
    onClaim: async () => alert('UBI Claimed'),
    onManageAccount: () => alert('Manage Account'),
    email:"harjaapdhillon.hrizn@gmail.com"
  } as CitizenUbiProps,
};
