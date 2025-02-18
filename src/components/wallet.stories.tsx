import type { Meta, StoryObj } from "@storybook/react";
import { Card } from "./card";
import { Provider as WalletCubidProvider } from "./provider";
import { WalletComponent } from "./wallet";

const FinalComponent = (props: any) => (
    <WalletCubidProvider>
        <WalletComponent {...props} />
    </WalletCubidProvider>
)

const meta = {
    title: "Wallet/Card",
    component: FinalComponent,
    tags: ["docsPage"],
} satisfies Meta<typeof WalletComponent>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Near: Story = {
    args: {
        type: 'near',
        user_id: 'e10346c4-9436-4975-b2a1-ee12fd6328bd',
        dapp_id: '34',
        api_key: '8c354e51-d323-482a-86ca-e931cd0e91d8',
    },
};


export const EVM: Story = {
    args: {
        type: 'evm',
        user_id: 'e10346c4-9436-4975-b2a1-ee12fd6328bd',
        dapp_id: '34',
        api_key: '8c354e51-d323-482a-86ca-e931cd0e91d8',
    },
};
