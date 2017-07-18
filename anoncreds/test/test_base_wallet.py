from anoncreds.protocol.wallet.wallet import Wallet


def test_wallet_name(publicRepo):
    walletName = "test-wallet-name-1"
    wallet = Wallet(walletName, publicRepo)
    assert wallet.name == walletName
    assert wallet.walletId == wallet.name
