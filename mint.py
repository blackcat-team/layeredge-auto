import asyncio
from random import randint

from web3 import AsyncWeb3, AsyncHTTPProvider
from web3.eth.eth import ChecksumAddress

from configs.config import MAX_DELAY_BETWEEN_ACCOUNTS
from utils.log_utils import logger
from utils.file_utils import read_json, read_wallets_to_mint_nft, write_success_mint, write_failed_mint
from utils.private_key_to_wallet import private_key_to_wallet
from core.account import Account
from configs import config

w3 = AsyncWeb3(provider=AsyncHTTPProvider(endpoint_uri="https://mainnet.base.org"))

CONTRACT_ADDRESS = "0x88C22d7A0E56fD58BCe849c3aF9c482c5166047b"
PRIVATE_KEYS_TO_MINT = read_wallets_to_mint_nft()

async def create_dict_transaction(wallet_address: str, multiplier: float = 1.3) -> dict:
    last_block = await w3.eth.get_block('latest')
    wallet_address = AsyncWeb3.to_checksum_address(wallet_address)
    max_priority_fee_per_gas = await w3.eth.max_priority_fee
    base_fee = int(last_block['baseFeePerGas'] * multiplier)
    max_fee_per_gas = base_fee + max_priority_fee_per_gas

    return {
        'chainId': await w3.eth.chain_id,
        'from': wallet_address,
        'maxPriorityFeePerGas': max_priority_fee_per_gas,
        'maxFeePerGas': max_fee_per_gas,
        'nonce': await w3.eth.get_transaction_count(wallet_address),
    }

async def send_txn(txn: dict, account, func: str | None = None):
    try:
        signed_txn = w3.eth.account.sign_transaction(txn, account.private_key)
        txn_hash = await w3.eth.send_raw_transaction(signed_txn.raw_transaction)
        logger.success(f"{account.wallet_address} | {func} | {txn_hash.hex()}")
        write_success_mint(account.private_key)
    except Exception as error:
        logger.error(f"{account.wallet_address} | {func} | {error}")
        write_failed_mint(account.wallet_address)

async def create_contract_and_txn(
address: str | ChecksumAddress,
abi_path: str,
wallet_address: str | ChecksumAddress
):
    contract_address = AsyncWeb3.to_checksum_address(address)
    abi = read_json(abi_path)

    return w3.eth.contract(contract_address, abi=abi), await create_dict_transaction(wallet_address)


async def mint_nft(private_key):
    try:
        nft_type = 1
        func = "Mint POH pass"
        
        account = Account(private_key)

        contract, dict_transaction = await create_contract_and_txn(
                CONTRACT_ADDRESS,
                "data/abis/free_mint_abi.json",
                account.wallet_address)

        dict_transaction['value'] = w3.to_wei('0.00007', 'ether')

        txn_mint = await contract.functions.mint(
            nft_type,
            account.wallet_address
        ).build_transaction(dict_transaction)

        await send_txn(txn_mint, account, func)
    except Exception as error:
        logger.error(f"{private_key_to_wallet(private_key)} | error: {error}")
        write_failed_mint(private_key_to_wallet(private_key))

async def start():
    tasks = []
    for private_key in PRIVATE_KEYS_TO_MINT:
        if config.MINT_FREE_PASS:
            task = asyncio.create_task(mint_nft(private_key))
            tasks.append(task)
            await asyncio.sleep(0.1)

        if config.MINT_OG_PASS:
            if config.MINT_FREE_PASS:
                await asyncio.sleep(randint(60, 90))
            task = asyncio.create_task(mint_nft(private_key, is_free=False))
            tasks.append(task)
            await asyncio.sleep(0.1)

        await asyncio.sleep(randint(config.MIN_DELAY_BETWEEN_ACCOUNTS, MAX_DELAY_BETWEEN_ACCOUNTS))

    while tasks:
        tasks = [task for task in tasks if not task.done()]
        await asyncio.sleep(5)

    logger.success(f"All accounts processed!")

if __name__ == '__main__':
    asyncio.run(start())
