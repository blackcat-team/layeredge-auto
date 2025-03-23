import asyncio
from random import randint
from fake_useragent import UserAgent

from core.reqs import start_node, stop_node, check_in
from utils.file_utils import read_proxies, read_farm
from utils.private_key_to_wallet import private_key_to_wallet
from configs import config
from utils.log_utils import logger
from core.account import Account
from core import db

PRIVATE_KEYS_TO_FARM = read_farm()
PROXIES = read_proxies()
ua_faker = UserAgent()

async def process_account(private_key: str, proxy):
    ua = await db.get_ua(private_key_to_wallet(private_key))

    if not ua:
        ua = ua_faker.random
        await db.add_account(private_key_to_wallet(private_key), ua)

    account = Account(private_key, ua)
    logger.success(f"{account.wallet_address} | Starting account..")
    await asyncio.sleep(randint(config.MIN_DELAY_BEFORE_START, config.MAX_DELAY_BEFORE_START))

    while True:
        await check_in(account, proxy)
        # await asyncio.sleep(randint(10, 30))
        # await stop_node(account, proxy)
        # await asyncio.sleep(randint(10, 30))
        # await start_node(account, proxy)
        # await asyncio.sleep(randint(10, 30))
        await asyncio.sleep(randint(24 * 60 * 60, 25 * 60 * 60))

async def start():
    for private_key, proxy in zip(PRIVATE_KEYS_TO_FARM, PROXIES):
        asyncio.create_task(process_account(private_key, proxy))
        await asyncio.sleep(0.1)
    await asyncio.sleep(float("inf"))