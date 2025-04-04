import asyncio
from random import randint
from fake_useragent import UserAgent

from core.reqs import send_prof, submit_prof, submit_light_node, submit_free_pass, submit_og_pass
from core.reqs import connect_twitter, complete_follow_task
from utils.file_utils import read_proxies, read_wallets_to_complete_tasks
from utils.private_key_to_wallet import private_key_to_wallet
from utils.file_utils import write_failed_tasks, write_success_tasks
from utils.file_utils import write_failed_connect_twitter_private_key, write_failed_connect_twitter_auth_token
from utils.file_utils import write_success_connect_twitter_private_key, write_success_connect_twitter_auth_token
from utils.file_utils import read_x_auth_tokens
from utils.log_utils import logger
from core.account import Account
from core import db
from configs import config
from configs.constants import TWITTER_USERNAMES

PRIVATE_KEYS_TO_COMPLETE_TASKS = read_wallets_to_complete_tasks()
PROXIES = read_proxies()
X_AUTH_TOKENS = read_x_auth_tokens()
ua_faker = UserAgent()
write_failed_tasks('------------------------------------------------')
write_success_tasks('------------------------------------------------')
write_failed_connect_twitter_private_key('------------------------------------------------')
write_failed_connect_twitter_auth_token('------------------------------------------------')
write_success_connect_twitter_auth_token('------------------------------------------------')
write_success_connect_twitter_private_key('------------------------------------------------')

async def complete_tasks(private_key: str, proxy, x_auth_token):
    ua = await db.get_ua(private_key_to_wallet(private_key))

    if not ua:
        ua = ua_faker.random
        await db.add_account(private_key_to_wallet(private_key), ua)

    account = Account(private_key, ua)
    logger.success(f"{account.wallet_address} | Start running tasks..")
    # await asyncio.sleep(randint(config.MIN_DELAY_BEFORE_START_TASKS, config.MAX_DELAY_BEFORE_START_TASKS))

    if config.DO_PROOF:
        await send_prof(account, proxy)
        await asyncio.sleep(20, 30)
    if config.DO_SUBMIT_PROOF_TASK:
        await submit_prof(account, proxy)
        await asyncio.sleep(10, 30)
    if config.DO_LIGHT_NODE_RUN_TASK:
        await submit_light_node(account, proxy)
        await asyncio.sleep(10, 30)
    if config.DO_PLEDGE_PASS_HOLD_TASK:
        await submit_free_pass(account, proxy)
        await asyncio.sleep(10, 30)
    if config.DO_OG_PLEDGE_PASS_HOLD_TASK:
        await submit_og_pass(account, proxy)
        await asyncio.sleep(10, 30)
    if config.DO_CONNECT_TWITTER_TASK:
        await connect_twitter(account, proxy, x_auth_token)
        await asyncio.sleep(10, 30)
    if config.DO_FOLLOW_LAYEREDGE_TASK:
        await complete_follow_task(account, proxy, TWITTER_USERNAMES['layeredge'])
        await asyncio.sleep(10, 30)


async def start():
    await db.create_database()
    tasks = []
    for private_key, proxy, x_auth_token in zip(PRIVATE_KEYS_TO_COMPLETE_TASKS, PROXIES, X_AUTH_TOKENS):
        task = asyncio.create_task(complete_tasks(private_key, proxy, x_auth_token))
        tasks.append(task)
        await asyncio.sleep(0.1)

    while tasks:
        tasks = [task for task in tasks if not task.done()]
        await asyncio.sleep(10)

    logger.success(f"All accounts processed!")

if __name__ == '__main__':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(start())