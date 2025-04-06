import asyncio
from random import randint
from fake_useragent import UserAgent

from core.reqs import send_prof, submit_prof, submit_light_node, submit_free_pass, submit_og_pass
from core.reqs import is_twitter_verified, connect_twitter, complete_follow_task
from utils.file_utils import read_proxies, read_wallets_to_complete_tasks
from utils.private_key_to_wallet import private_key_to_wallet
from utils.file_utils import write_failed_tasks, write_success_tasks
from utils.file_utils import write_failed_connect_twitter_private_key, write_failed_connect_twitter_auth_token
from utils.file_utils import write_success_connect_twitter_private_key, write_success_connect_twitter_auth_token
from utils.file_utils import write_twitter_verified, write_twitter_is_not_verified
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
write_twitter_verified('------------------------------------------------')
write_twitter_is_not_verified('------------------------------------------------')

async def complete_tasks(private_key: str, proxy, x_auth_token):
    ua = await db.get_ua(private_key_to_wallet(private_key))
    is_verified = False

    if not ua:
        ua = ua_faker.random
        await db.add_account(private_key_to_wallet(private_key), ua)

    account = Account(private_key, ua)
    logger.success(f"{account.wallet_address} | Start running tasks..")
    await asyncio.sleep(randint(config.MIN_DELAY_BEFORE_START_TASKS, config.MAX_DELAY_BEFORE_START_TASKS))

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
    if config.CHECK_IS_TWITTER_VERIFIED:
        is_verified = await is_twitter_verified(account, proxy)
        await asyncio.sleep(10, 30)
    if config.DO_FOLLOW_LAYEREDGE_TASK and not is_verified:
        await complete_follow_task(account, proxy, TWITTER_USERNAMES['layeredge'])
        await asyncio.sleep(10, 30)
    if config.DO_FOLLOW_AYUSHBUIDL_TASK:
        await complete_follow_task(account, proxy, TWITTER_USERNAMES['dev'])
        await asyncio.sleep(10, 30)

async def start():
    await db.create_database()
    tasks = []
    if config.DO_CONNECT_TWITTER_TASK:
        accounts_data = zip(PRIVATE_KEYS_TO_COMPLETE_TASKS, PROXIES, X_AUTH_TOKENS)
    else:
        accounts_data = zip(PRIVATE_KEYS_TO_COMPLETE_TASKS, PROXIES)
    for private_key, proxy, x_auth_token in accounts_data:
        task = asyncio.create_task(complete_tasks(private_key, proxy, x_auth_token))
        tasks.append(task)
        await asyncio.sleep(config.DELAY_BETWEEN_ACCOUNTS)

    while tasks:
        tasks = [task for task in tasks if not task.done()]
        await asyncio.sleep(10)

    logger.success(f"All accounts processed!")

if __name__ == '__main__':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(start())
