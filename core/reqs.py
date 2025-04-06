import asyncio
import time
from random import random, choice
from datetime import datetime, timezone
from socket import AF_INET

import aiohttp
from aiohttp import ClientHttpProxyError, ClientResponseError
from eth_account.messages import encode_defunct

from core.account import Account
from utils.file_utils import write_success_account, write_failed_account, write_success_tasks, write_failed_tasks
from utils.file_utils import read_proxies, read_proofs
from utils.file_utils import write_failed_connect_twitter_private_key, write_failed_connect_twitter_auth_token
from utils.file_utils import write_success_connect_twitter_private_key, write_success_connect_twitter_auth_token
from utils.file_utils import write_twitter_verified, write_twitter_is_not_verified
from configs.config import SSL
from utils.log_utils import logger
from fake_useragent import UserAgent
from core import db


base_headers = {
    'Accept': "application/json, text/plain, */*",
    'Origin': "https://dashboard.layeredge.io",
}

ua = UserAgent(os=["Windows", "Linux", "Ubuntu", "Mac OS X"])
proxies = read_proxies()
proofs = read_proofs()

BAD_PROXIES = []


async def make_request(
method: str,
url: str,
proxy: str,
user_agent: str,
payload: dict = None,
wallet_address: str = "",
retries = 10,
timeout: int = 10
):
    headers = base_headers.copy()
    headers['User-Agent'] = user_agent

    method = method.upper()
    if method == 'POST':
        headers['Content-Type'] = 'application/json'

    for _ in range(retries):
        async with aiohttp.ClientSession() as session:
            try:
                async with session.request(method, url, json=payload, headers=headers, proxy=proxy, timeout=timeout, ssl=SSL) as response:
                    response_json = await response.json()
                    status = response.status
                    response.raise_for_status()
                    return status, response_json
            except ClientHttpProxyError:
                logger.error(f"{wallet_address} | Bad proxy: {proxy}")
                if retries % 2 == 1:
                    proxy = choice(proxies[int(len(proxies)/1.5):])
                    logger.error(f"{wallet_address} | Changed proxy: {proxy}")
            except ClientResponseError:
                logger.error(f"{wallet_address} | request failed, attempt {_ + 1}/{retries}")
            except TimeoutError:
                logger.error(f"{wallet_address} | TimeoutError, attempt {_+1}/{retries}")
            except Exception as e:
                logger.error(f"{wallet_address} | Unexpected error: {e}, attempt {_+1}/{retries}")
            await asyncio.sleep(3, 10)
    return 400, {}


async def register_wallet(
private_key: str,
wallet_address: str,
proxy: str,
ref_code: str
) -> bool:
    register_data = {
        'walletAddress': wallet_address
    }

    user_agent = ua.random
    response_status, response_json = await make_request(
        'POST',
        f"https://referralapi.layeredge.io/api/referral/register-wallet/{ref_code}",
        proxy,
        user_agent,
        register_data,
        wallet_address,
        retries=20
    )

    if response_status < 300:
        try:
            write_success_account(private_key)
            await db.add_account(wallet_address, user_agent)
            logger.success(f"{wallet_address} | Successfully register account")
        except:
            logger.info(f"{wallet_address} | Wallet already registered")
            return True
        return True
    else:
        write_failed_account(private_key)
        if 'message' in response_json:
            if response_json['message'] == "wallet address already registered":
                logger.success(f"{wallet_address} | Wallet already registered, starting farm..")
                return True
            elif response_json['message'] == "invalid invite code":
                logger.error(f"{wallet_address} | Invalid invite code: {ref_code}")
        else:
            logger.error(f"{wallet_address} | Unexpected error: {response_json}")
        return False

async def get_node_status(
account: Account,
proxy: str
):
    url = f"https://referralapi.layeredge.io/api/light-node/node-status/{account.wallet_address}"

    response_status, response_json = await make_request(
        'GET',
        url,
        proxy,
        account.ua,
        wallet_address=account.wallet_address
    )

    if response_status < 300:
        return response_json['data']['startTimestamp']

async def get_points(
account: Account,
proxy: str
) -> int | None:
    url = f"https://referralapi.layeredge.io/api/referral/wallet-details/{account.wallet_address}"

    response_status, response_json = await make_request(
        'GET',
        url,
        proxy,
        account.ua,
        wallet_address=account.wallet_address
    )

    if response_status < 300:
        return response_json['data']["nodePoints"]
    else:
        return None

async def get_ref_code(
account: Account,
proxy: str
) -> str | None:
    url = f"https://referralapi.layeredge.io/api/referral/wallet-details/{account.wallet_address}"

    response_status, response_json = await make_request(
        'GET',
        url,
        proxy,
        account.ua,
        wallet_address=account.wallet_address
    )

    if response_status < 300:
        return response_json['data']["referralCode"]
    else:
        return None

async def start_node(account: Account, proxy):
    timestamp = int(time.time() * 1000)
    message = f"Node activation request for {account.wallet_address} at {timestamp}"
    msg_hash = encode_defunct(text=message)
    sign = account.evm_account.sign_message(msg_hash)['signature'].hex()
    data_start = {
        'sign': f"0x{sign}",
        'timestamp': timestamp,
    }

    response_status, response_json = await make_request(
        'POST',
        f"https://referralapi.layeredge.io/api/light-node/node-action/{account.wallet_address}/start",
        proxy,
        account.ua,
        data_start,
        account.wallet_address
    )

    if response_status < 400:
        logger.success(f"{account.wallet_address} | Successfully start node")
        return True
    else:
        if response_status == 405:
            if 'message' in response_json:
                if 'multiple light node' in response_json['message']:
                    logger.warning(f"{account.wallet_address} | Node is already working")
            else:
                logger.error(f"{account.wallet_address} | Error when starting node")
        return False

async def stop_node(account: Account, proxy):
    timestamp = int(time.time() * 1000)
    message = f"Node deactivation request for {account.wallet_address} at {timestamp}"
    msg_hash = encode_defunct(text=message)
    sign = account.evm_account.sign_message(msg_hash)['signature'].hex()

    data_stop = {
        'sign': f"0x{sign}",
        'timestamp': timestamp,
    }

    response_status, response_json = await make_request(
        'POST',
        f"https://referralapi.layeredge.io/api/light-node/node-action/{account.wallet_address}/stop",
        proxy,
        account.ua,
        data_stop,
        account.wallet_address
    )

    if response_status < 400:
        logger.success(f"{account.wallet_address} | Successfully stop node")
        return True
    else:
        if response_status == 404:
            if 'message' in response_json:
                if 'no node running' in response_json['message']:
                    # node is not running
                    pass
                    # logger.warning(f"{account.wallet_address} | Node is not running")
            else:
                logger.error(f"{account.wallet_address} | Error when stopping node")
        return False

async def check_in(account: Account, proxy):
    timestamp = int(time.time() * 1000)
    message = f"I am claiming my daily node point for {account.wallet_address} at {timestamp}"
    msg_hash = encode_defunct(text=message)
    sign = account.evm_account.sign_message(msg_hash)['signature'].hex()

    data_check_in = {
        'sign': f"0x{sign}",
        'timestamp': timestamp,
        'walletAddress': account.wallet_address,
    }

    response_status, response_json = await make_request(
        'POST',
        f"https://referralapi.layeredge.io/api/light-node/claim-node-points",
        proxy,
        account.ua,
        data_check_in,
        account.wallet_address
    )

    if response_status < 400:
        logger.success(f"{account.wallet_address} | Successfully claim daily check in")
        return True
    else:
        if response_status == 405:
            if 'message' in response_json:
                if '24 hours' in response_json['message']:
                    logger.warning(f"{account.wallet_address} | Check in is already done")
            else:
                logger.error(f"{account.wallet_address} | Failed to perform check in")
        return False

async def send_prof(account: Account, proxy):
    logger.success(f"{account.wallet_address} | Start submitting proof..")
    now_utc = datetime.now(timezone.utc)
    current_time = now_utc.isoformat(timespec='milliseconds').replace('+00:00', 'Z')

    message = f"I am submitting a proof for LayerEdge at {current_time}"
    msg_hash = encode_defunct(text=message)
    sign = account.evm_account.sign_message(msg_hash)['signature'].hex()

    data_prof = {
        'address': account.wallet_address,
        'message': message,
        'proof': choice(proofs),
        'signature': f"0x{sign}"
    }

    logger.info(f"{account.wallet_address} | Sending request for proof..")

    response_status, response_json = await make_request(
        'POST',
        f"https://dashboard.layeredge.io/api/send-proof",
        proxy,
        account.ua,
        data_prof,
        account.wallet_address,
        retries=3
    )

    if response_status < 400:
        logger.success(f"{account.wallet_address} | Successfully submit proof")
        write_success_tasks(account.wallet_address)
        return True
    else:
        if response_status == 429:
            if 'error' in response_json:
                if 'Proof already submitted' in response_json['error']:
                    logger.warning(f"{account.wallet_address} | Proof is already done")
            else:
                logger.error(f"{account.wallet_address} | Failed to send proof")
                write_failed_tasks(account.wallet_address)
        return False

async def submit_prof(account: Account, proxy):
    logger.success(f"{account.wallet_address} | Start submitting proof task..")
    timestamp = int(time.time() * 1000)
    message = f"I am claiming my proof submission node points for {account.wallet_address} at {timestamp}"
    msg_hash = encode_defunct(text=message)
    sign = account.evm_account.sign_message(msg_hash)['signature'].hex()

    data_proof_submit = {
        'sign': f"0x{sign}",
        'timestamp': timestamp,
        'walletAddress': account.wallet_address,
    }

    logger.info(f"{account.wallet_address} | Sending request for submit proof task..")

    response_status, response_json = await make_request(
        'POST',
        f"https://referralapi.layeredge.io/api/task/proof-submission",
        proxy,
        account.ua,
        data_proof_submit,
        account.wallet_address,
        timeout=30,
        retries=5
    )

    if response_status < 400:
        logger.success(f"{account.wallet_address} | Successfully complete task: submit proof")
        write_success_tasks(account.wallet_address)
        return True
    else:
        if response_status == 409:
            if 'message' in response_json:
                if 'task is already completed' in response_json['message']:
                    logger.warning(f'{account.wallet_address} | Submit proof task is already completed')
            else:
                logger.error(f"{account.wallet_address} | Failed to complete task: submit proof")
                write_failed_tasks(account.wallet_address)
        return False

async def submit_light_node(account: Account, proxy):
    logger.success(f"{account.wallet_address} | Starting light node run task..")
    timestamp = int(time.time() * 1000)
    message = f"I am claiming my light node run task node points for {account.wallet_address} at {timestamp}"
    msg_hash = encode_defunct(text=message)
    sign = account.evm_account.sign_message(msg_hash)['signature'].hex()

    data_proof_submit = {
        'sign': f"0x{sign}",
        'timestamp': timestamp,
        'walletAddress': account.wallet_address,
    }

    logger.info(f"{account.wallet_address} | Sending request for light node run task..")

    response_status, response_json = await make_request(
        'POST',
        f"https://referralapi.layeredge.io/api/task/node-points",
        proxy,
        account.ua,
        data_proof_submit,
        account.wallet_address
    )

    if response_status < 400:
        logger.success(f"{account.wallet_address} | Successfully complete task: submit light node")
        write_success_tasks(account.wallet_address)
        return True
    else:
        if response_status == 409:
            if 'message' in response_json:
                if 'task is already completed' in response_json['message']:
                    logger.warning(f'{account.wallet_address} | Node run task is already completed')
            elif response_json == 405:
                if 'message' in response_json:
                    if 'can not complete' in response_json['message']:
                        logger.error(f'{account.wallet_address} | Can not complete node run task without running light node at 12 hours')
            else:
                logger.error(f"{account.wallet_address} | Failed to complete task: submit light node")
                write_failed_tasks(account.wallet_address)
        return False

async def submit_free_pass(account: Account, proxy):
    logger.success(f"{account.wallet_address} | Starting free pass task..")
    timestamp = int(time.time() * 1000)
    message = f"I am claiming my SBT verification points for {account.wallet_address} at {timestamp}"
    msg_hash = encode_defunct(text=message)
    sign = account.evm_account.sign_message(msg_hash)['signature'].hex()

    data_proof_submit = {
        'sign': f"0x{sign}",
        'timestamp': timestamp,
        'walletAddress': account.wallet_address,
    }

    logger.info(f"{account.wallet_address} | Sending request to verify free SBT holding..")

    response_status, response_json = await make_request(
        'POST',
        f"https://referralapi.layeredge.io/api/task/nft-verification/1",
        proxy,
        account.ua,
        data_proof_submit,
        account.wallet_address
    )

    if response_status < 400:
        logger.success(f"{account.wallet_address} | Successfully complete task: verify free pass holding")
        write_success_tasks(account.wallet_address)
        return True
    else:
        if response_status == 404:
            if 'message' in response_json:
                if 'no nft found' in response_json['message']:
                    logger.error(f'{account.wallet_address} | Free pass holding: no nft found')
            else:
                logger.error(f"{account.wallet_address} | Failed to complete task: verify free pass holding")
                write_failed_tasks(account.wallet_address)
        return False

async def submit_og_pass(account: Account, proxy):
    logger.success(f"{account.wallet_address} | Starting OG pass task..")
    timestamp = int(time.time() * 1000)
    message = f"I am claiming my SBT verification points for {account.wallet_address} at {timestamp}"
    msg_hash = encode_defunct(text=message)
    sign = account.evm_account.sign_message(msg_hash)['signature'].hex()

    data_proof_submit = {
        'sign': f"0x{sign}",
        'timestamp': timestamp,
        'walletAddress': account.wallet_address,
    }

    logger.info(f"{account.wallet_address} | Sending request to verify OG SBT holding..")

    response_status, response_json = await make_request(
        'POST',
        f"https://referralapi.layeredge.io/api/task/nft-verification/2",
        proxy,
        account.ua,
        data_proof_submit,
        account.wallet_address
    )

    if response_status < 400:
        logger.success(f"{account.wallet_address} | Successfully complete task: verify OG pass holding")
        write_success_tasks(account.wallet_address)
        return True
    else:
        if response_status == 404:
            if 'message' in response_json:
                if 'no nft found' in response_json['message']:
                    logger.error(f'{account.wallet_address} | OG pass holding: no nft found')
            else:
                logger.error(f"{account.wallet_address} | Failed to complete task: verify OG pass holding")
                write_failed_tasks(account.wallet_address)
        return False

async def approve_twitter(account: Account, proxy, access_token, auth_token, session: aiohttp.ClientSession, headers):
    logger.infp(f"{account.wallet_address} | Starting proof twitter task..")
    url = "https://referralapi.layeredge.io/api/task/connect-twitter"
    message = f"I am connecting my Twitter account with LayerEdge for my wallet {account.wallet_address}"
    msg_hash = encode_defunct(text=message)
    sign = account.evm_account.sign_message(msg_hash)['signature'].hex()

    data_proof_submit = {
        'accessToken': access_token,
        'sign': f"0x{sign}",
        'walletAddress': account.wallet_address
    }

    logger.info(f"{account.wallet_address} | Sending request to proof twitter..")

    response_status, response_json = await make_request(
        'POST',
        url,
        proxy,
        account.ua,
        data_proof_submit,
        account.wallet_address,
        retries=5
    )

    if response_status == 400:
        logger.error(f"{account.wallet_address} | Couldn't verify the twitter account")
        write_failed_tasks(account.private_key)
        write_failed_connect_twitter_private_key(account.private_key)
        write_failed_connect_twitter_auth_token(auth_token)

    elif response_status < 400:
        if response_status == 200:
            if 'message' in response_json:
                if 'CORS policy blocked this request' in response_json['message']:
                    logger.error(f"{account.wallet_address} | Couldn't verify the twitter account")
                    write_failed_tasks(account.private_key)
                    write_failed_connect_twitter_private_key(account.private_key)
                    write_failed_connect_twitter_auth_token(auth_token)
                    return False
                else:
                    logger.success(f"{account.wallet_address} | Successfully complete task: connect twitter")
                    write_success_tasks(account.private_key)
                    write_success_connect_twitter_private_key(account.private_key)
                    write_success_connect_twitter_auth_token(auth_token)
                    await db.insert_private_key_twitter(account.private_key, auth_token)
                    return True
    else:
        if response_status == 401:
            if 'message' in response_json:
                if 'Twitter account verification failed or account does not exist' in response_json['message']:
                    logger.warning(
                        f'{account.wallet_address} | Twitter account with token "{auth_token} is already linked')
        elif response_status == 409:
            if 'message' in response_json:
                if 'account is already linked' in response_json['message']:
                    logger.warning(f'{account.wallet_address} | Twitter account with token "{auth_token} is already linked')
                elif 'Your wallet is already linked with a different Twitter account' in response_json['message']:
                    logger.warning(f'{account.wallet_address} | Wallet is already linked with a different Twitter account')
        logger.warning(f"{account.wallet_address} | Couldn't connect the twitter account")
        return False

# twitter connect
async def connect_twitter(account: Account, proxy, auth_token):
    logger.info(f"{account.wallet_address} | Starting connect twitter task..")
    headers = {
        "User-Agent": account.ua
    }
    connector = aiohttp.TCPConnector(family=AF_INET, limit_per_host=10)
    timeout = aiohttp.ClientTimeout(total=5)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector, max_line_size=8190 * 2, max_field_size=8190 * 2) as session:
        try:
            csrf_token = await get_csrf_token(account, proxy, session)
            await asyncio.sleep(1)
            auth_url = await get_x_auth_link(account, proxy, session, headers, csrf_token)
            await asyncio.sleep(3)
            x_cookies, twitter_id, url_to_get_auth_code = await get_twitter_data(account, proxy, session, headers, auth_url, auth_token)
            await asyncio.sleep(5)
            if twitter_id:
                logger.info(f"{account.wallet_address} | Successfully logged into the Twitter account")
            else:
                logger.error(f"{account.wallet_address} | Couldn't log into the twitter account")
                write_failed_connect_twitter_private_key(account.private_key)
                write_failed_connect_twitter_auth_token(auth_token)
                return
            auth_token_to_layer_redirect, x_headers = await get_x_auth_code(account, proxy, session, x_cookies, auth_url, url_to_get_auth_code)
            await asyncio.sleep(4)
            if auth_token_to_layer_redirect:
                logger.info(f"{account.wallet_address} | Successfully auth through twitter account")
            redirect_uri = await x_auth_and_get_redirect_url(account, proxy, session, x_headers, x_cookies, auth_token_to_layer_redirect)
            await asyncio.sleep(1)
            status, access_token = await request_to_redirect_url(account, proxy, session, redirect_uri)
            await asyncio.sleep(5)

            if status:
                logger.info(f"{account.wallet_address} | Successfully logged into LayerEdge via Twitter.")
                await asyncio.sleep(10)
                await approve_twitter(account, proxy, access_token, auth_token, session, headers)
        except:
            logger.error(f"{account.wallet_address} | Couldn't auth through twitter account")
            write_failed_connect_twitter_private_key(account.private_key)
            write_failed_connect_twitter_auth_token(auth_token)
    return

async def fetch_with_retries(method, url, session, wallet_address, proxy, retries=10, **kwargs) -> aiohttp.ClientResponse | None:
    """Выполняет HTTP-запрос с повторными попытками в случае ошибки."""
    for attempt in range(retries):
        try:
            response = await session.request(method, url, proxy=proxy, ssl=SSL, **kwargs)
            return response
        except ClientHttpProxyError:
            logger.error(f"{wallet_address} | Bad proxy: {proxy}")
            if retries % 2 == 1:
                proxy = choice(proxies[int(len(proxies) / 1.5):])
                logger.error(f"{wallet_address} | Changed proxy: {proxy}")
        except ClientResponseError:
            logger.error(f"{wallet_address} | Request failed, attempt {attempt + 1}/{retries}")
        except TimeoutError:
            logger.error(f"{wallet_address} | TimeoutError, attempt {attempt + 1}/{retries}")
        except Exception as e:
            logger.error(f"{wallet_address} | Unexpected error: {e}, attempt {attempt + 1}/{retries}")
        await asyncio.sleep(3, 10)

    return None

async def get_csrf_token(account: Account, proxy, session: aiohttp.ClientSession):
    url_to_get_crf = "https://dashboard.layeredge.io/api/auth/csrf"

    response = await fetch_with_retries(
        method="GET", url=url_to_get_crf, session=session, wallet_address=account.wallet_address, proxy=proxy
    )

    try:
        return (await response.json())["csrfToken"]
    except:
        return None

async def get_x_auth_link(account: Account, proxy, session: aiohttp.ClientSession, headers: dict, csrf_token: str):
    url_to_get_x_auth_link = "https://dashboard.layeredge.io/api/auth/signin/twitter"

    payload_to_get_x_auth_link = {
        "callbackUrl": "https://dashboard.layeredge.io/tasks",
        "csrfToken": csrf_token,
        "json": True
    }

    response = await fetch_with_retries(
        method="POST", url=url_to_get_x_auth_link, session=session, wallet_address=account.wallet_address, proxy=proxy,
        data=payload_to_get_x_auth_link, headers=headers
    )
    try:
        return str(response.url)
    except:
        return None

async def get_twitter_data(account: Account, proxy, session: aiohttp.ClientSession, headers: dict, auth_url, auth_token: str):
    x_cookies = {
        "auth_token": auth_token
    }

    response = await fetch_with_retries(
        method="GET", url="https://x.com", session=session, wallet_address=account.wallet_address, proxy=proxy,
        headers=headers, cookies=x_cookies
    )

    try:
        response_text = await response.text()
        a = response_text.find('"id_str":"')
        if a == -1:
            return None, None, None
        b = response_text[a + len('"id_str":"'):].find('"')
        twitter_id = response_text[a + len('"id_str":"'):a + len('"id_str":"') + b]
        ct0 = str(response.cookies.get("ct0"))

        a = ct0.find("ct0=")
        b = ct0.find(";")
        x_cookies["ct0"] = ct0[a + len("ct0="):b]

        # get token to x auth
        # create link to get x code
        a = auth_url.find("client_id")
        b = a + 44
        client_id = auth_url[a + len("client_id") + 1:b]

        a = auth_url.find("code_challenge")
        b = a + 58
        code_challenge = auth_url[a + len("code_challenge") + 1:b]

        a = auth_url.find("&state=")
        b = a + 50
        state = auth_url[a + len("&state") + 1:b]

        # link to get x code
        url_to_get_auth_code = f"https://twitter.com/i/api/2/oauth2/authorize?client_id={client_id}&code_challenge={code_challenge}&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fdashboard.layeredge.io%2Fapi%2Fauth%2Fcallback%2Ftwitter&response_type=code&scope=users.read%20tweet.read%20offline.access&state={state}"

        return x_cookies, twitter_id, url_to_get_auth_code
    except:
        return None, None, None

async def get_x_auth_code(account: Account, proxy, session: aiohttp.ClientSession, x_cookies: dict, auth_url, url_to_get_auth_code: str):
    headers = {
        "User-Agent": account.ua,
        "Referer": auth_url,
        "X-Csrf-Token": x_cookies["ct0"],
        "Authorization": "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
    }

    response = await fetch_with_retries(
        method="GET", url=url_to_get_auth_code, session=session, wallet_address=account.wallet_address, proxy=proxy,
        headers=headers, cookies=x_cookies
    )
    try:
        return (await response.json())["auth_code"], headers
    except:
        return None, None

async def x_auth_and_get_redirect_url(account: Account, proxy, session: aiohttp.ClientSession, x_headers, x_cookies, auth_token_to_layer_redirect):
    url_auth = "https://twitter.com/i/api/2/oauth2/authorize"

    payload_x_auth = {
        "approval": True,
        "code": auth_token_to_layer_redirect
    }

    response = await fetch_with_retries(
        method="POST", url=url_auth, session=session, wallet_address=account.wallet_address, proxy=proxy,
        data=payload_x_auth, headers=x_headers, cookies=x_cookies
    )

    try:
        return (await response.json())["redirect_uri"]
    except:
        return None, None

async def request_to_redirect_url(account: Account, proxy, session: aiohttp.ClientSession, redirect_uri):
    headers = {
        "User-Agent": account.ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Referer": "https://twitter.com/",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"
    }

    await session.get(redirect_uri, headers=headers, proxy=proxy)

    await fetch_with_retries(
        method="GET", url=redirect_uri, session=session, wallet_address=account.wallet_address, proxy=proxy,
        headers=headers
    )

    tasks_url = "https://dashboard.layeredge.io/tasks"
    headers["Referer"] = "https://twitter.com/"

    response = await fetch_with_retries(
        method="GET", url=tasks_url, session=session, wallet_address=account.wallet_address, proxy=proxy,
        headers=headers
    )
    text = await response.text()
    a = text.find(r"accessToken\":\"") + len(r"accessToken\":\"")
    b = text[a:].find('"')
    access_token = text[a:a+b-1]
    return response.ok, access_token

async def complete_follow_task(account: Account, proxy, twitter_username: str):
    url = "https://referralapi.layeredge.io/api/task/follow-twitter-account"

    payload_x_follow = {
        "twitterUsername": twitter_username,
        "walletAddress": account.wallet_address
    }

    response_status, response_json = await make_request(
        'POST',
        url,
        proxy,
        account.ua,
        payload_x_follow,
        account.wallet_address,
        retries=3
    )

    try:
        if response_status < 400:
            if 'message' in response_json:
                if response_json['message'] == 'follow twitter task completed successfully':
                    logger.success(f"{account.wallet_address} | Successfully complete task: follow to {twitter_username}")
                    return True
        logger.error(f"{account.wallet_address} | Bad response: {response_json}")
    except:
        logger.error(f"{account.wallet_address} | Failed to send request")

    return False

async def is_twitter_verified(account: Account, proxy):
    logger.info(f"{account.wallet_address} | Getting twitter status..")

    url = f"https://referralapi.layeredge.io/api/referral/wallet-details/{account.wallet_address}"

    response_status, response_json = await make_request(
        'GET',
        url,
        proxy,
        account.ua,
        wallet_address=account.wallet_address,
        retries=3
    )

    try:
        if response_status == 200:
            if 'data' in response_json:
                if 'isTwitterVerified' in response_json['data']:
                    is_verified = response_json['data']['isTwitterVerified']
                    if is_verified:
                        write_twitter_verified(account.private_key)
                    else:
                        write_twitter_is_not_verified(account.private_key)

                    logger.info(f"{account.wallet_address} | is Twitter Verified: {is_verified}")
            else:
                logger.error(f"{account.wallet_address} | Bad response: {response_json}")
    except:
        logger.error(f"{account.wallet_address} | Failed to send request")

    return False