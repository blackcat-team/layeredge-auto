import json
from configs.constants import REGISTER_PATH, FARM_PATH, WALLETS_TO_REFS_PATH, PROXIES_PATH, REFS_PATH
from configs.constants import SUCCESS_TASKS_PATH, FAILED_TASKS_PATH, WALLETS_TO_COMPLETE_TASKS_PATH, PROOFS_PATH
from configs.constants import WALLETS_TO_MINT_NFT, SUCCESS_MINT_PATH, FAILED_MINT_PATH, X_AUTH_TOKENS_PATH
from configs.constants import FAILED_PATH, SUCCESS_PATH, ACCS_REFS_PATH
from configs.constants import FAILED_CONNECT_TWITTER_PRIVATE_KEY, FAILED_CONNECT_TWITTER_AUTH_TOKEN
from configs.constants import SUCCESS_CONNECT_TWITTER_PRIVATE_KEY, SUCCESS_CONNECT_TWITTER_AUTH_TOKEN

def read_json(path: str, encoding: str | None = None) -> list | dict:
    return json.load(open(path, encoding=encoding))

def read_file(path: str):
    with open(path, encoding='utf-8') as file:
        return [line.strip() for line in file]

def read_farm() -> list[str]:
    return read_file(FARM_PATH)

def read_register() -> list[str]:
    return read_file(REGISTER_PATH)

def read_proxies() -> list[str]:
    return read_file(PROXIES_PATH)

def read_refs_codes() -> list[str]:
    return read_file(REFS_PATH)

def read_wallets_to_get_refs() -> list[str]:
    return read_file(WALLETS_TO_REFS_PATH)

def read_wallets_to_complete_tasks() -> list[str]:
    return read_file(WALLETS_TO_COMPLETE_TASKS_PATH)

def read_wallets_to_mint_nft() -> list[str]:
    return read_file(WALLETS_TO_MINT_NFT)

def read_proofs() -> list[str]:
    return read_file(PROOFS_PATH)

def read_x_auth_tokens() -> list[str]:
    return read_file(X_AUTH_TOKENS_PATH)

def write_failed_account(private_key: str):
    with open(FAILED_PATH, 'a', encoding="utf-8") as f:
        f.write(f'{private_key}\n')

def write_success_account(private_key: str):
    with open(SUCCESS_PATH, 'a', encoding="utf-8") as f:
        f.write(f'{private_key}\n')

def write_ref_codes(ref_code: str):
    with open(ACCS_REFS_PATH, 'a', encoding="utf-8") as f:
        f.write(f'{ref_code}\n')

def write_success_tasks(private_key: str):
    with open(SUCCESS_TASKS_PATH, 'a', encoding="utf-8") as f:
        f.write(f'{private_key}\n')

def write_failed_tasks(private_key: str):
    with open(FAILED_TASKS_PATH, 'a', encoding="utf-8") as f:
        f.write(f'{private_key}\n')

def write_success_mint(private_key: str):
    with open(SUCCESS_MINT_PATH, 'a', encoding="utf-8") as f:
        f.write(f'{private_key}\n')

def write_failed_mint(private_key: str):
    with open(FAILED_MINT_PATH, 'a', encoding="utf-8") as f:
        f.write(f'{private_key}\n')

def write_failed_connect_twitter_private_key(private_key: str):
    with open(FAILED_CONNECT_TWITTER_PRIVATE_KEY, 'a', encoding="utf-8") as f:
        f.write(f'{private_key}\n')

def write_failed_connect_twitter_auth_token(auth_token: str):
    with open(FAILED_CONNECT_TWITTER_AUTH_TOKEN, 'a', encoding="utf-8") as f:
        f.write(f'{auth_token}\n')

def write_success_connect_twitter_private_key(private_key: str):
    with open(SUCCESS_CONNECT_TWITTER_PRIVATE_KEY, 'a', encoding="utf-8") as f:
        f.write(f'{private_key}\n')

def write_success_connect_twitter_auth_token(auth_token: str):
    with open(SUCCESS_CONNECT_TWITTER_AUTH_TOKEN, 'a', encoding="utf-8") as f:
        f.write(f'{auth_token}\n')
