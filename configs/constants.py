import os
import sys
from pathlib import Path

if getattr(sys, 'frozen', False):
    ROOT_DIR = Path(sys.executable).parent.parent.absolute()
else:
    ROOT_DIR = Path(__file__).parent.parent.absolute()

LOG_DIR = os.path.join(ROOT_DIR, "log")
RESULTS_DIR = os.path.join(ROOT_DIR, "results")
CONFIGS_DIR = os.path.join(ROOT_DIR, "configs")
DATA_DIR = os.path.join(ROOT_DIR, "data")

FAILED_PATH = os.path.join(RESULTS_DIR, 'failed.txt')
SUCCESS_PATH = os.path.join(RESULTS_DIR, 'success.txt')
ACCS_REFS_PATH = os.path.join(RESULTS_DIR, 'accounts_refs.txt')
SUCCESS_TASKS_PATH = os.path.join(RESULTS_DIR, 'tasks_success.txt')
FAILED_TASKS_PATH = os.path.join(RESULTS_DIR, 'tasks_failed.txt')
SUCCESS_MINT_PATH = os.path.join(RESULTS_DIR, 'mint_success.txt')
FAILED_MINT_PATH = os.path.join(RESULTS_DIR, 'mint_failed.txt')
DATABASE_PATH = os.path.join(DATA_DIR, 'data.db')
LOG_PATH = os.path.join(LOG_DIR, 'log.log')
REFS_PATH = os.path.join(CONFIGS_DIR, "REFS.txt")
PROOFS_PATH = os.path.join(CONFIGS_DIR, "PROOF_TEXT.txt")
FARM_PATH = os.path.join(CONFIGS_DIR, "farm.txt")
REGISTER_PATH = os.path.join(CONFIGS_DIR, "register.txt")
PROXIES_PATH = os.path.join(CONFIGS_DIR, "proxies.txt")
WALLETS_TO_REFS_PATH = os.path.join(CONFIGS_DIR, "get_refs.txt")
WALLETS_TO_COMPLETE_TASKS_PATH = os.path.join(CONFIGS_DIR, "wallets_to_complete_tasks.txt")
WALLETS_TO_MINT_NFT = os.path.join(CONFIGS_DIR, "wallets_to_mint_nft.txt")
X_AUTH_TOKENS_PATH = os.path.join(CONFIGS_DIR, "x_tokens.txt")
FAILED_CONNECT_TWITTER_PRIVATE_KEY = os.path.join(RESULTS_DIR, 'twitter_private_keys_failed.txt')
FAILED_CONNECT_TWITTER_AUTH_TOKEN = os.path.join(RESULTS_DIR, 'twitter_auth_tokens_failed.txt')
SUCCESS_CONNECT_TWITTER_PRIVATE_KEY = os.path.join(RESULTS_DIR, 'twitter_private_keys_success.txt')
SUCCESS_CONNECT_TWITTER_AUTH_TOKEN = os.path.join(RESULTS_DIR, 'twitter_auth_tokens_success.txt')
TWITTER_VERIFIED = os.path.join(RESULTS_DIR, 'twitter_verified.txt')
TWITTER_IS_NOT_VERIFIED = os.path.join(RESULTS_DIR, 'twitter_is_not_verified.txt')

TWITTER_USERNAMES = {
    'layeredge': 'layeredge',
    'dev': 'ayushbuidl'
}