REGISTER_MODE = False
FARM_MODE = False

# ┏━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃     REFERRAL TIMING    ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━┛
# The time that referrals will be registering

DAYS = 0
HOURS = 0
MINUTES = 10

# ┏━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃   DELAY BEFORE START   ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━┛
# The time in seconds the account will wait before process, 60 * 60 = 1 hour

MIN_DELAY_BEFORE_START = 0
MAX_DELAY_BEFORE_START = 12 * 60 * 60

# ┏━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ SSL CERTIFICATE VERIFY ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━┛
# False only if error: SSLCertVerificationError: (1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed

SSL = True

# ┏━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃     CHECK TWITTER      ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━┛

CHECK_IS_TWITTER_VERIFIED = False

# ┏━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃      TASKS CONFIG      ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━┛
# Enable or disable tasks

DELAY_BETWEEN_ACCOUNTS = 0.2

MIN_DELAY_BEFORE_START_TASKS = 0
MAX_DELAY_BEFORE_START_TASKS = 20 * 60

DO_PROOF = False                         # Send proof
DO_SUBMIT_PROOF_TASK = False             # Complete the task with proof confirmation
DO_LIGHT_NODE_RUN_TASK = False           # Complete the task with light node confirmation
DO_PLEDGE_PASS_HOLD_TASK = False         # Complete the task with free pass
DO_OG_PLEDGE_PASS_HOLD_TASK = False      # Complete the task with OG pass
DO_CONNECT_TWITTER_TASK = True           # Connect twitter and verify task
DO_FOLLOW_LAYEREDGE_TASK = False          # Complete the task: 'Follow @layeredge on X'
DO_FOLLOW_AYUSHBUIDL_TASK = False          # Complete the task: 'Follow @ayushbuidl on X'

# ┏━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃      MINT PASSES       ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━┛
# Enable or disable tasks

MINT_FREE_PASS = False                   # Mint free pledge pass. Need ETH to pay transaction fees
MINT_MINT_POH = True                    # Mint OG pledge pass for 0.0009 ETH
MIN_DELAY_BETWEEN_ACCOUNTS = 30        # in seconds
MAX_DELAY_BETWEEN_ACCOUNTS = 120        # in seconds
