import os
print('TOKEN set:', bool(os.getenv('TELEGRAM_BOT_TOKEN')))
print('CHAT_ID:', os.getenv('TELEGRAM_CHAT_ID'))
