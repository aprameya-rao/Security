# ioc_approve.py — operator triage for zero-day kills awaiting confirmation.
#   python ioc_approve.py                      # list pending
#   python ioc_approve.py --approve TOKEN      # confirm + learn
#   python ioc_approve.py --approve-all        # confirm everything pending
#   python ioc_approve.py --reject TOKEN       # discard without learning
import argparse
import os
import sys

import redis

REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', '6379'))
LEARNED_SET = "threat_intel:learned"
PENDING_LIST = "threat_intel:pending_approval"


def get_redis():
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)
    r.ping()
    return r


def remove_token(r, token):
    removed = False
    for _ in range(r.llen(PENDING_LIST)):
        item = r.lpop(PENDING_LIST)
        if item is None:
            break
        if item == token:
            removed = True
        else:
            r.rpush(PENDING_LIST, item)
    return removed


def main():
    ap = argparse.ArgumentParser(description='Triage pending zero-day IOC confirmations.')
    ap.add_argument('--approve', metavar='TOKEN', help='confirm a token and learn it')
    ap.add_argument('--approve-all', action='store_true', help='confirm every pending token')
    ap.add_argument('--reject', metavar='TOKEN', help='discard a pending token without learning')
    args = ap.parse_args()

    r = get_redis()
    if not (args.approve or args.approve_all or args.reject):
        pending = r.lrange(PENDING_LIST, 0, -1)
        if not pending:
            print("No pending tokens.")
            return
        print("Pending zero-day kills awaiting triage:")
        for tok in pending:
            state = "learned" if r.sismember(LEARNED_SET, tok) else "pending"
            print(f"  {tok}  [{state}]")
        return

    if args.approve_all:
        tokens = list(r.lrange(PENDING_LIST, 0, -1))
        for tok in tokens:
            r.sadd(LEARNED_SET, tok)
        r.delete(PENDING_LIST)
        print(f"Approved and learned {len(tokens)} token(s).")
        return

    token = (args.approve or args.reject).strip().lower()
    if not remove_token(r, token):
        print(f"'{token}' not in pending list.")
        sys.exit(1)
    if args.approve:
        r.sadd(LEARNED_SET, token)
        print(f"Learned '{token}'.")
    else:
        print(f"Rejected '{token}'; not learned.")


if __name__ == '__main__':
    main()