#!/usr/bin/env python
import random
import string
import argparse
import subprocess

parser = argparse.ArgumentParser(description='Random testing')
parser.add_argument("--num", type=int, default=100)
parser.add_argument("--seed", type=int, default=None)
args = parser.parse_args()

if args.seed != None:
    random.seed(args.seed)

print ("Running %d testcases..." % (args.num))

for i in xrange(0,args.num):
    key_len = random.randint(1,16)
    plain_len = random.randint(1,1024)
    key = ''.join(random.choice(string.printable) for _ in range(key_len))
    plain = ''.join(random.choice(string.printable) for _ in range(plain_len))
    ripr = subprocess.check_output(["python", "myrc4.py", key, plain]).strip().upper()
    orig = subprocess.check_output(["./a.out", key, plain]).strip().upper()
    if ripr != orig:
        print ("FAIL:\n'%s' vs. '%s'" % (orig, ripr))
        print ("Key: %s\nPlain:\n'%s'" % (key, plain))
        exit()
print "Everything is OK!"
