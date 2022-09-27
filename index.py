import sys
import getopt


args, opts = getopt.getopt(sys.argv[1:], "i:o:")

for opt, arg in args:
    print(f"{opt}::::  {arg}")
