import sys
n = int(sys.argv[1])
# Only semiprimes n = p*q with p != q are useful to the caller; anything
# else (prime powers, multiprime) used to die on the unpack with a
# ValueError. Print "0 0" instead so the wrapper sees a plain miss.
if len(str(n)) >= 40:
  try:
    pq, z = qsieve(n)
    p, q = pq
    print(p, q)
  except (ValueError, TypeError):
    print(0, 0)
else:
  f = list(factor(n))
  if len(f) == 2 and f[0][1] == 1 and f[1][1] == 1:
    print(f[0][0], f[1][0])
  else:
    print(0, 0)
