# Hill (100 solves, 89 points)

## Problem:
I found these characters on top of a hill covered with algae ... bruh I can't figure it out can you help me?

wznqca{d4uqop0fk_q1nwofDbzg_eu}

by bnuno

## Solution:
From the title, it looks like we have a Hill cipher: https://en.wikipedia.org/wiki/Hill_cipher

And knowing the flag format, we can do a known plaintext attack.

With 6 known characters, we can guess that the key is a 2x2 matrix, which only requires 4 known characters. Any larger key requires more than 6 known characters.

Let the key be denoted as K.
Knowing that "utflag" maps to "wznqca", we know that:

<img src=http://latex2png.com/pngs/089bb66973de29ff6771dc4e2526e096.png>
<img src=http://latex2png.com/pngs/adb13f7b38f95632958c9476a0716d8e.png>
and
<img src=http://latex2png.com/pngs/86eac93e1f76e72a84bbd8292967d3d8.png>

Notice that from the first two equations,

<img src=http://latex2png.com/pngs/7d80e0cd1e6c2534ffd7e296631ba486.png>

Now since 

<img src=http://latex2png.com/pngs/79042ee0121f7fa183907de48b034dab.png>

we can do 

<img src=http://latex2png.com/pngs/ad483a5d32bd3e55484af3abf1fc3e6b.png>

to get K.

From there, we just need to split the characters into pairs, place them in a 2x1 matrix, and left multiply them by K<sup>-1</sup>.

We also need to be wary of the capital D and the other symbols in the flag.

## Code:
The code below prints the flag in small letters so I manually changed the T to caps to get the flag.
inv26 is just a helper function to find the inverse modulo 26 of a number using Extended Euclidean algorithm: https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm.
tempM is the known plaintext matrix and tempC is the corresponding ciphertext matrix. tempK is the key matrix.
```python3
from numpy import *

def inv26(x):
    a1 = 1
    b1 = 0
    c1 = x%26
    a2 = 0
    b2 = 1
    c2 = 26
    while c1>0 and c2>0:
        if c1>c2:
            a1-=a2*(c1//c2)
            b1-=b2*(c1//c2)
            c1%=c2
        elif c2>c1:
            a2-=a1*(c2//c1)
            b2-=b1*(c2//c1)
            c2%=c1
    if c1>0:
        return a1
    else:
        return a2

c = list("wznqca{d4uqop0fk_q1nwofDbzg_eu}".lower())
tempM = array([[20, 5], [19, 11]])

d = int(round(linalg.det(tempM)))
tempM = multiply(linalg.inv(tempM), d*inv26(d)).astype("int")
tempM = remainder(tempM, 26)

tempC = array([[22, 13], [25, 16]])

tempK = dot(tempC, tempM)
tempK = remainder(tempK, 26)
"""
print(remainder(dot(tempK, array([[20], [19]])), 26))#22, 25
print(remainder(dot(tempK, array([[5], [11]])), 26))#13, 16
print(remainder(dot(tempK, array([[0], [6]])), 26))#2, 0
"""
d = int(round(linalg.det(tempK)))
tempK = multiply(linalg.inv(tempK), d*inv26(d)).astype("int")
tempK = remainder(tempK, 26)

i=0
while i < len(c):
    if c[i]>="a" and c[i]<="z":
        for j in range(i+1, len(c)):
            if c[j]>="a" and c[j]<="z":
                C = array([[ord(c[i])-ord("a")], [ord(c[j])-ord("a")]])
                C = remainder(dot(tempK, C), 26)
                c[i] = chr(C[0][0]+ord("a"))
                c[j] = chr(C[1][0]+ord("a"))
                i=j
                break
    i+=1

ans = ""
for i in c:
    ans += i
print(ans)

```

## Flag
```
utflag{d4nger0us_c1pherText_qq}
```
