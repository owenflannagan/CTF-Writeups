from sage.all import *

pub_key = "99, 1235, 865, 990, 5, 1443, 895, 1477".split(", ")

length = len(pub_key)

ctxt_str = "11b90d6311b90ff90ce610c4123b10c40ce60dfa123610610ce60d450d000ce61061106110c4098515340d4512361534098509270e5d09850e58123610c9"

ctxt_arr = [ctxt_str[i:i+4] for i in range(0, len(ctxt_str), 4)]
#print ctxt_arr

flag = ""

def short_vec(row):
    for val in row[:-1]:
        if val != 1 and val != 0:
            return False
    return True

for ctxt in ctxt_arr:
    ctxt = int(ctxt, 16)
    A = Matrix(ZZ, length+1, length+1)
    for i in xrange(length):
        A[i, i] = 1
    for i in xrange(length):
        A[i, length] = int(pub_key[i])
    A[length, length] = -ctxt
    res = A.LLL()
    #print res
    #raw_input()
    
    good_row = []
    for row in res:
        if short_vec(row):
            good_row = row
    if good_row != []:
        flag += chr(int(''.join([str(i) for i in good_row[:-1]])[::-1], 2))

print("Done!")
print flag
