import struct
import time
import getpass
# --- IDEA block cipher.

out=[]
#multiplication of sub-key with part of plaintext
def _idea_mul(a, b):
  if a:
    if b:
      p = a * b
      b, a = p & 0xffff, p >> 16
      return (b - a + (b < a)) & 0xffff
    else:
      return (1 - a) & 0xffff
  else:
    return (1 - b) & 0xffff

#to compute multiplicative inverse of sub-keys required for decryption
def _idea_inv(x):
  if x <= 1:
    return x
  t1, y = divmod(0x10001, x)
  t0 = 1
  while y != 1:  # Eucledian GCD.
    q, x = divmod(x, y)
    t0 += q * t1
    if x == 1:
      return t0
    q, y = divmod(y, x)
    t1 += q * t0
  return (1 - t1) & 0xffff

#single round of modified IDEA
def _idea_crypt(ckey, block, _mul=_idea_mul, _pack=struct.pack, _unpack=struct.unpack):
  
  if ((len(block)%8)!=0 ):
        raise ValueError('IDEA block size must be multiple of 8, got: %d' % len(block))
  else:
      n=8 
      out = [(block[i:i+n]) for i in range(0, len(block), n)]     
      
   
      give=""
      for i in out:  
         a, b, c, d = _unpack('>4H', i)
         for j in xrange(0, 42, 6):
            a, b, c, d = _mul(a, ckey[j]), (b + ckey[j + 1]) & 0xffff, (c + ckey[j + 2]) & 0xffff, _mul(d, ckey[j + 3])
            t, u = c, b
            c = _mul(a ^ c, ckey[j + 4])
            b = _mul(((b ^ d) + c) & 0xffff, ckey[j + 5])
            c = (c + b) & 0xffff
            a ^= b
            d ^= c
            b ^= t
            c ^= u
         give = give + (_pack('>4H', _mul(a, ckey[42]), (c + ckey[43]) & 0xffff, (b + ckey[44]) & 0xffff, _mul(d, ckey[45])))
      return give

class IDEA(object):
  """IDEA block cipher."""

  key_size = 16
  block_size = 8

  __slots__ = ('_ckey', '_dkey')
#sub-key generation
  def __init__(self, key, _inv=_idea_inv):
    if ((len(key)%16)!=0 ):
        raise ValueError('IDEA key size must be multiple of 16, got: %d' % len(key))
    else:
       n=16 
       out = [(key[i:i+n]) for i in range(0, len(key), n)]     
        
      
       give=[]
       for j in out:  
         ckey = [0] * 46
         ckey[:8] = struct.unpack('>8H', j)
         for i in xrange(0, 38):
           ckey[i + 8] = (ckey[(i & ~7) + ((i + 1) & 7)] << 9 | ckey[(i & ~7) + ((i + 2) & 7)] >> 7) & 0xffff
         give = give + ckey
       ckey=tuple(give)       
       self._ckey = tuple(ckey)
       dkey = [0] * 46
       dkey[42], dkey[43], dkey[44], dkey[45] = _inv(ckey[0]), 0xffff & -ckey[1], 0xffff & -ckey[2], _inv(ckey[3])
       for i in xrange(36, -6, -6):
          dkey[i + 4], dkey[i + 5], dkey[i], dkey[i + 3] = ckey[40 - i], ckey[41 - i], _inv(ckey[42 - i]), _inv(ckey[45 - i])
          dkey[i + 1 + (i > 0)], dkey[i + 2 - (i > 0)] = 0xffff & -ckey[43 - i], 0xffff & -ckey[44 - i]
       self._dkey = tuple(dkey)
#encryption
  def encrypt(self, block, _idea_crypt=_idea_crypt):
    return _idea_crypt(self._ckey, block)
#decryption
  def decrypt(self, block, _idea_crypt=_idea_crypt):
    return _idea_crypt(self._dkey, block)


del _idea_mul, _idea_inv, _idea_crypt

#main
if __name__ == '__main__':
 
 
  print("INTERNATIONAL DATA ENCRYPTION ALGORITHM ")
  print (" \n")
  key1=raw_input("Enter key (multiple of 16) : ")
  
  hh=raw_input("Enter the plaintext (multiple of 8) : ")
  key=key1.encode('hex')
  #invoking time function
  ms1 = int(round(time.time() * 1000000))
  print("Start time of Execution ")
  print(ms1)
  hd=hh.encode('hex')
  plaintext=hd.decode('hex')

  cb = IDEA(key.decode('hex'))
  print "Encrypting"
  print (".\n.\n.\n.")
  ciphertext = cb.encrypt(plaintext)
  print "CipherText: " + ciphertext
  print ("\n\n")
  print "Decrypting"
  print (".\n.\n.\n.")
  assert cb.decrypt(ciphertext) == plaintext
  plaintext2 = cb.decrypt(ciphertext)
  print "PlainText:" + plaintext2
  import sys
  print >>sys.stderr, __file__ + ' OK.'
  ms2 = int(round(time.time() * 1000000))
  print("End time of Execution ")
  print(ms2)
  
  ms=ms2-ms1
  
  print("Estimated Execution time ")
  print(ms)