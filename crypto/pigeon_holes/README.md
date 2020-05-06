# Pigeon Holes (Crypto 350)
Cars are just computers on wheels these days! See if you can extract the secret device key from this electronic key customization server: challenge.acictf.com:27730 firmware_server.py
- The flag will be a recognizable english phrase
- The flag will consist of ascii characters, digits, and underscores (\_)
- The flag will contain a bit of '1337' speak

Solves: 15
# Source Analysis
This challenge provided us with the source code for the firmware server, located here.

Generally, since this is a high point crypto challenge, we're looking for issues with crypto implementation or use. So, we can ignore most of the source code and focus in a bit on exactly what is happening involving crypto.

```python
def generate_image(self):
    img = "Rev:%s::Vin:%s::DeviceKey:%s::Name:%s::User_Title:%s::Code:%s" % (
                                       self.revision,
                                       self.vin,
                                       self.device_key,
                                       self.name,
                                       self.user_title,
                                       self.firmware_code)
    #sys.stderr.write(img)
    #sys.stderr.write("\n")
    compressed_img = zlib.compress(img.encode('utf-8'), level=9)

    cipher = AES.new(self.aes_key, AES.MODE_GCM)
    final = cipher.encrypt_and_digest(compressed_img)[0]

    #sys.stderr.write("Legnth: %s" % len(final))

    if (len(final) > 229):
        print("[X] Fatal Error: Final Firmware Image too large: (%d bytes)" % len(final))
        sys.stdout.flush()
        return

    return final
```
This function handles the encryption of the generated image, which, is first constructed with some user input and some static variables (the flag is one of these). This data is then compressed and encrypted.

# Approach
Taking stock of what we have provided to us, the algorithm at use here is AES-GCM, we have an information leak regarding the length of the ciphertext, and the goal is to decrypt the flag (secret) located within the ciphertext. The source code also shows that the firmware image is compressed before it is encrypted.

These three things together set the stage for an attack based on CRIME, or a compression oracle.

The idea behind a compression oracle is that the attacker is able to observe how the compression effects the ciphertext; which will reveal whether a specific guess is correct or not. So, by observing the normal length of the ciphertext when a known incorrect guess is provided to the length when an arbitrary guess if provided, when the length appears lower, the attacker can deduce that their guess was correct.

So, this challenge is going to be similar to the previous AES related one, Speak Plainly -- we're going to leak the key one byte at a time.

# Solution
Thankfully, the challenge author picked AES-GCM, which operates in a counter mode vice a block mode. This means that the length of the ciphertext will be equal to the length of the plaintext, allowing us to easily compare the length of our guesses. _This doesn't mean this attack is not feasible on AES-CBC, it's just simpler without the block complexity._

```python
from pwn import *
import string

def guess(p, guess):
    vin = '45678901234567890'
    p.recvuntil('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@')
    p.sendline('1')
    p.sendline(vin)
    inp = '^:DeviceKey:'+guess
    p.sendline(inp)

    p.recvuntil('Reflash Code? (y/n)')
    p.sendline('y')
    result1 = p.recvuntil('bytes)').split(':')[2].split(' ')[1].lstrip('(')

    return int(result1)

p = remote('challenge.acictf.com', 62335)

length = 101

s = "ThiS_1s_th3_fl4G"

for x in '_'+string.ascii_letters+string.digits:
    p.info("Trying {:s}".format(s+x))
    res1 = guess(p,s+x)
    if res1 < 231:
        #ltrs.append(x)
        p.success("Found one character: {:s}, {:s}".format(x,s))
```

A known troublesome property to this type of attack is the fact that there are often false positives. As you get a longer input, the number of these diminishes, but, remains nonetheless. I simply took the approach of manually solving it byte by byte, vice automating the entire process. This actually saved me a good bit of time, as I could easily and logically tell if the next byte appeared logical or incorrect.

After some tweaking, I discovered that my result payload would typically result in a compressed size of 231 bytes. So, I would print out every time I received a ciphertext below that length, which, I then would know corresponded to a correct guess somewhere in the plaintext.

A second method to prevent false positives is called a recursive two try method, where the attacker sends a known good and a known bad guess for each attempt. They then compare the results, looking for when they differ in length. I had trouble getting this to work on this challenge.
