# Key Management

This directory includes tips to store and manage keys

---

### Store options and keys in a single file called "inputs.txt"

inputs.txt should contain the following:

- Transmit or Receive on **Line 1**
- Module Number on **Line 2**
- Frequency table number on **Line 3**
- 24 word key on **Line 4**

---

inputs.txt format example:

----START FILE----
1<br>
0<br>
17<br>
harmonics feline laziness paycheck swampland steadily bondless flatly legroom purplish paralyze regain spiritism armoire jogging legged landed destruct dictation tubular plated basics unvalued boxy
----END FILE----

---

### It is HIGHLY recommended to encrypt the key with gpg

- **Encryption:** *gpg --symmetric --cipher-algo AES256 --output inputs.txt.gpg inputs.txt*

- **Decryption / Piping:** *( gpg --batch --quiet --no-tty --decrypt inputs.txt.gpg | sed -n '1,4p'; cat ) | script -q -c 'env -i HOME="$HOME" PATH="/usr/bin:/bin" bash -c "set -o pipefail; stty -echo; trap \"stty echo\" EXIT; exec ./build/main"' /dev/null*

### decrypt_and_pipe.sh contains the Decryption / Piping command so you can just run it to decrypt and auto input your transmission options
