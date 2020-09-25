import sys
from collections import Counter
from math import gcd # for kasinski

alphabet = "abcdefghijklmnopqrstuvwxyz"
#Introdução, problema, solucao, resultados, conclusão e referências


#decryption method
def decrypt(ctxt, key):                     #ciphertext + key
    plaintext = ''                          #initializes the plaintext string
    for i in range(len(ctxt)):              #iterates the ciphertext
        # gets plain character position subtracting cipher character pos by key pos
        pchar_i = (alphabet.index(ctxt[i]) - alphabet.index(key[i % len(key)]) + len(alphabet)) % len(alphabet)
        plaintext += alphabet[pchar_i]      #appends the character to plaintext string
    return plaintext

def kasinski(ctxt):



#here the magic happens
def main(argv):
    if(len(argv) < 1):#need 1 argument (the file name plus extension)
        print("sorry, try again!")
        print("call example:\npython vigenere.py testfile.txt")
        exit()
    ciphertext = open(argv[0]).read().lower() #reads file context to lowercase
    language = input('from which language are you trying to decipher? (en,ptbr)')


    print(ciphertext)
    print(decrypt("gcyczfmlyleim","ayush"))

if __name__ == '__main__':
    main(sys.argv[1:])
