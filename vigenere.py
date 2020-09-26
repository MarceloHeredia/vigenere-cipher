import sys
from collections import Counter

alphabet = "abcdefghijklmnopqrstuvwxyz"
language = ''
ptbr_cindex = 0.072723  # default ptbr ioc
en_cindex = 0.0655  # default en ioc

# letter frequency in each language
ptbr_freqs = [.1463, .0104, .0388, .0499, .1257, .0102, .0130, .0128, .0618, .0040, .0002, .0278, .0474,
              .0505, .1073, .0252, .0120, .0653, .0781, .0434, .0463, .0167, .0001, .0021, .0001, .0047]
en_freqs = [.08167, .01492, .02782, .04253, .12702, .02228, .02015, .06094, .06966, .00153, .00772, .04025,
            .02406, .06749, .07507, .01929, .00095, .05987, .06327, .09056, .02758, .00150, .01974, .00074]

max_keylen = 0


# Introdução, problema, solucao, resultados, conclusão e referências
# aux functions
def is_closer(given, actual, target):  # determines if a given ioc is closer than the actually selected ioc
    if abs(target - given) < abs(target - actual):
        return True
    return False


# decryption method
def decrypt(ctxt, key):  # ciphertext + key
    plaintext = ''  # initializes the plaintext string
    for i in range(len(ctxt)):  # iterates the ciphertext
        # gets plain character position subtracting cipher character pos by key pos
        pchar_i = (alphabet.index(ctxt[i]) - alphabet.index(key[i % len(key)]) + len(alphabet)) % len(alphabet)
        plaintext += alphabet[pchar_i]  # appends the character to plaintext string
    return plaintext


def test_ioc(text):  # texts index of coincidence of given text
    freq_each_char = Counter(text)  # counts occurrences of each character in given text
    ioc = 0
    for index in list(alphabet):  # implements IOC summation formula
        ioc += (freq_each_char[index] * (freq_each_char[index] - 1))

    return ioc / (len(text) * (len(text) - 1))  # return sum divided by text len * text len -1


# splits the ciphertext  based on key size
def split_ciphertext(ctxt, ksize):
    sptexts = []  # list of strings to divide text by key size
    for i in range(ksize):  # initialize empty string in list position
        sptexts.append('')

    for i in range(len(ctxt)):  # foreach character in the ciphertext
        sptexts[i % ksize] += ctxt[i]  # adds character to selected

    return sptexts


def sum_iocs(sptext):  # sum IOC of each part of split text
    sum_iocs = 0

    for i in range(len(sptext)):
        sum_iocs += test_ioc(sptext[i])  # adds the IOC of each string part of the ciphertext
    return sum_iocs / len(sptext)  # returns average IOC of given text


def friedman(ctxt):
    used_lang_ioc = en_cindex if language == 'en' else ptbr_cindex  # default language is ptbr
    keylen = 0  # initial expected key length
    closest = 0  # initial expected closest value to the index of coincidence of the language
    avg_ioc = []  # average index of  coincidence list (index = keylength, value = average ioc)

    for i in range(1, max_keylen + 1):
        avg_ioc.append(sum_iocs(split_ciphertext(ctxt, i)))
    for i in range(max_keylen):
        if is_closer(avg_ioc[i], closest, used_lang_ioc):
            closest = avg_ioc[i]
            keylen = i + 1
    return keylen


def find_key(ctxt, key_size):
    split_text = split_ciphertext(ctxt, key_size)
    for i in range(key_size):
        cmmchars = []
        cnter_3 = Counter(split_text[i]).most_common(3)
        for j in range(len(cnter_3)):
            mfc = cnter_3[j][0]  # should be equal to the most freq alphabet letter
            freqs = en_freqs if language == 'en' else ptbr_freqs
            mfc_in_lang = alphabet[freqs.index(max(freqs))]  # most frequent character in choosen language
            cmmchars.append(alphabet[alphabet.index(mfc) - alphabet.index(mfc_in_lang)])

        print('the three most likely key character n', i, ' are: ', cmmchars[0],
              ', ', cmmchars[1],
              ', ', cmmchars[2])

# here the magic happens
def main(argv):
    if (len(argv) < 1):  # need 1 argument (the file name plus extension)
        print("sorry, try again!")
        print("call example:\npython vigenere.py testfile.txt")
        exit()
    ciphertext = open(argv[0]).read().lower()  # reads file context to lowercase
    # 'gcyczfmlyleim'

    global language
    language = input('from which language are you trying to decipher? (en,ptbr): ').lower()
    if language not in {'en', 'ptbr'}:
        print('language must be either en or ptbr')
        exit()
    global max_keylen
    max_keylen = int(
        input('type the maximum key length you think the cipher use (i suggest trying low values first):  '))

    print('the expected key size is ', friedman(ciphertext))

    used_size = int(input('which key size do you wish to use? '))

    find_key(ciphertext, used_size)

    used_key = input('which key do you want to use? ').lower()
    print('The plaintext is: ')
    print(decrypt(ciphertext, used_key))


if __name__ == '__main__':
    main(sys.argv[1:])
