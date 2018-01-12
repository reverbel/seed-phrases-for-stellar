# -*- python -*-
# -*- coding: UTF-8 -*-

# electrum_mnemonic
# Copyright (C) 2017 Francisco Reverbel
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


import binascii
import hashlib
import hmac
import string
import unicodedata

######################################################################
# This module is entirely made of code copied and/or adapted from the
# Electrum Bitcoin client (https://github.com/spesmilo/electrum)
######################################################################


# Start of section copied and/or adapted from
# https://github.com/spesmilo/electrum/blob/22d5d29b819bd7f2db221049144febe082d36882/lib/version.py


# The hash of the mnemonic seed must begin with this
ELECTRUM_SEED_PREFIX      = '01'      # Standard wallet
ELECTRUM_SEED_PREFIX_2FA  = '101'     # Two-factor authentication
ELECTRUM_SEED_PREFIX_SW   = '100'     # Segwit wallet


# Start of section copied and/or adapted from
# https://github.com/spesmilo/electrum/blob/857eb4ac1d8e1ee24b48245ecaf59edcf096cbfa/lib/mnemonic.py


# http://www.asahi-net.or.jp/~ax2s-kmtn/ref/unicode/e_asia.html
CJK_INTERVALS = [
    (0x4E00, 0x9FFF, 'CJK Unified Ideographs'),
    (0x3400, 0x4DBF, 'CJK Unified Ideographs Extension A'),
    (0x20000, 0x2A6DF, 'CJK Unified Ideographs Extension B'),
    (0x2A700, 0x2B73F, 'CJK Unified Ideographs Extension C'),
    (0x2B740, 0x2B81F, 'CJK Unified Ideographs Extension D'),
    (0xF900, 0xFAFF, 'CJK Compatibility Ideographs'),
    (0x2F800, 0x2FA1D, 'CJK Compatibility Ideographs Supplement'),
    (0x3190, 0x319F , 'Kanbun'),
    (0x2E80, 0x2EFF, 'CJK Radicals Supplement'),
    (0x2F00, 0x2FDF, 'CJK Radicals'),
    (0x31C0, 0x31EF, 'CJK Strokes'),
    (0x2FF0, 0x2FFF, 'Ideographic Description Characters'),
    (0xE0100, 0xE01EF, 'Variation Selectors Supplement'),
    (0x3100, 0x312F, 'Bopomofo'),
    (0x31A0, 0x31BF, 'Bopomofo Extended'),
    (0xFF00, 0xFFEF, 'Halfwidth and Fullwidth Forms'),
    (0x3040, 0x309F, 'Hiragana'),
    (0x30A0, 0x30FF, 'Katakana'),
    (0x31F0, 0x31FF, 'Katakana Phonetic Extensions'),
    (0x1B000, 0x1B0FF, 'Kana Supplement'),
    (0xAC00, 0xD7AF, 'Hangul Syllables'),
    (0x1100, 0x11FF, 'Hangul Jamo'),
    (0xA960, 0xA97F, 'Hangul Jamo Extended A'),
    (0xD7B0, 0xD7FF, 'Hangul Jamo Extended B'),
    (0x3130, 0x318F, 'Hangul Compatibility Jamo'),
    (0xA4D0, 0xA4FF, 'Lisu'),
    (0x16F00, 0x16F9F, 'Miao'),
    (0xA000, 0xA48F, 'Yi Syllables'),
    (0xA490, 0xA4CF, 'Yi Radicals'),
]


def is_CJK(c):
    n = ord(c)
    for imin,imax,name in CJK_INTERVALS:
        if n>=imin and n<=imax: return True
    return False


def normalize_text(seed):
    # normalize
    seed = unicodedata.normalize('NFKD', seed)
    # lower
    seed = seed.lower()
    # remove accents
    seed = ''.join([c for c in seed if not unicodedata.combining(c)])
    # normalize whitespaces
    seed = ' '.join(seed.split())
    # remove whitespaces between CJK
    seed = ''.join([seed[i] for i in range(len(seed))
                            if not (seed[i] in string.whitespace
                                    and is_CJK(seed[i-1])
                                    and is_CJK(seed[i+1]))])
    return seed


# Start of section copied and/or adapted from
# https://github.com/spesmilo/electrum/blob/6f954090e650f6415d922a3153b4cfb3c11fbb7f/lib/util.py


def bin_to_hexstr(x):
    """
    str with hex representation of a bytes-like object

    >>> x = bytes((1, 2, 10))
    >>> bin_to_hexstr(x)
    '01020A'

    :param x: bytes
    :rtype: str
    """
    return binascii.hexlify(x).decode('ascii')


# Start of section copied and/or adapted from
# https://github.com/spesmilo/electrum/blob/44a83c240120aca7bf35ea518cec393cb9232956/lib/bitcoin.py


hmac_sha_512 = lambda x, y: hmac.new(x, y, hashlib.sha512).digest()


def is_new_electrum_seed_phrase(x, prefix=ELECTRUM_SEED_PREFIX):
    s = bin_to_hexstr(hmac_sha_512(b'Seed version', x.encode('utf8')))
    return s.startswith(prefix)


def is_old_electrum_seed_phrase(seed):
    from . import old_electrum_mnemonic
    words = seed.split()
    try:
        # checks here are deliberately left weak for legacy reasons, see #3149
        old_electrum_mnemonic.mn_decode(words)
        uses_electrum_words = True
    except Exception:
        uses_electrum_words = False
    try:
        seed = bfh(seed)
        is_hex = (len(seed) == 16 or len(seed) == 32)
    except Exception:
        is_hex = False
    return is_hex or (uses_electrum_words
                      and (len(words) == 12 or len(words) == 24))


def electrum_seed_type(x):
    if is_old_electrum_seed_phrase(x):
        return 'Old (pre 2.0) Electrum'
    elif is_new_electrum_seed_phrase(x):
        return 'Electrum standard'
    elif is_new_electrum_seed_phrase(x, ELECTRUM_SEED_PREFIX_SW):
        return 'Electrum segwit'
    elif is_new_electrum_seed_phrase(x, ELECTRUM_SEED_PREFIX_2FA):
        return 'Electrum 2FA'
    return 'UNKNOWN'
