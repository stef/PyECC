#!/usr/bin/env python
import _pyecc, traceback

def _2user():
    # 1st user
    public, exp = _pyecc.dh1(u'p521')
    print "public:    \t%s\nexp:    \t%s" % (public, exp)
    print
    # 2nd user
    public, key, verification = _pyecc.dh2(public, u'p521')
    print "public:    \t%s\nkey:    \t%s\nverification:\t%s" % (public, key, verification)
    print
    # 1st user completing DH
    key, verification = _pyecc.dh3(public, exp, u'p521')
    print "key:    \t%s\nverification:\t%s" % (key, verification)

def shortkey():
    print "fail short key"
    public, exp = _pyecc.dh1(u'p521')
    public, key, verification = _pyecc.dh2(public[:-1], u'p521')

def wrongkey():
    print "fail wrong key"
    public, exp = _pyecc.dh1(u'p521')
    public, key, verification = _pyecc.dh2('x' * len(public), u'p521')

def _3user():
    pA, eA = _pyecc.dh1(u'p521')
    print "A public:    \t%s\nA exp:    \t%s" % (pA, eA)

    pB, eB = _pyecc.dh1(u'p521')
    print "B public:    \t%s\nB exp:    \t%s" % (pB, eB)

    pC, eC = _pyecc.dh1(u'p521')
    print "C public:    \t%s\nC exp:    \t%s" % (pC, eC)

    print
    pAB = _pyecc.dhn(pA, eB, 'p521')
    print "public AB", pAB
    pBA = _pyecc.dhn(pB, eA, 'p521')
    print "public BA", pBA
    pCA = _pyecc.dhn(pC, eA, 'p521')
    print "public CA", pCA

    print
    key, verification = _pyecc.dh3(pCA, eB, u'p521')
    print "key:    \t%s\nverification:\t%s" % (key, verification)
    key, verification = _pyecc.dh3(pBA, eC, u'p521')
    print "key:    \t%s\nverification:\t%s" % (key, verification)
    key, verification = _pyecc.dh3(pAB, eC, u'p521')
    print "key:    \t%s\nverification:\t%s" % (key, verification)

print '-' * 90
print ' '*30, '2 user DH test'
print
_2user()

print '-' * 90
print ' '*30, '3 user DH test'
print
_3user()

print '-' * 90
print ' '*30, 'error handling'
print
try: wrongkey()
except: print traceback.format_exc()
try: shortkey()
except: print traceback.format_exc()
