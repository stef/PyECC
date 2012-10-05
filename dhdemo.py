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

def test():
    print '-' * 90
    print ' '*30, '2 user DH test'
    print
    _2user()

    print '-' * 90
    print ' '*30, 'error handling'
    print
    try: wrongkey()
    except: print traceback.format_exc()
    try: shortkey()
    except: print traceback.format_exc()

    print '-' * 90
    print ' '*30, '3 user DH test'
    print
    _3user()

    print '-' * 90
    print ' '*30, 'multi-party ECDH'
    print
    mpecdh()

class ECDH:
    def __init__(self, curve="p521"):
        self.curve=curve
        self.key=None
        self.verify=None
        self.public, self.exp = _pyecc.dh1(curve)

    def MPDH(self, point, i, us, other):
        #print peers.index(self), i, us, other
        if not other:
            self.finish(point)
        elif i<len(us):
            us[i].MPDH(self.addpeer(point), i+1, us, other)
        else:
            half1=other[:len(other)/2]
            half2=other[len(other)/2:]
            p=self.addpeer(point)
            if half1: half1[0].MPDH(p, 1, half1, half2 )
            if half2: half2[0].MPDH(p, 1, half2, half1 )

    def addpeer(self, point):
        return _pyecc.dhn(point, self.exp, self.curve)

    def finish(self,point):
        self.key, self.verify=_pyecc.dh3(point, self.exp, self.curve)
        return (self.key, self.verify)

    def __repr__(self):
        return str(peers.index(self))

    def __str__(self):
        return str((self.key,self.verify))

def mpecdh():
    peers=[ECDH() for _ in range(9)]
    half1=peers[:len(peers)/2]
    half2=peers[len(peers)/2:]
    half1[1].MPDH(half1[0].public, 2, half1, half2)
    half2[1].MPDH(half2[0].public, 2, half2, half1)
    print '\n'.join(map(str,peers))

print "-" * 80
test()

