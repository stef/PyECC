#!/usr/bin/env python
import _pyecc

public, exp = _pyecc.dh1(u'p521')
print "public:    \t%s\nexp:    \t%s" % (public, exp)
print
public, key, verification = _pyecc.dh2(public, u'p521')
print "public:    \t%s\nkey:    \t%s\nverification:\t%s" % (public, key, verification)
print
public2, key, verification = _pyecc.dh3(public, exp, u'p521')
print "public:    \t%s\nkey:    \t%s\nverification:\t%s" % (public2, key, verification)

print "fail wrong key"
public, key, verification = _pyecc.dh2('x' * (len(public)-1), u'p521')
