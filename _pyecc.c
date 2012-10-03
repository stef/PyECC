/*
 *  _pyecc - Copyright 2009 Slide, Inc.
 *
 * This library is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU Lesser General Public License 
 * as published by the Free Software Foundation; either version 2.1 of 
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License 
 * for more details. 
 *
 * You should have received a copy of the GNU Lesser General Public License 
 * along with this library; if not, write to the 
 * Free Software Foundation, Inc., 
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <Python.h>

#include "_pyecc.h"

/*
 * Creating a function pointer type for casting
 */
typedef void (*fp)(void *);

static char pyecc_doc[] = "\
The _pyecc module provides underlying C hooks for the \
\"pyecc\" module\n\n\
Refer to the pyecc documentation for it's use as \
_pyecc is not intended for public consumption as \
it does not provide the proper wrapper and object-\
oriented support that the pyecc module does\n\
";



static char new_state_doc[] = "\
Generate a new ECC_State object that will ensure the \
libgcrypt state necessary for crypto is all set up and \
ready for use\n\
";
static void *_release_state(void *_state)
{
    if (_state)
        ecc_free_state((ECC_State)(_state));
    Py_RETURN_NONE;
}
static PyObject *py_new_state(PyObject *self, PyObject *args, PyObject *kwargs)
{
    ECC_State state = ecc_new_state(NULL);

    PyObject *rc = PyCObject_FromVoidPtr(state, (fp)(_release_state));
    if (!PyCObject_Check(rc)) {
        if (state)
            ecc_free_state(state);
        Py_RETURN_NONE;
    }
    return rc;
}


static char encrypt_doc[] = "\
Encrypt a string buffer of data, expects to be \
passed a buffer, a ECC_KeyPair PyCObject and a \
ECC_State PyCObject \
\n\
";
static PyObject *py_encrypt(PyObject *self, PyObject *args, PyObject *kwargs)
{
    PyObject *temp_state, *temp_keypair;
    ECC_State state;
    ECC_KeyPair keypair;
    char *data;
    unsigned int datalen;

    if (!PyArg_ParseTuple(args, "s#OO", &data, &datalen, &temp_keypair,
            &temp_state)) {
        return NULL;
    }

    if (datalen <= 0) {
        PyErr_SetString(PyExc_TypeError, "data can not have a length of zero");
        return NULL;
    }

    state = (ECC_State)(PyCObject_AsVoidPtr(temp_state));
    keypair = (ECC_KeyPair)(PyCObject_AsVoidPtr(temp_keypair));

    ECC_Data result = ecc_encrypt(data, datalen, keypair, state);

    if ( (result == NULL) || (result->data == NULL) )
        Py_RETURN_NONE;

    return PyString_FromStringAndSize((char *)(result->data), result->datalen);
}

static char decrypt_doc[] = "\
Decrypt a buffer of encrypted data, expects to be \
passed a buffer, a ECC_KeyPair PyCObject and a \
ECC_State PyCObject \
\n\
";
static PyObject *py_decrypt(PyObject *self, PyObject *args, PyObject *kwargs)
{
    PyObject *temp_state, *temp_keypair;
    ECC_State state;
    ECC_KeyPair keypair;
    ECC_Data encrypted;
    char *data;
    int datalen;

    if (!PyArg_ParseTuple(args, "s#OO", &data, &datalen, &temp_keypair,
            &temp_state)) {
        return NULL;
    }

    state = (ECC_State)(PyCObject_AsVoidPtr(temp_state));
    keypair = (ECC_KeyPair)(PyCObject_AsVoidPtr(temp_keypair));
    
    encrypted = ecc_new_data();
    encrypted->data = data;
    encrypted->datalen = datalen;

    ECC_Data result = ecc_decrypt(encrypted, keypair, state);

    if ( (result == NULL) || (result->data == NULL) )
        Py_RETURN_NONE;

    return PyString_FromStringAndSize((char *)(result->data), result->datalen);
}

static char new_keypair_doc[] = "\
Return a new ECC_KeyPair object that will contain the appropriate \
references to the public and private keys in memory\n\
";
static void *_release_keypair(void *_keypair)
{
    if (_keypair) {
        ECC_KeyPair kp = (ECC_KeyPair)(_keypair);
        if (kp->priv) {
            free(kp->priv);
        }
        if (kp->pub) {
            free(kp->pub);
        }
        free(kp);
    }
    Py_RETURN_NONE;
}
static PyObject *py_new_keypair(PyObject *self, PyObject *args, PyObject *kwargs)
{
    char *privkey, *temp_pubkey, *pubkey;
    PyObject *temp_state;
    ECC_State state;
    unsigned int pubkeylen, privkeylen;

    if (!PyArg_ParseTuple(args, "s#z#O", &temp_pubkey, &pubkeylen, 
                &privkey, &privkeylen, &temp_state))
        return NULL;

    /*
     * Copying into a separate buffer lest Python deallocate our
     * string out from under us
     */
    pubkey = (char *)(malloc(sizeof(char) * pubkeylen + 1));
    memcpy(pubkey, temp_pubkey, pubkeylen + 1);
    
    state = (ECC_State)(PyCObject_AsVoidPtr(temp_state));

    ECC_KeyPair kp = ecc_new_keypair_s(pubkey, pubkeylen, privkey, privkeylen, state);

    PyObject *rc = PyCObject_FromVoidPtr(kp, (fp)(_release_keypair));
    if (!PyCObject_Check(rc)) {
        if (kp)
            _release_keypair(kp);
        Py_RETURN_NONE;
    }
    return rc;
}


static char verify_doc[] = "\
Verify that the specified data matches the given signature \
and vice versa. Should return a True/False depending on the \
success of the verification call\n\
";
static PyObject *py_verify(PyObject *self, PyObject *args, PyObject *kwargs)
{
    PyObject *temp_state, *temp_keypair;
    ECC_State state;
    ECC_KeyPair keypair;
    char *data, *signature;

    if (!PyArg_ParseTuple(args, "ssOO", &data, &signature, &temp_keypair,
            &temp_state)) {
        return NULL;
    }

    state = (ECC_State)(PyCObject_AsVoidPtr(temp_state));
    keypair = (ECC_KeyPair)(PyCObject_AsVoidPtr(temp_keypair));

    if (ecc_verify(data, signature, keypair, state)) 
        Py_RETURN_TRUE;
    Py_RETURN_FALSE;
}


static char sign_doc[] = "\
Sign the specified string or block of data \
being passed in. Should return a string representation \
of the signature or None\n\
";
static PyObject *py_sign(PyObject *self, PyObject *args, PyObject *kwargs)
{
    PyObject *temp_state, *temp_keypair;
    ECC_State state;
    ECC_KeyPair keypair;
    char *data;

    if (!PyArg_ParseTuple(args, "zOO", &data, &temp_keypair,
            &temp_state)) {
        return NULL;
    }

    state = (ECC_State)(PyCObject_AsVoidPtr(temp_state));
    keypair = (ECC_KeyPair)(PyCObject_AsVoidPtr(temp_keypair));

    ECC_Data result = ecc_sign(data, keypair, state);
    if ( (result == NULL) || (result->data == NULL) ) 
        Py_RETURN_NONE;
    
    return PyString_FromString((const char *)(result->data));
}

static char keygen_doc[] = "\
Generate a set of keys, returns a tuple containing \
three values: (serialized public key, serialized private key, curve)\n\
";
static PyObject *py_keygen(PyObject *self, PyObject *args, PyObject *kwargs)
{
    ECC_State state;
    ECC_KeyPair keypair;
    PyObject *rc;

    state = ecc_new_state(NULL);
    if (!state)
        Py_RETURN_NONE;

    keypair = ecc_keygen(NULL, state);
    if (!keypair) {
        ecc_free_state(state);
        Py_RETURN_NONE;
    }

    rc = PyTuple_New(3);
   
    /*
     * Returns (pub, priv, curve)
     */
    PyTuple_SetItem(rc, 0, PyString_FromString((const char *)(keypair->pub)));
    PyTuple_SetItem(rc, 1, PyString_FromString(ecc_serialize_private_key(keypair, state)));
    PyTuple_SetItem(rc, 2, PyString_FromString(DEFAULT_CURVE));

    ecc_free_state(state);

    return rc;
}

const char* DHErrors[] = { "Unknown Error",
                           "Out of secure memory",
                           "Invalid key (wrong length)",
                           "Invalid key\n"
};

static char dh1_doc[] = "\
Initiates a DH request, takes the curve \
as a parameter. Should return \
a tuple (public part, exp) or None\n\
";
static PyObject *py_dh1(PyObject *self, PyObject *args, PyObject *kwargs)
{
    char *curve, *temp_curve;
    unsigned int curvelen;

    if (!PyArg_ParseTuple(args, "s#", &temp_curve, &curvelen ))
        return NULL;

    /*
     * Copying into a separate buffer lest Python deallocate our
     * string out from under us
     */
    curve = (char *)(malloc(sizeof(char) * curvelen + 1));
    memcpy(curve, temp_curve, curvelen + 1);

    ECC_DHState dhstate = ecc_dh1(curve);
    if(!dhstate) {
      PyErr_SetString(PyExc_RuntimeError,DHErrors[errno]);
      return NULL;
    }

    return Py_BuildValue("ss",
                         (const char *)(dhstate->public),
                         (const char *)(dhstate->exp)
                         );
}

static char dh2_doc[] = "\
Responds to a DH request, takes the public part from dh1 and \
the curve as a parameter being passed in. Should return \
a tuple (public part , key, verification) or None\n\
";
static PyObject *py_dh2(PyObject *self, PyObject *args, PyObject *kwargs)
{
    char *curve, *keyB, *temp_curve, *temp_keyB;
    unsigned int curvelen, keyBlen;

    if (!PyArg_ParseTuple(args, "s#s#", &temp_keyB, &keyBlen, &temp_curve, &curvelen ))
        return NULL;

    /*
     * Copying into a separate buffer lest Python deallocate our
     * string out from under us
     */
    curve = (char *)(malloc(sizeof(char) * curvelen + 1));
    memcpy(curve, temp_curve, curvelen + 1);
    keyB = (char *)(malloc(sizeof(char) * keyBlen + 1));
    memcpy(keyB, temp_keyB, keyBlen + 1);

    ECC_DHKey dhkey = ecc_dh2(keyB, curve);
    if(!dhkey) {
      PyErr_SetString(PyExc_RuntimeError,DHErrors[errno]);
      return NULL;
    }

    return Py_BuildValue("sss",
                         (const char *)(dhkey->public),
                         (const char *)(dhkey->key),
                         (const char *)(dhkey->verification)
                         );
}

static char dhn_doc[] = "\
Interim multiparty DH request, takes a public, the exp from dh1 and \
the curve as a parameter being passed in. Should return a new public\n";
static PyObject *py_dhn(PyObject *self, PyObject *args, PyObject *kwargs)
{
    char *curve, *keyB, *exp, *temp_exp, *temp_curve, *temp_keyB;
    unsigned int curvelen, keyBlen, explen;

    if (!PyArg_ParseTuple(args, "s#s#s#",
                          &temp_keyB, &keyBlen,
                          &temp_exp, &explen,
                          &temp_curve, &curvelen ))
        return NULL;

    curve = (char *)(malloc(sizeof(char) * curvelen + 1));
    memcpy(curve, temp_curve, curvelen + 1);
    keyB = (char *)(malloc(sizeof(char) * keyBlen + 1));
    memcpy(keyB, temp_keyB, keyBlen + 1);
    exp = (char *)(malloc(sizeof(char) * explen + 1));
    memcpy(exp, temp_exp, explen + 1);

    const char* public = ecc_dhn(keyB, exp, curve);
    if(!public) {
      PyErr_SetString(PyExc_RuntimeError,DHErrors[errno]);
      return NULL;
    }

    return PyString_FromString(public);
}
static char dh3_doc[] = "\
Finishes a DH request, takes the public share, the exp from dh1 and \
the curve as a parameter being passed in. Should return a tuple \
(key, verification) or None\n\
";
static PyObject *py_dh3(PyObject *self, PyObject *args, PyObject *kwargs)
{
    char *curve, *keyB, *exp, *temp_exp, *temp_curve, *temp_keyB;
    unsigned int curvelen, keyBlen, explen;

    if (!PyArg_ParseTuple(args, "s#s#s#",
                          &temp_keyB, &keyBlen,
                          &temp_exp, &explen,
                          &temp_curve, &curvelen ))
        return NULL;

    /*
     * Copying into a separate buffer lest Python deallocate our
     * string out from under us
     */
    curve = (char *)(malloc(sizeof(char) * curvelen + 1));
    memcpy(curve, temp_curve, curvelen + 1);
    keyB = (char *)(malloc(sizeof(char) * keyBlen + 1));
    memcpy(keyB, temp_keyB, keyBlen + 1);
    exp = (char *)(malloc(sizeof(char) * explen + 1));
    memcpy(exp, temp_exp, explen + 1);

    ECC_DHKey dhkey = ecc_dh3(keyB, exp, curve);
    if(!dhkey) {
      PyErr_SetString(PyExc_RuntimeError,DHErrors[errno]);
      return NULL;
    }

    return Py_BuildValue("ss",
                         (const char *)(dhkey->key),
                         (const char *)(dhkey->verification)
                         );
}

static struct PyMethodDef _pyecc_methods[] = {
    {"new_state", (PyCFunction)py_new_state, METH_NOARGS, new_state_doc},
    {"new_keypair", (PyCFunction)py_new_keypair, METH_VARARGS, new_keypair_doc},
    {"verify", (PyCFunction)py_verify, METH_VARARGS, verify_doc},
    {"sign", (PyCFunction)py_sign, METH_VARARGS, sign_doc},
    {"encrypt", (PyCFunction)py_encrypt, METH_VARARGS, encrypt_doc},
    {"decrypt", (PyCFunction)py_decrypt, METH_VARARGS, decrypt_doc},
    {"keygen", (PyCFunction)(py_keygen), METH_NOARGS, keygen_doc},
    {"dh1", (PyCFunction)(py_dh1), METH_VARARGS, dh1_doc},
    {"dh2", (PyCFunction)(py_dh2), METH_VARARGS, dh2_doc},
    {"dhn", (PyCFunction)(py_dhn), METH_VARARGS, dh3_doc},
    {"dh3", (PyCFunction)(py_dh3), METH_VARARGS, dh3_doc},
    {NULL}
};

PyMODINIT_FUNC init_pyecc(void)
{
    PyObject *module = Py_InitModule3("_pyecc", _pyecc_methods, pyecc_doc);
    PyModule_AddStringConstant(module, "DEFAULT_CURVE", DEFAULT_CURVE);
}
