# security-headers-checker

Audit **hors ligne** des en-têtes de sécurité HTTP d'une réponse web, en Python (bibliothèque standard). L'outil lit des en-têtes que vous avez déjà récupérés (par exemple avec `curl -I https://monsite` ou depuis les outils de développement du navigateur) : **il n'envoie aucune requête réseau**.

À utiliser sur vos propres sites ou sur des sites d'entraînement.

## Ce qu'il vérifie

- **Strict-Transport-Security** (HSTS) et durée d'application ;
- **Content-Security-Policy** : présence et directives risquées (`'unsafe-inline'`, `'unsafe-eval'`, joker `*`) ;
- **X-Content-Type-Options** (`nosniff`) ;
- protection contre le **clickjacking** (`X-Frame-Options` ou `frame-ancestors`) ;
- **Referrer-Policy** et **Permissions-Policy** ;
- fuite d'informations (`Server` avec version, `X-Powered-By`) ;
- drapeaux des **cookies** (`Secure`, `HttpOnly`, `SameSite`).

## Utilisation

```bash
curl -sI https://example.com > entetes.txt      # récupération (vos propres sites)
python3 headers_check.py entetes.txt
# ou directement : curl -sI https://example.com | python3 headers_check.py
```

Deux exemples fictifs sont fournis dans `samples/`. Sortie sur le mauvais exemple :

```
[MANQUANT ] Strict-Transport-Security: Absent : le navigateur n'est pas forcé à utiliser HTTPS.
[ATTENTION] Content-Security-Policy: Présent mais affaibli par : 'unsafe-inline', joker *.
[MANQUANT ] X-Content-Type-Options: Absent ou différent de 'nosniff' : le navigateur peut deviner un autre type de contenu.
[MANQUANT ] Protection anti-clickjacking: Ni X-Frame-Options ni frame-ancestors : la page peut être affichée dans une iframe tierce.
[MANQUANT ] Referrer-Policy: Absent : l'URL complète peut être transmise aux sites tiers.
[ATTENTION] Permissions-Policy: Absent : pas de limitation explicite caméra, micro, géolocalisation...
[ATTENTION] Fuite d'informations: Technologies et versions exposées : Server: Apache/2.4.41 (Ubuntu) (version visible) ; X-Powered-By: PHP/7.4.3.
[ATTENTION] Cookies: Drapeaux manquants : PHPSESSID (manque Secure, HttpOnly, SameSite) ; theme (manque HttpOnly, SameSite).

Note : 25/100
```

Le code de sortie vaut `0` si tout est conforme et `1` sinon, ce qui permet de l'utiliser dans une chaîne d'intégration continue.

## Concepts illustrés

- Rôle de chaque en-tête de sécurité et attaques qu'il atténue (XSS, clickjacking, interception, fuite d'URL).
- Analyse d'en-têtes HTTP (insensibles à la casse, plusieurs `Set-Cookie`).
- Lien avec la catégorie « Mauvaise configuration de sécurité » de l'OWASP Top 10.

## Tests

```bash
python3 -m unittest -v
```

## Limites

Les règles sont volontairement simples : une politique CSP sans `'unsafe-inline'` n'est pas pour autant parfaite. La note sur 100 est indicative. Les en-têtes dépendent aussi de la page demandée.

## Pistes d'amélioration

- Analyser la CSP directive par directive.
- Ajouter les en-têtes `Cross-Origin-*` (COOP, COEP, CORP).
- Proposer l'option de récupérer les en-têtes d'une URL que l'on possède, avec un avertissement d'usage.

## Licence

MIT, voir [LICENSE](LICENSE).

---

*Réalisé avec l'aide de Claude (IA), relu et testé par l'auteur.*
