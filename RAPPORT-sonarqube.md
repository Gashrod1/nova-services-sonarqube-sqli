# TP — Détection et correction d'une injection SQL avec SonarQube

NOVA SERVICES — Application étudiée : TIWAP (commit `1f9d2ac`), analysée sans
être exécutée.

## Environnement

| Élément | Valeur |
|---|---|
| SonarQube | Community Build **26.10.0.133078** (`sonarqube:community`) |
| Base SonarQube | PostgreSQL 17 (conteneur `db`, non publié sur l'hôte) |
| Scanner | `sonarsource/sonar-scanner-cli:latest`, réseau `sonarnet`, cible `http://sonarqube:9000` |
| Profil qualité Python | *Sonar way core* (profil par défaut, 232 règles actives) |
| Interface | `127.0.0.1:9000` uniquement |

Le mot de passe PostgreSQL est dans `.env` (exclu de Git). Le jeton d'analyse
est passé en variable d'environnement au moment du `docker compose run`. Il
n'apparaît ni dans `sonar-project.properties` ni dans ce rapport.

## Questions de déploiement (section 5)

**Q1 — Pourquoi PostgreSQL plutôt que le conteneur applicatif ?**
Un conteneur est jetable : il est recréé à chaque mise à jour de l'image. Les
projets, l'historique des analyses, les issues, les utilisateurs et les jetons
doivent survivre à ces recréations. La base H2 intégrée n'est prévue que pour
l'évaluation : elle ne supporte ni la volumétrie ni les montées de version. Une
base dédiée se sauvegarde, se restaure, se surveille et se sécurise
séparément. C'est aussi cet historique qui permet de suivre l'évolution des
anomalies d'une version à l'autre.

**Q2 — `http://sonarqube:9000` entre conteneurs, `http://localhost:9000` dans le navigateur ?**
Docker Compose fournit un DNS interne au réseau `sonarnet`, qui résout chaque
nom de service vers son conteneur. Dans le conteneur `scanner`, `localhost`
désignerait le scanner lui-même. Le navigateur, lui, tourne sur l'hôte : il ne
voit pas ce DNS et passe par le port publié `127.0.0.1:9000:9000`, accessible
uniquement depuis la machine locale.

## 8. Analyse initiale — état des lieux

```
84 fichiers indexés · 14 fichiers Python, 2 PHP, HTML, JS, Dockerfile
2 368 lignes de code
```

| Mesure | Valeur |
|---|---|
| Vulnérabilités | **31** |
| Note de sécurité | **E** (la plus mauvaise) |
| Bugs | 5 |
| Code smells | 16 |
| Security Hotspots | 0 (dans cette version, les anciens hotspots sont présentés comme des vulnérabilités, avec le tag `former-hotspot`) |

Répartition des 31 vulnérabilités par règle :

| Règle | Nb | Sujet |
|---|:-:|---|
| python:S4790 | 4 | Hachage faible (MD5) |
| Web:S5725 | 4 | Ressources externes sans contrôle d'intégrité (SRI) |
| python:S2092 / S3330 | 3 + 3 | Cookies sans `Secure` / `HttpOnly` |
| python:S4830 | 3 | Certificat TLS non vérifié (`verify=False`) |
| python:S2068 / javascript:S2068 | 2 + 2 | Mots de passe en dur |
| python:S6779 | 1 | Clé secrète Flask divulguée |
| python:S8392 | 1 | Application liée à toutes les interfaces |
| secrets:S6706 | 1 | Clé privée dans le dépôt |
| python:S4502 | 1 | Protection CSRF désactivée |
| python:S5659 | 1 | JWT sans vérification de signature |
| python:S5247 | 1 | Auto-échappement Jinja2 désactivé |
| python:S4507 | 1 | Mode debug activé |
| python:S2245 | 1 | Générateur pseudo-aléatoire |
| docker:S6470 / S6471 | 1 + 1 | `COPY .` récursif / image exécutée en root |

### Constat principal : **aucune injection SQL n'a été signalée**

TIWAP contient pourtant au moins **7 requêtes SQL construites par
concaténation** dans `vulnerabilities/SQLi.py` (lignes 22, 40, 63, 82, 100,
123, 145).

Exemple, `sqli_low` (`SQLi.py:22-25`) :

```python
stmt = "SELECT userid, username FROM users WHERE username='%s' AND password='%s'" \
       % (str(username), str(password))
result = cur.execute(stmt)
```

**Pourquoi l'outil ne la voit pas :**

1. La règle de **détection d'injection par analyse de flux** (taint analysis,
   `S3649` : « Database queries should not be vulnerable to injection attacks »)
   **n'existe pas dans SonarQube Community Build**. L'API répond
   `Rule not found: python:S3649`. Cette analyse, qui suit une donnée depuis
   `request.form` jusqu'à `cursor.execute()`, est réservée aux éditions
   commerciales.
2. La règle restante, `python:S2077` « SQL queries should not be dynamically
   formatted », **est bien active** dans le profil par défaut, mais ne s'est pas
   déclenchée. Explication probable : le curseur est obtenu via
   `dbmanager.get_db_connection().cursor()`, un objet global défini dans un
   autre module (`helper/db_manager.py`). L'analyseur ne parvient pas à
   déduire que `cur` est un curseur `sqlite3`, donc il ne reconnaît pas
   `cur.execute(...)` comme une exécution SQL. *(Hypothèse cohérente avec le
   comportement observé, non vérifiée dans le code de l'analyseur.)*

**Confirmation manuelle.** La requête de `sqli_low` a été rejouée à
l'identique sur une **copie** de `TIWAP.db`, sans lancer l'application :

| Entrée | Résultat |
|---|---|
| `inconnu` / `faux` | `[]` (refusé, comportement normal) |
| `x' OR '1'='1' --` / n'importe quoi | **les 5 comptes**, dont `admin` → contournement de l'authentification |
| Même charge, requête paramétrée (`?`) | `[]` → la correction neutralise l'attaque |

**Conclusion.** Pour ce TP, un rapport SonarQube Community sans injection SQL
ne prouve **pas** l'absence d'injection SQL. C'est exactement l'avertissement
de l'énoncé. L'outil doit être complété par :
- une revue de code ciblée (recherche de `execute(` + `%`, `f"`, `.format`, `+`) ;
- des tests de sécurité (tests unitaires d'injection, DAST) ;
- ou une édition disposant de l'analyse de flux, si le budget le permet.

### 8.1 Qualification des résultats

Légende **Confiance** :
- **Confirmé** : vérifié dans le code.
- **Contextuel** : réel dans le code, mais l'impact dépend du déploiement.
- **Non signalé** : trouvé par revue de code, pas par l'outil.

| Identifiant | Fichier:ligne | Règle | Type | Impact potentiel | Confiance | Action |
|---|---|---|---|---|---|---|
| — *(non signalé)* | `vulnerabilities/SQLi.py:22` (et 40, 63, 82, 100, 123, 145) | Aucune (S3649 absente, S2077 non déclenchée) | Vulnérabilité, injection SQL (CWE-89) | Contournement de l'authentification, lecture de toute la table `users` | **Confirmé** par rejeu | **Corriger** : requêtes paramétrées |
| `df2be43b-…-ebec8b9619b3` | `app.py:29` | python:S6779 | Vulnérabilité (Blocker) | `secret_key` Flask en dur, donc falsification des cookies de session (usurpation de compte) | Confirmé | Corriger : clé lue depuis l'environnement ou Vault, puis renouvelée |
| `5595860a-…-3a13c5ea6eba` | `certificate/server.key:1` | secrets:S6706 | Vulnérabilité (Blocker) | Clé privée TLS publique dans le dépôt : déchiffrement ou usurpation du serveur | Confirmé (`BEGIN RSA PRIVATE KEY`) | Corriger : retirer du dépôt, **révoquer**, régénérer |
| `425e5717-…-f09323215677` | `app.py:913` | python:S8392 (+ S4507) | Vulnérabilité (Blocker) | `host='0.0.0.0'` + `debug=True` : console de débogage Werkzeug joignable depuis le réseau, donc exécution de code | Confirmé | Corriger : `debug=False`, écoute limitée, serveur WSGI en production |
| `b3ed95ef-…-efa83a0d9b37` | `helper/auth.py:39` | python:S5659 | Vulnérabilité (Critical) | JWT décodé sans vérifier la signature : n'importe qui forge un jeton `sub=admin` | Confirmé (`verify_signature: False`) | Corriger : vérifier la signature avec une clé secrète |
| `82f32ad2-…-490780e1b574` | `app.py:28` | python:S4502 | Vulnérabilité (Critical) | Pas de protection CSRF : actions forcées depuis un site tiers | Contextuel | Corriger (Flask-WTF / CSRFProtect) |
| `137c3cb7-…-48949eb5ec5b` | `app.py:723` (+ 728, 731) | python:S4830 | Vulnérabilité (Critical) | `verify=False` : interception (MITM) des appels sortants | Contextuel (cible locale `0.0.0.0`) | Corriger : activer la vérification TLS |
| `445b9d04-…-b6f19e782ff5` | `helper/db_manager.py:47` (+ `SQLi.py:151`) | python:S4790 | Vulnérabilité (Critical) | Mots de passe stockés en **MD5** sans sel : cassables en quelques secondes en cas de fuite de la base | Confirmé | Corriger : bcrypt / argon2 |
| `b6445e5d-…-994794d28a39` | `helper/mongodb_manager.py:68` | python:S2068 | Vulnérabilité (Major) | Comptes de démonstration en dur (MD5 de `admin`) | Confirmé, données de démo | Documenter si démo, sinon retirer |
| `2244ab1c-…-6643b0139b84` | `app.py:40` | python:S5247 | Vulnérabilité (Major) | Jinja2 sans auto-échappement : XSS / injection de template | Confirmé | Corriger : `Environment(autoescape=True)` |
| `4c0434ce-…-1fd5b063e597` / `c561186b-…-c9383a900052` | `app.py:848` | python:S2092 / S3330 | Vulnérabilité (Minor) | Cookie JWT sans `Secure` ni `HttpOnly` : vol par XSS ou en clair | Confirmé | Corriger : `secure=True, httponly=True, samesite` |
| `1e22d322-…-7e6e4b716497` | `Dockerfile:4` | docker:S6470 | Vulnérabilité (Critical) | `COPY . /app` embarque `server.key`, `TIWAP.db` et `.git` dans l'image | Confirmé | Corriger : `.dockerignore`, copie sélective |
| `45a13f62-…-121a2e3668b7` | `app.py:760` | python:S2245 | Vulnérabilité (Major) | `randint` pour un niveau de stock affiché | **Faux positif** dans ce contexte (pas d'usage cryptographique) | Documenter et marquer comme sûr |

**Observations sur l'outil :**
- L'outil signale bien les **mauvaises configurations visibles localement**
  (secret, `verify=False`, `debug=True`). Il rate la vulnérabilité la plus
  emblématique de TIWAP, qui demande de suivre un flux de données.
- La sévérité SonarQube ne remplace pas la qualification : le PRNG (Major) est
  un faux positif ici, alors que l'injection SQL, absente du rapport, est la
  plus grave.
- `Dockerfile` : l'image de base `python:3.6` n'est plus maintenue depuis 2021.
  SonarQube ne le signale pas, c'est le rôle d'un scanner d'image comme Trivy.

## Architecture du laboratoire (§14, point 2)

```
 Navigateur (hôte) ──► 127.0.0.1:9000 ──┐
                                        ▼
 ┌──────────────────────── réseau Docker « sonarnet » ────────────────────────┐
 │  scanner (sonar-scanner-cli) ──http://sonarqube:9000──► sonarqube (UI+API) │
 │        │ monte ./TIWAP en lecture → /usr/src                │ JDBC        │
 │        ▼                                                    ▼             │
 │   code de TIWAP (non exécuté)                        db (PostgreSQL 17)   │
 └────────────────────────────────────────────────────────────────────────────┘
 Volumes persistants : postgresql_data, sonarqube_data, sonarqube_extensions, sonarqube_logs
```

- `db` n'est publié sur aucun port de l'hôte : seul `sonarqube` y accède.
- `sonarqube` n'est publié que sur `127.0.0.1` : pas d'accès depuis le réseau local.
- `scanner` est dans un profil Compose : il ne démarre pas avec `up -d`, seulement avec `docker compose run`.
- Le mot de passe PostgreSQL est dans `.env` (non versionné), le jeton d'analyse est passé au moment du `run`.

## 9. Mécanisme de l'injection SQL dans TIWAP

### 9.1 Chemin de données (de l'entrée utilisateur à la requête)

| Étape | Emplacement | Code |
|---|---|---|
| 1. Point d'entrée HTTP | `app.py:136-138` | `@app.route('/sql-injection', methods=['POST', 'GET'])` → `sql_injection()` (utilisateur connecté, niveau 0) |
| 2. Lecture de l'entrée | `app.py:145-146` | `username = request.form.get('username')`, `password = request.form.get('password')` |
| 3. Appel métier | `app.py:147` | `sqli.sqli_low(username=username, password=password)` |
| 4. Construction de la requête | `vulnerabilities/SQLi.py:22-23` | `"... WHERE username='%s' AND password='%s'" % (str(username), str(password))` |
| 5. Exécution | `vulnerabilities/SQLi.py:25` | `cur.execute(stmt)` sur la base SQLite `TIWAP.db` |
| 6. Retour à l'utilisateur | `app.py:149` | les lignes renvoyées (ou le message d'erreur SQL) sont affichées dans la page |

Aucune validation ni séparation entre l'étape 2 et l'étape 5 : la valeur saisie
dans le formulaire devient directement **du texte SQL**.

### Mécanisme

La requête est construite comme une chaîne, puis envoyée telle quelle à SQLite.
SQLite ne peut pas distinguer ce qui vient du développeur (la structure) de ce
qui vient de l'utilisateur (les valeurs). Avec la saisie `x' OR '1'='1' --` :

```sql
SELECT userid, username FROM users WHERE username='x' OR '1'='1' --' AND password='peu-importe'
```

- `'` ferme la chaîne ouverte par le développeur ;
- `OR '1'='1'` ajoute une condition toujours vraie ;
- `--` transforme la fin de la requête (le contrôle du mot de passe) en commentaire.

Résultat : la condition est vraie pour toutes les lignes, **les 5 comptes de
`users` sont renvoyés**, dont `admin` (rejoué sur une copie de la base, §8). Une
simple apostrophe (`O'Brien`) suffit aussi à casser la requête, et le message
d'erreur SQL brut (`near "Brien": syntax error`) est renvoyé à l'utilisateur,
ce qui aide un attaquant à comprendre la requête.

**Autres requêtes du fichier.** `sqli_medium`, `sqli_hard` et les trois
fonctions `blind_sqli_*` utilisent le même schéma (`'%s' % ...`). `sqli_hard`
ne fait qu'une liste noire de chaînes (`"1' OR 1=1"`…), contournable.
`secure_login` (ligne 147) utilise une f-string et retire `'` et `"` de
l'entrée : l'injection y est beaucoup plus difficile, mais c'est un filtrage,
pas une séparation des données, donc une mauvaise pratique. Conformément à
l'énoncé (« modifiez uniquement la fonction concernée »), seule `sqli_low` a
été corrigée : les autres restent en **risque résiduel** documenté (voir §13).

## 10. Correction de la requête

Branche de travail : `fix/sql-injection-lab` (commit `bd689a5`, dépôt local, non poussé).

```diff
     try:
-        stmt = "SELECT userid, username FROM users WHERE username='%s' AND password='%s'" \
-               % (str(username), str(password))
+        # Requête paramétrée : la structure SQL est fixe, les entrées sont
+        # transmises au pilote sqlite3 comme des valeurs (marqueur « ? »).
+        stmt = "SELECT userid, username FROM users WHERE username = ? AND password = ?"
 
-        result = cur.execute(stmt)
+        result = cur.execute(stmt, (str(username), str(password)))
 
-    except sqlite3.OperationalError as e:
-        return e
+    except sqlite3.OperationalError:
+        # Ne pas renvoyer le message SQL détaillé à l'utilisateur.
+        return "Erreur lors de la requête"
```

**Explication technique.**
- La requête SQL est désormais une **constante** : sa structure est fixée par le
  développeur et ne dépend plus des saisies.
- Les valeurs sont transmises **séparément** au pilote `sqlite3` dans un tuple.
  SQLite les lie aux marqueurs `?` comme des données : `x' OR '1'='1' --` est
  cherché comme un nom d'utilisateur littéral, il ne modifie plus la logique.
- Le marqueur `?` est celui du module `sqlite3` (paramstyle `qmark`). Avec
  PostgreSQL et `psycopg`, ce serait `%s` (passé en paramètre, jamais avec `%`).
- Le comportement fonctionnel est conservé : même colonnes, même type de retour
  (`list` de tuples), même cas « User Exists » pour un utilisateur existant.
- Le message d'erreur SQL brut n'est plus renvoyé (bonne pratique 10.2).

### 10.2 Bonnes pratiques complémentaires appliquées ou recommandées

| Pratique | Application ici |
|---|---|
| Requêtes paramétrées pour les valeurs | Appliquée dans `sqli_low` |
| Validation métier des entrées | Recommandée (longueur, jeu de caractères du nom d'utilisateur), **en complément** seulement |
| Compte de base de données à privilèges minimaux | Non applicable à SQLite (fichier local) ; pour NOVA : compte applicatif en lecture seule sur les tables nécessaires |
| Ne pas considérer le filtrage de caractères comme suffisant | `secure_login` et `sqli_hard` montrent ce mauvais schéma : à reprendre |
| Ne pas renvoyer les erreurs SQL détaillées | Appliquée (message générique) |
| Tests de non-régression | Ajoutés (`tests/test_sqli_regression.py`) |
| Liste blanche pour les identifiants SQL dynamiques (table, colonne) | Non nécessaire ici : aucun nom de table ou de colonne n'est dynamique |

Les mots de passe sont stockés en MD5 (S4790, §8.1) : c'est un autre problème,
non traité dans cette correction.

## 11. Copie de correction et tests

```
cd TIWAP
git switch -c fix/sql-injection-lab
git diff            # → uniquement vulnerabilities/SQLi.py (+ tests ajoutés)
```

TIWAP ne contient **aucun test Python**. Un test de non-régression a donc été
écrit : `TIWAP/tests/test_sqli_regression.py` (pytest). Chaque test travaille
sur une **copie temporaire** de `TIWAP.db` ; l'application n'est jamais lancée.

| Test | Ce qu'il vérifie |
|---|---|
| `test_injection_ne_contourne_pas_le_filtre` | La charge `x' OR '1'='1' --` ne renvoie aucun compte |
| `test_quote_traitee_comme_une_valeur` | Une apostrophe est une valeur : pas d'erreur SQL |
| `test_identifiants_inconnus` | Comportement normal : identifiants faux → liste vide |
| `test_utilisateur_existant_comportement_inchange` | Le cas « User Exists » est conservé |

**Le test a été écrit avant la correction et a d'abord échoué** (preuve qu'il
détecte réellement le défaut) :

| Moment | Résultat | Preuve |
|---|---|---|
| Avant correction (`master`) | **2 échecs**, 2 succès : `assert [(1, 'admin')...5, 'pconnor')] == []` et `OperationalError('near "Brien": syntax error')` | `preuve-tests-avant.txt` |
| Après correction (`fix/sql-injection-lab`) | **4 succès** | `preuve-tests-apres.txt` |

Commande : `.venv/bin/pytest -v tests` depuis `TIWAP/` (le `.venv` du dossier du
TP ne contient que pytest).

## 12. Nouvelle analyse et comparaison avant/après

Nouvelle analyse lancée sur la branche `fix/sql-injection-lab` (commit
`bd689a5`, `sonar.projectVersion=1.1-fix`) : `ANALYSIS SUCCESSFUL`, 85 fichiers
indexés (le dossier `tests/` est désormais inclus, 2 fichiers reconnus comme
tests). Le jeton a été passé en variable d'environnement au lancement, il
n'apparaît dans aucun fichier.

| Critère | Avant correction | Après correction |
|---|---|---|
| Anomalie étudiée | Injection SQL dans `sqli_low` (CWE-89), **non signalée** par SonarQube | Corrigée dans le code ; toujours non signalée (attendu, voir ci-dessous) |
| Règle concernée | Aucune : S3649 absente de Community Build, S2077 active mais non déclenchée | Idem |
| Emplacement | `vulnerabilities/SQLi.py:22-25`, appelé par `app.py:145-147` | `vulnerabilities/SQLi.py:22-26` (requête paramétrée) |
| Code vulnérable présent ? | **Oui** (concaténation `'%s' %`) | **Non** pour `sqli_low` ; oui pour les 6 autres fonctions (hors périmètre) |
| Tests de régression | Aucun test dans TIWAP ; test ajouté : 2 échecs | 4/4 succès |
| Mesures SonarQube | 31 vulnérabilités, note E, 5 bugs, 16 code smells | **31 vulnérabilités, note E, 5 bugs, 16 code smells**, 0 hotspot, 2 390 lignes de code (+22 avec le fichier de test) ; sur `SQLi.py`, seule reste l'alerte `python:S4790` (hachage, l. 153), déjà présente avant ; aucune alerte sur `tests/test_sqli_regression.py` |
| Risque résiduel | Contournement d'authentification, lecture de `users` | Faible pour `sqli_low` ; **élevé** pour les autres fonctions de `SQLi.py` |

**Pourquoi SonarQube ne peut pas montrer l'amélioration.** L'anomalie n'ayant
jamais été signalée, sa disparition ne peut pas apparaître dans le tableau de
bord. La conclusion repose donc sur **le code (diff), le rejeu et les tests**,
pas sur l'outil. C'est le cas prévu par l'énoncé : « un résultat inchangé ne
signifie pas automatiquement que la correction est mauvaise ; il faut d'abord
comprendre ce que la règle mesure ».

## 13. Pilotage pour NOVA SERVICES

### Fiche de traitement de l'anomalie

| Champ | Contenu |
|---|---|
| Référence | VULN-SQLI-001 |
| Anomalie | Injection SQL (CWE-89) dans `sqli_low`, contournement d'authentification |
| Origine de la détection | **Revue de code manuelle** (non détectée par SonarQube Community, §8) |
| Actif / application | Application TIWAP (laboratoire). Transposé à NOVA : application de gestion des clients (activité A) et sa base PostgreSQL |
| Données concernées | Table `users` (identifiants, empreintes de mots de passe) ; chez NOVA : données clients |
| Exposition | Laboratoire isolé (127.0.0.1). Chez NOVA : application exposée sur Internet via l'Ingress |
| Exploitabilité | Triviale : une seule requête HTTP, aucune authentification forte requise au niveau 0, charge publique et connue |
| Impact C / I / D | C : 4 (lecture de comptes) · I : 3 (selon les droits du compte SQL, modification possible) · D : 2 |
| Priorité | **P1 — critique** (exposition Internet + données clients + exploitation triviale) |
| Responsable de correction | Responsable de l'équipe de développement de l'application (*propriétaire à désigner*) |
| Valideur | RSSI / équipe sécurité applicative |
| Échéance | 7 jours calendaires pour un P1 exposé (à aligner sur la politique NOVA) ; mesure compensatoire immédiate (règle WAF) si le délai ne peut pas être tenu |
| Statut | `sqli_low` : **corrigé, à vérifier en revue** · 6 autres fonctions : **ouvert** |
| Preuve de correction | Commit `bd689a5`, diff, tests de non-régression (rouge → vert), rejeu de la charge, nouvelle analyse SonarQube |
| Risque résiduel | Autres requêtes concaténées de `SQLi.py` ; absence de détection automatique de ce type de défaut dans l'outil actuel |

### 13.1 Justification de la priorité

| Critère | Évaluation |
|---|---|
| 1. Criticité de l'application et des données | Critique : authentification et données clients (activité A du TP1) |
| 2. Exposition | Directe (Internet) chez NOVA ; nulle dans le laboratoire |
| 3. Exploitabilité | Très élevée : technique connue, outillée (sqlmap), sans prérequis |
| 4. Conséquences C/I/D | Fuite de données (RGPD, notification CNIL), usurpation de comptes, modification de données selon les droits |
| 5. Mesures compensatoires existantes | Inconnues : WAF, compte SQL restreint et journalisation des requêtes sont **à vérifier** |

La note fournie par l'outil n'aide pas ici : **l'outil ne l'a pas vue**. La
priorité vient de l'analyse de risque métier, pas du score.

### 13.2 Mini-tableau de bord (4 indicateurs)

| Indicateur | Définition | Source | Fréquence | Responsable | Décision permise |
|---|---|---|---|---|---|
| Vulnérabilités ouvertes par priorité | Nombre de vulnérabilités qualifiées (P1 à P4) non clôturées, par application | SonarQube (API `issues`) + revues manuelles + outil de tickets | Hebdomadaire | RSSI | Affecter les efforts de correction aux applications les plus exposées |
| P1/P2 hors délai | Nombre de vulnérabilités critiques/élevées dont l'échéance est dépassée | Outil de tickets (date de détection, échéance, statut) | Hebdomadaire | Responsables des équipes de développement | Escalade à la direction, mesure compensatoire, acceptation formelle du risque |
| Délai médian de correction | Médiane du temps entre la détection et la correction **vérifiée** | Tickets + date de la nouvelle analyse ou du test validé | Mensuelle | RSSI | Ajuster les échéances et les ressources des équipes |
| Taux de corrections vérifiées | Part des corrections confirmées par une nouvelle analyse, un test de non-régression ou un rejeu | Tickets (champ « preuve ») + CI | Mensuelle | Équipe sécurité applicative | Refuser la clôture d'un ticket sans preuve ; renforcer les tests |

Indicateur complémentaire : **part des projets analysés** par le SAST dans le
périmètre (couverture). Le nombre brut d'anomalies ne suffit pas : il dépend
des règles activées et de la couverture. Ici, 31 vulnérabilités sont signalées
alors que la plus grave n'en fait pas partie.

## 16. Questions de compréhension

1. **Rôle de PostgreSQL** : base de données de SonarQube (projets, historique des analyses, issues, utilisateurs, jetons). Voir Q1 en début de rapport.
2. **`localhost:9000` vs `sonarqube:9000`** : voir Q2 en début de rapport. Dans le conteneur du scanner, `localhost` désigne le scanner lui-même ; `sonarqube` est résolu par le DNS du réseau `sonarnet`.
3. **Analyse statique vs test d'intrusion dynamique** : le SAST lit le code sans l'exécuter. Il voit tout le code, y compris des chemins rarement atteints, mais il ne connaît pas l'environnement d'exécution et produit des faux positifs et des faux négatifs (comme ici). Le DAST ou le test d'intrusion attaque l'application en fonctionnement : il prouve qu'une faille est exploitable, mais ne couvre que les chemins qu'il atteint et ne montre pas la ligne de code fautive.
4. **Pourquoi la concaténation crée un risque** : la valeur saisie devient une partie du texte SQL. Le moteur ne distingue plus structure et données : une saisie peut fermer une chaîne, ajouter une condition ou commenter la suite (§9).
5. **Pourquoi la requête paramétrée réduit le risque** : la structure est envoyée séparément des valeurs, que le pilote lie comme des données. Quelle que soit la saisie, elle ne peut plus modifier la logique de la requête.
6. **Pourquoi la validation ne remplace pas les paramètres** : un filtre est une liste de cas interdits, toujours incomplète (encodages, guillemets alternatifs, commentaires). `sqli_hard` le montre : sa liste noire est contournable. La validation réduit la surface, le paramétrage supprime la cause.
7. **Pourquoi vérifier et qualifier un résultat SonarQube** : l'outil peut se tromper dans les deux sens. Ici, `randint` (S2245) est un faux positif, et l'injection SQL est un faux négatif. Sans qualification, on corrigerait des faux problèmes et on ignorerait le plus grave.
8. **Si aucune vulnérabilité SQL n'est signalée** : ne pas conclure à l'absence de faille. Vérifier les règles actives et l'édition (taint analysis), faire une revue ciblée (`execute(` + concaténation), écrire un test ou un rejeu, compléter par un DAST, et documenter l'examen manuel dans le compte rendu (ce qui a été fait ici).
9. **Prioriser sur une application métier critique** : combiner la criticité métier de l'application et des données (TP1), l'exposition, l'exploitabilité, l'impact C/I/D et les mesures compensatoires existantes. Fixer une échéance, un responsable et une mesure compensatoire si la correction ne peut pas être immédiate.
10. **Pourquoi le nombre total d'anomalies ne suffit pas** : il mélange des problèmes mineurs et critiques, dépend des règles activées et du volume de code, et ignore ce que l'outil ne voit pas. Ici : 31 vulnérabilités signalées, mais la plus grave absente. Il faut des indicateurs par priorité, par délai et par preuve de correction.
11. **Protections autour du scanner et de son jeton en CI/CD** : jeton de type *projet* (pas global, pas utilisateur administrateur), stocké en variable masquée et protégée de la CI (ou dans Vault), jamais dans le dépôt ni dans les logs ; rotation et révocation ; exécution seulement sur les branches protégées ; serveur SonarQube non exposé publiquement, en HTTPS ; image du scanner épinglée par version ou digest.
12. **Prouver qu'une correction est effective et durable** : effective = diff relu, rejeu de l'attaque qui échoue, nouvelle analyse ; durable = test de non-régression **exécuté en CI à chaque commit**, quality gate qui bloque la fusion, revue de code obligatoire, et indicateur de taux de réouverture.

## Conclusion — limites de l'analyse statique

SonarQube Community a signalé 31 vulnérabilités réelles ou plausibles, surtout
des **mauvaises configurations visibles localement** (secret en dur, debug,
`verify=False`, JWT non vérifié). En revanche, il **n'a pas détecté
l'injection SQL**, la faille la plus grave et la cible du TP. La raison : cette
édition n'a pas d'analyse de flux (taint analysis), et la règle restante (S2077)
ne reconnaît pas un curseur obtenu à travers un autre module.

Pour NOVA SERVICES, le SAST est utile mais **ne suffit pas** : il doit être
combiné à la revue de code, à des tests de sécurité automatisés (comme le test
de non-régression écrit ici) et à un test dynamique (DAST, voir TP3 ZAP). Un
tableau de bord sans vulnérabilité SQL ne prouve pas l'absence d'injection SQL.

## Livrables (§15)

| Livrable | Emplacement | État |
|---|---|---|
| `compose.yaml` sans secret | `compose.yaml` (mot de passe dans `.env`, exclu par `.gitignore`) | ✅ |
| `sonar-project.properties` | `TIWAP/sonar-project.properties` | ✅ |
| Capture de SonarQube montrant le projet | [`captures/`](captures/) | ✅ `sonarqube-projets.png` (liste des projets, TIWAP : Security E/31, Quality Gate Failed), `sonarqube-overview-1.1-fix.png` (vue d'ensemble, version 1.1-fix, 2,4k lignes), `sonarqube-issues-securite.png` (exemples d'anomalies de sécurité Blocker/High) |
| Tableau d'analyse initiale | §8.1 | ✅ |
| Code vulnérable et version corrigée | §9 et §10 (diff) | ✅ |
| Explication technique de la correction | §10 | ✅ |
| Preuve des tests / test de non-régression | §11, `TIWAP/tests/`, `preuve-tests-avant.txt`, `preuve-tests-apres.txt` | ✅ |
| Comparaison avant/après | §12 | ✅ |
| Fiche de traitement NOVA | §13 | ✅ |
| Mini-tableau de bord (4 indicateurs) | §13.2 | ✅ |
| Conclusion sur les limites du SAST | Conclusion | ✅ |

Aucun jeton ni mot de passe n'apparaît dans les livrables.

## À faire par l'utilisateur

1. ~~Relancer l'analyse sur la branche corrigée~~ : fait (commit `bd689a5`, version `1.1-fix`).
2. ~~Capture d'écran du projet `tiwap`~~ : faite (dossier `captures/`).
3. **Nettoyage (§17)** : `sudo docker compose down` (conserve l'historique) et **révoquer le jeton** dans SonarQube (Mon compte → Sécurité).
