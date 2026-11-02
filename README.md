# NOVA SERVICES — Injection SQL détectée/corrigée avec SonarQube et Docker

Rendu du TP « Détection et correction d'une injection SQL avec SonarQube et Docker ».

| Fichier | Contenu |
|---|---|
| [`RAPPORT-sonarqube.md`](RAPPORT-sonarqube.md) | Rapport complet (analyse, qualification, correction, comparaison, questions) |
| [`compose.yaml`](compose.yaml) | SonarQube Community + PostgreSQL 17 + scanner (profil `scan`) |
| [`correction/`](correction/) | Correctif (`git format-patch`), test de non-régression, `sonar-project.properties` |
| `preuve-tests-avant.txt` / `preuve-tests-apres.txt` | Sorties pytest avant (2 échecs) et après correction (4 succès) |

## Reproduire

```bash
git clone https://github.com/tombstoneghost/TIWAP.git
cd TIWAP && git checkout -b fix/sql-injection-lab
git am ../correction/0001-fix-sqli-requete-parametree.patch
cp ../correction/sonar-project.properties . && cd ..
cp .env.example .env              # puis mettre un mot de passe aléatoire
docker compose up -d db sonarqube # http://127.0.0.1:9000
docker compose run --rm -e SONAR_TOKEN='<jeton>' scanner
```

Le jeton SonarQube n'est jamais écrit dans un fichier du dépôt. TIWAP est une
application volontairement vulnérable : ne pas l'exposer hors de la machine locale.
