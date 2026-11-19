# Extractions partagées et transmission de l'installation

Chaque membre de `gitusers` peut lancer les extractions avec son propre compte.
Il n'est pas nécessaire de créer un compte technique pour cela. Linux attribue
toutefois un propriétaire individuel à chaque fichier : on transfère
l'installation existante à `root:gitusers`, puis les nouveaux rapports portent
le nom de leur créateur et le groupe `gitusers`. Leur accès ne dépend plus du
compte de la personne ayant installé l'application.

Cette procédure couvre `report`, `report-batch`, `compliance-report`,
`bouquets-report`, `search-rules` et `search-iplists`.

## 1. Préparer la migration avec un administrateur

Les captures confirment l'appartenance du collègue à `gitusers`. La base est
également associée à ce groupe. Cela ne prouve pas que son accès est suffisant :
le `+` affiché par `ls` indique des ACL, et les bits de groupe affichés peuvent
représenter le masque ACL plutôt que les permissions du groupe propriétaire.
Le dossier parent doit aussi permettre la création de WAL/SHM.

Avant de changer les droits, suspendre les collectes et les extractions en cours
et sauvegarder SQLite avec sa méthode de sauvegarde habituelle. Conserver un
relevé des ACL à un emplacement administrateur hors du dossier à modifier.
Ne pas supprimer les fichiers `-wal` ou `-shm`.

Vérifier les prérequis :

```bash
getent group gitusers
command -v getfacl
command -v setfacl
```

Les deux outils proviennent du paquet Linux `acl`. Les installer depuis les
sources internes de l'entreprise s'ils sont absents. Aucun téléchargement
n'est effectué par l'installateur.

## 2. Déployer la version intégrant le partage

Depuis le checkout de la nouvelle version, distinct du dossier de production :

```bash
sudo RULES_RECERTIFY_OWNER=root \
  RULES_RECERTIFY_SHARED_GROUP=gitusers \
  bash scripts/install-prod.sh
```

L'installateur transfère les fichiers existants à `root:gitusers`, conserve
la configuration et les données, et applique les droits de groupe utiles.
Les dossiers de travail reçoivent le bit setgid et des ACL par défaut : les
nouveaux fichiers héritent de `gitusers`. Le lanceur applique `umask 0007`.
Les ACL explicites de `gitusers` complètent les droits Unix de la base,
WAL/SHM, des logs, des rapports et des verrous.

Le `.env` existant en `0660` conserve ce mode. Les fichiers de configuration,
les références brutes, les fichiers d'entrée déjà présents à la racine et
Workloader reçoivent l'accès en lecture nécessaire au groupe. Les snapshots
publiés restent lisibles par le groupe selon leur politique existante.

Le propriétaire et le groupe sont mémorisés dans `var/.shared-owner` et
`var/.shared-group`. Pour les mises à jour suivantes, l'administrateur peut
relancer `sudo bash scripts/install-prod.sh` depuis la nouvelle version :
l'installation conserve `root` et `gitusers`.

Cette opération concerne l'installation sous
`/DATA/mco/illumio-mco/rules_recertify`. Les chemins montrés dans les captures
pour `state_db`, `raw_dir`, `output_dir` et `log_dir` sont tous couverts.
Un chemin configuré en dehors de ce dossier demande des droits équivalents
appliqués séparément par l'administrateur.

## 3. Vérifier avec les comptes des collègues

Dans la session de chaque utilisateur :

```bash
cd /DATA/mco/illumio-mco/rules_recertify
id
namei -l var/state/rules_recertify.sqlite
getfacl -e .env config/local.json var var/state var/state/rules_recertify.sqlite var/output var/logs
./scripts/rules-recertify --config config/local.json --env-file .env init-db
```

`id` doit contenir `gitusers`. Une nouvelle connexion est nécessaire après
l'ajout au groupe. Vérifier également les dossiers parents `/DATA`, `/DATA/mco`
et `/DATA/mco/illumio-mco` si `namei` révèle un défaut de traversée.

Exécuter ensuite les commandes d'extraction habituelles avec le même compte,
par exemple :

```bash
./scripts/rules-recertify --config config/local.json --env-file .env \
  compliance-report --input var/raw/inputs/microcosmos.xlsx
./scripts/rules-recertify --config config/local.json --env-file .env \
  report-batch --microcosmos-xlsx var/raw/inputs/microcosmos.xlsx --lookback-days 120
```

Placer au préalable un fichier Microcosmos lisible par `gitusers` au chemin
indiqué. Un transfert qui impose `0600` au fichier d'entrée peut nécessiter
`chmod g+r` par son propriétaire. Les sorties par défaut vont dans `var/output`.
Avec `--out`, choisir un chemin partagé accessible en écriture, par exemple
`var/output/compliance.xlsx`. La racine de l'application reste administrée par
`root` et ne sert pas de dossier de sortie.

Si l'accès reste refusé, examiner les ACL avec l'administrateur. Une entrée
ACL explicite pour un utilisateur est prioritaire sur les entrées de groupe ;
elle peut donc restreindre un collègue malgré son appartenance à `gitusers`.
L'installateur conserve les autres entrées ACL : faire ajuster ou retirer les
entrées devenues inutiles après examen, plutôt que supprimer toutes les ACL.
Vérifier également les éventuels refus SELinux et les montages en lecture seule.

## 4. Finaliser le départ de l'ancien propriétaire

Après déploiement, un administrateur peut rechercher les fichiers et liens
encore possédés par l'ancien compte, sans afficher leur contenu :

```bash
find /DATA/mco/illumio-mco/rules_recertify -user cx232293 -print
```

L'absence de résultat confirme le transfert de propriété dans cette arborescence.
Faire aussi vérifier les ACL nominatives, les éventuels liens vers un répertoire
personnel et les dépendances placées hors de l'installation.

Les extractions manuelles n'ont pas besoin de compte de service. Les tâches
planifiées, en revanche, s'exécutent toujours sous un compte Linux : faire
transférer les crontabs ou services dépendant de l'ancien compte vers un compte
approuvé par l'équipe, en évitant de lancer deux fois la même collecte.
Vérifier enfin la pérennité des accès PCE et SMTP s'ils dépendent d'identifiants
personnels. L'installateur ne modifie ni les planifications ni ces identifiants.
