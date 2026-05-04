# Guide — Mettre VulnScan Pro sur GitHub

## ÉTAPE 1 — Créer un compte GitHub (si pas encore fait)

Aller sur https://github.com et créer un compte.

---

## ÉTAPE 2 — Installer Git et configurer ton identité sur la VM Debian

Copier-coller ces commandes dans ton terminal Debian :

```bash
sudo apt-get install -y git
```

```bash
git config --global user.name "TonPrenomNom"
git config --global user.email "ton@email.com"
git config --global init.defaultBranch main
```

---

## ÉTAPE 3 — Créer un token GitHub (remplace le mot de passe)

GitHub n'accepte plus les mots de passe pour git push.
Il faut créer un token :

1. Aller sur https://github.com/settings/tokens
2. Cliquer sur "Generate new token (classic)"
3. Donner un nom : "vulnscan-debian"
4. Cocher : repo (tout cocher sous repo)
5. Cliquer "Generate token"
6. COPIER le token — il ne s'affiche qu'une fois (commence par ghp_...)

---

## ÉTAPE 4 — Créer le dépôt sur GitHub

1. Aller sur https://github.com/new
2. Repository name : vulnscan-pro
3. Description : Outil d'audit de sécurité automatisé — scan de vulnérabilités et rapport PDF professionnel
4. Choisir Public ou Private
5. NE PAS cocher "Add a README" (on en a déjà un)
6. Cliquer "Create repository"

---

## ÉTAPE 5 — Initialiser et pousser le projet depuis la VM

Se placer dans le dossier du projet :

```bash
cd ~/vulnscan
```

Initialiser Git et faire le premier commit :

```bash
git init
git add .
git commit -m "feat: initial release VulnScan Pro v1.0"
```

Connecter au dépôt GitHub (remplacer TON_USERNAME par ton pseudo GitHub) :

```bash
git remote add origin https://github.com/TON_USERNAME/vulnscan-pro.git
git branch -M main
git push -u origin main
```

GitHub va demander ton nom d'utilisateur et ton mot de passe.
- Username : ton pseudo GitHub
- Password : coller le token ghp_... (pas ton vrai mot de passe)

---

## ÉTAPE 6 — Sauvegarder le token pour ne plus le retaper (optionnel)

```bash
git config --global credential.helper store
```

La prochaine fois tu n'auras plus à retaper le token.

---

## Pour les prochaines mises à jour

Quand tu modifies le code, tu fais :

```bash
git add .
git commit -m "fix: description de ce que tu as changé"
git push
```

---

## Commandes Git utiles

| Commande | Description |
|----------|-------------|
| git status | Voir les fichiers modifiés |
| git add . | Ajouter tous les fichiers modifiés |
| git commit -m "message" | Sauvegarder les changements |
| git push | Envoyer sur GitHub |
| git log --oneline | Voir l'historique des commits |
| git diff | Voir les modifications en cours |
