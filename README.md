# VultureSec

VultureSec est un projet conçu pour automatiser le scan de cibles dans le cadre de CTFs (Capture The Flag) ou d'audit de sécurité. L'objectif est d'avoir un seul programme capable de centraliser et d'automatiser différentes étapes de reconnaissance et de detection, en s'appuyant sur des outils CLI sous Linux, comme Nmap ou Nikto par exemple.

Le programme commence par scanner la cible avec Nmap, identifiant ainsi tous les services ouverts ainsi que leurs versions respectives. VultureSec utilise ensuite Searchsploit pour rechercher des vulnérabilités associées aux services détectés via ExploitDB, listant ainsi les CVE potentiels.

En plus de cela, le programme vérifie s'il existe des scans additionnels pertinents et les propose à l'utilisateur, comme par exemple l'utilisation d'enum4linux pour les services SMB.

L'objectif final de VultureSec est de fournir un scan rapide et automatisé, spécifiquement adapté aux CTFs. D'autres tests additionnels seront intégrés en fonction des outils de scan disponibles.


## Installation

Pour installer VultureSec, commencez par télécharger le code source sur votre système Linux (de préférence Debian Based)

`gcc main.c -o vulturesec`

Pour vérifier que toutes les dépendances nécessaires sont bien installées, vous pouvez utiliser la commande : `vulturesec -td`

Si la vérification échoue, cela signifie que certains outils requis ne sont pas installés. Si vous êtes sur une distribution basée sur Debian, il vous suffit d'exécuter la commande suivante pour installer automatiquement toutes les dépendances manquantes : `vulturesec --install`

Note : Dans cette version de VultureSec, l'outil nuclei n'est pas nécessaire. Ainsi, si la commande `vulturesec -td` échoue en raison de l'absence de nuclei, vous pouvez simplement ignorer cette erreur pour le moment.

## Utilisation

### Commandes de base

`vulturesec <target>` : Lance un scan Nmap sur la cible spécifiée, extrait les services détectés, effectue une recherche de vulnérabilités via Searchsploit, et propose des scans additionnels en fonction des services trouvés. Chaque étape génère un fichier contenant les résultats des scans.

### Options

`vulturesec -td` : Vérifie que toutes les dépendances nécessaires sont bien installées.

`vulturesec --install` : Installe toutes les dépendances manquantes.

`vulturesec -s <file>` ou `vulturesec --search <file>` : Prend en entrée un fichier d'output Nmap, filtre ce fichier pour en extraire les services, puis effectue une recherche Searchsploit.

`vulturesec -us <file>` ou `vulturesec --unfiltered-search <file>` : Prend en entrée un fichier et effectue une recherche Searchsploit sans filtrage préalable. Note : Le fichier doit être au format suivant : PORT SERVICE VERSION.
