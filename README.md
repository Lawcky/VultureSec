# VultureSec

VultureSec est un projet conçu pour automatiser le scan de cibles dans le cadre de CTFs (Capture The Flag) ou d'évaluations de sécurité. L'objectif est de disposer d'un seul programme capable de centraliser et d'automatiser différentes étapes de reconnaissance, en s'appuyant sur des outils CLI sous Linux, comme Nmap ou Nikto par exemple.

Le programme commence par scanner la cible avec Nmap, identifiant ainsi tous les services ouverts ainsi que leurs versions respectives. VultureSec utilise ensuite Searchsploit pour rechercher des vulnérabilités associées aux services détectés via ExploitDB, listant ainsi les CVE potentiels.

En plus de cela, le programme vérifie s'il existe des scans additionnels pertinents et les propose à l'utilisateur, comme par exemple l'utilisation d'enum4linux pour les services SMB.

L'objectif final de VultureSec est de fournir un scan rapide et automatisé, spécifiquement adapté aux CTFs. D'autres tests additionnels seront intégrés en fonction des outils de scan disponibles.
