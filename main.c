#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>

// outils à rajouter : subfinder (nom de domaine), implémenter nuclei
// a ajouter également la création du dossier "target" avec tout les scans à l'intérieur (potentiellement une options pour preciser le dossier)
// à ajouter : creation d'un readme pour chaque cible qui regroupera les informations pour chaque scans pour meilleur suivi. 

int website_found, ssh_found, smb_found, dns_found = 0;
//variable global pour les scans additionnel dans main(), ils sont set dans servicesChecker()


int td_found = 0; // test-dependencies
int install_found = 0; // install-dependencies
int toBeFiltered = 0, search_found = 0; // search file 0 = unfiltered-search & 1 = filtered-search
//variable global pour les options dans main(), ils sont set dans argumentChecking()



/////////////////////////////////////////////////////////////
//////////////////////////UNTOCUHED//////////////////////////
/////////////////////////////////////////////////////////////

int filterNmapOutput(char *inputFile, char *outputFile) {
    // create the filtering command
    char filteringCommand[256];
    snprintf(filteringCommand, sizeof(filteringCommand), "grep 'open' %s | awk '{print $1, $3, $4, $5}' | uniq > %s", inputFile, outputFile);

    // Execute the filtering command
    if (system(filteringCommand) != 0) {
        perror("\033[31mErreur lors de l'exécution de grep et awk\033[0m\n");
        return 1;
    }

    return 0;
}

int searchFileVulnerabilities(const char *filteredFile, const int beenFiltered) {

    if (beenFiltered == 0) {
        //the file hasn't been filtered
        printf("\033[33m[Warning]\033[0mCette option à été conçu pour lire un fichier mis dans le même format que l'output classique de Nmap \nsoit:\n");
        printf("\033[1m    PORT     SERVICE    VERSION\033[0m\n");
        printf("Des erreurs peuvent apparaitre si le format n'est pas respecté.\n\n");
    }

    
    FILE *servicesFile = fopen(filteredFile, "r");
    if (servicesFile == NULL) {
        fprintf(stderr, "\033[31mErreur lors de l'ouverture de %s\033[0m\n", filteredFile);
        return 1;
    }

    char ports[20], typeService[50], service[50], version[50];
    char searchsploitCommand[350];
    char buffer[300];

    // Read the filtered services file and search for vulnerabilities
    while (fgets(buffer, sizeof(buffer), servicesFile) != NULL) {
        int fieldCount = sscanf(buffer, "%19s %49s %49s %49s", ports, typeService, service, version);

        if (fieldCount < 3) {
            // en dessous de 3 champs skip la ligne
            continue;
        }

        printf("\033[4;31mService : %s %s\033[0m\n", service, (fieldCount == 4) ? version : "(pas de version)");

        // Construit la commande Searchsploit en fonction du nombre de champs par lignes
        if (fieldCount == 4) {
            // si les 4 champs sont présent
            snprintf(searchsploitCommand, sizeof(searchsploitCommand), "searchsploit \"%s %s\"", service, version);
        } else {
            // si il manque la version
            snprintf(searchsploitCommand, sizeof(searchsploitCommand), "searchsploit \"%s\"", service);
        }

        if (system(searchsploitCommand) == -1) {
            perror("\033[31mErreur lors de l'exécution de searchsploit\033[0m\n");
            fclose(servicesFile);
            return 1;
        }
        printf("\n");
    }
    fclose(servicesFile);
    return 0;
}

/////////////////////////////////////////////////////////////


//recupère l'url du site pour futur scan
char* getSiteURL() {
    static char url[256];  // Taille maximale pour stocker l'URL
    printf("\nEntrez l'URL du site à scanner: ");

    // Utilisation de scanf pour capturer l'URL
    if (scanf("%255s", url) == 1) {
        return url;  // Retourne l'URL saisie
    } else {
        fprintf(stderr, "Erreur lors de la lecture de l'URL.\n");
        return NULL;
    }
}

//fonction pour recupéré la clé api de WPscan dans ~/.wpscankey
char* getWpscanAPIKey() {
    
    static char apiKey[64];  // Taille maximale pour la clé API
    char *homeDir = getenv("HOME");  // Récupère le chemin vers le home directory
    if (homeDir == NULL) {
        fprintf(stderr, "Erreur: Impossible de trouver le home directory.\n");
        return NULL;
    }

    // Construire le chemin vers ~/.wpscankey
    char keyFilePath[64];
    snprintf(keyFilePath, sizeof(keyFilePath), "%s/.wpscankey", homeDir);

    FILE *file = fopen(keyFilePath, "r");
    if (file == NULL) {
        // Si le fichier n'existe pas ou ne peut pas être lu

        fprintf(stderr, "Le fichier %s n'existe pas ou ne peut être lu.\n", keyFilePath);
        return NULL;
    }

    if (fgets(apiKey, sizeof(apiKey), file) != NULL) {

        apiKey[strcspn(apiKey, "\n")] = '\0';  // Supprimer le retour à la ligne de l'API Key
        fclose(file);
        return apiKey;
    } else {

        fprintf(stderr, "Le fichier %s est vide ou ne peut être lu correctement.\n", keyFilePath);
        fclose(file);
        return NULL;
    }
}


/////////////////////////////////////////////////////////////
///////////////////////////CLEARED///////////////////////////
/////////////////////////////////////////////////////////////

int checkDependencies(const char *prog, const char *command) {
    //verifie que la commande donnée est bien installé et fonctionnel
   
    // Vérification des arguments d'entrée
    if (prog == NULL || command == NULL) {
        fprintf(stderr, "\033[41mArguments invalides : prog ou command est NULL.\033[0m\n");
        return 1;
    }

    int status = system(command);
    
    if (status == -1) {
        // Une erreur system()
        fprintf(stderr, "\033[41mErreur lors de l'exécution de la commande : %s. Raison : %s\033[0m\n", command, strerror(errno));
        return 1;

    } else if (WIFEXITED(status)) {
        // Vérification que la commande s'est arrêtée normalement
        int exit_code = WEXITSTATUS(status);

        // Traitement spécial pour Enum4Linux qui retourne != 0
        if (strcmp(prog, "Enum4Linux") == 0 && exit_code == 255) {
            printf("\033[32m%s est installé et fonctionne correctement.\033[0m\n", prog);
            return 0;  // On retourne 0 ici puisque le programme a fonctionné comme attendu
        }

        // Vérification du code de sortie pour les autres programmes
        if (exit_code == 0) {
            printf("\033[32m%s est installé et fonctionne correctement.\033[0m\n", prog);
            return 0;
        } else {
            fprintf(stderr, "\033[31m%s n'a pas fonctionné correctement (code de sortie : %d).\033[0m\n", prog, exit_code);
            return exit_code;
        }
        
    } else {
        // Si la commande ne s'est pas terminée normalement
        fprintf(stderr, "\033[31mLa commande %s n'a pas terminé normalement.\033[0m\n", command);
        return 1;
    }
}

int createScanDirectory(char *directoryName, size_t size) {
    // Fonction pour créer un dossier avec le format "scan(%d-%H-%M)"
    
    // Récupérer la date et l'heure actuelle
    time_t rawtime;
    struct tm *timeinfo;

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    // Formater le nom du dossier: scan(%d-%H-%M)
    snprintf(directoryName, size, "secscan%02d-%02dh-%02dm", 
             timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min);

    // Créer le dossier avec les permissions par défaut (0755)
    if (mkdir(directoryName, 0755) != 0) {
        fprintf(stderr, "\033[31mErreur lors de la création du dossier %s : %s\033[0m\n", directoryName, strerror(errno));
        return 1;
    }

    return 0;
}

int nmapVulnScanner(const char *target, const char *directoryName) {
    // Fonction principale pour exécuter un scan Nmap sur une cible
    if (target == NULL) {
        fprintf(stderr, "\033[31mErreur: la cible est NULL.\033[0m\n");
        return 1;
    }

    // Formater la commande Nmap avec un fichier de sortie dans le nouveau dossier
    char nmapCommand[200];
    snprintf(nmapCommand, sizeof(nmapCommand), "nmap -sV -sC %s -oN %s/nmapScan.txt", target, directoryName);

    printf("\n\033[1mCela peut prendre un peu de temps, veuillez patienter...\033[0m\n");

    // Exécuter la commande Nmap
    if (system(nmapCommand) == -1) {
        perror("\033[31mErreur lors de l'exécution de nmap\033[0m\n");
        return 1;
    }

    printf("\n\033[32mScan terminé avec succès. Les résultats sont disponibles dans le fichier %s/nmapScan.txt\033[0m\n", directoryName);
    return 0;
}

int isHostAlive(const char *ip_address) {
    // Fonction pour vérifier si une IP ou un domaine répond au ping
    if (ip_address == NULL) {
        fprintf(stderr, "\033[31mErreur: l'adresse IP ou nom d'hôte est NULL.\033[0m\n");
        return 1;
    }

    // Vérification par ping
    char command[100];
    snprintf(command, sizeof(command), "ping -c 1 -W 1 %s > /dev/null 2>&1", ip_address);
    
    int ping_status = system(command);

    if (ping_status != 0) {
        // Si le ping échoue
        fprintf(stderr, "\033[33mAlerte: la cible %s ne répond pas aux requêtes ICMP (ping)\033[0m\n", ip_address);
        return 1;
    }

    printf("PING : OK");
    // Si tout va bien (ping OK)
    return 0;
}

char* targetSnatcher(const char *source, const int extractionMode) {
    // Utilisé pour créer la variable target, mode: 0 récupéré par la ligne de commande (argv[1]), mode 1 par fichier (via -s ou -us)
    char *host = NULL;

    switch (extractionMode) {
    case 0:
        host = strdup(source);
        if (host == NULL) {
            fprintf(stderr, "Erreur : allocation mémoire pour host a échoué.\n");
            return NULL;
        }
        break;
    
    default:
        // Autres modes à implémenter si nécessaire
        fprintf(stderr, "Erreur : mode d'extraction non supporté.\n");
        return NULL;
    }

    return host;  // Retourne la chaîne du target
}

/////////////////////////////////////////////////////////////


void enum4linuxSMBvulnScanner(int smb_found, const char directoryName[], const char target[]) {
    //Function pour le scan de Enum4Linux
    if (smb_found) {

        printf("\n\033[1;45;33mADDITIONNEL: Scan SMB via Enum4Linux\033[0m\n\n");

        char enum4linuxCommand[100];
        snprintf(enum4linuxCommand, sizeof(enum4linuxCommand), "enum4linux %s > %s/enum4linxScan.txt", target, directoryName);

        printf("\n\033[1mCela peut prendre un peu de temps veuillez patienter...\033[0m\n");
        if (system(enum4linuxCommand) == -1) {
            perror("\033[31mErreur lors de l'exécution de Enum4Linux\033[0m\n");
            return;
        } else {
            char readScan[100];
            snprintf(readScan, sizeof(readScan), "cat %s/enum4linxScan.txt", directoryName);

            system(readScan);
        }
        return;

    } else {return;}
}

/////////////////////////////////////////////////////////////
////////////////////////TO BE UPDATED////////////////////////
/////////////////////////////////////////////////////////////


// pour ces 3 : 
// - rajouter une fonction qui demandera l'url 

void wpscanWordpressScanner(int website_found, const char directoryName[], char target[]) {
    //Function pour le scan de WPscan

    char *url = getSiteURL();  // getSiteURL retourne un pointeur, pas une chaîne directement

    if (url != NULL && strlen(url) > 4) {  
        strncpy(url, target, sizeof(url) - 1);  
        url[sizeof(url) - 1] = '\0'; 
    } 

    if (website_found) {

        printf("\n\033[1;45;33mADDITIONNEL: Scan WordPress via WPscan (avec Token)\033[0m\n\n");

        //recupération de la clé api si présente
        char *apiKey = getWpscanAPIKey();
        char apikeyInput[64];
        
        char wpscanCommand[128];
        if (apiKey == NULL) {
            printf("\033[43m[Warning]\033[0mAucune clé d'api trouvé dans ~/.wpscankey\n");
            snprintf(wpscanCommand, sizeof(wpscanCommand), "wpscan --url %s -o %s/wpScan.txt", url, directoryName);
        } else {
            snprintf(apikeyInput, sizeof(apikeyInput), "--api-token %s", apiKey);
            snprintf(wpscanCommand, sizeof(wpscanCommand), "wpscan --url %s %s -o %s/wpScan.txt", url, apikeyInput, directoryName);
        }

        printf("%s\n", wpscanCommand);
        printf("\n\033[1mCela peut prendre un peu de temps veuillez patienter...\033[0m\n");
        if (system(wpscanCommand) == -1) {
            perror("\033[31mErreur lors de l'exécution de WPscan\033[0m\n");
            return;
        } else {
            char readScan[100];
            snprintf(readScan, sizeof(readScan), "cat %s/wpScan.txt", directoryName);

            system(readScan);
        }

    } else {return;}
}

void dirsearchWeb(int dodir, const char directoryName[], const char target[]) {
    //Function pour le scan de dirsearch
    if (dodir) {

        printf("\n\033[1;45;33mADDITIONNEL: Enumération Basique des dossiers Web\033[0m\n\n");

        char dirsearchCommand[100];
        snprintf(dirsearchCommand, sizeof(dirsearchCommand), "dirsearch -u %s/ > %s/dirsearch.txt", target, directoryName);

        printf("\n\033[1mCela peut prendre un peu de temps veuillez patienter...\033[0m\n");
        if (system(dirsearchCommand) == -1) {
            perror("\033[31mErreur lors de l'exécution de Dirsearch\033[0m\n");
            return;
        } else {
            char readScan[100];
            snprintf(readScan, sizeof(readScan), "cat %s/dirsearch.txt", directoryName);

            system(readScan);
        }

    } else {return;}
}

int niktoWebsiteScanner(int website_found, const char directoryName[], const char website[]) {
    //Function pour le scan de Nikto

    if (website_found) {

        printf("\n\033[1;45;33mADDITIONNEL: Scan site internet via Nikto\033[0m\n\n");

        char niktoCommand[100];
        snprintf(niktoCommand, sizeof(niktoCommand), "nikto -h %s -output %s/niktoScan.txt", website, directoryName);

        if (system(niktoCommand) == -1) {
            perror("\033[31mErreur lors de l'exécution de Nikto\033[0m\n");
            return 1;
        } 
        
        return 0;

    } else {return 0;}
}

/////////////////////////////////////////////////////////////









/////////////////////////////////////////////////////////////
///////////////////////////CLEARED///////////////////////////
/////////////////////////////////////////////////////////////

int argumentChecking(int argc, char *argv[]) {
    // return une valeur pour argVariable (utilisé pour les fichié en entré)

    for (int i = 1; i < argc ; i++) { 

        if (strcmp(argv[i], "-td") == 0) {
            //option pour tester les dependances
            td_found = 1;
            return 1; //si l'option est présente elle sera seul lancer


        } else if (strcmp(argv[i], "--install") == 0) {
            //option pour installer les dependances
            install_found = 1;
            return 1; //si l'option est présente elle sera seul lancer


        } else if ((strcmp(argv[i], "--search") == 0) || (strcmp(argv[i], "-s") == 0)) {
            //un fichier à été donner et il doit être filtré (raw nmap output)
            toBeFiltered = 1; //doit être filtré avant traitement par Searchsploit
            search_found = 1; //sera cherché
            return i+1; // pour argVariable (donne l'emplacement du fichier d'entré)

        } else if ((strcmp(argv[i], "--unfiltered-search") == 0) || (strcmp(argv[i], "-us") == 0)) {
            // un fichier à été donner 
            toBeFiltered = 0; //il n'a pas été filtré / ne doit pas l'être
            search_found = 1; //sera cherché
            return i+1;

        } else if (i == 1) {
            continue;

        } else {
            fprintf(stderr, "\033[31mle paramètre %s est inconnu.\033[0m\n", argv[i]);
            return -1;
        }
    }
    return 0;

}

void additionnalTesting(const char directoryName[], char target[], const int website_found, const int smb_found) {

    //ajouter tout les scans additionnels ici 
    //---------------------------------------
    

    if (website_found) {
        //si un site internet est trouvé propose 3 outils (nikto, dirsearch & wpscan)
        
        char input; // simple var pour stocker l'input user

        printf("\n\033[1;4mUn site internet à été trouvé, voulez-vous realisé un scan Nikto ?\033[1;0m \ny/n : \033[0m");
        scanf(" %c", &input);
        printf("\n");

        if (input == 'y') { 
            if (niktoWebsiteScanner(1, directoryName, target) != 0) {
                fprintf(stderr, "\033[31mErreur lors de l'exécution de Nikto\033[0m\n");
            }
        } else {
            printf("Le scan Nikto ne sera pas réalisé.\n");
        }


        //offre scan dirsearch à l'utilisateur
        
        printf("\n\033[1;4mUn site internet à été trouvé, voulez-vous realisé une enumération des dossiers via Dirsearch ?\033[1;0m \ny/n : \033[0m");
        scanf(" %c", &input);
        printf("\n");

        if (input == 'y') { 
            dirsearchWeb(1,directoryName, target);
        } else {
            printf("l'énumération dirsearch ne sera pas réalisé.\n");
        }

        //offre scan wpscan à l'utilisateur
        printf("\n\033[1;4mUn site internet à été trouvé, voulez-vous ajouter un scan WPscan (pour les sites utilisant WordPress) ?\033[1;0m \ny/n : \033[0m");
        scanf(" %c", &input);
        printf("\n");

        if (input == 'y') { 
            wpscanWordpressScanner(1, directoryName, target);
        } else {
            printf("le scan WPscan ne sera pas réalisé.\n");
        }
    }


    enum4linuxSMBvulnScanner(smb_found, directoryName, target);
    //---------------------------------------

    printf("\n\033[1;34m-------------------------------\033[0m\n");
    printf("\n\033[1;34mFin des scans\033[0m\n");
    return;
    
}

int servicesChecker(char *serviceFiles) {
    //verifie les services trouvé et offre des testes additionnels
    FILE *servicesFile = fopen(serviceFiles, "r");
    
    if (servicesFile == NULL) {
        perror("\033[31mErreur lors de l'ouverture de allServices.txt\033[0m\n");
        return 1;
    }

    char line[200];
    char ports[20], typeService[50];
    int i = 1;
    int port_found = 0;

    while (fgets(line, sizeof(line), servicesFile)) {
        //lis chaque lignes et recherche un service (pour valider des futurs scans)

        sscanf(line, "%19s %49s", ports, typeService);

        if ((strcmp(ports, "80/tcp") == 0) || (strcmp(ports, "443/tcp") == 0) ) {
            printf("Site internet : ligne %d \"%s\".\n", i, ports);
            website_found = 1;
            port_found = 1;

        } else if ((strcmp(typeService, "http") == 0) || (strcmp(typeService, "ssl/https") == 0) ) {
            printf("Site internet : ligne %d \"%s\".\n", i, typeService);
            website_found = 1;
            port_found = 1;        
        } else if (strcmp(ports, "139/tcp") == 0 || strcmp(ports, "445/tcp") == 0) {
            printf("Service SMB : ligne %d \"%s\".\n", i, ports);
            smb_found = 1;
            port_found = 1;          
        }
        
        i++;
    }
    fclose(servicesFile);

    int moreScans = 0;
    //verifie que l'utilisateur veut faire des scans additionnel

    if (port_found) {

        while (moreScans != 1) {
            char input;  

            printf("\n\033[1mAu moins 1 service peut être scanné, voulez-vous lancer des scans additionnels? y/n : \033[0m");
            scanf(" %c", &input);  
            printf("\n");

            if (input == 'y') { 
                moreScans = 1;
                break;

            } else if (input == 'n') {
                break;

            } else {
                printf("Entrée invalide. Veuillez entrer 'y' ou 'n'.\n");
            }
        }
    } else {
        printf("\n\033[1;31mAucun scan additionnel n'est disponible.\033[0m\n");
    }

    return moreScans;
}

/////////////////////////////////////////////////////////////
int main(int argc, char *argv[]) {
    
    
    if (argc < 2) {
        // Vérifier que la cible est passée en argument
        fprintf(stderr, "Usage: %s <target> [Options]\n", argv[0]);
        return 1;
    } 
    
    int argVariable = argumentChecking(argc, argv);

    if (td_found) {
        //si l'option pour tester les dépendence (-td) est présente
        printf("\n\033[1;45;37mLancement du test des dépendances\033[0m\n");
        if (
            checkDependencies("Nmap", "nmap -h > /dev/null 2> /dev/null") == 0 
            && checkDependencies("Nikto", "nikto > /dev/null 2> /dev/null") == 0 
            && checkDependencies("WPscan", "wpscan --help > /dev/null 2> /dev/null") == 0 
            && checkDependencies("Searchsploit", "searchsploit exemple > /dev/null 2> /dev/null") == 0
            && checkDependencies("Enum4Linux", "enum4linux --help > /dev/null 2> /dev/null") == 0
            && checkDependencies("Dirsearch","dirsearch --help > /dev/null 2> /dev/null") == 0
            && checkDependencies("Nuclei","nuclei --help > /dev/null 2> /dev/null") == 0
            //si une erreur apparait les testes suivant s'arrête
        ) {
            printf("\033[42mToutes les dépendances sont fonctionnels\033[0m\n");
            //tout les testes ont reussi
        } else {
            fprintf(stderr, "\033[41mErreur lors du test des dépendances\033[0m\n");
            //au moins 1 teste à raté
        }

        return 0;

    } else if (install_found) {
        //si l'option pour installer les dépendances (--install) est présente

        if (geteuid()) {
            //verifie la présence de sudo
            fprintf(stderr, "\033[41mErreur: Les privilèges ROOT sont nécéssaires\033[0m\n");
            return 1;
        }

        printf("\n\033[1;40;33mINSTALLATION DES DEPENDANCES\033[0m\n");
        printf("\033[43m[Warning]\033[0m L'installation ne marchera que sur des debian based système.\n");

        char installPackagesApt[] = "sudo apt install nmap nikto ruby-full dirsearch grep";
        char installPackagesSearchsploit[] = "sudo snap install searchsploit";
        char installPackagesEnum4Linux[] = "sudo snap install enum4linux";
        char installPackagesGo[] = "sudo snap install go --classic";
        char installPackagesGem[] = "sudo gem install wpscan"; 
        char installPackagesNuclei[] = "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest";
        //liste de toutes les commandes nécéssaire à l'installation des dépendances

        printf("\033[1;45;37mINSTALLATION DES PAQUETS\033[0m\n");
        //espace retirer pour simplicité
        //si le paquets est bien installé ou deja installer alors retourne 0, sinon print l'endroit où il y a eu un probleme et retourne 1
        if (system(installPackagesApt) == 0) {printf("\033[42mInstallation des paquets APT reussi\033[0m\n");} else {printf("\033[41mErreur lors de l'installation des paquets APT\033[0m\n");return 1;}
        if (system(installPackagesSearchsploit) == 0) {printf("\033[42mInstallation des paquets Searchsploit reussi\033[0m\n");} else {printf("\033[41mErreur lors de l'installation des paquets SNAP\033[0m\n");return 1;}
        if (system(installPackagesEnum4Linux) == 0) {printf("\033[42mInstallation des paquets Enum4Linux reussi\033[0m\n");} else {printf("\033[41mErreur lors de l'installation des paquets SNAP\033[0m\n");return 1;}
        if (system(installPackagesGo) == 0) {printf("\033[42mInstallation du languages GO reussi\033[0m\n");} else {printf("\033[41mErreur lors de l'installation du language GO\033[0m\n");return 1;}
        if (system(installPackagesGem) == 0) {printf("\033[42mInstallation de WPscan reussi\033[0m\n");} else {printf("\033[41mErreur lors de l'installation de WPscan\033[0m\n");return 1;}
        if (system(installPackagesNuclei) == 0) {printf("\033[42mInstallation de Nuclei reussi\033[0m\n");} else {printf("\033[41mErreur lors de l'installation de Nuclei\033[0m\n");return 1;}
        return 0;
    } else if (search_found) {

        if (toBeFiltered) {
            
            argv[argVariable]; //nom du fichier (garder sous ce format car snprintf crash quand cette var est utilisé) 
            //fichier donné sur la ligne de commande

            char filteredFile[13] = "services.txt"; //fichier qui contiendra les services filtré

            // filtre le fichier pour n'extraire que les services & leur version
            if (filterNmapOutput(argv[argVariable], filteredFile) == 0) {

                // cherche ensuite des vulnérabilité sur ces mêmes services
                if (searchFileVulnerabilities(filteredFile, toBeFiltered) == 0) {
                    return 0;

                } else {
                    fprintf(stderr, "\033[31mErreur lors de l'exécution de Searchsploit\033[0m\n");
                    return -1;
                }

            } else {
                fprintf(stderr, "\033[31mErreur lors de l'exécution de du Filtrage\033[0m\n");
                return -1;
            }
        } else {

            // check les services pour des vulnérabilité
            if (searchFileVulnerabilities(argv[argVariable], toBeFiltered) == 0) {
                return 0;
            } else {
                fprintf(stderr, "\033[31mErreur lors de l'exécution de searchsploit\033[0m\n");
                return -1;
            }
        }




    } else {
        //partie automatisé classique
        char *target = targetSnatcher(argv[1], 0);

        isHostAlive(target);


        if (target != NULL) {
            //une cible à bien été récupéré alors le scans peut commencer.

            // Créer le dossier pour stocker les résultats
            char directoryName[100];
            if (createScanDirectory(directoryName, sizeof(directoryName)) != 0) {
                return 1; 
            }

            printf("\n\033[1;45mTOUT LES FICHIERS DE CE SCANS SERONT DANS\033[34m %s\033[0m\n", directoryName);

            /////////////////////////////////////////////////////////////
            ////////////////debut des actions automatiques///////////////
            /////////////////////////////////////////////////////////////

            printf("\n\033[1;45;34mScan réseau via Nmap\033[0m\n");

            if (nmapVulnScanner(target, directoryName) != 0) {
                // scan de vulnérabilité avec nmap et creation du fichier "nmapScan.txt" dans le dossier.
                fprintf(stderr, "\033[31mErreur lors de l'exécution de nmap\033[0m\n");
                return 1;

            } else {
                // recherche ensuite les vulnérabilité depuis ExploitDB
                printf("\n\n\033[1;45;31mRecherche de CVE via ExploitDB\033[0m\n\n");

                char nmapfile[31];       // 17 (dir) + 1 (slash) + 12 ("nmapScan.txt") + 1 (null byte)
                char servicefiles[34];   // 17 (dir) + 1 (slash) + 15 ("allServices.txt") + 1 (null byte)

                // Construire les chemins des fichiers
                int nmap_len = snprintf(nmapfile, sizeof(nmapfile), "%s/nmapScan.txt", directoryName);
                int service_len = snprintf(servicefiles, sizeof(servicefiles), "%s/allServices.txt", directoryName);

                // Vérifier que snprintf n'a pas tronqué les chaînes
                if (nmap_len < 0 || nmap_len >= sizeof(nmapfile)) {
                    fprintf(stderr, "\033[31mErreur : le chemin de nmapScan.txt est trop long.\033[0m\n");
                    return 1;
                }
                if (service_len < 0 || service_len >= sizeof(servicefiles)) {
                    fprintf(stderr, "\033[31mErreur : le chemin de allServices est trop long.\033[0m\n");
                    return 1;
                }
                
                if (filterNmapOutput(nmapfile, servicefiles) == 0) {
                //filtre le fichier nmapScan.txt & crée le fichier allServices.txt

                    if (searchFileVulnerabilities(servicefiles, 1) == 0) { 
                    //utilise le fichier allServices.txt pour rechercher des CVEs via ExploitDB

                        printf("\n\033[1;45;36mRecherche des services pour scans additionnels\033[0m\n\n");
                        
                        if (servicesChecker(servicefiles) == 0) {
                        //si il n'y a pas de service à scanner en plus / l'utilisateur à refuser

                            printf("\n\033[1;34m-------------------------------\033[0m\n");
                            printf("\n\033[1;34mFin du scan\033[0m\n");
                            return 0;

                        } else {
                        // l'utilisateur souhaite avoir des scans supplémentaire
                            additionnalTesting(directoryName, target, website_found, smb_found);
                        }

                    } else {
                        return 1;
                    }
                     
                } else {
                    return 1;
                }

            }

        } else {
            fprintf(stderr, "\033[31mErreur : La cible est NULL.\033[0m\n");
            return 1;
        }

    } 

}




//function de test
int main1() {
    enum4linuxSMBvulnScanner(1,"test","127.0.0.1");
}
