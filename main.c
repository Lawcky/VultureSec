#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// outils à rajouter : dirsearch (site internet), subfinder (nom de domaine), implémenter nuclei
// a ajouter également la création du dossier "target" avec tout les scans à l'intérieur (potentiellement une options pour preciser le dossier)

//ajout d'une option pour lire un fichier nmap et en sortir les vuln avec searchsploit

int website_found, ssh_found, smb_found, dns_found = 0;
//variable global pour les scans additionnel dans main(), ils sont set dans portChecking()


int checkDependencies(const char *prog, const char *command) {
    //verifie que la commande donnée est bien installé et fonctionnel
   
    int status = system(command);
    
    if (status == -1) {
        // Une erreur system()
        perror("\033[41mErreur lors de l'exécution de la commande avec system()\033[0m\n");
        return 1;

    } else {
        // La commande a été exécutée
        if (WIFEXITED(status)) {
            // Vérifie que la commande s'est arrêtée via exit()
            int exit_code = WEXITSTATUS(status);
            // Récupère le statut de la commande (0 = réussi | autre = erreur)

            if (strcmp(prog, "Enum4Linux") == 0) {
                //enum4linux retourne des valeurs différentes que 0 lors de la commande --help
                //petit coup de scotch pour l'instant... :(
                if (exit_code == 255) {
                    // La commande a fonctionné pour enum4linux
                    printf("\033[32m%s est installé et fonctionne correctement.\033[0m\n", prog); 
                    return exit_code;

                } else {
                    // La commande a échoué
                    fprintf(stderr, "\033[31m%s n'a pas fonctionné correctement (code de sortie : %d).\033[0m\n", prog, exit_code);
                    return exit_code;
                }
            }


            if (exit_code == 0) {
                // l'outil est bien installé
                printf("\033[32m%s est installé et fonctionne correctement.\033[0m\n", prog); 
                return exit_code;

            } else {
                // l'outil n'est pas bien installé
                fprintf(stderr, "\033[31m%s n'a pas fonctionné correctement (code de sortie : %d).\033[0m\n", prog, exit_code);
                return exit_code;
            }
        
        } else {
            fprintf(stderr, "\033[31mLa commande %s n'a pas terminé normalement.\033[0m\n", command);
            return 1;
        }
    }
}

int nmapVulnScanner(char target[]) {
    // Exécuter la commande nmap et enregistrer le résultat dans un fichier ".txt"
    char nmapCommand[100];
    snprintf(nmapCommand, sizeof(nmapCommand), "nmap -sV -sC %s -oN nmapScan.txt", target);
    
    printf("\n\033[1mCela peut prendre un peu de temps veuillez patienter...\033[0m\n");
    
    if (system(nmapCommand) == -1) {
        perror("\033[31mErreur lors de l'exécution de nmap\033[0m\n");
        return 1;
    } 
}

int niktoWebsiteScanner(int website_found,char website[]) {
    //Function pour le scan de Nikto

    if (website_found) {

        printf("\n\033[1;45;33mADDITIONNEL: Scan site internet via Nikto\033[0m\n\n");

        char niktoCommand[100];
        snprintf(niktoCommand, sizeof(niktoCommand), "nikto -h %s -output niktoScan.txt", website);

        if (system(niktoCommand) == -1) {
            perror("\033[31mErreur lors de l'exécution de Nikto\033[0m\n");
            return 1;
        } 

    } else {return 0;}
}

int enum4linuxSMBvulnScanner(int smb_found, char target[]) {
    //Function pour le scan de Enum4Linux
    if (smb_found) {

        printf("\n\033[1;45;33mADDITIONNEL: Scan SMB via Enum4Linux\033[0m\n\n");

        char enum4linuxCommand[100];
        snprintf(enum4linuxCommand, sizeof(enum4linuxCommand), "enum4linux %s > enum4linxScan.txt", target);

        printf("\n\033[1mCela peut prendre un peu de temps veuillez patienter...\033[0m\n");
        if (system(enum4linuxCommand) == -1) {
            perror("\033[31mErreur lors de l'exécution de Enum4Linux\033[0m\n");
            return 1;
        } else {
            system("cat enum4linxScan.txt");
        }

    } else {return 0;}
}

int wpscanWordpressScanner(int website_found, char target[]) {
    //Function pour le scan de WPscan
    if (website_found) {

        printf("\n\033[1;45;33mADDITIONNEL: Scan WordPress via WPscan (avec Token)\033[0m\n\n");

        char enum4linuxCommand[100];
        snprintf(enum4linuxCommand, sizeof(enum4linuxCommand), "wpscan --url %s --api-token CxGjO8T0AaTs9WmoJXMQemLNlgOytE2jXe6LJzxGczs -o wpScan.txt", target);

        printf("\n\033[1mCela peut prendre un peu de temps veuillez patienter...\033[0m\n");
        if (system(enum4linuxCommand) == -1) {
            perror("\033[31mErreur lors de l'exécution de WPscan\033[0m\n");
            return 1;
        } else {
            system("cat wpScan.txt");
        }

    } else {return 0;}
}

int filterNmapOutput(char *inputFile, char *outputFile) {
    // create the filtering command
    char filteringCommand[256];
    snprintf(filteringCommand, sizeof(filteringCommand), "grep 'open' %s | awk '{print $1, $3, $4, $5}' | uniq > %s", inputFile, outputFile);

    // Execute the filtering command
    if (system(filteringCommand) == -1) {
        perror("Erreur lors de l'exécution de grep et awk");
        return 1;
    }

    return 0;
}

int searchFileVulnerabilities(char *filteredFile, int beenFiltered) {

    if (beenFiltered == 0) {
        //the file hasn't been filtered
        printf("\033[33m[Warning]\033[0mCette option à été conçu pour lire un fichier mis dans le même format que l'output classique de Nmap soit:\n");
        printf("\033[1mPORT SERVICE VERSION\033[0m\n");
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
            // If there are fewer than 3 fields skip this line
            continue;
        }

        printf("\033[4;31mService : %s %s\033[0m\n", service, (fieldCount == 4) ? version : "(no version)");

        // Build the searchsploit command based on available fields
        if (fieldCount == 4) {
            // If the line has all four fields
            snprintf(searchsploitCommand, sizeof(searchsploitCommand), "searchsploit \"%s %s\"", service, version);
        } else {
            // If the line is missing the version
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

int portChecking() {
    //verifie les services trouvé et offre des testes additionnels
    FILE *servicesFile = fopen("allServices.txt", "r");
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

//        }else if (strcmp(typeService, "ssh") == 0) {
//            printf("Service SSH : ligne %d \"%s\".\n", i, typeService);
//            ssh_found = 1;
//            port_found = 1;
//
//        } else if (strcmp(ports, "22/tcp") == 0) {
//            printf("Service SSH : %d \"%s\".\n", i, ports);
//            ssh_found = 1;
//            port_found = 1;
//            
        } else if (strcmp(ports, "139/tcp") == 0 || strcmp(ports, "445/tcp") == 0) {
            printf("Service SMB : ligne %d \"%s\".\n", i, ports);
            smb_found = 1;
            port_found = 1;
            
//        } else if (strcmp(ports, "53/udp") == 0) {
//            printf("Service DNS : %d \"%s\".\n", i, ports);
//            dns_found = 1;
//            port_found = 1;
//            
//        } else if (strcmp(typeService, "dns") == 0) {
//            printf("Service DNS : %d \"%s\".\n", i, typeService);
//            dns_found = 1;
//            port_found = 1;
//            
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

int main(int argc, char *argv[]) {
    //fonction principale

    int td_found = 0; // test-dependencies
    int install_found = 0; // install-dependencies
    int search_found = 0; // search file
    //liste des argument autorisé

    if (strcmp(argv[1], "-td") == 0) {
        //verifie le premier argument pour les arg de verification/installation (evite le crash si une cible est renseigné à la place)
        td_found = 1;
    } else if (strcmp(argv[1], "--install") == 0) {
        install_found = 1;

    } else if ((strcmp(argv[1], "--search") == 0) || (strcmp(argv[1], "-s") == 0)) {
        // A file has been given
        search_found = 1;
        //it has been filtered
        char nmapFile[256], filteredFile[300];
        strncpy(nmapFile, argv[1+1], sizeof(nmapFile) - 1);
        nmapFile[sizeof(nmapFile) - 1] = '\0';

        snprintf(filteredFile, sizeof(filteredFile), "services.%s", nmapFile);

        // Filter the file's content to retrieve only services in nmap output format
        if (filterNmapOutput(nmapFile, filteredFile) == 0) {
            // Search those services using searchsploit
            if (searchFileVulnerabilities(filteredFile, search_found) == 0) {
                return 0;
            } else {
                fprintf(stderr, "\033[31mErreur lors de l'exécution de searchsploit\033[0m\n");
                return 1;
            }
        } else {
            fprintf(stderr, "\033[31mErreur lors de l'exécution de filterNmapOutput\033[0m\n");
            return 1;
        }


    } else if ((strcmp(argv[1], "--unfiltered-search") == 0) || (strcmp(argv[1], "-us") == 0)) {
        // A file has been given
        search_found = 0;
        //it hasn't been filtered
        char File[256];
        strncpy(File, argv[1+1], sizeof(File) - 1);
        File[sizeof(File) - 1] = '\0';

        // Filter the file's content to retrieve only services in nmap output format
        if (searchFileVulnerabilities(File, search_found) == 0) {
            return 0;
        } else {
            fprintf(stderr, "\033[31mErreur lors de l'exécution de searchsploit\033[0m\n");
            return 1;
        }
    }

    for (int i = 2; i < argc ; i++) { 
        //liste tout les arguments à partir du 3eme pour les vérifier

        if (strcmp(argv[i], "-td") == 0) {
            td_found = 1;


        } else if (strcmp(argv[i], "-install") == 0) {
            install_found = 1;


        } else if ((strcmp(argv[i], "-search") == 0) || (strcmp(argv[i], "-s") == 0)) {
            // A file has been given
            search_found = 1;
            //it has been filtered
            char nmapFile[256], filteredFile[300];
            strncpy(nmapFile, argv[i+1], sizeof(nmapFile) - 1);
            nmapFile[sizeof(nmapFile) - 1] = '\0';
            snprintf(filteredFile, sizeof(filteredFile), "services.%s", nmapFile);

            // Filter the file's content to retrieve only services in nmap output format
            if (filterNmapOutput(nmapFile, filteredFile) == 0) {
                // Search those services using searchsploit
                if (searchFileVulnerabilities(filteredFile, search_found) == 0) {
                    return 0;
                } else {
                    fprintf(stderr, "\033[31mErreur lors de l'exécution de searchsploit\033[0m\n");
                    return 1;
                }
            } else {
                fprintf(stderr, "\033[31mErreur lors de l'exécution de filterNmapOutput\033[0m\n");
                return 1;
            }


        } else if ((strcmp(argv[i], "--unfiltered-search") == 0) || (strcmp(argv[i], "-us") == 0)) {
            // A file has been given
            search_found = 0;
            //it hasn't been filtered
            char File[256];
            strncpy(File, argv[i+1], sizeof(File) - 1);
            File[sizeof(File) - 1] = '\0';

            // Filter the file's content to retrieve only services in nmap output format
            if (searchFileVulnerabilities(File, search_found) == 0) {
                return 0;
            } else {
                fprintf(stderr, "\033[31mErreur lors de l'exécution de searchsploit\033[0m\n");
                return 1;
            }
        }
    }

    if (td_found) {
        //si l'option pour tester les dépendence est présente
        printf("\n\033[1;45;37mLancement du test des dépendances\033[0m\n");
        if (
            checkDependencies("Nmap", "nmap -h > /dev/null 2> /dev/null") == 0 
            && checkDependencies("Nikto", "nikto > /dev/null 2> /dev/null") == 0 
            && checkDependencies("WPscan", "wpscan --help > /dev/null 2> /dev/null") == 0 
            && checkDependencies("Searchsploit", "searchsploit exemple > /dev/null 2> /dev/null") == 0
            && checkDependencies("Enum4Linux", "enum4linux --help > /dev/null 2> /dev/null") == 255
            && checkDependencies("nuclei","nuclei > /dev/null 2> /dev/null") == 0
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
        //si l'option pour installer les dépendances est présente

        if (geteuid()) {
            //verifie la présence de sudo
            fprintf(stderr, "\033[41mErreur: Les privilèges ROOT sont nécéssaires\033[0m\n");
            return 1;
        }

        printf("\n\033[1;40;33mINSTALLATION DES DEPENDANCES\033[0m\n");
        printf("\033[43m[Warning]\033[0m L'installation ne marchera que sur des debian based système.\n");

        char installPackagesApt[] = "sudo apt install nmap nikto ruby-full";
        char installPackagesSearchsploit[] = "sudo snap install searchsploit";
        char installPackagesEnum4Linux[] = "sudo snap install enum4linux";
        char installPackagesGo[] = "sudo snap install go --classic";
        char installPackagesGem[] = "sudo gem install wpscan"; 
        char installPackagesNuclei[] = "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest";
        //liste de toutes les commandes nécéssaire à l'installation des dépendances

        printf("\033[1;45;37mINSTALLATION DES PAQUETS\033[0m\n");
        if (system(installPackagesApt) == 0) {
            printf("\033[42mInstallation des paquets APT reussi\033[0m\n");
        } else {
            printf("\033[41mErreur lors de l'installation des paquets APT\033[0m\n");
            return 1;
        }
        if (system(installPackagesSearchsploit) == 0) {
            printf("\033[42mInstallation des paquets Searchsploit reussi\033[0m\n");
        } else {
            printf("\033[41mErreur lors de l'installation des paquets SNAP\033[0m\n");
            return 1;
        }
        if (system(installPackagesEnum4Linux) == 0) {
            printf("\033[42mInstallation des paquets Enum4Linux reussi\033[0m\n");
        } else {
            printf("\033[41mErreur lors de l'installation des paquets SNAP\033[0m\n");
            return 1;
        }
        if (system(installPackagesGo) == 0) {
            printf("\033[42mInstallation du languages GO reussi\033[0m\n");
        } else {
            printf("\033[41mErreur lors de l'installation du language GO\033[0m\n");
            return 1;
        }
        if (system(installPackagesGem) == 0) {
            printf("\033[42mInstallation de WPscan reussi\033[0m\n");
        } else {
            printf("\033[41mErreur lors de l'installation de WPscan\033[0m\n");
            return 1;
        }
        if (system(installPackagesNuclei) == 0) {
            printf("\033[42mInstallation de Nuclei reussi\033[0m\n");
        } else {
            printf("\033[41mErreur lors de l'installation de Nuclei\033[0m\n");
            return 1;
        }
        return 0;
    } else {
        printf("\033[1;45;37mLes dépendances n'ont pas été tester\033[0m\n");
    }

    //-------------------------------------------------------------------------------------------------
    //debut des actions automatiques


    // Vérifier que la cible est passée en argument
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <target> [Options]\n", argv[0]);
        return 1;
    }

    // Récupére la cible depuis les arguments
    char target[100];
    strncpy(target, argv[1], sizeof(target) - 1);
    target[sizeof(target) - 1] = '\0';

    
    
    printf("\n\n\033[1;45;34mScan réseau via Nmap\033[0m\n");

    if (nmapVulnScanner(target) != 0) {
        // scan de vulnérabilité avec nmap et creation des fichier allServices.txt & "nmapScan.txt"
        fprintf(stderr, "\033[31mErreur lors de l'exécution de nmap\033[0m\n");
        return 1;

    } else {
        printf("\n\n\033[1;45;31mRecherche de CVE via ExploitDB\033[0m\n\n");
        filterNmapOutput("nmapScan.txt", "allServices.txt");
        searchFileVulnerabilities("allServices.txt", 1);
        // utilise les fichiers du scan précédent pour faire des recherches de vulnérabilité via ExploitDB

        printf("\n\033[1;45;36mRecherche des services pour scans additionnels\033[0m\n\n");
        if (portChecking() == 0) {
            //si il n'y a pas de service à scanner en plus / l'utilisateur à refuser
            printf("\n\033[1;34m-------------------------------\033[0m\n");
            printf("\n\033[1;34mFin du scan\033[0m\n");
            return 0;
        }

        //printf("%d %d %d %d\n", website_found, ssh_found, smb_found, dns_found);
        //pour debug

        //ajouter tout les scans additionnels ici 
        //---------------------------------------
        niktoWebsiteScanner(website_found, target);

        if (website_found) {
            //offre scan wpscan à l'utilisateur
            char a;
            printf("\n\033[1;4mUn site internet à été trouvé, voulez-vous ajouter un scan WPscan (pour les sites utilisant WordPress) ?\033[1;0m \ny/n : \033[0m");
            scanf("%c", &a);

            if (a == 'y') { 
                wpscanWordpressScanner(1, target);
            } else {
                printf("le scan WPscan ne sera pas réalisé.\n");

            }
        }

        enum4linuxSMBvulnScanner(smb_found, target);
        //---------------------------------------
        //mis sous la forme de fonction aulieu de if meme si legèrement moins performant mais plus clean
        //si un service scannable est trouvé (service_found = 1) alors le scan est lancé

        printf("\n\033[1;34m-------------------------------\033[0m\n");
        printf("\n\033[1;34mFin des scans\033[0m\n");
        return 0;
    }

}

int main1() {}
//function de test
