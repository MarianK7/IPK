#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

void GetCPULoad(int socket)
{
    int a[10];
    int b[10];
    char Load[5];
    char daco[2] = "%";
    int new_socket = socket;
    FILE *fp;

    fp = fopen("/proc/stat", "r");

    fscanf(fp, "%ls %d %d %d %d %d %d %d %d %d", &a[0], &a[1], &a[2], &a[3], &a[4], &a[5], &a[6], &a[7], &a[8], &a[9]);

    fclose(fp);

    sleep(1);

    fp = fopen("/proc/stat", "r");

    fscanf(fp, "%ls %d %d %d %d %d %d %d %d %d", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &b[6], &b[7], &b[8], &b[9]);

    fclose(fp);

    /*******************************************************************************************************************************/

    unsigned long long int PrevIdle = a[4] + a[5];
    unsigned long long int Idle = b[4] + b[5];
    unsigned long long int PrevNonIdle = a[1] + a[2] + a[3] + a[6] + a[7] + a[8];
    unsigned long long int NonIdle = b[1] + b[2] + b[3] + b[6] + b[7] + b[8];
    unsigned long long int PrevTotal = PrevIdle + PrevNonIdle;
    unsigned long long int Total = Idle + NonIdle;
    unsigned long long int totald = Total - PrevTotal;
    unsigned long long int idled = Idle - PrevIdle;

    float res1 = totald - idled;
    float res2 = res1 / totald;
    float final = res2 * 100;

    char http2[128] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
    sprintf(Load, "%d", (int) final);
    strcat(Load, daco);
    strcat(Load, "\n");
    strcat(http2, Load);

    send(new_socket, http2, strlen(http2), 0);
}

void GetCPUName(int socket)
{
    FILE *fpp;
    char CPUname[1024];
    int new_socket = socket;

    fpp = popen("cat /proc/cpuinfo | grep 'model name' | head -n 1 | awk -F: '{print $2}'", "r");

    fgets(CPUname, 1024, fpp);

    fclose(fpp);

    char http1[128] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
    strcat(http1, CPUname);

    send(new_socket, http1, strlen(http1), 0);
}

void GetHostName(int socket)
{
    FILE *fp;
    char Hostname[20];
    int new_socket = socket;

    fp = fopen("/proc/sys/kernel/hostname", "r");

    fscanf(fp, "%s", Hostname);

    fclose(fp);

    char http[128] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
    strcat(Hostname, "\n");
    strcat(http, Hostname);

    send(new_socket, http, strlen(http), 0);
}

int main(int argc, char *argv[])
{

    int port = 8080;
    int server_fd, new_socket, valread;
    int opt = 1;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};
    char *HostNameReq = "GET /hostname ";
    char *CPUNameReq = "GET /cpu-name ";
    char *LoadReq = "GET /load ";
    char *Error = "400 Bad Request\n";
    char http3[128] = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\n";
    
    strcat(http3, Error);

    if (argc > 1)
    {
        port = atoi(argv[1]);
    }

    if ((server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    while (1)
    {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
        {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        if ((valread = read(new_socket, buffer, 1024)) < 0)
        {
            perror("read");
            exit(EXIT_FAILURE);
        }

        int HostNameCompare = strncmp(buffer, HostNameReq, 14);
        int CPUNameCompare = strncmp(buffer, CPUNameReq, 14);
        int LoadCompare = strncmp(buffer, LoadReq, 10);

        if (HostNameCompare == 0)
        {
            GetHostName(new_socket);
        }
        else if (CPUNameCompare == 0)
        {
            GetCPUName(new_socket);
        }
        else if (LoadCompare == 0)
        {
            GetCPULoad(new_socket);
        }
        else
        {
            send(new_socket, http3, strlen(http3), 0);
        }

        close(new_socket);
    }

    return 0;
}
