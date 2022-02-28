#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

float GetCPULoad()
{
    int a[10];
    int b[10];
    FILE *fp;

    fp = fopen("/proc/stat", "r");

    fscanf(fp, "%ls %d %d %d %d %d %d %d %d %d", &a[0], &a[1], &a[2], &a[3], &a[4], &a[5], &a[6], &a[7], &a[8], &a[9]);

    // printf("Read String1 |%d| |%d| |%d| |%d| |%d| |%d| |%d| |%d| |%d|\n", a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9]);

    fclose(fp);

    sleep(1);

    fp = fopen("/proc/stat", "r");

    fscanf(fp, "%ls %d %d %d %d %d %d %d %d %d", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &b[6], &b[7], &b[8], &b[9]);

    // printf("Read String2 |%d| |%d| |%d| |%d| |%d| |%d| |%d| |%d| |%d|\n", b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9]);

    fclose(fp);

    /*******************************************************************************************************************************/

    int PrevIdle = a[4] + a[5];
    int Idle = b[4] + b[5];
    int PrevNonIdle = a[1] + a[2] + a[3] + a[6] + a[7] + a[8];
    int NonIdle = b[1] + b[2] + b[3] + b[6] + b[7] + b[8];
    int PrevTotal = PrevIdle + PrevNonIdle;
    int Total = Idle + NonIdle;
    int totald = Total - PrevTotal;
    int idled = Idle - PrevIdle;

    // printf("Totald; %d\n", totald);
    // printf("Total; %d\n", totald - idled);

    // float CPUusage = ((totald - idled) / totald) * 100;
    float res1 = totald - idled;
    // printf("res1: %f \n", res1);
    float res2 = res1 / totald;
    // printf("res2: %f \n", res2);
    float final = res2 * 100;
    // printf("final: %f \n", final);

    // printf("CPUusage: %f \n", CPUusage);

    return final;
}

int main(int argc, char *argv[])
{

    int server_fd, new_socket, valread;
    int opt = 1;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};
    char *HostNameReq = "GET /hostname";
    char *CPUNameReq = "GET /cpu-name";
    char *LoadReq = "GET /load";
    char *Error = "400 Bad Request\n";
    char Load[5];
    float cpu = GetCPULoad();
    int cpu2 = cpu;
    char daco[2] = "%";
    char http[128] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    char http1[128] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    char http2[128] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    char http3[128] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    sprintf(Load, "%d", cpu2);
    strcat(Load, daco);
    strcat(Load, "\n");
    strcat(http2, Load);
    strcat(http3, Error);

    /********************************************************Hostname********************************************************************************/
    FILE *fp;
    char Hostname[20];

    fp = fopen("/proc/sys/kernel/hostname", "r");

    fscanf(fp, "%s", Hostname);

    fclose(fp);
    /****************************************************************************************************************************************/

    /********************************************************CPUname********************************************************************************/
    FILE *fpp;
    char CPUname[1024];

    fpp = popen("cat /proc/cpuinfo | grep 'model name' | head -n 1 | awk -F: '{print $2}'", "r");

    fgets(CPUname, 1024, fpp);

    fclose(fpp);
    /****************************************************************************************************************************************/

    strcat(Hostname, "\n");
    strcat(http1, CPUname);
    strcat(http, Hostname);
    // strcat(CPUname, "\n");

    int port = 8000;
    if (argc > 1)
    {
        port = atoi(argv[1]);
        // printf("Port: %d\n", port);
    }
    else
    {
        printf("No port was selected\n");
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

        int HostNameCompare = strncmp(buffer, HostNameReq, 13);
        int CPUNameCompare = strncmp(buffer, CPUNameReq, 13);
        int LoadCompare = strncmp(buffer, LoadReq, 9);

        if (HostNameCompare == 0)
        {
            send(new_socket, http, strlen(http), 0);
        }
        else if (CPUNameCompare == 0)
        {
            send(new_socket, http1, strlen(http1), 0);
        }
        else if (LoadCompare == 0)
        {
            send(new_socket, http2, strlen(http2), 0);
        }
        else
        {
            send(new_socket, http3, strlen(http3), 0);
        }

        close(new_socket);
    }

    return 0;
}