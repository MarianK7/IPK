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

    //printf("Read String1 |%d| |%d| |%d| |%d| |%d| |%d| |%d| |%d| |%d|\n", a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9]);

    fclose(fp);

    sleep(1);

    fp = fopen("/proc/stat", "r");

    fscanf(fp, "%ls %d %d %d %d %d %d %d %d %d", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &b[6], &b[7], &b[8], &b[9]);

    //printf("Read String2 |%d| |%d| |%d| |%d| |%d| |%d| |%d| |%d| |%d|\n", b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9]);

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

    //printf("Totald; %d\n", totald);
    //printf("Total; %d\n", totald - idled);

    // float CPUusage = ((totald - idled) / totald) * 100;
    float res1 = totald - idled;
    //printf("res1: %f \n", res1);
    float res2 = res1 / totald;
    //printf("res2: %f \n", res2);
    float final = res2 * 100;
    //printf("final: %f \n", final);

    // printf("CPUusage: %f \n", CPUusage);

    return final;
}

void GetHostName()
{
    FILE *fp;
    char name[20];

    fp = fopen("/proc/sys/kernel/hostname", "r");

    fscanf(fp, "%s", name);

    printf("Hostname: %s\n", name);

    fclose(fp);
}

void GetCpuName()
{
    FILE *fp;
    char name[1024];

    fp = popen("cat /proc/cpuinfo | grep 'model name' | head -n 1 | awk -F: '{print $2}'", "r");

    if (fgets(name, 1024, fp) != NULL)
    {
        printf("%s", name);
    }
    
    fclose(fp);
}

int main(int argc, char *argv[])
{
    char *port = "8000";
    if (argc > 1)
    {
        port = argv[1];
        printf("Port: %s\n", port);
    }
    else
        printf("No port was selected");

    float cpu = GetCPULoad();
    int cpu2 = cpu;
    printf("Usage int: %d%% \n", cpu2);
    printf("Usage: %f%% \n", cpu);

    GetHostName();
    GetCpuName();
}