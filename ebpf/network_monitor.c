#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#define NUM_PORTS 2
int monitored_ports[NUM_PORTS] = {22, 80}; // SSH & HTTP

typedef struct {
    char *dev;
    int dlt; // Data Link Type
} interface_arg;

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    interface_arg *iarg = (interface_arg*)args;

    // Determine offset based on DLT
    int offset;
    switch(iarg->dlt) {
        case DLT_NULL:   offset = 4; break;    // Loopback
        case DLT_EN10MB: offset = 14; break;   // Ethernet
        default:         offset = 0; break;    // fallback
    }

    struct ip *iph = (struct ip*)(packet + offset);
    if (iph->ip_p != IPPROTO_TCP) return;

    struct tcphdr *tcph = (struct tcphdr*)(packet + offset + iph->ip_hl*4);
    int src_port = ntohs(tcph->source);
    int dst_port = ntohs(tcph->dest);

    for (int i = 0; i < NUM_PORTS; i++) {
        if (src_port == monitored_ports[i] || dst_port == monitored_ports[i]) {
            char ts[64];
            time_t t = header->ts.tv_sec;
            struct tm *tm_info = localtime(&t);
            strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm_info);

            printf("{\"timestamp\":\"%s\",\"interface\":\"%s\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"src_port\":%d,\"dst_port\":%d,\"packet_size\":%d}\n",
                   ts, iarg->dev, inet_ntoa(iph->ip_src), inet_ntoa(iph->ip_dst),
                   src_port, dst_port, header->len);
            fflush(stdout);
            break;
        }
    }
}

void* monitor_interface(void* arg) {
    interface_arg *iarg = (interface_arg*)arg;
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_live(iarg->dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Couldn't open %s: %s\n", iarg->dev, errbuf);
        free(iarg->dev);
        free(iarg);
        return NULL;
    }

    // Store the data link type
    iarg->dlt = pcap_datalink(handle);

    // Build BPF filter for monitored ports
    char filter_exp[256] = "";
    for (int i = 0; i < NUM_PORTS; i++) {
        char temp[32];
        sprintf(temp, "tcp port %d", monitored_ports[i]);
        strcat(filter_exp, temp);
        if (i != NUM_PORTS - 1) strcat(filter_exp, " or ");
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter '%s' on %s\n", filter_exp, iarg->dev);
        pcap_close(handle);
        free(iarg->dev);
        free(iarg);
        return NULL;
    }

    printf("Monitoring interface: %s\n", iarg->dev);
    pcap_loop(handle, -1, packet_handler, (u_char*)iarg);

    pcap_close(handle);
    free(iarg->dev);
    free(iarg);
    return NULL;
}

int main() {
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    if (alldevs == NULL) {
        fprintf(stderr, "No network interfaces found.\n");
        return 1;
    }

    pthread_t threads[64];
    int idx = 0;

    // Only monitor active interfaces
    for (d = alldevs; d != NULL; d = d->next) {
        if (!(d->flags & PCAP_IF_UP)) continue;

        interface_arg *iarg = malloc(sizeof(interface_arg));
        iarg->dev = strdup(d->name);

        pthread_create(&threads[idx++], NULL, monitor_interface, iarg);
    }

    for (int i = 0; i < idx; i++) pthread_join(threads[i], NULL);

    pcap_freealldevs(alldevs);
    return 0;
}
