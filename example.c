// Init:
pcapif->pcap = pcap_create(pcapif->name, pcap_errbuf);
if (!pcapif->pcap) {
    ethfp_log_message("PCAP", "error creating pcap: %s", pcap_errbuf);
    goto err_free_if;
}

if (pcap_activate(pcapif->pcap) < 0) {
    ethfp_log_message("PCAP",
        "error ativating pcap for interface %s: %s, %s", pcapif->name,
        pcap_geterr(pcapif->pcap), strerror(errno));
    goto err_free_pcap;
}

// Callback:
void ethfp_eng_doframe(
        const unsigned char *if_name,
        const unsigned char * packet,
        const unsigned int packetsz,
        const struct timeval *tv)
{...}

// Loop:
ret = pcap_dispatch(
                    pcapif->pcap,
                    1,
                    ethfp_eng_doframe,
                    (unsigned char*)pcapif->name);