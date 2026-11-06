var analysisData = {
    totalPackets: 2435,
    tcpPackets: 1783,
    udpPackets: 632,
    dnsPackets: 164,
    httpPackets: 41,
    tlsPackets: 360,
    quicPackets: 468,
    icmpv6Packets: 18,

    tcpRetransmissions: 16,
    tcpResets: 8,

    tcpPortScanAvailable: true,
    tcpPortScanDetected: false,
    tcpPortScanSource: "",
    tcpPortScanUniquePorts: 0,

    dnsAnomalyDetected: false,
    dnsAnomalySource: "",
    dnsAnomalyCount: 0,

    securityIndicators: 2,

    protocols: {
        TCP: 1783,
        UDP: 632,
        DNS: 164,
        HTTP: 41,
        TLS: 360,
        QUIC: 468,
        ICMPv6: 18
    },

    topSources: [
        {"name":"ENDPOINT-1","count":540},
        {"name":"ENDPOINT-2","count":525},
        {"name":"ENDPOINT-3","count":434},
        {"name":"ENDPOINT-4","count":163},
        {"name":"ENDPOINT-5","count":139}
    ],

    topDestinations: [
        {"name":"ENDPOINT-1","count":702},
        {"name":"ENDPOINT-2","count":666},
        {"name":"ENDPOINT-3","count":284},
        {"name":"ENDPOINT-4","count":139},
        {"name":"ENDPOINT-5","count":73}
    ],

    topTCPPorts: [
        {"name":"22796","count":434},
        {"name":"443","count":387},
        {"name":"80","count":357},
        {"name":"18905","count":139},
        {"name":"22128","count":53},
        {"name":"27401","count":44},
        {"name":"22795","count":41},
        {"name":"38173","count":23},
        {"name":"64444","count":20},
        {"name":"12082","count":19}
    ],

    topUDPPorts: [
        {"name":"443","count":213},
        {"name":"49569","count":163},
        {"name":"53","count":98},
        {"name":"49765","count":42},
        {"name":"60110","count":20},
        {"name":"58291","count":18},
        {"name":"53774","count":12},
        {"name":"53436","count":6},
        {"name":"51389","count":5},
        {"name":"59851","count":3}
    ]
};