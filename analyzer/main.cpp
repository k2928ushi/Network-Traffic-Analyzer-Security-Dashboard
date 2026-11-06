#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <windows.h>
#include <direct.h>
#include <cstdlib>
#include <cctype>

using namespace std;

/* =========================================================
   HELPERS
   ========================================================= */

string trimString(string s)
{
    while (!s.empty() && (s[0] == ' ' || s[0] == '\t' ||
           s[0] == '\r' || s[0] == '\n'))
        s.erase(0, 1);

    while (!s.empty() && (s[s.length() - 1] == ' ' ||
           s[s.length() - 1] == '\t' ||
           s[s.length() - 1] == '\r' ||
           s[s.length() - 1] == '\n'))
        s.erase(s.length() - 1, 1);

    return s;
}

string lowerString(string s)
{
    unsigned int i;
    for (i = 0; i < s.length(); i++)
        s[i] = (char)tolower((unsigned char)s[i]);
    return s;
}

string upperString(string s)
{
    unsigned int i;
    for (i = 0; i < s.length(); i++)
        s[i] = (char)toupper((unsigned char)s[i]);
    return s;
}

string cleanField(string s)
{
    s = trimString(s);

    if (!s.empty() && s[0] == '"')
        s.erase(0, 1);

    if (!s.empty() && s[s.length() - 1] == '"')
        s.erase(s.length() - 1, 1);

    return s;
}

vector<string> splitCSV(const string& line)
{
    vector<string> fields;
    string field = "";
    bool quotes = false;
    unsigned int i;

    for (i = 0; i < line.length(); i++)
    {
        char c = line[i];

        if (c == '"')
        {
            if (quotes && i + 1 < line.length() && line[i + 1] == '"')
            {
                field += '"';
                i++;
            }
            else
            {
                quotes = !quotes;
            }
        }
        else if (c == ',' && !quotes)
        {
            fields.push_back(cleanField(field));
            field = "";
        }
        else
        {
            field += c;
        }
    }

    fields.push_back(cleanField(field));
    return fields;
}

int findColumn(const vector<string>& headers, const string& name)
{
    unsigned int i;
    string wanted = lowerString(cleanField(name));

    for (i = 0; i < headers.size(); i++)
    {
        if (lowerString(cleanField(headers[i])) == wanted)
            return (int)i;
    }

    return -1;
}

string getField(const vector<string>& fields, int index)
{
    if (index < 0 || index >= (int)fields.size())
        return "";

    return cleanField(fields[index]);
}

bool fieldSet(string s)
{
    s = trimString(s);
    return !s.empty() && s != "0";
}

bool parseHexOrNumber(string value, unsigned int& result)
{
    value = trimString(value);
    if (value.empty())
        return false;

    char* endPtr = NULL;
    unsigned long v;

    if (value.length() > 2 && value[0] == '0' &&
        (value[1] == 'x' || value[1] == 'X'))
    {
        v = strtoul(value.c_str() + 2, &endPtr, 16);
    }
    else
    {
        v = strtoul(value.c_str(), &endPtr, 0);
        if (endPtr == value.c_str())
            v = strtoul(value.c_str(), &endPtr, 16);
    }

    if (endPtr == value.c_str())
        return false;

    result = (unsigned int)v;
    return true;
}

bool comparePairs(const pair<string, int>& a,
                  const pair<string, int>& b)
{
    if (a.second != b.second)
        return a.second > b.second;

    return a.first < b.first;
}

string getExecutableDirectory()
{
    char buffer[MAX_PATH];
    DWORD n = GetModuleFileNameA(NULL, buffer, MAX_PATH);

    if (n == 0)
        return ".";

    string fullPath(buffer, n);
    size_t p = fullPath.find_last_of("\\/");

    if (p == string::npos)
        return ".";

    return fullPath.substr(0, p);
}

/* frame.protocols is colon-separated, for example:
   eth:ethertype:ip:tcp:tls
   This checks for the TLS protocol as a layer. */
bool hasProtocolLayer(string layers, string wanted)
{
    layers = lowerString(layers);
    wanted = lowerString(wanted);

    string token = "";
    unsigned int i;

    for (i = 0; i <= layers.length(); i++)
    {
        char c = (i < layers.length()) ? layers[i] : ':';

        if (c == ':')
        {
            if (token == wanted)
                return true;

            token = "";
        }
        else
        {
            token += c;
        }
    }

    return false;
}

string jsEscape(string s)
{
    string out = "";
    unsigned int i;

    for (i = 0; i < s.length(); i++)
    {
        char c = s[i];

        if (c == '\\') out += "\\\\";
        else if (c == '"') out += "\\\"";
        else if (c == '\r') out += "\\r";
        else if (c == '\n') out += "\\n";
        else out += c;
    }

    return out;
}

void writeList(ofstream& js,
               vector<pair<string, int> > values,
               int limit)
{
    sort(values.begin(), values.end(), comparePairs);

    if ((int)values.size() < limit)
        limit = (int)values.size();

    js << "[";

    int i;
    for (i = 0; i < limit; i++)
    {
        if (i > 0)
            js << ",";

        js << "{\"name\":\""
           << jsEscape(values[i].first)
           << "\",\"count\":"
           << values[i].second
           << "}";
    }

    js << "]";
}

/* =========================================================
   MAIN
   ========================================================= */

int main()
{
    /* -----------------------------------------------------
       Directory layout:

       ...\\wireshark project\\analyzer\\main.exe
       ...\\wireshark project\\captures\\packets.csv
       ...\\wireshark project\\dashboard\\analysis.js
       ----------------------------------------------------- */

    string analyzerDir = getExecutableDirectory();
    size_t separator = analyzerDir.find_last_of("\\/");

    string projectRoot = analyzerDir;

    if (separator != string::npos)
        projectRoot = analyzerDir.substr(0, separator);

    string csvPath = projectRoot + "\\captures\\packets.csv";
    string dashboardDir = projectRoot + "\\dashboard";
    string jsPath = dashboardDir + "\\analysis.js";
    string reportPath = dashboardDir + "\\network_analysis_report.txt";

    _mkdir(dashboardDir.c_str());

    cout << endl;
    cout << "============================================" << endl;
    cout << "        NETWORK TRAFFIC ANALYZER" << endl;
    cout << "============================================" << endl;

    cout << endl;
    cout << "Project Root:" << endl;
    cout << projectRoot << endl;

    cout << endl;
    cout << "CSV File:" << endl;
    cout << csvPath << endl;

    ifstream file(csvPath.c_str());

    if (!file.is_open())
    {
        cout << endl;
        cout << "ERROR: Could not open packets.csv" << endl;
        cout << "Expected: " << csvPath << endl;
        cout << endl;
        cout << "Make sure packets.csv has been regenerated with" << endl;
        cout << "the frame.protocols column." << endl;
        cout << endl;
        cout << "Press Enter to continue...";
        cin.get();
        return 1;
    }

    string line;

    if (!getline(file, line))
    {
        cout << "ERROR: packets.csv is empty." << endl;
        return 1;
    }

    vector<string> headers = splitCSV(line);

    int protocolIndex = findColumn(headers, "_ws.col.Protocol");
    if (protocolIndex < 0)
        protocolIndex = findColumn(headers, "protocol");

    int ipSrcIndex = findColumn(headers, "ip.src");
    int ipDstIndex = findColumn(headers, "ip.dst");
    int ipv6SrcIndex = findColumn(headers, "ipv6.src");
    int ipv6DstIndex = findColumn(headers, "ipv6.dst");

    int tcpSrcPortIndex = findColumn(headers, "tcp.srcport");
    int tcpDstPortIndex = findColumn(headers, "tcp.dstport");
    int udpSrcPortIndex = findColumn(headers, "udp.srcport");
    int udpDstPortIndex = findColumn(headers, "udp.dstport");

    int retransmissionIndex =
        findColumn(headers, "tcp.analysis.retransmission");

    int tcpFlagsIndex = findColumn(headers, "tcp.flags");
    int tcpResetIndex = findColumn(headers, "tcp.flags.reset");

    int frameProtocolsIndex = findColumn(headers, "frame.protocols");

    cout << endl;
    cout << "CSV columns: " << headers.size() << endl;
    cout << "Protocol column: " << protocolIndex << endl;
    cout << "frame.protocols column: " << frameProtocolsIndex << endl;

    if (frameProtocolsIndex < 0)
    {
        cout << endl;
        cout << "WARNING: frame.protocols was not found." << endl;
        cout << "TLS calculation cannot use the dedicated layer test." << endl;
        cout << "Regenerate packets.csv using the command supplied with this file." << endl;
        cout << endl;
        cout << "Press Enter to continue...";
        cin.get();
        return 1;
    }

    int totalPackets = 0;
    int tcpPackets = 0;
    int udpPackets = 0;
    int dnsPackets = 0;
    int httpPackets = 0;
    int tlsPackets = 0;
    int quicPackets = 0;
    int icmpv6Packets = 0;

    int tcpRetransmissions = 0;
    int tcpResets = 0;

    map<string, int> protocolCount;
    map<string, int> sourceIPCount;
    map<string, int> destinationIPCount;
    map<string, int> tcpDestinationPorts;
    map<string, int> udpDestinationPorts;
    map<string, int> dnsSourceCount;

    map<string, set<string> > tcpSynPortsBySource;

    /* -----------------------------------------------------
       READ PACKETS
       ----------------------------------------------------- */

    while (getline(file, line))
    {
        if (line.empty())
            continue;

        vector<string> fields = splitCSV(line);

        string protocol = getField(fields, protocolIndex);
        string protocolUpper = upperString(protocol);

        string source = getField(fields, ipSrcIndex);
        string destination = getField(fields, ipDstIndex);

        if (source.empty())
            source = getField(fields, ipv6SrcIndex);

        if (destination.empty())
            destination = getField(fields, ipv6DstIndex);

        string tcpSrcPort = getField(fields, tcpSrcPortIndex);
        string tcpDstPort = getField(fields, tcpDstPortIndex);
        string udpSrcPort = getField(fields, udpSrcPortIndex);
        string udpDstPort = getField(fields, udpDstPortIndex);
        string retransmission = getField(fields, retransmissionIndex);
        string tcpFlags = getField(fields, tcpFlagsIndex);
        string tcpReset = getField(fields, tcpResetIndex);
        string frameProtocols = getField(fields, frameProtocolsIndex);

        totalPackets++;

        if (!protocol.empty())
            protocolCount[protocol]++;

        if (!source.empty())
            sourceIPCount[source]++;

        if (!destination.empty())
            destinationIPCount[destination]++;

        /* -------------------------------------------------
           TRANSPORT COUNTS
           ------------------------------------------------- */

        if (protocolUpper == "TCP")
            tcpPackets++;

        if (protocolUpper == "UDP")
            udpPackets++;

        /* -------------------------------------------------
           APPLICATION PROTOCOL COUNTS
           ------------------------------------------------- */

        if (protocolUpper == "DNS")
            dnsPackets++;

        if (protocolUpper.find("HTTP") == 0)
            httpPackets++;

        if (protocolUpper == "QUIC" ||
            hasProtocolLayer(frameProtocols, "quic"))
        {
            quicPackets++;
        }

        if (protocolUpper == "ICMPV6")
            icmpv6Packets++;

        /* -------------------------------------------------
           TLS COUNT

           IMPORTANT:
           This is based on the actual TLS protocol layer
           in frame.protocols rather than a broad string
           match on the protocol column.
           ------------------------------------------------- */

        if (hasProtocolLayer(frameProtocols, "tls"))
            tlsPackets++;

        /* -------------------------------------------------
           TCP ANALYSIS
           ------------------------------------------------- */

        if (protocolUpper == "TCP")
        {
            if (!tcpDstPort.empty())
                tcpDestinationPorts[tcpDstPort]++;

            if (fieldSet(retransmission))
                tcpRetransmissions++;

            bool resetDetected = false;

            if (fieldSet(tcpReset))
            {
                resetDetected = true;
            }
            else if (!tcpFlags.empty())
            {
                unsigned int flags = 0;

                if (parseHexOrNumber(tcpFlags, flags))
                {
                    if ((flags & 0x04) != 0)
                        resetDetected = true;

                    bool syn = ((flags & 0x02) != 0);
                    bool ack = ((flags & 0x10) != 0);

                    if (syn && !ack &&
                        !source.empty() &&
                        !tcpDstPort.empty())
                    {
                        tcpSynPortsBySource[source].insert(tcpDstPort);
                    }
                }
            }

            if (resetDetected)
                tcpResets++;
        }

        /* -------------------------------------------------
           UDP ANALYSIS
           ------------------------------------------------- */

        if (protocolUpper == "UDP")
        {
            if (!udpDstPort.empty())
                udpDestinationPorts[udpDstPort]++;
        }

        /* -------------------------------------------------
           DNS SOURCE ANALYSIS
           ------------------------------------------------- */

        if (protocolUpper == "DNS")
        {
            if (!source.empty())
                dnsSourceCount[source]++;
        }
    }

    file.close();

    /* =====================================================
       SORT TOP DATA
       ===================================================== */

    vector<pair<string, int> > sources;
    vector<pair<string, int> > destinations;
    vector<pair<string, int> > tcpPorts;
    vector<pair<string, int> > udpPorts;

    map<string, int>::iterator it;

    for (it = sourceIPCount.begin();
         it != sourceIPCount.end(); ++it)
        sources.push_back(*it);

    for (it = destinationIPCount.begin();
         it != destinationIPCount.end(); ++it)
        destinations.push_back(*it);

    for (it = tcpDestinationPorts.begin();
         it != tcpDestinationPorts.end(); ++it)
        tcpPorts.push_back(*it);

    for (it = udpDestinationPorts.begin();
         it != udpDestinationPorts.end(); ++it)
        udpPorts.push_back(*it);

    sort(sources.begin(), sources.end(), comparePairs);
    sort(destinations.begin(), destinations.end(), comparePairs);
    sort(tcpPorts.begin(), tcpPorts.end(), comparePairs);
    sort(udpPorts.begin(), udpPorts.end(), comparePairs);

    /* =====================================================
       PORT SCAN
       ===================================================== */

    bool portScanAvailable =
        tcpFlagsIndex >= 0 &&
        tcpDstPortIndex >= 0;

    bool possiblePortScan = false;
    string portScanSource = "";
    int portScanUniquePorts = 0;

    map<string, set<string> >::iterator scanIt;

    for (scanIt = tcpSynPortsBySource.begin();
         scanIt != tcpSynPortsBySource.end(); ++scanIt)
    {
        int count = (int)scanIt->second.size();

        if (count >= 10)
        {
            possiblePortScan = true;

            if (count > portScanUniquePorts)
            {
                portScanUniquePorts = count;
                portScanSource = scanIt->first;
            }
        }
    }

    /* =====================================================
       DNS ANOMALY
       ===================================================== */

    bool dnsAnomaly = false;
    string dnsAnomalySource = "";
    int dnsAnomalyCount = 0;

    map<string, int>::iterator dnsIt;

    for (dnsIt = dnsSourceCount.begin();
         dnsIt != dnsSourceCount.end(); ++dnsIt)
    {
        if (dnsIt->second > 100)
        {
            dnsAnomaly = true;

            if (dnsIt->second > dnsAnomalyCount)
            {
                dnsAnomalySource = dnsIt->first;
                dnsAnomalyCount = dnsIt->second;
            }
        }
    }

    int securityIndicators = 0;

    if (tcpRetransmissions > 0)
        securityIndicators++;

    if (tcpResets > 0)
        securityIndicators++;

    if (possiblePortScan)
        securityIndicators++;

    if (dnsAnomaly)
        securityIndicators++;

    /* =====================================================
       CONSOLE OUTPUT
       ===================================================== */

    cout << endl;
    cout << "Traffic Summary" << endl;
    cout << "---------------" << endl;
    cout << "Total Packets : " << totalPackets << endl;
    cout << "TCP Packets   : " << tcpPackets << endl;
    cout << "UDP Packets   : " << udpPackets << endl;
    cout << "DNS Packets   : " << dnsPackets << endl;
    cout << "HTTP Packets  : " << httpPackets << endl;
    cout << "TLS Packets   : " << tlsPackets << endl;
    cout << "QUIC Packets  : " << quicPackets << endl;
    cout << "ICMPv6        : " << icmpv6Packets << endl;

    cout << endl;
    cout << "Security Analysis" << endl;
    cout << "-----------------" << endl;
    cout << "TCP Retransmissions : " << tcpRetransmissions << endl;
    cout << "TCP Resets          : " << tcpResets << endl;

    cout << endl;
    cout << "TCP Port Scan       : ";

    if (!portScanAvailable)
        cout << "UNAVAILABLE" << endl;
    else if (possiblePortScan)
        cout << "POTENTIAL SCAN" << endl;
    else
        cout << "NONE" << endl;

    cout << "DNS Anomaly         : "
         << (dnsAnomaly ? "POTENTIAL ANOMALY" : "NONE")
         << endl;

    cout << "Indicators to Review: "
         << securityIndicators << endl;

    cout << endl;
    cout << "TLS count method: frame.protocols contains TLS" << endl;

    cout << endl;
    cout << "============================================" << endl;
    cout << "           ANALYSIS COMPLETED" << endl;
    cout << "============================================" << endl;

    /* =====================================================
       GENERATE analysis.js
       ===================================================== */

    ofstream js(jsPath.c_str());

    if (!js.is_open())
    {
        cout << endl;
        cout << "WARNING: Could not create analysis.js" << endl;
    }
    else
    {
        js << "var analysisData = {\n";
        js << "  totalPackets:" << totalPackets << ",\n";
        js << "  tcpPackets:" << tcpPackets << ",\n";
        js << "  udpPackets:" << udpPackets << ",\n";
        js << "  dnsPackets:" << dnsPackets << ",\n";
        js << "  httpPackets:" << httpPackets << ",\n";
        js << "  tlsPackets:" << tlsPackets << ",\n";
        js << "  quicPackets:" << quicPackets << ",\n";
        js << "  icmpv6Packets:" << icmpv6Packets << ",\n";
        js << "  tcpRetransmissions:" << tcpRetransmissions << ",\n";
        js << "  tcpResets:" << tcpResets << ",\n";
        js << "  tcpPortScanAvailable:" << (portScanAvailable ? "true" : "false") << ",\n";
        js << "  tcpPortScanDetected:" << (possiblePortScan ? "true" : "false") << ",\n";
        js << "  tcpPortScanSource:\"" << jsEscape(portScanSource) << "\",\n";
        js << "  tcpPortScanUniquePorts:" << portScanUniquePorts << ",\n";
        js << "  dnsAnomalyDetected:" << (dnsAnomaly ? "true" : "false") << ",\n";
        js << "  dnsAnomalySource:\"" << jsEscape(dnsAnomalySource) << "\",\n";
        js << "  dnsAnomalyCount:" << dnsAnomalyCount << ",\n";
        js << "  securityIndicators:" << securityIndicators << ",\n";

        js << "  protocols:{";
        js << "TCP:" << tcpPackets << ",";
        js << "UDP:" << udpPackets << ",";
        js << "TLS:" << tlsPackets << ",";
        js << "DNS:" << dnsPackets << ",";
        js << "HTTP:" << httpPackets << ",";
        js << "QUIC:" << quicPackets << ",";
        js << "ICMPv6:" << icmpv6Packets;
        js << "},\n";

        js << "  topSources:";
        writeList(js, sources, 5);
        js << ",\n";

        js << "  topDestinations:";
        writeList(js, destinations, 5);
        js << ",\n";

        js << "  topTCPPorts:";
        writeList(js, tcpPorts, 10);
        js << ",\n";

        js << "  topUDPPorts:";
        writeList(js, udpPorts, 10);
        js << "\n";

        js << "};\n";
        js.close();

        cout << endl;
        cout << "[OK] analysis.js generated." << endl;
        cout << "Path: " << jsPath << endl;
    }

    /* =====================================================
       GENERATE REPORT
       ===================================================== */

    ofstream report(reportPath.c_str());

    if (!report.is_open())
    {
        cout << "WARNING: Could not create network_analysis_report.txt" << endl;
    }
    else
    {
        report << "NETWORK TRAFFIC ANALYSIS REPORT\n";
        report << "================================\n\n";
        report << "Total Packets Analyzed: " << totalPackets << "\n\n";

        report << "TRAFFIC SUMMARY\n";
        report << "---------------\n";
        report << "TCP Packets: " << tcpPackets << "\n";
        report << "UDP Packets: " << udpPackets << "\n";
        report << "DNS Packets: " << dnsPackets << "\n";
        report << "HTTP Packets: " << httpPackets << "\n";
        report << "TLS Packets: " << tlsPackets << "\n";
        report << "QUIC Packets: " << quicPackets << "\n";
        report << "ICMPv6 Packets: " << icmpv6Packets << "\n\n";

        report << "SECURITY ANALYSIS\n";
        report << "-----------------\n";
        report << "TCP Retransmissions: " << tcpRetransmissions << "\n";
        report << "TCP Resets: " << tcpResets << "\n";

        if (!portScanAvailable)
            report << "TCP Port Scan: Analysis unavailable\n";
        else if (possiblePortScan)
            report << "TCP Port Scan: Potential scan detected\n";
        else
            report << "TCP Port Scan: No potential scan detected\n";

        if (dnsAnomaly)
            report << "DNS Anomaly: Potential anomaly detected\n";
        else
            report << "DNS Anomaly: No potential anomaly detected\n";

        report << "\nTLS metric: counted from the TLS layer in frame.protocols.\n";
        report << "Detection indicators do not by themselves prove malicious activity.\n";

        report.close();

        cout << endl;
        cout << "[OK] network_analysis_report.txt generated." << endl;
        cout << "Path: " << reportPath << endl;
    }

    cout << endl;
    cout << "Analysis completed successfully." << endl;
    cout << endl;
    cout << "Press Enter to continue...";
    cin.get();

    return 0;
}
