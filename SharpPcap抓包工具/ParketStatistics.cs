using PacketDotNet;
using PacketDotNet.Utils;
using SharpPcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;
using TwzyProtocol;
using TwzyProtocol.DNS;

namespace SharpPcap抓包工具
{
    //数据包统计类（对抓到的RawCapture包进行解析，用于datagridview的数据绑定）
    public class ParketStatistics
    {
        //字段定义
        public List<string> ProtocolList = new List<string>();
        public PacketDotNet.EthernetPacket epacket;         //链路包
        public Packet packet;      //原始包
        public RawCapture rawpacket;             //基础包
        public string time;             //时间
        public string protocol;             //协议
        int length;         //长度
        public string detail;           //细节
        public int no;          //编号
        public string src;          //原地址
        public string dst;          //目的地址

        //属性定义
        public int No { get { return no; } }            //编号
        public string Time { get { return time; } }   //时间
        public string Sourse { get { return src; } }        //源地址
        public string Destination { get { return dst; } }      //目的地址
        public string Protocol { get { return protocol; } }       //协议
        public int Length { get { return length; } }        //长度
        public string Info { get { return detail; } }         //信息


        //构造函数（参数1 编号 参数2 基础包）
        public ParketStatistics(int no, RawCapture rp)
        {
            try
            {
                var packet = PacketDotNet.Packet.ParsePacket(rp.LinkLayerType, rp.Data);
                this.packet = packet;       //原始包
                this.epacket = (PacketDotNet.EthernetPacket)packet;             //转换为链路包
                this.rawpacket = rp;            //基础包
                this.no = no;       //编号
                this.time = DateTime.Now.ToString();    //时间
                //解析长度
                this.length = this.rawpacket.Data.Length;    //长度
                Resolving();        //解析数据包其他信息
            }
            catch (Exception ex)
            {
                return;
            }
        }

        //解析方法(解析数据包相关内容)
        private void Resolving()
        {
            ParketAnalysis pa = new ParketAnalysis(this);
            //解析源地址和目的地址
            if(pa.IpSrc==""||pa.IpDst==""||pa.IpSrc==null||pa.IpDst==null)          //如果不存在IP，则填写物理地址
            {
                this.src = pa.MacSrc;
                this.dst = pa.MacDst;
            }
            else
            {
                this.src = pa.IpSrc;
                this.dst = pa.IpDst;
            }
            //解析协议
            this.protocol = pa.Protocol;
            //解析细节
            if(this.protocol=="ARP")
            {
                this.detail = "who has " + pa.ArpSenderIpAddress + " ，tell " + pa.ArpTargetIpAddress;
            }
            else if(this.protocol=="LCP")
            {
                this.detail = pa.LcpCode;
            }
            else if(this.protocol=="TCP")
            {
                this.detail = "源端口：" + pa.TcpSrcPort + "---->目的端口：" + pa.TcpDstPort + "，序列号：" + pa.TcpSequenceNum+"，确认号："+pa.TcpAcknowledgmentNum;
            }
            else if(this.protocol=="UDP")
            {
                this.detail = "源端口：" + pa.UdpSrcPort + "---->目的端口：" + pa.UdpDstPort;
            }
            else if (this.protocol == "ICMP")
            {
                this.detail = pa.IcmpCodeType + "  "+pa.IcmpId+"，序列号："+pa.IcmpSequenceNumBE+"/"+pa.IcmpSequenceNumLE;
            }
            else if (this.protocol == "IGMP")
            {
                this.detail = "类型：" + pa.IgmpType + "，组地址：" + pa.IgmpAddress;
            }
            else if (this.protocol == "HTTP")
            {
                this.detail = pa.HttpList[0].Content;
            }
            else if (this.protocol=="FTP"|| this.protocol == "SMTP")
            {
                this.detail = pa.CommandStr[0];
            }
            else if (this.protocol == "POP3")
            {
                if(pa.CommandStr[0][0]=='+'&& pa.CommandStr[0][1] == 'O'&& pa.CommandStr[0][2] == 'K')
                    this.detail ="S："+ pa.CommandStr[0];
                else
                    this.detail ="C：" + pa.CommandStr[0];
            }
            else if(this.protocol== "DNS")
            {
                this.detail = pa.DnsQueriesName;
            }
            else if (this.protocol == "DHCP")
            {
                this.detail = "消息类型："+pa.dhcpop+"，传输ID：" + pa.dhcptranid;
            }
            else if (this.protocol == "SSDP")
            {
                this.detail = pa.CommandStr[0];
            }
            else if(this.protocol== "SNMP")
            {
                this.detail = "共同体名称：" + pa.snmpcommunityname + "，类型：" + pa.snmppudtype;
            }
            else if (this.protocol == "TFTP")
            {
                this.detail = pa.TFtpOp + "，";
                if (pa.TFtpOpInt == 1 || pa.TFtpOpInt == 2)         //写入包或请求包
                {
                    detail += "文件名：" + pa.TFtpFileName + "，传输模式：" + pa.TFtpType;
                }
                else if (pa.TFtpOpInt == 3)       //数据包
                {
                    detail += "数据：" + pa.TFtpData;
                }
                else if (pa.TFtpOpInt == 5)       //错误包
                {
                    detail += "错误类型：" + pa.TFtperror + "，错误消息：" + pa.TFtperrorMessage;
                }
                else if (pa.TFtpOpInt == 4)         //确认包
                {
                    detail += "块编号：" + pa.TFtpBlockId;
                }
            }
            //获取协议列表
            this.ProtocolList = pa.ProtocolList;

        }


    }

    //数据包详细信息分析类
    class ParketAnalysis
    {
        //协议列表（保存该数据包所用的全部协议）
        public List<string> ProtocolList=new List<string>();

        //字段定义
        private PacketDotNet.EthernetPacket epacket;         //链路包
        private RawCapture rawpacket;             //基础包
        private Packet packet;      //原始包
        private string time;             //时间
        private string protocol;             //最上层协议
        private int length;         //长度
        private int no;          //编号
        private string encapsulationtype;       //链路层封装类型
        private string epochtime;       //Epo时间
        private string protocolsframe;      //协议结构
        //private LinkLayers linktype;       //链路类型

        //数据链路层
        private string macsrc;              //物理源地址
        private string macdst;              //物理目的地址
        private string linktype;            //链路类型

        //解析为PPPoE协议
        private string pppoeversion;           //版本
        private string pppoetype;           //类型
        private string pppoecode;       //编码
        private string pppoeid;           //id
        private string pppoelength;           //长度
        //ppp协议
        private string pppprotocol;         //ppp的上层协议



        //网络层
        //解析为LCP协议
        private string lcpcode;           //code
        private int lcpidentifier;         
        private int lcplength;        
        private string lcpdata;           
        //解析为IP协议
        #region IP
        private string ipversion;           //版本
        private int ipheaderlength;           //头部长度
        private string ipdifferentiatedservicesfield;        //差分服务
        private int iptotallength;           //总长度
        private string ipflag;     //标记
        private string ipid;       //标识
        private int ipfragmentoffset;     //分段偏移
        private int ipttl;     //生存周期
        private string ipprotocol;      //上层协议
        private string ipchecksum;      //头部校验和
        private string ipsrc;      //源地址
        private string ipdst;      //目的地址 
        #endregion
        //IPv6
        public string ipv6version;           //版本
        public int ipv6headerlength;           //头部长度
        public int ipv6ttl;     //生存周期
        public string ipv6protocol;      //上层协议
        public string ipv6src;      //源地址
        public string ipv6dst;      //目的地址 
        public string ipv6trafficclass;  //流量类别
        public string ipv6payloadlength;  //载荷长度
        public string ipv6hoplimit;        //跳数限制

        //解析为ICMP协议
        #region ICMP
        private string icmpcodetype;        //类型/代码
        private string icmpchecksum;        //校验和
        private string icmpid;  //      id
        private string icmpsequencenumbe;  //      序列号 
        private string icmpsequencenumle;  //      序列号 
        #endregion
        //解析为IGMP协议
        #region IGMP
        private string igmpversion;     //版本
        private string igmptype;        //类型
        private string igmpmrt;     //mrt
        private string igmpchecksum;        //校验和
        private string igmpaddress;     //组地址 
        #endregion
        //解析为ARP协议
        #region ARP
        private string arphardwaretype;         //硬件类型
        private string arpprotocoltype;         //协议类型
        private int arphardwaresize;         //硬件大小
        private int arpprotocolsize;         //协议大小
        private ARPOperation arpopcode;         //操作码
        private string arpsendermacaddress;     //发送物理地址
        private IPAddress arpsenderipaddress;          //发送IP地址
        private string arptargetmacaddress;     //接收物理地址
        private IPAddress arptargetipaddress;          //接收IP地址 
        #endregion

        //传输层协议
        //解析为TCP协议
        #region TCP
        private int tcpsrcport;     //源端口
        private int tcpdstport;     //目的端口
        private string tcpsequencenum;     //序列号
        private string tcpacknowledgmentnum;     //确认号
        private int tcpheaderlength;     //头部长度
        private byte tcpflag;            //标志位
        private int tcpwindowsize;  //窗口大小
        private string tcpchecksum;       //校验和
        private int tcpurgentpointer;     //紧急指针
        private byte[] tcppayloaddata;
        #endregion
        //解析为UDP协议
        #region UDP
        private int udpsrcport;     //源端口
        private int udpdstport;     //目的端口
        private int udplength;     //头部长度
        private string udpchecksum;       //校验和
        private byte[] udppayloaddata;
        #endregion


        //应用层
        //基于TCP协议的应用层协议（该部分为命令行形式）
        private List<string> commandstr = new List<string>();      //包括 http ssdp（udp） pop3 ftp smtp
        private List<CommandTypeHead> httplist;
        public string type = "";
        //基于UDP的应用层协议
        #region DNS
        private string dnsid;      //id
        private string dnsflag;      //标志
        private string dnsquestion;        //问题数
        private string dnsanswerrr;        //回答rr数
        private string dnsauthorityrr;        //回答rr数
        private string dnsaddrr;        //附加rr数
        private string dnsqueriesname;      //问题区域
        private string dnsqueriestype;      //问题区域
        private string dnsqueriesclass;      //问题区域
        private List<DnsResponse> dnsanswerers;      //回答区域 
        #endregion

        #region TFTP
        private string tftpop;      //操作码
        private int tftpopint;      //操作码int
        private string tftpfilename;    //文件名
        private string tftptype;        //类型 
        private string tftperror;        //错误码
        private string tftperrormessage;        //错误消息
        private string tftpdata;        //数据
        private int tftpblockid;        //块编号
        #endregion

        #region DHCP
        public string dhcpop;      //操作码（消息类型）
        public string dhcphardwaretype;    //硬件类型
        public string dhcphwlen;        //硬件长度 
        public string dhcphops;        //hops
        public string dhcptranid;        //传输id
        public string dhcpsecond;       //传输时间
        public string dhcpflag;       //标识
        public string dhcpcip;            //客户端IP
        public string dhcpycip;           //你的IP
        public string dhcpnsip;           //下一个服务器IP
        public string dhcpraip;           //延迟代理IP
        public string dhcpcmac;            //客户端MAC
        public string dhcphap;           //硬件地址填充
        public string dhcpshname;           //服务器主机名称
        public string dhcpfname;           //引导文件名称
        public string dhcpmagiccookie = "";
        public List<DhcpOption> dhcpoplist;

        #endregion

        #region SNMP
        public string snmpversion;                      //版本
        public string snmpcommunityname;            //共同体名称
        public string snmppudtype;        //pud类型
        public int snmprequestid;          //请求标识符
        public string snmperror;                 //错误状态
        public int snmperrorix;                  //错误索引
        #endregion


        //数据
        private string data;

        //属性定义
        //public LinkLayers LinkType { get { return linktype; } }       //链路类型
        public int No { get { return no; } }
        public string Time { get { return time; } }
        public string Protocol { get { return protocol; } }
        public int Length { get { return length; } }
        public string Encapsulationtype { get { return encapsulationtype; } }
        public string EpochTime { get { return epochtime; } }
        public string ProtocolsFrame { get { return protocolsframe; } }
        public string MacSrc { get { return macsrc; } }
        public string MacDst { get { return macdst; } }
        public string LinkType { get { return linktype; } }//链路类型

        public string PPPoEVersion { get { return pppoeversion; } }
        public string PPPoEType { get { return pppoetype; } }
        public string PPPoECode { get { return pppoecode; } }
        public string PPPoEId { get { return pppoeid; } }
        public string PPPoELength { get { return pppoelength; } }
        public string PPPProtocol { get { return pppprotocol; } }

        public string ArpHardwareType { get { return arphardwaretype; } }
        public string ArpProtocolType { get { return arpprotocoltype; } }
        public int ArpHardwareSize { get { return arphardwaresize; } }
        public int ArpProtocolSize { get { return arpprotocolsize; } }
        public ARPOperation ArpOpCode { get { return arpopcode; } }
        public string ArpSenderMacAddress { get { return arpsendermacaddress; } }
        public string ArpTargetMacAddress { get { return arptargetmacaddress; } }
        public IPAddress ArpSenderIpAddress { get { return arpsenderipaddress; } }
        public IPAddress ArpTargetIpAddress { get { return arptargetipaddress; } }

        public string IpVersion { get { return ipversion; } }
        public int IpHeaderlength { get { return ipheaderlength; } }
        public string IpDifferentiatedServicesfield { get { return ipdifferentiatedservicesfield; } }
        public int IpTotolLength { get { return iptotallength; } }
        public string IpId { get { return ipid; } }
        public string IpFlag { get { return ipflag; } }
        public int IpFragmentOffset { get { return ipfragmentoffset; } }
        public int IpTTL { get { return ipttl; } }
        public string IpProtocol { get { return ipprotocol; } }
        public string IpCheckSum { get { return ipchecksum; } }
        public string IpSrc { get { return ipsrc; } }
        public string IpDst { get { return ipdst; } }

        public string LcpCode { get { return lcpcode; } }
        public int LcpIdentifier { get { return lcpidentifier; } }
        public int LcpLength { get { return lcplength; } }
        public string LcpData { get { return lcpdata; } }


        public int TcpSrcPort { get { return tcpsrcport; } }
        public int TcpDstPort { get { return tcpdstport; } }
        public string TcpSequenceNum { get { return tcpsequencenum; } }
        public string TcpAcknowledgmentNum { get { return tcpacknowledgmentnum; } }
        public int TcpHeaderLength { get { return tcpheaderlength; } }
        public int TcpWindowSize { get { return tcpwindowsize; } }
        public string TcpCheckSum { get { return tcpchecksum; } }
        public int TcpUrgentPointer { get { return tcpurgentpointer; } }
        public byte TcpFlag { get { return tcpflag; } }
        public byte[] TcpPayloadData { get { return tcppayloaddata; } }

        public int UdpSrcPort { get { return udpsrcport; } }
        public int UdpDstPort { get { return udpdstport; } }
        public int UdpLength { get { return udplength; } }
        public string UdpCheckSum { get { return udpchecksum; } }

        public string IcmpCodeType { get { return icmpcodetype; } }
        public string IcmpCheckSum { get { return icmpchecksum; } }
        public string IcmpId { get { return icmpid; } }
        public string IcmpSequenceNumBE { get { return icmpsequencenumbe; } }
        public string IcmpSequenceNumLE { get { return icmpsequencenumle; } }

        public string IgmpVersion { get { return igmpversion; } }
        public string IgmpType { get { return igmptype; } }
        public string IgmpMRT { get { return igmpmrt; } }
        public string IgmpCheckSum { get { return igmpchecksum; } }
        public string IgmpAddress { get { return igmpaddress; } }

        public List<string> CommandStr { get { return commandstr; } }
        public List<CommandTypeHead> HttpList { get { return httplist; } }
        //public List<CommandTypeHead> HttpList { get { return httplist; } }

        public string DnsId { get { return dnsid; } }     //id
        public string DnsFlag { get { return dnsflag; } }     //标志
        public string DnsQuestion { get { return dnsquestion; } }       //问题数
        public string DnsAnswerRr { get { return dnsanswerrr; } }        //回答rr数
        public string DnsAuthorityRr { get { return dnsauthorityrr; } }         //权威rr数
        public string DnsAddRr { get { return dnsaddrr; } }       //附加rr数
        public string DnsQueriesName { get { return dnsqueriesname; } }    //问题区域
        public string DnsQueriesType { get { return dnsqueriestype; } }      //问题区域
        public string DnsQueriesClass { get { return dnsqueriesclass; } }      //问题区域
        public List<DnsResponse> DnsAnswerers { get { return dnsanswerers; } }     //回答区域


        public string TFtpOp { get { return tftpop; } }
        public string TFtpFileName { get { return tftpfilename; } }
        public string TFtpType { get { return tftptype; } }
        public int TFtpOpInt { get { return tftpopint; } }
        public string TFtperror { get { return tftperror; } }
        public string TFtperrorMessage { get { return tftperrormessage; } }
        public string TFtpData { get { return tftpdata; } }
        public int TFtpBlockId { get { return tftpblockid; } }

        public string Data { get { return data; } }





        //构造函数（参数1 编号 参数2 基础包）
        public ParketAnalysis(ParketStatistics ps)
        {
            try
            {
                this.packet = ps.packet;
                this.epacket = ps.epacket;   //链路包
                this.rawpacket = ps.rawpacket;            //基础包
                this.no = ps.No;       //编号
                this.time = ps.Time;        //捕获时间
                Resolving();        //解析数据包其他信息
            }
            catch (Exception ex)
            {
                ex.ToString();
                return;
            }
        }

        //解析方法(解析数据包相关内容)
        private void Resolving()
        {
            //物理层的数据帧概况
            this.encapsulationtype = this.rawpacket.LinkLayerType.ToString();        //封装类型
            this.epochtime = rawpacket.Timeval.ToString();      //Epo时间
            this.protocolsframe = "ect : entertype ";       //协议结构

            //链路层报文解析
            this.macsrc = this.epacket.SourceHwAddress.ToString();       //原地址
            this.macsrc = TranMac(this.macsrc);
            this.macdst = this.epacket.DestinationHwAddress.ToString();      //目的地址
            this.macdst = TranMac(this.macdst);
            this.linktype = this.epacket.Type.ToString().ToUpper();           //链路类型
            if (this.linktype == "56329")
                this.linktype = "未知";



            //判断网络层协议
            switch (this.epacket.Type)
            {
                case EthernetPacketType.Arp://ARP协议
                    Arp();      //Arp分析
                    break;
                case EthernetPacketType.IpV4://IPV4协议
                    IpV4();
                    break;
                case EthernetPacketType.IpV6://IPV4协议
                    IpV6();
                    break;
                case EthernetPacketType.PointToPointProtocolOverEthernetDiscoveryStage:   //PPPoE
                case EthernetPacketType.PPPoE:
                    PPPoE();
                    break;
                case EthernetPacketType.None://无可用协议
                default:
                    this.protocol = "未知协议"; break;
            }


            //基于IP协议的上层协议
            if (this.ipprotocol == "TCP"||this.ipv6protocol=="TCP")
            {
                #region TCP
                TcpPacket tcppacket = TcpPacket.GetEncapsulated(this.packet);      //TCP包
                this.tcpsrcport = tcppacket.SourcePort;     //源端口
                this.tcpdstport = tcppacket.DestinationPort;     //目的端口
                this.tcpsequencenum =tcppacket.SequenceNumber.ToString();    //序列号  
                this.tcpacknowledgmentnum = tcppacket.AcknowledgmentNumber.ToString();     //确认号
                this.tcpheaderlength = tcppacket.Header.Length;     //头部长度
                this.tcpflag = tcppacket.AllFlags;      //标志位            
                this.tcpwindowsize = tcppacket.WindowSize;      //窗口大小
                this.tcpchecksum = "0x" + tcppacket.Checksum.ToString("X");      //校验和
                this.tcpurgentpointer = tcppacket.UrgentPointer;      //紧急指针
                this.tcppayloaddata = this.packet.PayloadData;
                ProtocolList.Add("TCP");
                #endregion
                //应用层解析
                //判断协议类别
                int src = tcppacket.SourcePort;        //获取端口号
                int dst = tcppacket.DestinationPort;        //获取端口号
                byte[] Byte = tcppacket.PayloadData;
                //http
                if (ProtocolType(80, src, dst, Byte) || ProtocolType(8080, src, dst, Byte) || ProtocolType(3128, src, dst, Byte))     //http协议
                {
                    this.protocol = "HTTP";
                    HttpPacket p = new HttpPacket(Byte);    //构造HTTP包
                    //this.commandlist = p.CreatHeadList();                   //Http数据包头部
                    MyHttpPacket http = new MyHttpPacket(Byte,p);
                    this.commandstr = http.Command;
                    this.httplist = http.httplist;
                    this.protocolsframe += ": http ";
                    ProtocolList.Add("HTTP");
                }
                //ftp
                else if (ProtocolType(21, src, dst, Byte))
                {
                    this.protocol = "FTP";
                    MyFtpPacket ftp = new MyFtpPacket(Byte);
                    this.type = ftp.Type;       //包类型
                    CommandStr.Add(ftp.Command);
                    ProtocolList.Add("FTP");
                    this.protocolsframe += ": ftp ";
                }
                //smtp
                else if (ProtocolType(25, src, dst, Byte))
                {
                    this.protocol = "SMTP";
                    MySmtpPacket p = new MySmtpPacket(Byte);    //构smtp包         
                    this.commandstr.Add(p.Command);
                    //this.commandlist = p.CreatHeadList();                   //smtp数据包头部
                    ProtocolList.Add("SMTP");
                    this.protocolsframe += ": smtp ";
                }
                //pop3
                else if (ProtocolType(110, src, dst, Byte))
                {
                    this.protocol = "POP3";
                    MyPop3Packet p = new MyPop3Packet(Byte);    //构Pop3包     
                    this.CommandStr.Add(p.Command);
                    //this.commandlist = p.CreatHeadList();                   //Http数据包头部
                    this.protocolsframe += ": pop3 ";
                    ProtocolList.Add("POP3");
                }
                else
                    this.protocol = "TCP";

            }
            else if (this.ipprotocol == "UDP" || this.ipv6protocol == "UDP")  //UDP
            {
                #region UDP
                UdpPacket udppacket = UdpPacket.GetEncapsulated(this.epacket);      //UDP包
                //UdpPacket udppacket = UdpPacket.GetEncapsulated(this.packet);      //UDP包
                this.udpsrcport = udppacket.SourcePort;     //源端口
                this.udpdstport = udppacket.DestinationPort;     //目的端口
                this.udplength = udppacket.Length;     //长度
                this.udpchecksum = "0x" + udppacket.Checksum.ToString("X");  //校验和
                this.udppayloaddata = this.packet.PayloadData;
                ProtocolList.Add("UDP");
                #endregion
                //应用层解析
                //判断协议类别
                int src = udppacket.SourcePort;        //获取端口号
                int dst = udppacket.DestinationPort;        //获取端口号
                byte[] Byte = udppacket.PayloadData;
                //dns
                if (ProtocolType(53, src, dst, Byte))
                {
                    this.protocol = "DNS";
                    DnsPacket dnsp = new DnsPacket(Byte);
                    this.dnsid = "0x" + dnsp.ID.ToString("X");      //标识
                    this.dnsflag = "0x" + dnsp.Flags.ToString("X");      //标志
                    this.dnsquestion = dnsp.QusetionCounts.ToString();        //问题数
                    this.dnsanswerrr = dnsp.AnswerCounts.ToString();        //回答rr数
                    this.dnsauthorityrr = dnsp.AuthorityCounts.ToString();        //权威rr数
                    this.dnsaddrr = dnsp.AdditionalCounts.ToString();        //附加rr数
                    this.dnsqueriesname = dnsp.Query.name;      //问题区域
                    this.dnsqueriestype = dnsp.Query.DnsType.ToString();      //问题区域
                    this.dnsqueriesclass = dnsp.Query.DnsClass.ToString();      //问题区域
                    this.dnsanswerers = dnsp.Answers;      //回答区域
                    this.protocolsframe += ": dns ";
                    ProtocolList.Add("DNS");
                }
                //tftp
                else if (ProtocolType(69, src, dst, Byte))
                {
                    this.protocol = "TFTP";
                    MyTftpPacket tp = new MyTftpPacket(Byte);
                    this.tftpop = tp.Opcode;         //操作码
                    this.tftpfilename = tp.FileName;        //文件名
                    this.tftptype = tp.Type;            //类型
                    this.tftperror = tp.Error;          //错误
                    this.tftperrormessage = tp.ErrorMessage;        //错误消息
                    this.tftpdata = tp.TftpData;            //数据
                    this.tftpopint = tp.OP;       //操作码int
                    this.tftpblockid = tp.BlockId;      //块编号
                    this.protocolsframe += ": tftp ";
                    ProtocolList.Add("TFTP");
                }
                //snmp
                else if (ProtocolType(161, src, dst, Byte))
                {
                    this.protocol = "SNMP";
                    MySnmpPacket snmp = new MySnmpPacket(Byte);
                    this.snmpversion = snmp.Version;
                    this.snmpcommunityname=snmp.CommunityName;            //共同体名称
                    this.snmppudtype=snmp.PUDType;        //pud类型
                    this.snmprequestid=snmp.RequestId;          //请求标识符
                    this.snmperror=snmp.Error;                 //错误状态
                    this.snmperrorix=snmp.Errorix;                  //错误索引
                    this.protocolsframe += ": snmp ";
                    ProtocolList.Add("SNMP");
                }
                //ssdp
                else if (ProtocolType(1900, src, dst, Byte))       
                {
                    this.protocol = "SSDP";
                    MySsdpPacket ssdp = new MySsdpPacket(Byte);
                    this.commandstr = ssdp.Command;
                    this.protocolsframe += ": ssdp ";
                    ProtocolList.Add("SSDP");
                }
                //dhcp
                else if (ProtocolType(67, src, dst, Byte) || ProtocolType(68, src, dst, Byte))          //DHCP
                {
                    this.protocol = "DHCP";
                    DhcpPackets dhcp = new DhcpPackets(Byte);
                    string opString = (dhcp.OP == 1) ? "Boot Request" : "Boot Reply";
                    this.dhcpop = opString;
                    this.dhcphardwaretype = dhcp.HType.ToString();
                    this.dhcphwlen = dhcp.HLen.ToString();
                    this.dhcphops = dhcp.Hops.ToString();
                    this.dhcptranid = dhcp.XID;
                    this.dhcpsecond = dhcp.Secs.ToString();
                    string unicast = (dhcp.Unicast == 0) ? "No Broadcast" : "Broadcast";
                    this.dhcpflag = "0x" + dhcp.Flags.ToString("X2") + "(" + unicast + ")";
                    this.dhcpcip = dhcp.CiAddr.ToString();            //客户端IP
                    this.dhcpycip = dhcp.YiAddr.ToString();           //你的IP
                    this.dhcpnsip = dhcp.SiAddr.ToString();           //下一个服务器IP
                    this.dhcpraip = dhcp.GiAddr.ToString();           //延迟代理IP
                    this.dhcpcmac = dhcp.CHaddr.ToString();            //客户端MAC
                    this.dhcpshname = dhcp.SName;           //服务器主机名称
                    this.dhcpfname = dhcp.File;           //引导文件名称
                    this.dhcpmagiccookie = dhcp.MagicCookie;
                    this.dhcpoplist = dhcp.Option;
                    this.protocolsframe += ": dhcp ";
                    ProtocolList.Add("DHCP");
                }
                else
                    this.protocol = "UDP";

            }
            else if (this.ipprotocol == "ICMP" || this.ipv6protocol == "ICMP")    //ICMP协议
            {
                ICMPv4Packet icmpv4parket = ICMPv4Packet.GetEncapsulated(this.epacket);      //ICMP包
                this.icmpcodetype = icmpv4parket.TypeCode.ToString();
                this.icmpchecksum = "0x" + icmpv4parket.Checksum.ToString("X");
                this.icmpid = icmpv4parket.ID.ToString();
                this.icmpsequencenumbe = icmpv4parket.Sequence.ToString();
                this.icmpsequencenumle = (icmpv4parket.Sequence*256).ToString();
                this.ProtocolList.Add("ICMP");
            }
            else if (this.ipprotocol == "IGMPv2" || this.ipprotocol == "IGMP"|| this.ipv6protocol == "IGMP")
            {
                IGMPv2Packet igmpv2parket = IGMPv2Packet.GetEncapsulated(this.epacket);     //IGMP包
                this.igmpversion = "IGMP Version：2";
                this.igmptype = igmpv2parket.Type.ToString();       //类型
                this.igmpmrt = igmpv2parket.MaxResponseTime.ToString(); //最大回应时间
                this.igmpchecksum = "0x" + igmpv2parket.Checksum.ToString("X");       //校验和
                this.igmpaddress = igmpv2parket.GroupAddress.ToString();       //组地址
                this.ProtocolList.Add("IGMP");
            }


           
            //解析数据
            this.data = HexConvert.ConvertToHexText(rawpacket.Data);

            //解析长度
            this.length = this.rawpacket.Data.Length;
        }

        //获取最上层协议（如果应用层存在协议则为应用层所用协议，否则为传输层协议）
        private void TopLyaerProtocol(IpPacket ippacket)
        {
            //获取传输层协议
            string TransportLayer = ippacket.Protocol.ToString();
            if (TransportLayer == "TCP")
            {
                #region 传输层为TCP
                //IP数据包转换为TCP数据包
                TcpPacket tcppacket = TcpPacket.GetEncapsulated(this.epacket);
                this.protocolsframe += ": tcp ";            //协议结构
                if (tcppacket != null)
                {
                    int src = tcppacket.SourcePort;        //获取端口号
                    int dst = tcppacket.DestinationPort;
                    byte[] Byte = tcppacket.PayloadData;
                    #region 根据端口号判断传输层协议
                    if (ProtocolType(80, src, dst, Byte) || ProtocolType(8080, src, dst, Byte) || ProtocolType(3128, src, dst, Byte))
                    {
                        this.protocol = "HTTP";
                        this.protocolsframe += ": http ";
                    }
                    else if (ProtocolType(21, src, dst, Byte))
                    {
                        this.protocol = "FTP";
                        this.protocolsframe += ": ftp ";
                    }
                    else if (ProtocolType(25, src, dst, Byte))
                    {
                        this.protocol = "SMTP";
                        this.protocolsframe += ": smtp ";
                    }
                    else if (ProtocolType(110, src, dst, Byte))
                    {
                        this.protocol = "POP3";
                        this.protocolsframe += ": pop3 ";
                    }
                    else
                        this.protocol = "TCP";
                    #endregion
                }
                else
                    this.protocol = "TCP";
                #endregion
            }
            else if (TransportLayer == "UDP")
            {
                #region 传输层为UDP
                //IP数据包转换为UDP数据包
                UdpPacket udppacket = UdpPacket.GetEncapsulated(this.epacket);
                this.protocolsframe += ": udp ";
                if (udppacket != null)
                {
                    int src = udppacket.SourcePort;        //获取端口号
                    int dst = udppacket.DestinationPort;        //获取端口号
                    byte[] Byte = udppacket.PayloadData;
                    #region 根据端口号判断传输层协议
                    if (ProtocolType(53, src, dst, Byte))
                    {
                        this.protocol = "DNS";
                        this.protocolsframe += ": dns ";
                    }
                    else if (ProtocolType(69, src, dst, Byte))
                    {
                        this.protocol = "TFTP";
                        this.protocolsframe += ": tftp ";
                    }
                    else if (ProtocolType(161, src, dst, Byte))
                    {
                        this.protocol = "SNMP";
                        this.protocolsframe += ": snmp ";
                    }
                    else if (ProtocolType(1900, src, dst, Byte))
                    {
                        this.protocol = "SSDP";
                        this.protocolsframe += ": ssdp ";
                    }
                    else if (ProtocolType(67, src, dst, Byte) || ProtocolType(68, src, dst, Byte))
                    {
                        this.protocol = "DHCP";
                        this.protocolsframe += ": dhcp ";
                    }
                    else
                        this.protocol = "UDP";
                    #endregion
                }
                else
                    this.protocol = "UDP";
                #endregion
            }
            else        //其他协议
            {
                this.protocol = TransportLayer;
                this.protocolsframe += ": " + this.protocol.ToLower() + " ";
            }
        }


        //Arp协议
        private void Arp()
        {
            #region ARP协议解析
            ARPPacket arppacket = PacketDotNet.ARPPacket.GetEncapsulated(this.epacket); //arp包
            this.arphardwaretype = arppacket.HardwareAddressType.ToString();       //硬件类型
            this.arpprotocoltype = arppacket.ProtocolAddressType.ToString();        //协议类型
            this.arphardwaresize = arppacket.HardwareAddressLength;       //硬件大小
            this.arpprotocolsize = arppacket.ProtocolAddressLength;       //协议大小
            this.arpopcode = arppacket.Operation;           //操作类型
            this.arpsendermacaddress = TranMac(arppacket.SenderHardwareAddress.ToString());        //物理发送地址
            this.arptargetmacaddress = TranMac(arppacket.TargetHardwareAddress.ToString());        //物理接收地址
            this.arpsenderipaddress = arppacket.SenderProtocolAddress;         //接收ip地址
            this.arptargetipaddress = arppacket.TargetProtocolAddress;         //接收ip地址
            this.protocolsframe += ": arp ";
            this.protocol = "ARP";
            ProtocolList.Add("ARP");
            #endregion
        }
        //IpV4
        private void IpV4()
        {
            #region IPV4
            IpPacket ippacket = PacketDotNet.IpPacket.GetEncapsulated(this.epacket); //ip包
            ByteArraySegment bas = new ByteArraySegment(ippacket.Bytes);
            IPv4Packet ipv4packet = new IPv4Packet(bas);     //转换为IPV4包
            this.ipheaderlength = ippacket.HeaderLength;           //头部长度
            this.ipversion = ipv4packet.Version.ToString();           //协议版本
            this.ipdifferentiatedservicesfield = "0x" + ipv4packet.DifferentiatedServices.ToString("X"); //差分服务
            this.iptotallength = ipv4packet.TotalLength;        //总长
            this.ipfragmentoffset = ipv4packet.FragmentOffset;      //分段偏移
            this.ipttl = ipv4packet.TimeToLive;     //生存周期
            this.ipprotocol = ipv4packet.Protocol.ToString();      //上层协议
            this.ipchecksum = "0x" + ipv4packet.Checksum.ToString("X");      //头部校验和
            this.ipsrc = ipv4packet.SourceAddress.ToString();       //原地址
            this.ipdst = ipv4packet.DestinationAddress.ToString();      //目的地址
            this.ipflag = "0x" + ipv4packet.FragmentFlags.ToString("X");     //标记
            this.ipid = "0x" + ipv4packet.Id.ToString("X");          //标识
            this.protocolsframe += ": ip ";
            ProtocolList.Add("IPV4");
            TopLyaerProtocol(ippacket);                //获取最上层所用的协议 
            #endregion
        }
        //IpV6
        private void IpV6()
        {
            #region IPV6
            IpPacket ippacket = PacketDotNet.IpPacket.GetEncapsulated(this.epacket); //ip包
            ByteArraySegment bas = new ByteArraySegment(ippacket.Bytes);
            IPv6Packet ipv6packet = new IPv6Packet(bas);
            this.ipv6version=ipv6packet.Version.ToString();     //版本
            this.ipv6trafficclass=ipv6packet.TrafficClass.ToString();  //流量类别
            this.ipv6trafficclass=ipv6packet.TimeToLive.ToString();      //生存周期
            this.ipv6src=ipv6packet.DestinationAddress.ToString();   //目的地址
            this.ipv6dst=ipv6packet.SourceAddress.ToString();       //源地址
            this.ipv6headerlength=ipv6packet.HeaderLength;            //头部长度
            this.ipv6payloadlength=ipv6packet.PayloadLength.ToString();    //载荷长度
            this.ipv6hoplimit=ipv6packet.HopLimit.ToString();        //跳数限制
            this.ipv6protocol=ipv6packet.NextHeader.ToString();   //上层协议
            this.protocolsframe += ": ip ";
            ProtocolList.Add("IPV6");
            TopLyaerProtocol(ippacket);                //获取最上层所用的协议 
            #endregion
        }

        //PPPoE
        private void PPPoE()
        {
            PPPoEPacket pppoe = PPPoEPacket.GetEncapsulated(packet);        //转换为PPPoE的包
            this.pppoeversion = pppoe.Version.ToString();    //类型
            this.pppoetype = pppoe.Type.ToString();     //种类
            this.pppoecode = "0x" + pppoe.Code.ToString("X");     //代码
            this.pppoeid = "0x" + pppoe.SessionId.ToString("X");      //id
            this.pppoelength = pppoe.Length.ToString();     //长度
            this.protocol = "PPPOE";
            ProtocolList.Add("PPPOE");
            //PPPoE使用的以太网络中转播PPP帧信息的技术
            PacketDotNet.PPPPacket ppp =PacketDotNet.PPPPacket.GetEncapsulated(packet);
            this.pppprotocol = ppp.Protocol.ToString();        ///ppp的上层协议
            if (pppprotocol == "IPv4")
                IpV4();
            else if(pppprotocol=="LCP")
            {
                byte[] lcpb=ppp.Bytes;
                LCP(lcpb);
            }
        }
        //LCP协议
        private void LCP(byte[] data)
        {
            MyLCPPacket lcp = new MyLCPPacket(data);
            this.lcpcode = lcp.lcpcode;
            this.lcpidentifier = lcp.lcpidentifier;
            this.lcplength = lcp.lcplength;
            this.lcpdata = lcp.lcpdata;
            this.protocol = "LCP";
            ProtocolList.Add("LCP");
        }

        //MAC地址转换方法
        string TranMac(string mac)
        {
            string r = "";
            for (int i = 0; i < mac.Length - 2; i = i + 2)
            {
                string temp = mac.Substring(i, 2); ;
                r += temp;
                r += ":";
            }
            r += mac.Substring(10, 2);
            return r;
        }

        //应用层协议类型判断
        private bool ProtocolType(int port, int srcport, int dstport, byte[] BYTE)
        {
            return ((srcport == port || dstport == port) && BYTE.Length > 0) ? true : false;
        }
    }

    //数据转换类
    class HexConvert
    {
        /// 拼接十六进制字符串
        public static string ConvertToHexText(byte[] data)
        {
            var buffer = new StringBuilder();
            string bytes = "";
            string ascii = "";
            //转化原始数据
            for (int i = 1; i <= data.Length; i++)
            {
                // hex
                bytes += (data[i - 1].ToString("X2")) + " ";

                // ascii
                if (data[i - 1] < 0x21 || data[i - 1] > 0x7e)
                {
                    ascii += ".";
                }
                else
                {
                    ascii += Encoding.ASCII.GetString(new byte[1] { data[i - 1] });
                }

                //空格换行
                if (i % 16 != 0 && i % 8 == 0)
                {
                    bytes += " ";
                    ascii += " ";
                }

                //拼接字符串
                if (i % 16 == 0)
                {
                    // 构建每一行
                    buffer.AppendLine(i.ToString("X5") + "  " + bytes + "  " + ascii);

                    // 重置数据
                    bytes = "";
                    ascii = "";

                    continue;
                }

                // 构建最后一行
                if (i == data.Length)
                {
                    // build the line
                    buffer.AppendLine(i.ToString("X5") + "  " + bytes.PadRight(49, ' ') + "  " + ascii);
                }
            }

            return buffer.ToString();
        }

        public static int bytesToInt(byte[] des, int offset)
        {
            int mask = 0xff;
            int temp = 0;
            int n = 0;
            for (int i = 0; i < des.Length; i++)
            {
                n <<= 8;
                temp = des[i] & mask;
                n |= temp;
            }
            return n;
        }



    }
    //Lcp包
    class MyLCPPacket
    {
        public string lcpcode = "";
        public int lcpidentifier;
        public int lcplength;
        public string lcpdata = "";
        public MyLCPPacket(byte[] data)
        {
            byte[] lcpdata = data.Skip(2).Take(10).ToArray();      //截取
            int code = lcpdata[0];
            switch(code)
            {
                case 1: lcpcode = "configure-request"; break;
                case 2: lcpcode = "configure-ACK"; break;
                case 3: lcpcode = "configure-NACK"; break;
                case 4: lcpcode = "configure-REJECT"; break;
                case 5: lcpcode = "teminate-request"; break;
                case 6: lcpcode = "terminate-ACK	"; break;
                case 7: lcpcode = "code-REJECT"; break;
                case 8: lcpcode = "	Protocol-REJECT"; break;
                case 9: lcpcode = "echo-request"; break;
                case 10: lcpcode = "echo-reply"; break;
                case 11: lcpcode = "discard-request"; break;
                case 12: lcpcode = "identification"; break;
                case 13: lcpcode = "Time-Remaining"; break;
            }
            lcpidentifier = lcpdata[1];
            lcplength =lcpdata[2] << 8 | lcpdata[3];    
            byte []temp= lcpdata.Skip(4).ToArray();
            this.lcpdata =System.Text.Encoding.Default.GetString(temp);      //选项域
        }
    }
    //传输层包
    //Ftp包
    class MyFtpPacket
    {
        byte[] Data;        //数据
        public string Command="";           //命令行
        public string Type = "";        //类型
        public MyFtpPacket(byte[] data)
        {
            Data = data;
            string str = System.Text.Encoding.Default.GetString(data);      //转换
            string []Arr = str.Split(new char[] { '-', ' ' }, StringSplitOptions.None);  //分割判断
            if (Regex.IsMatch(Arr[0], @"^\d+$") == true)       //纯数字字符串
            {
                Command = "Response：" + str;
                Type = "Response";
            }
            else
            {
                Command = "Request：" + str;
                Type = "Request";
            }
        }
    }
    //Http包
    class MyHttpPacket
    {
        byte[] Data;        //数据
        public List<CommandTypeHead> httplist;
        public List<string> Command = new List<string>();
        public MyHttpPacket(byte[] data,HttpPacket http)
        {
            httplist = http.CreatHeadList();
            //Data = data;
            //string str = System.Text.Encoding.Default.GetString(data);      //转换
            //string[] Arr = str.Split("\r\n".ToCharArray(), StringSplitOptions.RemoveEmptyEntries);   //分割判断
            //for(int i=0;i<Arr.Length;++i)
            //    Command.Add(Arr[i]+@"\r\n");
        }
    }
    //Smtp包
    class MySmtpPacket
    {
        byte[] Data;        //数据
        public string Command = "";
        //public string Type = "";
        public MySmtpPacket(byte[] data)
        {
            Data = data;
            string str = System.Text.Encoding.Default.GetString(data);      //转换
            string[] Arr = str.Split(new char[] { '-', ' ' }, StringSplitOptions.None);  //分割判断
            if (Regex.IsMatch(Arr[0], @"^\d+$") == true)       //纯数字字符串
            {
                Command = "Response：" + str + @"\r\n";
            }
            else
                Command = "Request：" + str + @"\r\n";
        }
    }
    //Pop3包
    class MyPop3Packet
    {
        byte[] Data;        //数据
        public string Command = "";
        public MyPop3Packet(byte[] data)
        {
            Data = data;
            string str = System.Text.Encoding.Default.GetString(data);      //转换
            Command = str ;
        }
    }


    //Ssdp包
    class MySsdpPacket
    {
        byte[] Data;        //数据
        public List<string> Command = new List<string>();
        public MySsdpPacket(byte[] data)
        {
            Data = data;
            string str = System.Text.Encoding.Default.GetString(data);      //转换
            string[] Arr = str.Split("\r\n".ToCharArray(), StringSplitOptions.RemoveEmptyEntries);   //分割判断
            for (int i = 0; i < Arr.Length; ++i)
                Command.Add(Arr[i] + @"\r\n");
        }
    }
    //Tftp包
    class MyTftpPacket
    {
        byte[] Data;        //数据
        public int OP;      //操作码
        public string Opcode = "";      //操作码
        public string FileName = "";        //文件名
        public string Type = "";        //类型
        public string Error = "";        //错误码
        public string ErrorMessage = "";        //错误消息
        public string TftpData = "";        //数据
        public int BlockId;     //块编号
        public MyTftpPacket(byte [] data)
        {
            Data = data;
            int op = Data[0] << 8 | Data[1];     //操作码(前两比特)
            this.OP = op;        //操作码
            //操作码转换为对应的操作字符串
            switch(op)
            {
                case 1: Opcode = "Read request(1)"; break;
                case 2: Opcode = "Write request (2)"; break;
                case 3: Opcode = "Data (3)"; break;
                case 4: Opcode = "Acknowledgment (4)"; break;
                case 5: Opcode = "Error (5)"; break;
            }
            if (op == 1 || op == 2)      //写入包或请求包
            {
                byte[] Skip = Data.Skip(2).ToArray();      //截取
                string str = System.Text.Encoding.Default.GetString(Skip);
                string[] Arr = str.Split('\0');      //分割
                FileName = Arr[0];      //文件名
                Type = Arr[1];      //类型
            }
            else if(op==3)          //数据包
            {
                this.BlockId = Data[2] << 8 | Data[3];     //块编号
                byte[] Skip = Data.Skip(4).ToArray();      //截取数据部分
                string str = System.Text.Encoding.Default.GetString(Skip);
                this.TftpData = str;
            }
            else if (op == 4)          //确认包
            {
                this.BlockId = Data[2] << 8 | Data[3];     //块编号
            }
            else if(op==5)   //错误包
            {
                int errorcode = Data[2] << 8 | Data[3];     //错误码
                switch (errorcode)      //错误码（字符串）
                {
                    case 1: Error = "文件未找到"; break;
                    case 2: Error = "访问非法"; break;
                    case 3: Error = "磁盘满或超过分配的配额"; break;
                    case 4: Error = "非法的TFTP操作"; break;
                    case 5: Error = "未知的传输ID"; break;
                    case 6: Error = "文件已经存在"; break;
                    case 7: Error = "没有类似的用户"; break;
                    case 0: Error = "未定义，请参阅错误信息"; break;
                }
                byte[] Skip = Data.Skip(4).ToArray();      //截取错误消息
                string str = System.Text.Encoding.Default.GetString(Skip);
                this.ErrorMessage = str.Substring(0,str.Length-2);        //去掉\0
            }
            else
            {
                return;
            }

        }
    }
    //Snmp包
    class MySnmpPacket
    {
        public string Version;
        public string CommunityName;
        public string PUDType;
        public int RequestId;
        public string Error;
        public int Errorix;


        public MySnmpPacket(byte[] data)
        {
            //第0位表示SNMP的标识域
            //第1位表示SNMP的长度域
            //第2位SNMP的协议版本标识域
            //第3位SNMP的协议版本长度
            int temp = data[4];            //第4位SNMP的协议版本
            switch (temp)
            {
                case 0: this.Version = "Snmp V1";break;
                case 1: this.Version = "Snmp V2C"; break;
                case 2: this.Version = "Snmp V3"; break;
            }
            //第5位SNMP的共同体标识域
            //第6位SNMP的共同体长度
            //第7位开始为SNMP共同体名称
            temp = data[6];     //获取长度
            int offset = temp;        //转换为字节数组长度
            byte[] Skip = data.Skip(7).Take(offset).ToArray();      //从第7位开始截取len位
            this.CommunityName = System.Text.Encoding.Default.GetString(Skip);      //共同体名称
            //第7+offset位开始为PUD部分
            int pudix = 7 + offset;
            temp = data[pudix];                   //PUD标识域（PUD类型）
            int pudtype = temp;
            switch (temp)
            {
                case 160: this.PUDType = "get-request（0xA0） "; break;
                case 161: this.PUDType = " get-next-request (0xA1)"; break;
                case 162: this.PUDType = "get-response (0xA2)"; break;
                case 163: this.PUDType = " set-request (0xA3)"; break;
                case 164: this.PUDType = "  trap (0xA4) "; break;
                case 165: this.PUDType = "GetBulk (0xA5)"; break;
                case 166:this.PUDType = "Inform (0xA6)"; break;
            }
            temp = data[pudix + 1];     //获取长度
            int Now = 0;  //变量绑定起始位置
            //pud类型（缺少snmpv2部分）
            if (pudtype<=163)           //get、set类型
            {
                //请求标识
                int now = pudix + 2;                //now位请求标识符标识域
                int len = data[now+1];                //now+1位请求标识符长度域
                //截取值域
                byte[] ss = data.Skip(now + 2).Take(len).ToArray();      //从第now + 2位开始截取len位 
                this.RequestId = HexConvert.bytesToInt(ss, 0);

                //差错状态
                now = now + 2 + len;
                //now为标识域
                len= data[now + 1];      //长度域
                int error = data[now + 2];      //错误状态
                switch (error)
                {
                    case 0: this.Error = "noError(0)"; break;
                    case 1: this.Error = "tooBig(1)"; break;
                    case 2: this.Error= "noSuchName(2)"; break;
                    case 3: this.Error = "badValue(3)"; break;
                    case 4: this.Error = "readOnly(4)"; break;
                    case 5: this.Error = "genErr(5)"; break;
                }
                //错误索引
                now = now + 3;
                //now为标识域
                len = data[now + 1];      //长度域
                Errorix = data[now + 2];      //错误索引
                Now = now + 3;   //变量绑定起始位置
            }
            else   //trap类型
            {
                
            }
            temp = data[Now];    //标识
            temp = data[Now + 1];       //长度
            temp = data[Now+2];    //标识
            temp = data[Now +3];       //长度
            temp = data[Now + 4];    //标识
            temp = data[Now + 5];       //长度
            Skip = data.Skip(Now+6).Take(temp).ToArray();      
            









            string str = System.Text.Encoding.Default.GetString(data);      //转换
            string[] Arr = str.Split("\r\n".ToCharArray(), StringSplitOptions.RemoveEmptyEntries);   //分割判断
        }
    }



}
