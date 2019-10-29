using PacketDotNet;
using SharpPcap;
using System.Windows.Forms;
using System.Text;
using System;
using TwzyProtocol;
using System.Collections.Generic;

namespace MySniffer
{
    partial class PacketInfo
    {
        /// <summary>
        /// 添加应用层协议
        /// </summary>
        /// <param name="payloadData">载荷数据</param>
        /// <param name="SourcePort">源端口</param>
        /// <param name="DestinationPort">目的端口</param>
        private void AppNode(byte[] payloadData, ushort SourcePort, ushort DestinationPort)
        {
            if (payloadData.Length == 0)
                return;
            AppsrcPort = SourcePort;
            AppdstPort = DestinationPort;
            //HTTP 80
            if (isAnalysProtocol(80))
            {
                HttpPacket http = new HttpPacket(payloadData);
                Http(http);
            }
            //smtp 25
            else if (isAnalysProtocol(25))
            {
                SmtpPacket smtp = new SmtpPacket(payloadData);
                SMTP(smtp);
            }
            //pop3 110
            else if (isAnalysProtocol(110))
            {
                Pop3Packet pop3 = new Pop3Packet(payloadData);
                POP3(pop3);
            }
            //DNS 53
            else if (isAnalysProtocol(53))
            {
                DnsPacket dns = new DnsPacket(payloadData);
                DNS(dns);
            }
            //ftp 21
            else if (isAnalysProtocol(21))
            {
                FtpPacket ftp = new FtpPacket(payloadData);
                FTP(ftp);
            }
            //DHCP 67 68
            else if (isAnalysProtocol(67) || isAnalysProtocol(68))
            {
                DhcpPackets dp = new DhcpPackets(payloadData);
                DHCP(dp);
            }
            else if (isAnalysProtocol(520))
            {
                RipPacket rp = new RipPacket(payloadData);
                RIP(rp);
            }
            //ssdp 1900
            else if (isAnalysProtocol(1900))
            {
                SSDPPacket ssdp = new SSDPPacket(payloadData);
                SSDP(ssdp);
            }
        }

        ushort AppsrcPort;
        ushort AppdstPort;
        /// <summary>
        /// 确定是否为可分析的应用层协议
        /// </summary>
        /// <param name="port">端口号</param>
        /// <returns></returns>
        private bool isAnalysProtocol(ushort port)
        {
            return (AppsrcPort == port || AppdstPort == port) ? true : false;
        }

        #region  命令行解析 http smtp pop3 ftp ssdp
        //http
        TreeNode HttpNode;
        private void Http(HttpPacket httpPacket)
        {
            if (httpPacket == null)
                return;
            if (HttpNode == null)
            {
                HttpNode = CreatNode("HTTP", 7);
            }
            HttpNode.Nodes.Clear();

            List<CommandTypeHead> httplist = httpPacket.CreatHeadList();
            if (httplist.Count == 0)
                return;
            //显示数据
            setAppTreeNode(httplist, HttpNode);
            //加入选定模式
        }
        //SMTP
        TreeNode SmtpNode;
        private void SMTP(SmtpPacket smtpPacket)
        {
            if (smtpPacket == null)
                return;
            if (SmtpNode == null)
            {
                SmtpNode = CreatNode("SMTP", 7);
            }
            SmtpNode.Nodes.Clear();

            List<CommandTypeHead> smtpList = smtpPacket.CreatHeadList();
            if (smtpList.Count == 0)
                return;
            //显示数据
            setAppTreeNode(smtpList, SmtpNode);
            //加入选定模式

        }
        TreeNode POP3Node;
        private void POP3(Pop3Packet pop3Packet)
        {
            if (pop3Packet == null)
                return;
            if (POP3Node == null)
            {
                POP3Node = CreatNode("POP3", 7);
            }
            POP3Node.Nodes.Clear();

            List<CommandTypeHead> pop3List = pop3Packet.CreatHeadList();
            if (pop3List.Count == 0)
                return;
            //显示数据
            setAppTreeNode(pop3List, POP3Node);
            //加入选定模式

        }

        //Ftp
        TreeNode FTPNode;
        private void FTP(FtpPacket ftpPacket)
        {
            if (ftpPacket == null)
                return;
            if (FTPNode == null)
            {
                FTPNode = CreatNode("FTP", 7);
            }
            FTPNode.Nodes.Clear();

            List<CommandTypeHead> ftpList = ftpPacket.CreatHeadList();
            if (ftpList.Count == 0)
                return;
            //显示数据
            setAppTreeNode(ftpList, FTPNode);
            //加入选定模式

        }

        //ssdp
        TreeNode SSDPNode;
        private void SSDP(SSDPPacket ssdpPacket)
        {
            if (ssdpPacket == null)
                return;
            if (SSDPNode == null)
            {
                SSDPNode = CreatNode("SSDP", 7);
            }
            SSDPNode.Nodes.Clear();

            List<CommandTypeHead> ssdpList = ssdpPacket.CreatHeadList();
            if (ssdpList.Count == 0)
                return;
            //显示数据;
            setAppTreeNode(ssdpList, SSDPNode);
            //加入选定模式

        }

        /// <summary>
        /// 需要处理的转义字符
        /// </summary>
        char[] replaceCharArry ={
                                    '\0','\a','\b','\f',
                                    '\t','\v','?'
                               };

        /// <summary>
        /// 将数据显示在协议树上
        /// </summary>
        /// <param name="list">列表</param>
        /// <param name="node">节点</param>
        private void setAppTreeNode(List<CommandTypeHead> list, TreeNode node)
        {
            //显示数据
            foreach (var i in list)
            {
                string tmpStr = i.Content;
                foreach (var j in replaceCharArry)
                {
                    tmpStr = tmpStr.Replace(j, '.');
                }
                node.Nodes.Add(tmpStr);
            }
            Tree.Nodes.Add(node);
        }

        #endregion

        TreeNode DnsNode;
        TreeNode dnsFlagsNode;
        TreeNode dnsQueryNode;
        List<TreeNode> dnsAnswerNodeList;
        private void DNS(DnsPacket dns)
        {
            if (dns == null)
                return;
            if (DnsNode == null)
            {
                DnsNode = CreatNode("DNS", 7);
            }
            DnsNode.Nodes.Clear();

            DnsNode.Nodes.Add("Transaction ID: [0x" + dns.ID.ToString("X4") + "]");
            #region Flags
            if (dnsFlagsNode == null)
            {
                dnsFlagsNode = new TreeNode();
            }
            dnsFlagsNode.Nodes.Clear();
            dnsFlagsNode.Text = "Flags: [0x" + dns.Flags.ToString("X4") + "]";

            string quMsg = (dns.QR == 0) ? "Message is a query" : "Message is a response";
            dnsFlagsNode.Nodes.Add(dns.QR.ToString() + "... .... .... .... = Response: " + quMsg);
            string opCodeStr = Convert.ToString(dns.OpCode, 2).PadLeft(4, '0').Insert(3, " ");
            string opcodeResult = "";
            switch (dns.OpCode)
            {
                case 0:
                    opcodeResult = "Standar Query";
                    break;
                case 1:
                    opcodeResult = "Opposite Query";
                    break;
                case 2:
                    opcodeResult = "Server status Query";
                    break;
                default:
                    opcodeResult = "Undefined";
                    break;

            }
            dnsFlagsNode.Nodes.Add("." + opCodeStr + "... .... .... = OpCode: " + opcodeResult + " (" + dns.OpCode + ")");
            string AAStr = (dns.AA == 0) ? "Server is not an authority for aomain" : "Server is  an authority for aomain";
            dnsFlagsNode.Nodes.Add(".... ." + dns.AA + ".. .... .... = Authoritative: " + AAStr);
            string trcStr = (dns.TC == 0) ? "Message is No truncated" : "Message is truncated";
            dnsFlagsNode.Nodes.Add(".... .." + dns.TC + ". .... .... = Truncated: " + trcStr);
            string RdStr = (dns.RD == 0) ? " Don't do query recursively" : "Do query recursively";
            dnsFlagsNode.Nodes.Add(".... ..." + dns.RD + " .... .... = Recursion desired: " + RdStr);
            string RaStr = (dns.RA == 0) ? "Server can do recursive queries" : "Server can't do recursive queries";
            dnsFlagsNode.Nodes.Add(".... .... " + dns.RA + "... .... = Recursion avaiable: " + RaStr);
#warning 此处可能已经定义，以后希望修改
            dnsFlagsNode.Nodes.Add(".... .... .000 .... = Reserved bits");
            string rcodeStr = "";
            switch (dns.rCode)
            {
                case 0:
                    rcodeStr = "No error";
                    break;
                case 1:
                    rcodeStr = "Format error";
                    break;
                case 2:
                    rcodeStr = "Dns server error";
                    break;
                case 3:
                    rcodeStr = "Domain parameters error";
                    break;
                case 4:
                    rcodeStr = "type is not supported";
                    break;
                case 5:
                    rcodeStr = "Management banned";
                    break;
                default:
                    rcodeStr = "Undefined";
                    break;
            }
            string dnsRCodestr = Convert.ToString(dns.rCode, 2).PadLeft(4, '0');
            dnsFlagsNode.Nodes.Add(".... .... .... " + dnsRCodestr + " = Reply code: " + rcodeStr + " (" + dns.rCode + ")");
            DnsNode.Nodes.Add(dnsFlagsNode);
            #endregion
            DnsNode.Nodes.Add("Questions: " + dns.QusetionCounts);
            DnsNode.Nodes.Add("Answer RRs: " + dns.AnswerCounts);
            DnsNode.Nodes.Add("Authority RRs: " + dns.AuthorityCounts);
            DnsNode.Nodes.Add("Additional RRs: " + dns.AdditionalCounts);

            #region Query Part

            if (dnsQueryNode == null)
            {
                dnsQueryNode = new TreeNode();
                dnsQueryNode.Text = "Questions";

            }
            TwzyProtocol.DNS.DnsQuery dnsQuery = dns.Query;
            dnsQueryNode.Nodes.Clear();
            if (dnsQuery != null)
            {
                dnsQueryNode.Name = "DNS_QU";
                dnsQueryNode.Text = "Questions [Name=" + dnsQuery.name + "] [Type=" + dnsQuery.DnsType + "] [Class=" + dnsQuery.DnsClass + "]";
                dnsQueryNode.Nodes.Add("Name: " + dnsQuery.name);
                dnsQueryNode.Nodes.Add("Type: " + dnsQuery.DnsType + " [0x" + dnsQuery.DnsType.ToString("X") + "]");
                dnsQueryNode.Nodes.Add("Class: " + dnsQuery.DnsClass + " [0x" + dnsQuery.DnsClass.ToString("X") + "]");
            }
            else
            {
                dnsQueryNode.Nodes.Add("Error Data: " + Encoding.ASCII.GetString(dns.ErrData));
            }
            DnsNode.Nodes.Add(dnsQueryNode);
            #endregion

            #region Response Parts

            List<TwzyProtocol.DNS.DnsResponse> relist = null;

            if (dns.QR == 1 && dnsQuery != null)
            {
                relist = dns.ResponseList;
                if (dnsAnswerNodeList == null)
                {
                    dnsAnswerNodeList = new List<TreeNode>();
                }
                dnsAnswerNodeList.Clear();
                foreach (var k in relist)
                {
                    TreeNode reNode = new TreeNode();
                    reNode.Name = "DNS_AN";
                    reNode.Text = k.AnswerType.ToString() + " [Name=" + k.name + "] [Type=" + k.dnsType + "] [Class=" + k.dnsClass + "] [Legth=" + k.payLength.ToString() + "bytes] [TTL=" + k.TTL.ToString() + "s] [Address=" + k.rescData + "]";
                    reNode.Nodes.Add("Name: " + k.name);
                    reNode.Nodes.Add("Type: " + k.dnsType + " [0x" + k.dnsType.ToString("X") + "]");
                    reNode.Nodes.Add("Class: " + k.dnsClass + " [0x" + k.dnsClass.ToString("X") + "]");
                    reNode.Nodes.Add("TTL: " + k.TTL.ToString() + "s");
                    reNode.Nodes.Add("Data Length: " + k.payLength.ToString());
                    reNode.Nodes.Add("Address: " + k.rescData);
                    dnsAnswerNodeList.Add(reNode);
                }
                DnsNode.Nodes.AddRange(dnsAnswerNodeList.ToArray());

            }

            #endregion

            Tree.Nodes.Add(DnsNode);

        }

        //DHCP
        TreeNode DhcpNode;
        TreeNode DhcpFlagsNodes;
        private void DHCP(DhcpPackets dhcp)
        {
            if (dhcp == null)
                return;
            if (DhcpNode == null)
            {
                DhcpNode = CreatNode("DHCP", 7);
            }
            DhcpNode.Nodes.Clear();

            string opString = (dhcp.OP == 1) ? "Boot Request" : "Boot Reply";
            DhcpNode.Nodes.Add("Op Code: " + opString + " (" + dhcp.OP + ")");
            DhcpNode.Nodes.Add("Hareware Type: " + dhcp.HType + " [0x" + ((ushort)dhcp.HType).ToString("X2") + "]");
            DhcpNode.Nodes.Add("Hareware Address Length: " + dhcp.HLen);
            DhcpNode.Nodes.Add("Hops: " + dhcp.Hops);
            DhcpNode.Nodes.Add("XID: " + dhcp.XID);
            DhcpNode.Nodes.Add("Seconds: " + dhcp.Secs.ToString());
            if (DhcpFlagsNodes == null)
            {
                DhcpFlagsNodes = new TreeNode();
            }
            DhcpFlagsNodes.Nodes.Clear();
            DhcpFlagsNodes.Text = "Flags: 0x" + dhcp.Flags.ToString("X2");
            string unicast = (dhcp.Unicast == 0) ? "No Broadcast" : "Broadcast";
            DhcpFlagsNodes.Nodes.Add(dhcp.Unicast.ToString() + "... .... .... .... = " + unicast);
            DhcpFlagsNodes.Nodes.Add(".000 0000 0000 0000 = Reserved Flags");
            DhcpNode.Nodes.Add(DhcpFlagsNodes);

            DhcpNode.Nodes.Add("Client IP Address: " + dhcp.CiAddr);
            DhcpNode.Nodes.Add("Your IP Address: " + dhcp.YiAddr);
            DhcpNode.Nodes.Add("Server IP Address: " + dhcp.SiAddr);
            DhcpNode.Nodes.Add("Relay agent IP Address: " + dhcp.GiAddr);
            DhcpNode.Nodes.Add("Client Hard Address: " + dhcp.CHaddr);
            DhcpNode.Nodes.Add("Server host name: " + dhcp.SName);
            DhcpNode.Nodes.Add("Boot file name: " + dhcp.File);
            //选项字段
            if (!string.IsNullOrEmpty(dhcp.MagicCookie))
            {
                DhcpNode.Nodes.Add("Magic Cookie: " + dhcp.MagicCookie);
                foreach (var i in dhcp.Option)
                {
                    TreeNode tre = new TreeNode("Option: [Type= " + i.Type + " 0x" + ((ushort)i.Type).ToString("X2") + "] [Length= " + i.Length.ToString() + "]");
                    tre.Name = "DHCP_OP";
                    tre.Nodes.Add("Option Type: " + i.Type + " [0x" + ((ushort)i.Type).ToString("X2") + "]");
                    tre.Nodes.Add("Length: " + i.Length.ToString());
                    tre.Nodes.Add("Value: 0x" + i.value);

                    DhcpNode.Nodes.Add(tre);
                }
            }
            Tree.Nodes.Add(DhcpNode);

        }
        //RIPv1/RIPv2
        TreeNode RipNode;
        private void RIP(RipPacket rip)
        {
            if (rip == null)
                return;
            if (RipNode == null)
            {
                RipNode = CreatNode("RIP", 7);
            }
            RipNode.Nodes.Clear();

            RipNode.Nodes.Add("Command: " + rip.Command + " [0x" + ((ushort)rip.Command).ToString("X2") + "]");
            string verStr = (rip.Version == 1) ? "RIPv1" : "RIPv2";
            RipNode.Nodes.Add("Version: " + verStr + " (" + rip.Version + ")");
            RipNode.Nodes.Add("0000 0000 0000 0000 = Reserved Bits");
            if (rip.RouterItem.Count > 0)
            {
                foreach (var i in rip.RouterItem)
                {
                    string addressFamilyStr = (i.AddressFamily == 2) ? "IPv4 (" + i.AddressFamily + ")" : i.AddressFamily.ToString();
                    TreeNode tp = new TreeNode("[Family: " + addressFamilyStr + "] [Address: " + i.IPaddress + "] [Metric: " + i.Metric + "]");
                    tp.Nodes.Add("Address Family: " + addressFamilyStr);
                    string routerTag = (rip.Version == 1) ? "0000 0000 0000 0000 = Reserved Bits" : "Router Tag: " + i.RouteTag;
                    tp.Nodes.Add(routerTag);
                    tp.Nodes.Add("IP Address: " + i.IPaddress);
                    string mask = (rip.Version == 1) ? "0000 0000 0000 0000 0000 0000 0000 0000 = Reserved Bits" : "Net Mask: " + i.NetMask;
                    tp.Nodes.Add(mask);
                    string nextHops = (rip.Version == 1) ? "0000 0000 0000 0000 0000 0000 0000 0000 = Reserved Bits" : "Next Hops: " + i.NextHop;
                    tp.Nodes.Add(nextHops);
                    tp.Nodes.Add("Metric: " + i.Metric);

                    RipNode.Nodes.Add(tp);
                }
            }
            Tree.Nodes.Add(RipNode);
        }

        #region 未知协议
        //未知应用层协议
        TreeNode AppLicationNode;
        private void AppUnknowNode(string app, int payLength)
        {
            if (AppLicationNode == null)
            {
                AppLicationNode = new TreeNode();
                AppLicationNode.ImageIndex = 8;
                AppLicationNode.SelectedImageIndex = 8;
                AppLicationNode.Name = "APP";
            }
            AppLicationNode.Nodes.Clear();
            AppLicationNode.Text = app;
            // appNode.Expand();
            AppLicationNode.Nodes.Add("Data Length: " + payLength.ToString());
            Tree.Nodes.Add(AppLicationNode);
        }
        #endregion
    }
}
