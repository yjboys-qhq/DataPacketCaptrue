using SharpPcap;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using TwzyProtocol;
using TwzyProtocol.DNS;

namespace SharpPcap抓包工具
{
    public partial class Form1 : Form
    {
        private CaptureDeviceList devices;        //接口列表
        public static string[] name = new string[100];      //接口名称
        public static int Selectid=-1;        //用于捕获的接口的索引
        string NowIP="";        //当前接口的IP地址
        public static DeviceMode mode;        //捕获模式
        public bool State=false;          //状态（1正在捕获，1未打开）


        private BindingSource BS=new BindingSource();        //DataGridView数据绑定
        List<ParketAnalysis> listAn = new List<ParketAnalysis>();     //分析数据包容器
        private List<ParketStatistics> listSs = new List<ParketStatistics>();       //统计数据包容器
        public static Dictionary<string, int> SendCnt = new Dictionary<string, int>();       //用于统计发送到某个IP地址包的数目
        public static Dictionary<string, int> ReceiveCnt = new Dictionary<string, int>();       //用于统计接收某个IP地址包的数目
        int No = 0;     //数据包包编号
        object Lock=new object();//线程锁

        //过滤部分
        string Filter="";      //过滤字段
        string FilterIP = "";   //过滤IP


        public Form1()
        {
            InitializeComponent();
            CheckForIllegalCrossThreadCalls = false;
        }

        //配置
        private void toolStripButton1_Click(object sender, EventArgs e)
        {
            devices = CaptureDeviceList.Instance;       //获取当前的所有网卡
            if (devices.Count < 1)
            {
                MessageBox.Show("当前没有活动的网络设备！");
                return;
            }
            //初始化接口
            Config cf = new Config(devices);
            cf.ShowDialog();
            if(Selectid==-1)
            {
                return;
            }
            else
            {
                string[] t = devices[Selectid].ToString().Split('\n');      //分割
                string[] t2 = t[13].Split('：');
                NowIP = t2[1];      //本机IP
                toolStripLabel1.Text = "准备捕获网络" + name[Selectid] + "的数据包";
            }
        }

        //启动
        private void toolStripButton2_Click_1(object sender, EventArgs e)
        {
            if (Selectid == -1)
            {
                MessageBox.Show("请选择需要捕获的网络！");
                return;
            }
            else if (listAn.Count != 0)
            {
                #region 是否保存
                //弹出对话窗
                DialogResult dr1 = MessageBox.Show("重新捕获将清空现有内容，是否继续？", "提示", MessageBoxButtons.OKCancel);
                if (dr1 == DialogResult.OK)      //清空重新捕获
                {
                    //保存过程
                    Reset();        //清空
                    BtnStart.Enabled = false;
                    btnStop.Enabled = true;
                    dataGridView.DataSource = BS;
                    toolStripLabel1.Text = "正在捕获网络" + name[Selectid] + "的数据包";
                    Start_Capture(devices[Selectid]);                    //开始捕获
                }
                else             //取消
                {
                    return;
                }
                #endregion
            }
            else
            {
                Reset();        //清空
                BtnStart.Enabled = false;
                btnStop.Enabled = true;
                dataGridView.DataSource = BS;
                toolStripLabel1.Text = "正在捕获网络" + name[Selectid] + "的数据包";
                //开始捕获
                Start_Capture(devices[Selectid]);
            }
        }

        //暂停
        private void btnStop_Click(object sender, EventArgs e)
        {
            this.State = false;  //设置状态
            BtnStart.Enabled = true;
            btnStop.Enabled = false;
            toolStripLabel1.Text = "准备捕获网络" + name[Selectid] + "的数据包";
            this.Stop();        //停止捕获
        }

        //开始捕获方法
        private void Start_Capture(ICaptureDevice dev)
        {
            this.State = true;      //设置运行状态
            dev.OnPacketArrival += new PacketArrivalEventHandler(Fun_Arrival);           //注册处理包事件
            dev.Open(mode);         //开启
            dev.StartCapture();           //开始捕获（异步）
        }

        //包处理事件方法
        private void Fun_Arrival(object sender, CaptureEventArgs e)
        {
            this.BeginInvoke(new MethodInvoker(delegate
            {
                ParketStatistics temp = new ParketStatistics(No, e.Packet);         //转换为数据包统计
                lock (Lock)
                {
                    int ID = ConditonType(Filter);          //判断过滤方式
                    if (ID == 0)      //无过滤
                    {
                        BS.Add(temp);      //添加到数据绑定
                    }
                    else if(ID==1)      //协议过滤
                    {
                            for (int k = 0; k < temp.ProtocolList.Count; ++k)
                            {
                                if (temp.ProtocolList[k] == Filter)
                                    BS.Add(temp);
                            }
                        }
                    else if (ID == 2)      //源IP过滤
                    {
                        if (temp.src == FilterIP)
                            BS.Add(temp);      //添加到数据绑定
                    }
                    else if (ID == 3)      //目的IP过滤
                    {
                        if (temp.dst == FilterIP)
                            BS.Add(temp);      //添加到数据绑定
                    }
                    else if (ID == 4)      //源IP或目的IP过滤
                    {
                        if (temp.src == FilterIP|| temp.dst == FilterIP)
                            BS.Add(temp);      //添加到数据绑定
                    }
                    toolStripLabel1.Text = "正在捕获网络" + name[Selectid] + "的数据包，已捕获："+(listSs.Count+1)+"，已显示："+BS.Count;
                    listSs.Add(temp);
                    //分析数据包 添加到容器
                    ParketAnalysis pa = new ParketAnalysis(temp);
                    listAn.Add(pa);
                    //发送到目的地址的包数目统计（发送地址为本机）
                    if (temp.src == NowIP)
                    {
                        if (SendCnt.ContainsKey(temp.dst) == false)
                            SendCnt.Add(temp.dst, 0);
                        SendCnt[temp.dst]++;
                    }
                    //本机从某个IP接收的包数目统计（接收地址为本机）
                    if (temp.dst==NowIP)
                    {
                        if (ReceiveCnt.ContainsKey(temp.src) == false)
                            ReceiveCnt.Add(temp.src, 0);
                        ReceiveCnt[temp.src]++;
                    }
                    No++;
                }
            }));
        }

        //拆分数据包，并进行显示
        void analysis(ParketAnalysis ParketAn)
        {
            treeView.Nodes.Clear();
            richTextBox1.Text = "";

            //网络接口层与网络层
            #region 物理部分
            string rootStr = ParketAn.No + "号帧结构，线路" + ParketAn.Length + "字节（" + ParketAn.Length * 8 + "）实际捕获" + ParketAn.Length + "字节（" + ParketAn.Length * 8 + "）"; //框架根节点
            TreeNode frameNode = new TreeNode(rootStr);         //根节点
            string str = "接口名称：" +name[Selectid]+"（id："+ Selectid+"）";          //接口ID
            TreeNode tn = new TreeNode(str);
            frameNode.Nodes.Add(tn);
            str = "封装类型：" + ParketAn.Encapsulationtype;          //封装类型
            tn = new TreeNode(str);
            frameNode.Nodes.Add(tn);
            str = "捕获时间：" + ParketAn.Time;          //捕获时间
            tn = new TreeNode(str);
            frameNode.Nodes.Add(tn);
            //此包时移
            str = "Epoch时间：" + ParketAn.EpochTime;          //Epoch时间
            tn = new TreeNode(str);
            frameNode.Nodes.Add(tn);
            //此包与前一包的时间间隔
            //此包与第一帧的时间间隔
            str = "帧序号：" + ParketAn.No;          //帧序号
            tn = new TreeNode(str);
            frameNode.Nodes.Add(tn);
            str = "帧长度：" + ParketAn.Length;          //帧长度
            tn = new TreeNode(str);
            frameNode.Nodes.Add(tn);
            str = "捕获长度：" + ParketAn.Length;          //捕获长度
            tn = new TreeNode(str);
            frameNode.Nodes.Add(tn);
            //是否标记
            //是否丢弃
            str = "协议结构：" + ParketAn.ProtocolsFrame;          //协议结构
            tn = new TreeNode(str);
            frameNode.Nodes.Add(tn);
            this.treeView.Nodes.Add(frameNode);
            #endregion  
            #region 链路部分
            rootStr = "Ethernet II ， MAC源地址:" + ParketAn.MacSrc + "，MAC目的地址:" + ParketAn.MacDst;
            TreeNode EthernetNode = new TreeNode(rootStr);         //根节点
            str = "MAC目的地址：" + ParketAn.MacDst;          //目的地址
            tn = new TreeNode(str);
            EthernetNode.Nodes.Add(tn);
            str = "MAC源地址：" + ParketAn.MacSrc;          //源地址
            tn = new TreeNode(str);
            EthernetNode.Nodes.Add(tn);
            str = "类型：" + ParketAn.LinkType;          //链路类型
            tn = new TreeNode(str);
            EthernetNode.Nodes.Add(tn);
            this.treeView.Nodes.Add(EthernetNode);
            #endregion
            if(ParketAn.LinkType=="ARP")            
            {
                #region ARP
                rootStr = "地址解析协议（Address Resolution Protocol）（" + ParketAn.ArpOpCode + ")";
                TreeNode ArpNode = new TreeNode(rootStr);         //根节点
                str = "硬件类型：" + ParketAn.ArpHardwareType;          //硬件类型
                tn = new TreeNode(str);
                ArpNode.Nodes.Add(tn);
                str = "协议类型：" + ParketAn.ArpProtocolType;          //协议类型
                tn = new TreeNode(str);
                ArpNode.Nodes.Add(tn);
                str = "硬件大小：" + ParketAn.ArpHardwareSize;          //硬件大小
                tn = new TreeNode(str);
                ArpNode.Nodes.Add(tn);
                str = "协议大小：" + ParketAn.ArpProtocolSize;          //协议大小
                tn = new TreeNode(str);
                ArpNode.Nodes.Add(tn);
                str = "操作码：" + ParketAn.ArpOpCode;          //操作码
                tn = new TreeNode(str);
                ArpNode.Nodes.Add(tn);
                str = "发送人MAC地址：" + ParketAn.ArpSenderMacAddress;          //发送人Mac地址
                tn = new TreeNode(str);
                ArpNode.Nodes.Add(tn);
                str = "发送人IP地址：" + ParketAn.ArpSenderIpAddress;          //发送人IP地址
                tn = new TreeNode(str);
                ArpNode.Nodes.Add(tn);
                str = "目标MAC地址：" + ParketAn.ArpTargetMacAddress;          //目标Mac地址
                tn = new TreeNode(str);
                ArpNode.Nodes.Add(tn);
                str = "发送人IP地址：" + ParketAn.ArpTargetIpAddress;          //目标IP地址
                tn = new TreeNode(str);
                ArpNode.Nodes.Add(tn);
                this.treeView.Nodes.Add(ArpNode); 
                #endregion
            }
            else if(ParketAn.LinkType == "IPV4")
            {
                #region IPV4
                rootStr = "互联网协议（Internet Protocol），源IP地址：" + ParketAn.IpSrc + "  目的IP地址：" + ParketAn.IpDst;
                TreeNode IpNode = new TreeNode(rootStr);         //根节点
                str = "互联网协议：IPV4";
                tn = new TreeNode(str);
                IpNode.Nodes.Add(tn);
                str = "IP包头部长度：" + ParketAn.IpHeaderlength;
                tn = new TreeNode(str);
                IpNode.Nodes.Add(tn);
                str = "差分服务：" + ParketAn.IpDifferentiatedServicesfield;
                tn = new TreeNode(str);
                IpNode.Nodes.Add(tn);
                str = "IP包总长：" + ParketAn.IpTotolLength;
                tn = new TreeNode(str);
                IpNode.Nodes.Add(tn);
                str = "标志：" + ParketAn.IpId;
                tn = new TreeNode(str);
                IpNode.Nodes.Add(tn);
                str = "标记：" + ParketAn.IpFlag;
                tn = new TreeNode(str);
                IpNode.Nodes.Add(tn);
                str = "分段位偏移：" + ParketAn.IpFragmentOffset;
                tn = new TreeNode(str);
                IpNode.Nodes.Add(tn);
                str = "生存周期：" + ParketAn.IpTTL;
                tn = new TreeNode(str);
                IpNode.Nodes.Add(tn);
                str = "上层协议：" + ParketAn.IpProtocol;
                tn = new TreeNode(str);
                IpNode.Nodes.Add(tn);
                str = "校验和：" + ParketAn.IpCheckSum;
                tn = new TreeNode(str);
                IpNode.Nodes.Add(tn);
                str = "源IP地址：" + ParketAn.IpSrc;
                tn = new TreeNode(str);
                IpNode.Nodes.Add(tn);
                str = "目的IP地址：" + ParketAn.IpDst;
                tn = new TreeNode(str);
                IpNode.Nodes.Add(tn);
                this.treeView.Nodes.Add(IpNode); 
                #endregion
            }
            else if(ParketAn.LinkType=="PPPOE")      //中继协议PPPOE及PPP协议
            {
                #region PPPOE
                rootStr = "基于以太网的点对点通讯协议（Point to Point Protocol over Ethernet）";
                TreeNode PPPoENode = new TreeNode(rootStr);         //根节点
                str = "版本：" + ParketAn.PPPoEVersion;          //版本
                tn = new TreeNode(str);
                PPPoENode.Nodes.Add(tn);
                str = "类型：" + ParketAn.PPPoEType;          //类型
                tn = new TreeNode(str);
                PPPoENode.Nodes.Add(tn);
                str = "编码：" + ParketAn.PPPoECode;          //编码
                tn = new TreeNode(str);
                PPPoENode.Nodes.Add(tn);
                str = "ID：" + ParketAn.PPPoEId;          //版本
                tn = new TreeNode(str);
                PPPoENode.Nodes.Add(tn);
                str = "长度：" + ParketAn.PPPoELength;          //长度
                tn = new TreeNode(str);
                PPPoENode.Nodes.Add(tn);
                this.treeView.Nodes.Add(PPPoENode);
                #endregion

                rootStr = "点对点协议（Point to Point Protocol）";
                TreeNode tempNode = new TreeNode(rootStr);         //根节点
                str = "协议："+ParketAn.PPPProtocol;          //上层协议
                tn = new TreeNode(str);
                tempNode.Nodes.Add(tn);
                this.treeView.Nodes.Add(tempNode);

                //根据ppp协议判断其上层协议
                if (ParketAn.PPPProtocol == "IPv4")
                {
                    #region IPV4
                    if (ParketAn != null && ParketAn.IpSrc != null)
                    {
                        rootStr = "互联网协议（Internet Protocol），源IP地址：" + ParketAn.IpSrc + "  目的IP地址：" + ParketAn.IpDst;
                        TreeNode IpNode = new TreeNode(rootStr);         //根节点
                        str = "互联网协议：IPV4";
                        tn = new TreeNode(str);
                        IpNode.Nodes.Add(tn);
                        str = "IP包头部长度：" + ParketAn.IpHeaderlength;
                        tn = new TreeNode(str);
                        IpNode.Nodes.Add(tn);
                        str = "差分服务：" + ParketAn.IpDifferentiatedServicesfield;
                        tn = new TreeNode(str);
                        IpNode.Nodes.Add(tn);
                        str = "IP包总长：" + ParketAn.IpTotolLength;
                        tn = new TreeNode(str);
                        IpNode.Nodes.Add(tn);
                        str = "标志：" + ParketAn.IpId;
                        tn = new TreeNode(str);
                        IpNode.Nodes.Add(tn);
                        str = "标记：" + ParketAn.IpFlag;
                        tn = new TreeNode(str);
                        IpNode.Nodes.Add(tn);
                        str = "分段位偏移：" + ParketAn.IpFragmentOffset;
                        tn = new TreeNode(str);
                        IpNode.Nodes.Add(tn);
                        str = "生存周期：" + ParketAn.IpTTL;
                        tn = new TreeNode(str);
                        IpNode.Nodes.Add(tn);
                        str = "上层协议：" + ParketAn.IpProtocol;
                        tn = new TreeNode(str);
                        IpNode.Nodes.Add(tn);
                        str = "校验和：" + ParketAn.IpCheckSum;
                        tn = new TreeNode(str);
                        IpNode.Nodes.Add(tn);
                        str = "源IP地址：" + ParketAn.IpSrc;
                        tn = new TreeNode(str);
                        IpNode.Nodes.Add(tn);
                        str = "目的IP地址：" + ParketAn.IpDst;
                        tn = new TreeNode(str);
                        IpNode.Nodes.Add(tn);
                        this.treeView.Nodes.Add(IpNode);
                    }
                    #endregion
                }
                else if (ParketAn.PPPProtocol == "LCP")
                {
                    rootStr = "链路控制协议（Link Control Protocol）";
                    tempNode = new TreeNode(rootStr);         //根节点
                    str = "代码：" + ParketAn.LcpCode;
                    tn = new TreeNode(str);
                    tempNode.Nodes.Add(tn);
                    str = "标识：" + ParketAn.LcpIdentifier;          //标识
                    tn = new TreeNode(str);
                    tempNode.Nodes.Add(tn);
                    str = "长度：" + ParketAn.LcpLength;
                    tn = new TreeNode(str);
                    tempNode.Nodes.Add(tn);
                    this.treeView.Nodes.Add(tempNode);
                }
                else return;
            }
            //新添加
            else if(ParketAn.LinkType == "IPV6")
            {
                rootStr = "互联网协议IPV6（Internet Protocol Version 6），源IP地址：" + ParketAn.ipv6src + "  目的IP地址：" + ParketAn.ipv6dst;
                TreeNode IpNode = new TreeNode(rootStr);         //根节点
                str = "版本："+ParketAn.ipv6version;
                tn = new TreeNode(str);
                IpNode.Nodes.Add(tn);
                str = "上层协议：" + ParketAn.ipv6protocol;
                tn = new TreeNode(str);
                IpNode.Nodes.Add(tn);
                str = "流量类别：" + ParketAn.ipv6trafficclass;
                tn = new TreeNode(str);
                IpNode.Nodes.Add(tn);
                str = "载荷长度：" + ParketAn.ipv6payloadlength;
                tn = new TreeNode(str);
                IpNode.Nodes.Add(tn);
                str = "跳数限制：" + ParketAn.ipv6hoplimit;
                tn = new TreeNode(str);
                IpNode.Nodes.Add(tn);
                str = "源地址：" + ParketAn.ipv6src;
                tn = new TreeNode(str);
                IpNode.Nodes.Add(tn);
                str = "目的地址：" + ParketAn.ipv6dst;
                tn = new TreeNode(str);
                IpNode.Nodes.Add(tn);
                this.treeView.Nodes.Add(IpNode);
            }

            //基于IP协议的上层协议
            if (ParketAn.IpProtocol=="TCP"||ParketAn.ipv6protocol=="TCP")      //TCP协议
            {
                #region TCP
                rootStr = "传输控制协议（Transmission Control Protocol ），源端口号：" + ParketAn.TcpSrcPort + "，目的端口号：" + ParketAn.TcpDstPort + "，序列号：" + ParketAn.TcpSequenceNum + "，确认号" + ParketAn.TcpAcknowledgmentNum;
                TreeNode TcpNode = new TreeNode(rootStr);         //根节点
                str = "源端口号：" + ParketAn.TcpSrcPort;          //源端口
                tn = new TreeNode(str);
                TcpNode.Nodes.Add(tn);
                str = "目的端口号：" + ParketAn.TcpDstPort;          //目的端口
                tn = new TreeNode(str);
                TcpNode.Nodes.Add(tn);
                str = "序列号：" + ParketAn.TcpSequenceNum;          //序列号
                tn = new TreeNode(str);
                TcpNode.Nodes.Add(tn);
                str = "确认号：" + ParketAn.TcpAcknowledgmentNum;          //确认号
                tn = new TreeNode(str);
                TcpNode.Nodes.Add(tn);
                //标志位
                byte b = ParketAn.TcpFlag;
                #region 标志位计算
                string fin = ".... ..." + ((b & 128) == 128 ? 1 : 0).ToString();
                string syn = ".... .." + ((b & 64) == 64 ? 1 : 0).ToString() + ".";
                string rst = ".... ." + ((b & 32) == 32 ? 1 : 0).ToString() + "..";
                string psh = ".... " + ((b & 16) == 16 ? 1 : 0).ToString() + "...";
                string ack = "..." + ((b & 8) == 8 ? 1 : 0).ToString() + " ....";
                string urg = ".." + ((b & 4) == 4 ? 1 : 0).ToString() + ". ....";
                string ecn = "." + ((b & 2) == 2 ? 1 : 0).ToString() + ".. ....";
                string cwr = ((b & 1) == 1 ? 1 : 0).ToString() + "... ....";
                #endregion
                str = "标志位：" + ParketAn.TcpFlag.ToString();          //标志位
                tn = new TreeNode(str);
                #region 标志位子节点
                tn.Nodes.Add("Congestion Window Reduced(CWR) = " + cwr);
                tn.Nodes.Add("ECN-ECHO = " + ecn);
                tn.Nodes.Add("URG = " + urg);
                tn.Nodes.Add("ACK = " + ack);
                tn.Nodes.Add("PUSH = " + psh);
                tn.Nodes.Add("RESET = " + rst);
                tn.Nodes.Add("SYN = " + syn);
                tn.Nodes.Add("FIN = " + fin);
                #endregion
                TcpNode.Nodes.Add(tn);
                str = "窗口大小：" + ParketAn.TcpWindowSize;       //窗口大小
                tn = new TreeNode(str);
                TcpNode.Nodes.Add(tn);
                str = "校验和：" + ParketAn.TcpCheckSum;       //校验和
                tn = new TreeNode(str);
                TcpNode.Nodes.Add(tn);
                str = "紧急指针：" + ParketAn.TcpUrgentPointer;       //紧急指针
                tn = new TreeNode(str);
                TcpNode.Nodes.Add(tn);
                this.treeView.Nodes.Add(TcpNode); 
                #endregion
            }
            else if (ParketAn.IpProtocol == "UDP" || ParketAn.ipv6protocol == "UDP")
            {
                #region UDP
                rootStr = "用户数据报协议（User Datagram Protocol），源端口号：" + ParketAn.UdpSrcPort + "，目的端口号：" + ParketAn.UdpDstPort;
                TreeNode UdpNode = new TreeNode(rootStr);         //根节点
                str = "源端口号：" + ParketAn.UdpSrcPort;          //源端口
                tn = new TreeNode(str);
                UdpNode.Nodes.Add(tn);
                str = "目的端口号：" + ParketAn.UdpDstPort;          //目的端口
                tn = new TreeNode(str);
                UdpNode.Nodes.Add(tn);
                str = "长度：" + ParketAn.UdpLength;          //长度
                tn = new TreeNode(str);
                UdpNode.Nodes.Add(tn);
                str = "校验和：" + ParketAn.UdpCheckSum;          //校验和
                tn = new TreeNode(str);
                UdpNode.Nodes.Add(tn);
                this.treeView.Nodes.Add(UdpNode); 
                #endregion
            }
            else if(ParketAn.IpProtocol=="ICMP" || ParketAn.ipv6protocol == "ICMP")
            {
                #region ICMP
                rootStr = "Internet控制报文协议（Internet Control Message Protocol）";
                TreeNode IcmpNode = new TreeNode(rootStr);         //根节点
                str = "代码/类型：" + ParketAn.IcmpCodeType;          //代码类型
                tn = new TreeNode(str);
                IcmpNode.Nodes.Add(tn);
                str = "校验和：" + ParketAn.IcmpCheckSum;          //校验和
                tn = new TreeNode(str);
                IcmpNode.Nodes.Add(tn);
                str = "ID（BE）：" + ParketAn.IcmpId;          //id
                tn = new TreeNode(str);
                IcmpNode.Nodes.Add(tn);
                str = "ID（LE）：" + Convert.ToInt32(ParketAn.IcmpId)*256;          //id
                tn = new TreeNode(str);
                IcmpNode.Nodes.Add(tn);
                str = "序号（BE）：" + ParketAn.IcmpSequenceNumBE;          //序列号
                tn = new TreeNode(str);
                IcmpNode.Nodes.Add(tn);
                str = "序号（LE）：" + ParketAn.IcmpSequenceNumLE;          //序列号
                tn = new TreeNode(str);
                IcmpNode.Nodes.Add(tn);
                this.treeView.Nodes.Add(IcmpNode); 
                #endregion
            }
            else if(ParketAn.IpProtocol=="IGMP" || ParketAn.ipv6protocol == "IGMP")
            {
                #region IGMP
                rootStr = "组管理协议（Internet Group Management Protocol）";
                TreeNode IgmpNode = new TreeNode(rootStr);         //根节点
                str = "版本：" + ParketAn.IgmpVersion;          //版本
                tn = new TreeNode(str);
                IgmpNode.Nodes.Add(tn);
                str = "类型：" + ParketAn.IgmpType;          //类型
                tn = new TreeNode(str);
                IgmpNode.Nodes.Add(tn);
                str = "最大回应时间：" + ParketAn.IgmpMRT;          //最大回应时间
                tn = new TreeNode(str);
                IgmpNode.Nodes.Add(tn);
                str = "校验和：" + ParketAn.IgmpCheckSum;          //校验和
                tn = new TreeNode(str);
                IgmpNode.Nodes.Add(tn);
                str = "组地址：" + ParketAn.IgmpAddress;          //最低值
                tn = new TreeNode(str);
                IgmpNode.Nodes.Add(tn);
                this.treeView.Nodes.Add(IgmpNode);
                #endregion
            }

            //应用层部分
            if (ParketAn.IpProtocol == "TCP")
            {
                #region 基于TCP
                int port = ParketAn.TcpSrcPort;
                string Protocol = ParketAn.Protocol;        //最上层协议
                if (Protocol=="HTTP")     //http
                {
                    rootStr = "超文本传输协议（HyperText Transfer Protocol）";
                    TreeNode Node = new TreeNode(rootStr);         //根节点
                                                                   //for (int i = 0; i < ParketAn.CommandStr.Count; ++i)
                                                                   //{
                                                                   //    str = ParketAn.CommandStr[i];
                                                                   //    tn = new TreeNode(str);
                                                                   //    Node.Nodes.Add(tn);
                                                                   //}
                    for (int i = 0; i < ParketAn.HttpList.Count; ++i)
                    {
                        str = ParketAn.HttpList[i].Content;
                        tn = new TreeNode(str);
                        Node.Nodes.Add(tn);
                    }
                    this.treeView.Nodes.Add(Node);
                }
                else if (Protocol == "FTP")
                {
                    rootStr = "文件传输协议（File Transfer Protocol）";
                    TreeNode Node = new TreeNode(rootStr);         //根节点
                    for (int i = 0; i < ParketAn.CommandStr.Count; ++i)
                    {
                        str = ParketAn.CommandStr[i];
                        tn = new TreeNode(str);
                        Node.Nodes.Add(tn);
                    }
                    //for (int i = 0; i < ParketAn.CommandList.Count; ++i)
                    //{
                    //    str = ParketAn.CommandList[i].Content;
                    //    tn = new TreeNode(str);
                    //    Node.Nodes.Add(tn);
                    //}
                    this.treeView.Nodes.Add(Node);
                }
                else if (Protocol == "SMTP")
                {
                    rootStr = "简单邮件传输协议（Simple Mail Transfer Protocol）";
                    TreeNode Node = new TreeNode(rootStr);         //根节点
                    for (int i = 0; i < ParketAn.CommandStr.Count; ++i)
                    {
                        str = ParketAn.CommandStr[i];
                        tn = new TreeNode(str);
                        Node.Nodes.Add(tn);
                    }
                    this.treeView.Nodes.Add(Node);
                }
                else if (Protocol == "POP3")
                {
                    rootStr = "邮局协议版本3（Post Office Protocol - Version 3）";
                    TreeNode Node = new TreeNode(rootStr);         //根节点
                    for (int i = 0; i < ParketAn.CommandStr.Count; ++i)
                    {
                        str = ParketAn.CommandStr[i];
                        tn = new TreeNode(str);
                        Node.Nodes.Add(tn);
                    }
                    this.treeView.Nodes.Add(Node);
                }
                else; 
                #endregion
            }
            else
            {
                #region 基于UDP
                int port = ParketAn.UdpSrcPort;
                string Protocol = ParketAn.Protocol;        //最上层协议
                if (Protocol=="DNS")
                {
                    rootStr = "域名系统（Domain Name System）";
                    TreeNode Node = new TreeNode(rootStr);         //根节点
                    str = "标识："+ParketAn.DnsId;       //ID
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    str = "标志："+ParketAn.DnsFlag;       //标志
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    str = "问题数："+ParketAn.DnsQuestion;       //问题数
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    str = "回答RR数：" + ParketAn.DnsAnswerRr;       //回答RR数
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    str = "权威RR数：" + ParketAn.DnsAuthorityRr;       //权威RR数
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    str = "附加RR数：" + ParketAn.DnsAddRr;       //附加RR数
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    //查询区域
                    #region 查询区域
                    str = "查询区域";       //附加RR数
                    tn = new TreeNode(str);
                    str = "查询名：" + ParketAn.DnsQueriesName;
                    TreeNode temp = new TreeNode(str);
                    tn.Nodes.Add(temp);
                    str = "查询类型：" + ParketAn.DnsQueriesType;
                    temp = new TreeNode(str);
                    tn.Nodes.Add(temp);
                    str = "查询类：" + ParketAn.DnsQueriesClass;
                    temp = new TreeNode(str);
                    tn.Nodes.Add(temp);
                    Node.Nodes.Add(tn);
                    #endregion
                    //回答区域
                    if (ParketAn.DnsAnswerers.Count > 0)
                    {
                        str = "回答区域";
                        tn = new TreeNode(str);
                        for (int i = 0; i < ParketAn.DnsAnswerers.Count; ++i)
                        {
                            DnsResponse now = ParketAn.DnsAnswerers[i];
                            str = now.name;
                            TreeNode T = new TreeNode(str);
                            str = "查询名：" + now.name;
                            temp = new TreeNode(str);
                            T.Nodes.Add(temp);
                            str = "查询类型：" + now.dnsType;
                            temp = new TreeNode(str);
                            T.Nodes.Add(temp);
                            str = "查询类：" + now.dnsClass;
                            temp = new TreeNode(str);
                            T.Nodes.Add(temp);
                            str = "生存周期：" + now.TTL;
                            temp = new TreeNode(str);
                            T.Nodes.Add(temp);
                            str = "数据长度：" + now.length;
                            temp = new TreeNode(str);
                            T.Nodes.Add(temp);
                            str = "地址：" + now.rescData;
                            temp = new TreeNode(str);
                            T.Nodes.Add(temp);
                            tn.Nodes.Add(T);
                        }
                        Node.Nodes.Add(tn);
                    }
                    this.treeView.Nodes.Add(Node);
                }
                else if (Protocol == "TFTP")
                {
                    rootStr = "简单文件传输协议（Trivial File Transfer Protocol）";
                    TreeNode Node = new TreeNode(rootStr);         //根节点
                    str = "操作类型：" + ParketAn.TFtpOp;       
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    if (ParketAn.TFtpOpInt == 1 || ParketAn.TFtpOpInt == 2)         //写入包或请求包
                    {
                        str = "文件名：" + ParketAn.TFtpFileName;
                        tn = new TreeNode(str);
                        Node.Nodes.Add(tn);
                        str = "类型：" + ParketAn.TFtpType;
                        tn = new TreeNode(str);
                        Node.Nodes.Add(tn);
                    }
                    else if (ParketAn.TFtpOpInt == 3)       //数据包
                    {
                        str = "数据：" + ParketAn.TFtpData;
                        tn = new TreeNode(str);
                        Node.Nodes.Add(tn);
                    }
                    else if (ParketAn.TFtpOpInt == 5)       //错误包
                    {
                        str = "错误类型：" + ParketAn.TFtperror;
                        tn = new TreeNode(str);
                        Node.Nodes.Add(tn);
                        str = "错误消息：" + ParketAn.TFtperrorMessage;
                        tn = new TreeNode(str);
                        Node.Nodes.Add(tn);
                    }
                    else if (ParketAn.TFtpOpInt == 5)  //确认包
                    {
                        str = "块编号：" + ParketAn.TFtpBlockId;
                        tn = new TreeNode(str);
                        Node.Nodes.Add(tn);
                    }        
                    this.treeView.Nodes.Add(Node);
                }
                else if (Protocol == "SNMP")
                {
                    rootStr = "简单网络管理协议（Simple Network Management Protocol ）";
                    TreeNode Node = new TreeNode(rootStr);         //根节点
                    str = "版本：" + ParketAn.snmpversion;
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    str = "共同体名称：" + ParketAn.snmpcommunityname;
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    str = "PUD类型：" + ParketAn.snmppudtype;
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    str = "请求标识符：" + ParketAn.snmprequestid;
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    str = "错误状态：" + ParketAn.snmperror;       //错误状态
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    str = "错误索引：" + ParketAn.snmperrorix;       
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    this.treeView.Nodes.Add(Node);
                }
                else if(Protocol=="SSDP")
                {
                    rootStr = "简单服务发现协议（Simple Service Discovery Protocol）";
                    TreeNode Node = new TreeNode(rootStr);         //根节点
                    for (int i = 0; i < ParketAn.CommandStr.Count; ++i)
                    {
                        str = ParketAn.CommandStr[i];
                        tn = new TreeNode(str);
                        Node.Nodes.Add(tn);
                    }
                    this.treeView.Nodes.Add(Node);
                }
                else if(Protocol=="DHCP")
                {
                    rootStr = "动态主机配置协议（Dynamic Host Configuration Protocol）";
                    TreeNode Node = new TreeNode(rootStr);         //根节点
                    str = "消息类型：" + ParketAn.dhcpop;       
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    str = "硬件类型：" + ParketAn.dhcphardwaretype;
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    str = "硬件地址长度：" + ParketAn.dhcphwlen;
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    str = "Hops：" + ParketAn.dhcphops;
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    str = "传输ID：" + ParketAn.dhcptranid;
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    str = "用户指定时间：" + ParketAn.dhcpsecond;
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    str = "标志：" + ParketAn.dhcpflag;
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    str = "用户IP地址：" + ParketAn.dhcpcip;
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    str = "客户IP地址：" + ParketAn.dhcpycip;
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    str = "下一个服务器IP地址：" + ParketAn.dhcpnsip;
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    str = "转发代理IP地址：" + ParketAn.dhcpraip;
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    str = "客户MAC地址：" + ParketAn.dhcpcmac;
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    str = "服务器主机名称：" + ParketAn.dhcpshname;
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    str = "引导文件名：" + ParketAn.dhcpfname;
                    tn = new TreeNode(str);
                    Node.Nodes.Add(tn);
                    //选项部分
                    if (!string.IsNullOrEmpty(ParketAn.dhcpmagiccookie))
                    {
                        str = "Magic Cookie：" + ParketAn.dhcpmagiccookie;
                        tn = new TreeNode(str);
                        Node.Nodes.Add(tn);
                        foreach(var i in ParketAn.dhcpoplist)
                        {
                            str = "选项："+i.Type;
                            tn = new TreeNode(str);
                            str = "选项类型： " + i.Type;
                            TreeNode tt = new TreeNode(str);
                            tn.Nodes.Add(tt);
                            str = "长度：" + i.Length;
                            tt = new TreeNode(str);
                            tn.Nodes.Add(tt);
                            str = "值： 0x" + i.value.ToString();
                            tt = new TreeNode(str);
                            tn.Nodes.Add(tt);
                            Node.Nodes.Add(tn);
                        }
                    }
                    this.treeView.Nodes.Add(Node);
                }
                else; 
                #endregion
            }

           
            //数据
            richTextBox1.Text = ParketAn.Data;

        }

        //停止捕获
        void Stop()
        {
            if (Selectid!=-1&&devices!=null&&devices[Selectid] != null && devices[Selectid].Started)
            {
                this.State = false;     //设置状态
                devices[Selectid].StopCapture();      //停止捕获
                devices[Selectid].Close();      //关闭接口
            }

        }

        //重置事件
        void Reset()
        {
            this.State = false;     //设置状态
            listAn.Clear();     //清空容器
            listSs.Clear();
            BS.Clear();     //清空数据绑定
            richTextBox1.Text = "";     //清空数据部分
            treeView.Nodes.Clear();     //清空解析节点部分
            toolStripComboBox1.Text = "";
            No = 0;
            Filter = "";
            FilterIP = "";
        }

        //双击事件
        private void dataGridView_MouseDoubleClick(object sender, MouseEventArgs e)
        {
            int index=dataGridView.CurrentRow.Index;    //获取选中行索引
            int id =Convert.ToInt32(dataGridView.Rows[index].Cells[0].Value);
            analysis(listAn[id]);
        }

        //关闭
        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            this.Stop();
        }

        //选中事件
        private void dataGridView_SelectionChanged(object sender, EventArgs e)
        {
            if (dataGridView.CurrentRow != null)
            {
                int index = dataGridView.CurrentRow.Index;    //获取选中行索引
                int id = Convert.ToInt32(dataGridView.Rows[index].Cells[0].Value);
                if (listAn.Count > 0)
                {
                    if(id>=listAn.Count)
                        analysis(listAn[0]);
                    else
                        analysis(listAn[id]);
                }
            }
        }

        //过滤条件类型
        private int ConditonType(string STR)
        {
            string str = STR.ToUpper();     
            string[] Protocol = {"TCP","IPV4","IPV6","UDP","HTTP","ICMP" ,"ARP","SSDP","DNS","FTP","IGMP","TFTP","DHCP","SMTP","POP3","SNMP","LCP","PPPOE"};      //协议
            if (str == "")      //无条件
                return 0;
            else
            {
                for(int i=0;i<Protocol.Length;++i)          //协议判断
                {
                    if (str == Protocol[i])
                        return 1;
                }
                string ConType;
                string Ip;
                string[] part = str.Split('=');         //分割字符串
                if (part.Length != 2)           //不满足任何一种条件
                    return -1;
                Ip = part[1];       //IP
                ConType = part[0];      //条件
                //校验IP
                if (ConType == "src"|| ConType == "SRC")          //源IP
                {
                    FilterIP = Ip;
                    return 2;
                }
                else if (ConType == "dst"|| ConType == "DST")        //目的IP
                {
                    FilterIP = Ip;
                    return 3;
                }
                else if (ConType == "all"|| ConType == "ALL")         //全部
                {
                    FilterIP = Ip;
                    return 4;
                }
                else
                    return -1;
            }
        }

        //过滤按钮
        private void toolStripButton2_Click(object sender, EventArgs e)
        {
            if (this.State == false)
                return;
            Filter = toolStripComboBox1.Text.Trim();      //设置过滤字段
            int ID = ConditonType(Filter);          //判断过滤方式
            if (ID == -1)
            {
                MessageBox.Show("过滤条件填写不正确，无法过滤！");
                toolStripComboBox1.Text = Filter;
                return;
            }
            lock (Lock)
            {
                BS.Clear();     //清空原始数据
                //（1）无过滤
                if (ID == 0)
                {
                    for (int i = 0; i < listSs.Count; ++i)     //重新装载原始数据
                        BS.Add(listSs[i]);
                }
                //（2）协议过滤
                else if (ID == 1)           //协议过滤
                {
                    Filter = Filter.ToUpper();      //转换为大写
                    for (int i = 0; i < listSs.Count; ++i)     //重新装载原始数据
                    {
                        for(int k=0;k<listSs[i].ProtocolList.Count;++k)
                        {
                            if (listSs[i].ProtocolList[k] == Filter)
                                BS.Add(listSs[i]);
                        }
                    }
                }
                //（3）源地址过滤
                else if (ID == 2)          //源IP
                {
                    for (int i = 0; i < listSs.Count; ++i)     //重新装载原始数据
                    {
                        if (listSs[i].src == FilterIP)
                            BS.Add(listSs[i]);
                    }
                }
                //（4）目的地址过滤
                else if (ID == 3)          //目的IP
                {
                    for (int i = 0; i < listSs.Count; ++i)     //重新装载原始数据
                    {
                        if (listSs[i].dst == FilterIP)
                            BS.Add(listSs[i]);
                    }
                }
                //（5）地址过滤
                else if (ID == 4)          //全部IP
                {
                    for (int i = 0; i < listSs.Count; ++i)     //重新装载原始数据
                    {
                        if (listSs[i].src == FilterIP || listSs[i].dst == FilterIP)
                            BS.Add(listSs[i]);
                    }
                }
                toolStripLabel1.Text = "正在捕获网络" + name[Selectid] + "的数据包，已捕获：" + listSs.Count + "，已显示：" + BS.Count;    //显示提示
                dataGridView.Refresh();     //刷新
            }
        }
        
        //统计
        private void toolStripButton3_Click(object sender, EventArgs e)
        {
            Statistics s = new Statistics(listSs);
            s.Show();
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }
    }
}


