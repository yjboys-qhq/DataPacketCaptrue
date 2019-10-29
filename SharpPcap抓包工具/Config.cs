using SharpPcap;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SharpPcap抓包工具
{
    public partial class Config : Form
    {
        string[] name=new string[10];
        bool[] state=new bool[10];
        CaptureDeviceList devicelist;
        int count=0;

        public Config(CaptureDeviceList devicelist)
        {
            InitializeComponent();
            this.devicelist = devicelist;
        }

        //初始化
        private void Config_Load(object sender, EventArgs e)
        {
            foreach (var dev in devicelist)
            {
                string STR = dev.ToString();      //获取设备相关信息
                string[] Arr = STR.Split('\n');        //分割字符串
                string[] temp = Arr[3].Split('：');
                Form1.name[count]=name[count] = temp[1];  //添加网络名称
                state[count] = false;    //网络状态
                dataGridView1.Rows.Add(name[count], "未活动");
                dataGridView1.Rows[count].Cells[1].Style.BackColor = Color.Red;
                //如果存在数据包传输，将网络状态改为活动
                devicelist[count].OnPacketArrival += new PacketArrivalEventHandler(Fun_Arrival);           
                devicelist[count].Open();         //开启
                devicelist[count].StartCapture();           //开始捕获（异步）
                count++;
            }
            radioButton1.Checked = true;        //初始化选中正常模式
        }

        //接收到数据包
        void Fun_Arrival(object sender, CaptureEventArgs e)
        {
            var now = e.Device;           //获取数据包来源的接口
            for (int i = 0; i < devicelist.Count; ++i)         //判断接口在数组中的位置
            {
                if (now == devicelist[i])        //将接口状态设置为活动中
                {
                    dataGridView1.Rows[i].Cells[1].Value = "活动中";     
                    dataGridView1.Rows[i].Cells[1].Style.BackColor = Color.Green;
                }
            }
        }

        //确认
        private void button1_Click(object sender, EventArgs e)
        {
            int temp = dataGridView1.CurrentRow.Index;        //获取选中索引
            Form1.Selectid = temp;       //设置所选择的接口索引
            //选择模式
            if (radioButton1.Checked == true)
                Form1.mode = DeviceMode.Normal;     //正常模式
            else
                Form1.mode = DeviceMode.Promiscuous;     //混杂模式
            this.Close();
        }

        //取消
        private void button2_Click(object sender, EventArgs e)
        {
            this.Close();
            Form1.Selectid = -1;
        }

        //关闭事件
        private void Config_FormClosing(object sender, FormClosingEventArgs e)
        {
            for (int i = 0; i < devicelist.Count; ++i)         //判断接口在数组中的位置
            {
                if (devicelist[i].Started == true)        //如果接口已经打开，关闭该接口
                {
                    devicelist[i].StopCapture();
                    devicelist[i].Close();
                }
            }
        }
    }
}
