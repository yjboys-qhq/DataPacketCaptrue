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
    public partial class Statistics : Form
    {
        int cnt = 0;        //X轴计数器
        int Xmin = 1;
        int Xmax = 10;
        List<ParketStatistics> List;
        int pre = 0;        //前一秒数量
        int now = 0;      //当前数量

        //饼图数据
       // Dictionary<string, int> SendCnt=new Dictionary<string, int>();       //用于统计发送到IP地址的数目

        List<int> SendCount = new List<int>();              //每个IP地址的计数
        List<string> SendStr = new List<string>();          //发送包的IP地址
        int[] ReceiveTopCount = new int[3];     //接收包最多的三个地址

        public Statistics(List<ParketStatistics> List)
        {
            InitializeComponent();
            this.List = List;
        }
        //Load事件
        private void Statistics_Load(object sender, EventArgs e)
        {
            //折线图
            chartZx.Series["Series1"].Points.Clear();  
            chartZx.Series["Series1"].LegendText = "每秒钟捕获的数据包数据量";//设置图例
            chartZx.ChartAreas[0].AxisX.MajorGrid.LineWidth = 0;        //隐藏纵向网格
            chartZx.ChartAreas[0].AxisY.MajorGrid.LineWidth = 0;        //隐藏横向网格
            chartZx.ChartAreas[0].AxisX.Interval = 1;            //间距
             //设置图表的X轴显示范围
            chartZx.ChartAreas[0].AxisX.Minimum = Xmin;       //下界
            chartZx.ChartAreas[0].AxisX.Maximum = Xmax;       //上届

            //柱状图 
            //发送
            chartFs.ChartAreas[0].AxisX.MajorGrid.LineWidth = 0;
            chartFs.ChartAreas[0].AxisY.MajorGrid.LineWidth = 0;
            //接收
            chartJs.ChartAreas[0].AxisX.MajorGrid.LineWidth = 0;
            chartJs.ChartAreas[0].AxisY.MajorGrid.LineWidth = 0;

            pre = List.Count;       //前一秒数量
            timer1.Start();     //启动
        }

        //定时器事件
        private void timer1_Tick(object sender, EventArgs e)
        {
            DataSource();
            if (cnt > 10)
            {
                Xmin++;      //下界自加
                Xmax++;     //上界自加
                chartZx.ChartAreas[0].AxisX.Minimum = Xmin;       //设置下界
                chartZx.ChartAreas[0].AxisX.Maximum = Xmax;       //设置上届
            }
        }

        //数据获取与添加
        private void DataSource()
        {
            //折线图
            now = List.Count;       //此时的数量
            int x = now - pre;      //计算差值
            chartZx.Series[0].Points.Add(x, cnt);       //添加数据
            cnt++;     //总时间
            pre = now;      //变量交换

            //柱状图
            int k = 0;     //计数
            var Sort = from pair in Form1.SendCnt orderby pair.Value descending select pair;
            var Sort2 = from pair in Form1.ReceiveCnt orderby pair.Value descending select pair;
            chartFs.Series[0].Points.Clear();
            chartJs.Series[0].Points.Clear();
            foreach (KeyValuePair<string, int> pair in Sort)
            {
                chartFs.Series[0].Points.Add(pair.Value);
                chartFs.Series[0].Points[k].AxisLabel =pair.Key;
                k++;
                if (k >=5)
                    break;
            }
            k = 0;
            foreach (KeyValuePair<string, int> pair in Sort2)
            {
                chartJs.Series[0].Points.Add(pair.Value);
                chartJs.Series[0].Points[k].AxisLabel = pair.Key;
                k++;
                if (k >= 5)
                    break;
            }
        }
    }
}
