namespace SharpPcap抓包工具
{
    partial class Statistics
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            System.Windows.Forms.DataVisualization.Charting.ChartArea chartArea1 = new System.Windows.Forms.DataVisualization.Charting.ChartArea();
            System.Windows.Forms.DataVisualization.Charting.Legend legend1 = new System.Windows.Forms.DataVisualization.Charting.Legend();
            System.Windows.Forms.DataVisualization.Charting.Series series1 = new System.Windows.Forms.DataVisualization.Charting.Series();
            System.Windows.Forms.DataVisualization.Charting.ChartArea chartArea2 = new System.Windows.Forms.DataVisualization.Charting.ChartArea();
            System.Windows.Forms.DataVisualization.Charting.Legend legend2 = new System.Windows.Forms.DataVisualization.Charting.Legend();
            System.Windows.Forms.DataVisualization.Charting.Series series2 = new System.Windows.Forms.DataVisualization.Charting.Series();
            System.Windows.Forms.DataVisualization.Charting.ChartArea chartArea3 = new System.Windows.Forms.DataVisualization.Charting.ChartArea();
            System.Windows.Forms.DataVisualization.Charting.Legend legend3 = new System.Windows.Forms.DataVisualization.Charting.Legend();
            System.Windows.Forms.DataVisualization.Charting.Series series3 = new System.Windows.Forms.DataVisualization.Charting.Series();
            this.chartZx = new System.Windows.Forms.DataVisualization.Charting.Chart();
            this.timer1 = new System.Windows.Forms.Timer(this.components);
            this.chartFs = new System.Windows.Forms.DataVisualization.Charting.Chart();
            this.chartJs = new System.Windows.Forms.DataVisualization.Charting.Chart();
            ((System.ComponentModel.ISupportInitialize)(this.chartZx)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.chartFs)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.chartJs)).BeginInit();
            this.SuspendLayout();
            // 
            // chartZx
            // 
            chartArea1.Name = "ChartArea1";
            this.chartZx.ChartAreas.Add(chartArea1);
            legend1.Name = "Legend1";
            this.chartZx.Legends.Add(legend1);
            this.chartZx.Location = new System.Drawing.Point(0, 29);
            this.chartZx.Name = "chartZx";
            series1.ChartArea = "ChartArea1";
            series1.ChartType = System.Windows.Forms.DataVisualization.Charting.SeriesChartType.Line;
            series1.IsValueShownAsLabel = true;
            series1.Legend = "Legend1";
            series1.Name = "Series1";
            this.chartZx.Series.Add(series1);
            this.chartZx.Size = new System.Drawing.Size(781, 264);
            this.chartZx.TabIndex = 0;
            this.chartZx.Text = "chartZX";
            // 
            // timer1
            // 
            this.timer1.Interval = 1000;
            this.timer1.Tick += new System.EventHandler(this.timer1_Tick);
            // 
            // chartFs
            // 
            chartArea2.Name = "ChartArea1";
            this.chartFs.ChartAreas.Add(chartArea2);
            legend2.Name = "Legend1";
            this.chartFs.Legends.Add(legend2);
            this.chartFs.Location = new System.Drawing.Point(0, 299);
            this.chartFs.Name = "chartFs";
            this.chartFs.Palette = System.Windows.Forms.DataVisualization.Charting.ChartColorPalette.EarthTones;
            series2.ChartArea = "ChartArea1";
            series2.ChartType = System.Windows.Forms.DataVisualization.Charting.SeriesChartType.Bar;
            series2.IsValueShownAsLabel = true;
            series2.Legend = "Legend1";
            series2.Name = "从本机发送的包的数目";
            this.chartFs.Series.Add(series2);
            this.chartFs.Size = new System.Drawing.Size(380, 181);
            this.chartFs.TabIndex = 1;
            this.chartFs.Text = "chartZX";
            // 
            // chartJs
            // 
            chartArea3.Name = "ChartArea1";
            this.chartJs.ChartAreas.Add(chartArea3);
            legend3.Name = "Legend1";
            this.chartJs.Legends.Add(legend3);
            this.chartJs.Location = new System.Drawing.Point(399, 299);
            this.chartJs.Name = "chartJs";
            this.chartJs.Palette = System.Windows.Forms.DataVisualization.Charting.ChartColorPalette.Berry;
            series3.ChartArea = "ChartArea1";
            series3.ChartType = System.Windows.Forms.DataVisualization.Charting.SeriesChartType.Bar;
            series3.IsValueShownAsLabel = true;
            series3.Legend = "Legend1";
            series3.Name = "本机接收的包的数目";
            this.chartJs.Series.Add(series3);
            this.chartJs.Size = new System.Drawing.Size(380, 181);
            this.chartJs.TabIndex = 2;
            this.chartJs.Text = "chartZX";
            // 
            // Statistics
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(782, 486);
            this.Controls.Add(this.chartJs);
            this.Controls.Add(this.chartFs);
            this.Controls.Add(this.chartZx);
            this.Name = "Statistics";
            this.Text = "Statistics";
            this.Load += new System.EventHandler(this.Statistics_Load);
            ((System.ComponentModel.ISupportInitialize)(this.chartZx)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.chartFs)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.chartJs)).EndInit();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.DataVisualization.Charting.Chart chartZx;
        private System.Windows.Forms.Timer timer1;
        private System.Windows.Forms.DataVisualization.Charting.Chart chartFs;
        private System.Windows.Forms.DataVisualization.Charting.Chart chartJs;
    }
}