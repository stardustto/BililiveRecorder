﻿using BililiveRecorder.FlvProcessor;
using Newtonsoft.Json;
using NLog;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace BililiveRecorder.Core.Config
{
    [JsonObject(memberSerialization: MemberSerialization.OptIn)]
    public class ConfigV1 : INotifyPropertyChanged
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        /// <summary>
        /// 当前工作目录
        /// </summary>
        [JsonIgnore]
        [Utils.DoNotCopyProperty]
        public string WorkDirectory { get => _workDirectory; set => SetField(ref _workDirectory, value); }


        /// <summary>
        /// 房间号列表
        /// </summary>
        [JsonProperty("roomlist")]
        public List<RoomV1> RoomList { get; set; } = new List<RoomV1>();

        /// <summary>
        /// 启用的功能
        /// </summary>
        [JsonProperty("feature")]
        public EnabledFeature EnabledFeature { get => _enabledFeature; set => SetField(ref _enabledFeature, value); }

        /// <summary>
        /// 剪辑-过去的时长(秒)
        /// </summary>
        [JsonProperty("clip_length_future")]
        public uint ClipLengthFuture { get => _clipLengthFuture; set => SetField(ref _clipLengthFuture, value); }

        /// <summary>
        /// 剪辑-将来的时长(秒)
        /// </summary>
        [JsonProperty("clip_length_past")]
        public uint ClipLengthPast { get => _clipLengthPast; set => SetField(ref _clipLengthPast, value); }

        /// <summary>
        /// 自动切割模式
        /// </summary>
        [JsonProperty("cutting_mode")]
        public AutoCuttingMode CuttingMode { get => _cuttingMode; set => SetField(ref _cuttingMode, value); }

        /// <summary>
        /// 自动切割数值（分钟/MiB）
        /// </summary>
        [JsonProperty("cutting_number")]
        public uint CuttingNumber { get => _cuttingNumber; set => SetField(ref _cuttingNumber, value); }

        /// <summary>
        /// 录制断开重连时间间隔 毫秒
        /// </summary>
        [JsonProperty("timing_stream_retry")]
        public uint TimingStreamRetry { get => _timingStreamRetry; set => SetField(ref _timingStreamRetry, value); }

        /// <summary>
        /// 连接直播服务器超时时间 毫秒
        /// </summary>
        [JsonProperty("timing_stream_connect")]
        public uint TimingStreamConnect { get => _timingStreamConnect; set => SetField(ref _timingStreamConnect, value); }

        /// <summary>
        /// 弹幕服务器重连时间间隔 毫秒
        /// </summary>
        [JsonProperty("timing_danmaku_retry")]
        public uint TimingDanmakuRetry { get => _timingDanmakuRetry; set => SetField(ref _timingDanmakuRetry, value); }

        /// <summary>
        /// HTTP API 检查时间间隔 秒
        /// </summary>
        [JsonProperty("timing_check_interval")]
        public uint TimingCheckInterval { get => _timingCheckInterval; set => SetField(ref _timingCheckInterval, value); }

        /// <summary>
        /// 最大未收到新直播数据时间 毫秒
        /// </summary>
        [JsonProperty("timing_watchdog_timeout")]
        public uint TimingWatchdogTimeout { get => _timingWatchdogTimeout; set => SetField(ref _timingWatchdogTimeout, value); }

        /// <summary>
        /// 最大直播数据落后时间 毫秒
        /// </summary>
        [JsonProperty("timing_watchdog_behind")]
        public uint TimingWatchdogBehind { get => _timingWatchdogBehind; set => SetField(ref _timingWatchdogBehind, value); }

        /// <summary>
        /// 是否对API请求使用HTTP代理
        /// </summary>
        [JsonProperty("proxy_enable")]
        public bool UseProxyForApi { get => _useProxyForApi; set => SetField(ref _useProxyForApi, value); }

        /// <summary>
        /// HTTP代理服务器地址
        /// </summary>
        [JsonProperty("proxy_address")]
        public string ProxyAddress { get => _proxyAddress; set => SetField(ref _proxyAddress, value); }

        /// <summary>
        /// HTTP代理是否需要身份验证
        /// </summary>
        [JsonProperty("proxy_auth")]
        public bool ProxyRequireCredentials { get => _proxyRequireCredentials; set => SetField(ref _proxyRequireCredentials, value); }

        /// <summary>
        /// HTTP代理用户名
        /// </summary>
        [JsonProperty("proxy_user")]
        public string ProxyUsername { get => _proxyUsername; set => SetField(ref _proxyUsername, value); }

        /// <summary>
        /// HTTP代理密码
        /// </summary>
        [JsonProperty("proxy_pass")]
        public string ProxyPassword { get => _proxyPassword; set => SetField(ref _proxyPassword, value); }

        #region INotifyPropertyChanged
        public event PropertyChangedEventHandler PropertyChanged;
        protected virtual void OnPropertyChanged(string propertyName) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        protected bool SetField<T>(ref T field, T value, [CallerMemberName] string propertyName = "")
        {
            if (EqualityComparer<T>.Default.Equals(field, value)) { return false; }
            logger.Debug("设置 [{0}] 的值已从 [{1}] 修改到 [{2}]", propertyName, field, value);
            field = value; OnPropertyChanged(propertyName); return true;
        }
        #endregion

        private uint _clipLengthPast = 20;
        private uint _clipLengthFuture = 10;
        private uint _cuttingNumber = 10;
        private EnabledFeature _enabledFeature = EnabledFeature.Both;
        private AutoCuttingMode _cuttingMode = AutoCuttingMode.Disabled;
        private string _workDirectory;

        private uint _timingWatchdogTimeout = 5 * 1000;
        private uint _timingWatchdogBehind = 5 * 1000;
        private uint _timingStreamRetry = 6 * 1000;
        private uint _timingStreamConnect = 3 * 1000;
        private uint _timingDanmakuRetry = 2 * 1000;
        private uint _timingCheckInterval = 5 * 60;

        private bool _useProxyForApi = false;
        private string _proxyAddress = "";
        private bool _proxyRequireCredentials = false;
        private string _proxyUsername = "";
        private string _proxyPassword = "";
    }
}
