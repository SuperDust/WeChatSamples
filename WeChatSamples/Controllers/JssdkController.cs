using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace WeChatSamples.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class JssdkController : ControllerBase
    {
        private readonly string _agentId = "1000002";
        private readonly string _secret = "wRbF8g5Fo9007dvzLYAzklNk1sKfCboXY0q8z9yJJ3w";
        private readonly string _corpId = "ww7abc273f2c3a8369";

        /// <summary>
        /// 获取access_token地址
        /// </summary>
        private readonly string _gettokenurl = "https://qyapi.weixin.qq.com/cgi-bin/gettoken";

        /// <summary>
        /// 获取企业的jsapi_ticket
        /// </summary>
        private readonly string _qyticketurl = "https://qyapi.weixin.qq.com/cgi-bin/get_jsapi_ticket";

        /// <summary>
        /// 当前网页URL 不包函#之后
        /// </summary>
        private readonly string _currentpageurl = "http://**.zicp.vip/";

        private readonly ILogger<JssdkController> _logger;
        private readonly IHttpClientFactory _clientFactory;
        private readonly IMemoryCache _memoryCache;

        public JssdkController(ILogger<JssdkController> logger, IHttpClientFactory clientFactory, IMemoryCache memoryCache)
        {
            _logger = logger;
            _clientFactory = clientFactory;
            _memoryCache = memoryCache;
        }

        /// <summary>
        /// 获取随机字符串
        /// </summary>
        /// <param name="codeCount"> 多少位的随机字符串 </param>
        /// <returns> </returns>
        public string GetNoncestr(int codeCount)
        {
            int rep = 0;
            string str = string.Empty;
            long num2 = DateTime.Now.Ticks + rep;
            rep++;
            Random random = new Random(((int)(((ulong)num2) & 0xffffffffL)) | ((int)(num2 >> rep)));
            for (int i = 0; i < codeCount; i++)
            {
                char ch;
                int num = random.Next();
                if ((num % 2) == 0)
                {
                    ch = (char)(0x30 + ((ushort)(num % 10)));
                }
                else
                {
                    ch = (char)(0x41 + ((ushort)(num % 0x1a)));
                }
                str = str + ch.ToString();
            }
            return str;
        }

        /// <summary>
        /// 加密签名 对jsapi_ticket返回的值进行sha1签名，得到signature
        /// </summary>
        /// <param name="value"> </param>
        /// <returns> </returns>
        public string GetSignature(string value)
        {
            SHA1 sha1 = new SHA1CryptoServiceProvider();
            byte[] bytes_sha1_in = UTF8Encoding.Default.GetBytes(value);
            byte[] bytes_sha1_out = sha1.ComputeHash(bytes_sha1_in);
            string str_sha1_out = BitConverter.ToString(bytes_sha1_out);
            str_sha1_out = str_sha1_out.Replace("-", "");
            return str_sha1_out;
        }

        [HttpGet]
        public async Task<IActionResult> GetJsSDKAsync()
        {
            TimeSpan ts = DateTime.Now - new DateTime(1970, 1, 1, 0, 0, 0, 0);
            string timestamp = Convert.ToUInt64(ts.TotalSeconds).ToString();
            string nonceStr = GetNoncestr(16);

            //签名用的noncestr和timestamp必须与wx.config中的nonceStr和timestamp相同。
            //签名用的url必须是调用JS接口页面的完整URL。
            string qysignature = string.Format("jsapi_ticket={0}&noncestr={1}&timestamp={2}&url={3}",
               await GetQyJssdkTicket(),
                nonceStr,
                timestamp,
                _currentpageurl);
            string appsignature = string.Format("jsapi_ticket={0}&noncestr={1}&timestamp={2}&url={3}",
              await GetAppJssdkTicket(),
                nonceStr,
                timestamp,
                _currentpageurl);
            qysignature = GetSignature(qysignature);
            appsignature = GetSignature(appsignature);
            var parmas = new
            {
                corpid = _corpId, // 必填，企业微信的corpid，必须与当前登录的企业一致
                agentid = _agentId, // 必填，企业微信的应用id （e.g. 1000247）
                timestamp = timestamp, // 必填，生成签名的时间戳
                noncestr = nonceStr, // 必填，生成签名的随机串
                signature = qysignature,
                appsignature = appsignature
            };

            return Ok(parmas);
        }

        /// <summary>
        /// 获取企业的JssdkTicket
        /// </summary>
        /// <returns> </returns>
        public async Task<string> GetQyJssdkTicket()
        {
            if (_memoryCache.Get<string>("QyJssdkTicket") == null)
            {
                string url = $"{_qyticketurl}?access_token={ await GetAccessToken()}";
                HttpResponseMessage response = await _clientFactory.CreateClient().GetAsync(url);
                if (response.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    using (var responseStream = await response.Content.ReadAsStreamAsync())
                    {
                        var jssdkticket_result = JsonConvert.DeserializeObject<dynamic>(new StreamReader(responseStream).ReadToEnd());
                        int errcode = jssdkticket_result.errcode;
                        if (errcode == 0)
                        {
                            string ticket = jssdkticket_result.ticket;
                            int expires_in = jssdkticket_result.expires_in;
                            _memoryCache.Set<string>("QyJssdkTicket", ticket, DateTimeOffset.Now.AddSeconds(expires_in - 10));
                        }
                        else
                        {
                            _logger.LogError($"JssdkTicket请求错误:{jssdkticket_result.errmsg }");
                        }
                    }
                }
            }
            return _memoryCache.Get<string>("QyJssdkTicket");
        }

        /// <summary>
        /// 获取AccessToken
        /// </summary>
        /// <returns> </returns>
        public async Task<string> GetAccessToken()
        {
            if (_memoryCache.Get<string>("AccessToken") == null)
            {
                string url = $"{_gettokenurl}?corpid={_corpId}&corpsecret={_secret}";
                HttpResponseMessage response = await _clientFactory.CreateClient().GetAsync(url);
                if (response.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    using (var responseStream = await response.Content.ReadAsStreamAsync())
                    {
                        var access_token_result = JsonConvert.DeserializeObject<dynamic>(new StreamReader(responseStream).ReadToEnd());
                        int errcode = access_token_result.errcode;
                        if (errcode == 0)
                        {
                            string access_token = access_token_result.access_token;
                            int expires_in = access_token_result.expires_in;
                            _memoryCache.Set<string>("AccessToken", access_token, DateTimeOffset.Now.AddSeconds(expires_in - 10));
                        }
                        else
                        {
                            _logger.LogError($"access_token请求错误:{access_token_result.errmsg }");
                        }
                    }
                }
            }
            return _memoryCache.Get<string>("AccessToken");
        }
    }
}
