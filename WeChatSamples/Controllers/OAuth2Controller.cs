using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace WeChatSamples.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class OAuth2Controller : ControllerBase
    {
        private readonly string _agentId = "1000002";
        private readonly string _secret = "Y3f8ESBIBJoC8M_FPHOlpvmghS_Nn2ceFePRVZjw9_E";
        private readonly string _corpId = "wwbf72a7a059eac0f8";

        /// <summary>
        /// 授权地址
        /// </summary>
        private readonly string _auth2url = "https://open.weixin.qq.com/connect/oauth2/authorize";

        /// <summary>
        /// 授权回调地址
        /// </summary>
        private readonly string _callbackurl = "http://****.zicp.vip/auth2callback/api/Auth2/Callback";

        /// <summary>
        /// 获取access_token地址
        /// </summary>
        private readonly string _gettokenurl = "https://qyapi.weixin.qq.com/cgi-bin/gettoken";

        /// <summary>
        /// 获取访问用户身份地址
        /// </summary>
        private readonly string _getuserurl = "https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo";

        private readonly ILogger<OAuth2Controller> _logger;
        private readonly IHttpClientFactory _clientFactory;
        private readonly IMemoryCache _memoryCache;

        public OAuth2Controller(ILogger<OAuth2Controller> logger, IHttpClientFactory clientFactory, IMemoryCache memoryCache)
        {
            _logger = logger;
            _clientFactory = clientFactory;
            _memoryCache = memoryCache;
        }

        [HttpGet]
        public IActionResult Auth2(string redirecturi)
        {
            string strurl = $"{_auth2url}?" +
                    $"&appid={_corpId}" +
                    $"&redirect_uri={System.Web.HttpUtility.UrlEncode(_callbackurl)}" +
                    $"&response_type=code" +
                    $"&scope={_secret}" +
                    $"&agentid={_agentId}" +
                    $"&state={System.Web.HttpUtility.UrlEncode(redirecturi)}#wechat_redirect";
            return Redirect(strurl);
        }

        [HttpGet("Callback")]
        public async Task<IActionResult> Callback(string code, string state)
        {
            /**
             1）code只能消费一次，不能重复消费。比如说，是否存在多个服务器同时消费同一code情况。
             2）code需要在有效期间消费（5分钟），过期会自动失效。
             */
            string access_token = await GetAccessToken();
            string url = $"{_getuserurl}?access_token={access_token}&code={code}";
            HttpResponseMessage response = await _clientFactory.CreateClient().GetAsync(url);
            if (response.StatusCode == System.Net.HttpStatusCode.OK)
            {
                using (var responseStream = await response.Content.ReadAsStreamAsync())
                {
                    var userinfo = JsonConvert.DeserializeObject<dynamic>(new StreamReader(responseStream).ReadToEnd());
                    int errcode = userinfo.errcode;
                    if (errcode == 0)
                    {
                        //企业成员
                        string UserId = userinfo.UserId;
                        //外部成员
                        string OpenId = userinfo.OpenId;
                        /**
                         userid是系统生成的可以修改一次;
                         所以后面的业务逻辑如果遇到错误就要重新授权一下;
                         */
                        if (UserId == null)
                        {
                            _memoryCache.Set<string>("UserId", OpenId);
                        }
                        else
                        {
                            _memoryCache.Set<string>("UserId", UserId);
                        }
                    }
                    else
                    {
                        _logger.LogError($"getuserinfo请求错误:{userinfo.errmsg}");
                        return Ok();
                    }
                }
            }
            return Redirect($"{System.Web.HttpUtility.UrlDecode(state)}?UserId={_memoryCache.Get<string>("UserId")}");
        }

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
