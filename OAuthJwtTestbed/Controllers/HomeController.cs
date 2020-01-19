using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using OAuthJwtTestbed.Models;
using TokenHelper;

namespace OAuthJwtTestbed.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            FileInfo fi = new FileInfo(Assembly.GetExecutingAssembly().Location);
            string ddd = fi.DirectoryName + "\\" + fi.Name;
            fi = new FileInfo(ddd);

            var yyy = WindowsIdentity.GetCurrent();
            //var xxx = System.Threading.Thread.CurrentPrincipal.Identity;
            ConfigValues vm = new ConfigValues()
            {
                OAuthEndpointUrl = "https://services.github5775.com/api/oauth/v3/token",
                OAuthClientId = "f6615593-05c0-4ae7-a1b4-da09f3c2bc04",
                OAuthSecret = "f6615593-05c0-4ae7-a1b4-da09f3c2bc04",
                OAuthScope = "xyz-abc",
                StsEndpointUrl = "https://services.github5775.com/api/jwt/v6/token",
                StsKey1 = "admin",
                StsValue1 = Uri.EscapeDataString("michoelz"),
                StsKey2 = "user",
                StsValue2 = "jerryr",
                ApiEndpointUrl = "https://services.github5775.com/api/translation/RR45442"
            };

            vm.OAuthEndpointUrl = "https://services.github5775.com/api/oauth/v4/token";
            vm.ApiEndpointUrl = "https://services.github5775.com/api/location/v5.2/map";
            vm.OAuthClientId = "f6615593-05c0-4ae7-a1b4-da09f3c2bc04";
            vm.OAuthSecret = "f6615593-05c0-4ae7-a1b4-da09f3c2bc04";

            return View(vm);
        }

        public IActionResult About()
        {
            ViewData["Message"] = "Your application description page.";

            return View();
        }

        public IActionResult Contact()
        {
            ViewData["Message"] = "Your contact page.";

            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public async Task<JsonResult> GetOAuthTokenAsync(string oauthEndpointUrl, string clientId, string secret, string scope, string certIssuerName = "", string username = "", bool useCurrentUser = false)
        {
            string token = await TokenHelper.OAuthHelper.GetOAuthTokenAsync(oauthEndpointUrl,
                  clientId, secret, scope, SecurityProtocolType.Tls12, certIssuerName, username, true);

            return Json(token);
        }
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public async Task<JsonResult> GetJwtUsingOAuthAsync(string stsEndpointUrl, string oauthToken)
        {
            List<KeyValuePair<string, string>> keyValues = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("admin", "michoelz"),
                    new KeyValuePair<string, string>("user", Uri.EscapeDataString("jerryr"))
                };
            string token = await JwtHelper.GetJwtUsingOAuthToken(stsEndpointUrl, oauthToken, keyValues);

            return Json(token);
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public async Task<JsonResult> CallApiWithBearerTokenAsync(string apiEndpointUrl, string token)
        {
            string results = await JwtHelper.CallApiUsingBearerToken(apiEndpointUrl, token, HttpMethod.Get, null);

            return Json(results);
        }
    }
    public class ConfigValues
    {
        public string OAuthEndpointUrl { get; set; }
        public string OAuthClientId { get; set; }
        public string OAuthSecret { get; set; }
        public string OAuthScope { get; set; }
        public string StsEndpointUrl { get; set; }
        public string StsKey1 { get; set; }
        public string StsValue1 { get; set; }
        public string StsKey2 { get; set; }
        public string StsValue2 { get; set; }
        public string ApiEndpointUrl { get; set; }
    }
}
