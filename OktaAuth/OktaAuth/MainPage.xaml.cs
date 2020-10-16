using Newtonsoft.Json.Linq;
using RestSharp;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Xamarin.Essentials;
using Xamarin.Forms;

namespace OktaAuth
{
    // Learn more about making custom code visible in the Xamarin.Forms previewer
    // by visiting https://aka.ms/xamarinforms-previewer
    [DesignTimeVisible(false)]
    public partial class MainPage : ContentPage
    {
        private readonly LoginService loginService = new LoginService();

        public MainPage()
        {
            InitializeComponent();
        }

        private void LoginButtonClicked(object sender, EventArgs e)
        {
            try
            {
                var u = uName.Text;
                var p = pWord.Text;
                var getArray = loginService.GetAuthzCode(u, p);
                var authzCode = getArray[0];
                var codeVerifier = getArray[1];
                var tokenResults = loginService.GetTokens(authzCode, codeVerifier);
                var idToken = tokenResults[0];
                var acToken = tokenResults[1];

                var jwtHandler = new JwtSecurityTokenHandler();
                var idtokenSec = jwtHandler.ReadToken(idToken) as JwtSecurityToken;
                var actokenSec = jwtHandler.ReadToken(acToken) as JwtSecurityToken;

                var idtokenStr = idtokenSec.ToString();
                var idtokenJson = idtokenStr.Substring(idtokenStr.IndexOf(".") + 1);
                var idObject = JObject.Parse(idtokenJson.ToString());

                var actokenStr = actokenSec.ToString();
                var actokenJson = actokenStr.Substring(actokenStr.IndexOf(".") + 1);
                var acObject = JObject.Parse(actokenJson.ToString());

                var a = idObject.GetValue("name").ToString();
                var b = idObject.GetValue("email").ToString();
                var c = acObject.GetValue("scp").ToString();

                WelcomeLabel.Text = a + " - " + b + "\r\n" + c;
                LogoutButton.IsVisible = !(LoginButton.IsVisible = false);
                uName.IsVisible = false;
                pWord.IsVisible = false;
                lblUsr.IsVisible = false;
                lblPwd.IsVisible = false;
            }
            catch (Exception ex)
            {
                WelcomeLabel.Text = ex.Message;
            }
        }

        private void LogoutButtonClicked(object sender, EventArgs e)
        {
            LogoutButton.IsVisible = !(LoginButton.IsVisible = true);
            WelcomeLabel.Text = "";
            uName.IsVisible = true;
            pWord.IsVisible = true;
            lblUsr.IsVisible = true;
            lblPwd.IsVisible = true;
        }
    }
}
