namespace WebRole.Modules
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Net;
    using System.Web;
    using Microsoft.WindowsAzure.ServiceRuntime;

    public class IPModule: IHttpModule
    {
        private const string FilterFromConfiguration = "FilterInBoundIP";
        private const string AllowedIpFromConfiguration = "AllowedIPAddresses";
        private static List<IPAddress> _allowed = null;
        
        public void Init(HttpApplication context)
        {
            bool filter;
            if (bool.TryParse(RoleEnvironment.GetConfigurationSettingValue(FilterFromConfiguration), out filter))
            {
                if (filter)
                {
                    Trace.TraceInformation("IP Filter is Enabled");
                    GetAllowedIPRange();
                    context.BeginRequest += new EventHandler(ContextBeginRequest);
                }
            }   
        }

        private void GetAllowedIPRange()
        {
            _allowed = new List<IPAddress>();
            foreach (
                string address in
                    RoleEnvironment.GetConfigurationSettingValue(AllowedIpFromConfiguration).Split(
                        new string[] { ",", ";" }, StringSplitOptions.RemoveEmptyEntries))
            {
                IPAddress ipaddress;

                if (IPAddress.TryParse(address, out ipaddress))
                    _allowed.Add(ipaddress);
            }
        }

        public static bool IsAllowed(string source)
        {
            if (_allowed.Count == 0)
                return false;
            if (string.IsNullOrEmpty(source))
                return false;
            IPAddress sourceAddress;
            if (!IPAddress.TryParse(source, out sourceAddress))
                return false;
            if (_allowed.Contains(sourceAddress))
                return true;
            else
                return false;
        }

        static void ContextBeginRequest(object sender, EventArgs e)
        {
            if (!IsAllowed(HttpContext.Current.Request.UserHostAddress))
            {
                Trace.TraceInformation("IP Address {0} Refused", HttpContext.Current.Request.UserHostAddress);
                HttpContext.Current.ApplicationInstance.CompleteRequest();
                HttpContext.Current.Response.StatusCode = 401;
            }
        }

        public void Dispose()
        {
            _allowed.Clear();
        }
    }
}