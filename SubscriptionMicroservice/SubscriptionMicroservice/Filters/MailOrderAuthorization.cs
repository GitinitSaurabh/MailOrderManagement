using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json;
using SubscriptionMicroservice.Token;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace SubscriptionMicroservice.Filters
{
    public class MailOrderAuthorization : ActionFilterAttribute, IAuthorizationFilter
    {
         public void OnAuthorization(AuthorizationFilterContext context)
         {
            var token = context.HttpContext.Request.Headers["Authorization"].Single().Split(" ")[1];
           // var token = context.HttpContext.Request.Headers[HeaderNames.Authorization].ToString().Replace("Bearer ", "");
            if (token == null)
            {
                context.Result = new UnauthorizedResult();
            }
            else
            {
                ConstHelpers.TokenString = token;
                Client obj = new Client();
                HttpClient client = obj.Authapi();
                client.DefaultRequestHeaders.TryAddWithoutValidation("Authorization","Bearer "+token);
                HttpResponseMessage res = client.GetAsync("api/Auth/CheckAuthentication").Result;
                if (!res.IsSuccessStatusCode)
                {
                    context.Result = new UnauthorizedResult();
                }
            }

         }
        
    }
   
}
