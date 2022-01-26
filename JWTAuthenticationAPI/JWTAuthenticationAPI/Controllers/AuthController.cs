using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using JWTAuthenticationAPI.Provider;
using JWTAuthenticationAPI.Models;
using Microsoft.Net.Http.Headers;

namespace JWTAuthenticationAPI.Controllers
{
 
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        static readonly log4net.ILog _log4net = log4net.LogManager.GetLogger(typeof(AuthController));
        private readonly IAuthProvider _authProvider;

        public AuthController(IAuthProvider authProvider)
        {
            _authProvider = authProvider;
        }

        [HttpPost]
        public IActionResult AuthenticateUser(User user)
        {
            try
            {
                var token = _authProvider.AuthenticateUser(user);
                if (string.IsNullOrEmpty(token))
                {
                    return Unauthorized();
                }
                return Ok(token);
            }
            catch(Exception exception)
            {
                _log4net.Error("Exception found while authenticating the user=" + exception.Message);
                return new StatusCodeResult(500);

            }
        }

        [HttpGet]
        public IActionResult CheckAuthentication()
        {
            string headerToken = this.HttpContext.Request.Headers[HeaderNames.Authorization].ToString().Replace("Bearer ", "");
            string token = HttpContext.Session.GetString(SessionName);
            if (String.Equals(token, headerToken))
            {
                return Ok();
            }
            return Unauthorized();
        }
    }
}
