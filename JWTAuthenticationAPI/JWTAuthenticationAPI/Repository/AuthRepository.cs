using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using JWTAuthenticationAPI.Models;
using Microsoft.Extensions.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace JWTAuthenticationAPI.Repository
{
    
    public class AuthRepository : IAuthRepository
    {
        static readonly log4net.ILog _log4net = log4net.LogManager.GetLogger(typeof(AuthRepository));
        private IConfiguration _config;

        /// <summary>
        /// Static data for user model is created.
        /// </summary>
        private readonly Dictionary<string, string> users = new Dictionary<string, string>() {
            { "abc","abc"},
            {"cde","cde" },
            {"efg","efg" }
        };


        /// <summary>
        /// Constructor of AuthRepository which initializes IConfiguration Object.
        /// </summary>
        /// <param name="config"></param>
        public AuthRepository(IConfiguration config)
        {
            _log4net.Info("AuthenticationRepository constructor initiated.");
            _config = config;
        }

        /// <summary>
        ///  Generates the token if the user credentials are correct.
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>

        public string GenerateToken(User user)
        {
            try
            {
                _log4net.Info("Token generation started");
                if (!users.Any(u => u.Key == user.Username && u.Value == user.Password))
                {
                    return null;
                }
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_config["Jwt:Key"]);
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[]
                    {
                        new Claim(ClaimTypes.Name, user.Username.ToString())
                    }),
                    Expires = DateTime.UtcNow.AddHours(1),
                    SigningCredentials = new SigningCredentials(
                        new SymmetricSecurityKey(key),
                        SecurityAlgorithms.HmacSha256Signature)
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                return tokenHandler.WriteToken(token);
            }
            catch(Exception)
            {
                throw ;
            }

        }
    }
}
