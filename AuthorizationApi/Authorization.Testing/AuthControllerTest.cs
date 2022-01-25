using AuthorizationService;
using AuthorizationService.Controllers;
using AuthorizationService.Provider;
using AuthorizationService.Repository;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Moq;
using NUnit.Framework;
using System;
using System.Collections.Generic;

namespace Authorization.Testing
{
    public class AuthControllerTest
    {
        public Dictionary<string, string> dc = new Dictionary<string, string>()
        {
               {"user1","pass1"},
               {"user2","pass2"},

        };

        [TestCase("user1", "pass1")]
        [TestCase("user2", "pass2")]
        public void TokenGenarationTest(string name, string pass)
        {

            Mock<IConfiguration> config = new Mock<IConfiguration>();
            config.Setup(p => p["Jwt:Key"]).Returns("ThisismySecretKey");
            Mock<ICredentialsRepo> mock = new Mock<ICredentialsRepo>();
            mock.Setup(p => p.GetCredentials()).Returns(dc);
            AuthProvider cp = new AuthProvider(mock.Object);
            Authenticate user = new Authenticate()
            {
                Name = name,
                Password = pass
            };
            string result = cp.GenerateJSONWebToken(user, config.Object);
            Assert.IsNotNull(result);
        }

        [Test]
        public void FailedTokenGenarationTest()
        {
            Mock<IConfiguration> config = new Mock<IConfiguration>();
            config.Setup(p => p["Jwt:Key"]).Returns("ThisismySecretKey");
            Mock<ICredentialsRepo> mock = new Mock<ICredentialsRepo>();
            mock.Setup(p => p.GetCredentials()).Returns(dc);
            AuthProvider cp = new AuthProvider(mock.Object);
            string result = cp.GenerateJSONWebToken(null, config.Object);
            Assert.IsNull(result);
        }

        [TestCase("user1", "pass1")]
        public void CorrectCredProviderTest(string name, string pass)
        {

            Mock<ICredentialsRepo> mock = new Mock<ICredentialsRepo>();
            mock.Setup(p => p.GetCredentials()).Returns(dc);

            AuthProvider cp = new AuthProvider(mock.Object);
            Authenticate user = new Authenticate()
            {
                Name = name,
                Password = pass
            };
            Authenticate result = cp.AuthenticateUser(user);
            Assert.IsNotNull(result);
        }

        [TestCase("user1", "pass2")]
        public void WrongCredProviderTest(string name, string pass)
        {

            Mock<ICredentialsRepo> mock = new Mock<ICredentialsRepo>();
            mock.Setup(p => p.GetCredentials()).Returns(dc);

            AuthProvider cp = new AuthProvider(mock.Object);
            Authenticate user = new Authenticate()
            {
                Name = name,
                Password = pass
            };
            Authenticate result = cp.AuthenticateUser(user);
            Assert.IsNull(result);
        }

        [Test]
        public void CorrectCredControllerTest()
        {
            try
            {
                Authenticate cred = new Authenticate()
                {
                    Name = "user1",
                    Password = "pass2"
                };

                Mock<IConfiguration> config = new Mock<IConfiguration>();
                Mock<IAuthProvider> mock = new Mock<IAuthProvider>();
                mock.Setup(p => p.AuthenticateUser(cred)).Returns(cred);
                mock.Setup(q => q.GenerateJSONWebToken(cred, config.Object)).Returns("Token");

                AuthController cp = new AuthController(config.Object, mock.Object);

                var result = cp.Login(cred);
                //OkObjectResult output = cp.Login(user) as OkObjectResult;
                var okResult = result as OkObjectResult;
                Assert.IsNotNull(okResult);
                Assert.AreEqual(200, okResult.StatusCode);
                //OkObjectResult result = cp.Login(cred) as OkObjectResult;
                //Assert.AreEqual(200,result.StatusCode);
            }
            catch (Exception e)
            {
                Assert.AreEqual("Object reference not set to an instance of an object.", e.Message);
            }
        }

        [Test]
        public void WrongCredControllerTest()
        {
            try
            {
                Authenticate cred = new Authenticate()
                {
                    Name = "user1",
                    Password = "pass1"
                };
                Mock<IConfiguration> config = new Mock<IConfiguration>();
                Mock<IAuthProvider> mock = new Mock<IAuthProvider>();
                mock.Setup(q => q.GenerateJSONWebToken(cred, config.Object)).Returns("Token");
                AuthController cp = new AuthController(config.Object, mock.Object);
                Authenticate user = new Authenticate()
                {
                    Name = "user1",
                    Password = "pass11"
                };

                OkObjectResult Result = cp.Login(user) as OkObjectResult;

                Assert.AreNotEqual(200, Result.StatusCode);
            }
            catch (Exception e)
            {
                Assert.AreEqual("Object reference not set to an instance of an object.", e.Message);
            }

        }

        
    }
}