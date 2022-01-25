using DrugApi.Filters;
using DrugApi.Model;
using DrugApi.Provider;
using DrugApi.Repository;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DrugApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]    
    [MailOrderAuthorization]
    public class DrugController : ControllerBase
    {
        readonly log4net.ILog _log4net;
         Iprovider ip;


        public DrugController(Iprovider _ip)
        {
             ip= _ip;
            _log4net = log4net.LogManager.GetLogger(typeof(DrugController));
        }

       


        /// <summary>
        /// This method responsible for returning the Drug Details searched by Drug ID
        /// </summary>
        /// <param name="drugId"></param>
        /// <returns></returns>
        [HttpGet("id")]
        public IActionResult Get(int drugId)
        {
            _log4net.Info(" Http Get Drug Details request");
            try
            {
                ip = new providerclass();
                return Ok(ip.GetdrugDetail(drugId));
            }
            catch
            {
                return BadRequest();
            }

        }



        [HttpGet("name")]
        public IActionResult Get(string name)
        {
            _log4net.Info(" Http Get Drug Details request");
            try
            {
                ip = new providerclass();
                return Ok(ip.GetdrugDetailByName(name));
            }
            catch
            {
                return BadRequest();
            }

        }

        /// <summary>
        /// This method responsible for returing the Drug Details searched by Drug ID and Location
        /// </summary>
        /// <param name="drugId"></param>
        /// <param name="location"></param>
        /// <returns></returns>
        [HttpGet("Location/id")]
        public IActionResult Get(int drugId, string location)
        {

            _log4net.Info(" Http Get Request for Drug Details by Location and ID");
            try
            {
                ip = new providerclass();
                return Ok(ip.GetDispatchableStocks(drugId, location));
            }
            catch
            {
                return BadRequest();
            }
        }

        //Invoked by Refill microservice - check drugs availble for refill order
        [HttpGet("checkDrugsToRefill")]
        public IActionResult getDrugs(int drugId, string location)
        {
            
            _log4net.Info("checkfor DRug availability using id and loc" + drugId +location+"");
            try
            {
                ip = new providerclass();
                return Ok(ip.AdhocRefillOrder(drugId, location));
            }
            catch
            {
                return BadRequest();
            }
        }

        //Invoked by sybscription microservice - check drugs availble for getting subscribe
        [HttpGet("checkAvailbleForSubscription")]
        public IActionResult CheckAvailableDrug(int drugId)
        {
            
            _log4net.Info("checkfor Drug availability for subscription using id " + drugId );
            try
            {
                ip = new providerclass();
                return Ok(ip.CheckAvailbleDrug(drugId));
            }
            catch
            {
                return BadRequest();
            }
        }
    }

    
}
