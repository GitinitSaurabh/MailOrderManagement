using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using RefillMicroservice.Model;
using RefillMicroservice.Provider;
using RefillMicroservice.Repository;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using RefillMicroservice.TokeInfo;
using RefillMicroservice.Filters;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace RefillMicroservice.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [MailOrderAuthorization]
    public class RefillController : ControllerBase
    {
        static readonly log4net.ILog _log4net = log4net.LogManager.GetLogger(typeof(RefillController));
        IRefillProvider _refillProvider;
        string Token;
        
        public RefillController(IRefillProvider refillProvider)
        {
            _refillProvider = refillProvider;

            //HttpContext httpContext = HttpContext.Current;
        }

       

        //To View the latest Refill Status of a subscription
        [HttpGet("SubscriptionId")]
        
        public IActionResult viewRefillStatus(int subscriptionId)
        {
            if(subscriptionId==0)
            {
                return NotFound();
            }
            try
            {                
                  _refillProvider = new RefillProvider();
                 _log4net.Info("get refill status");
                 return Ok(_refillProvider.ViewLatestRefillDetails(subscriptionId));
            }
            catch(Exception e)
            {
                _log4net.Error(e.Message);
                return StatusCode(500);
            }
             
        }


        //Refill microservice endpoint - get refill dues as of date
        //(return the list of subscriptions that are due to refill from the last refill date )
        [HttpGet("GetRefillDueAsofdate")]
        
        public IActionResult GetRefillDueAsofdate(int subscriptionId, DateTime fromDates)
        {
            if (subscriptionId == 0)
            {
                return NotFound();
            }
            try
            {
                _refillProvider = new RefillProvider();
                _log4net.Info("Get refill due as of date");
                return Ok(_refillProvider.GetRefillDueAsofdates(subscriptionId, fromDates));
                
            }
            catch(Exception e)
            {
                _log4net.Error(e.Message);
                return StatusCode(500);
            }

        }


        //Refill microservice endpoint - request for refill order
        [HttpPost("requestAdhocRefill")]
        public IActionResult requestAdhocRefill(RefillOrderLineItem lineItem)
        {
            if (lineItem==null)
            {
                return NotFound();
            }
            try
            {
               _refillProvider = new RefillProvider();
               _log4net.Info("Get Adhoc refill");
               return Ok(_refillProvider.requestAdhocRefill(lineItem.Policy_ID, lineItem.Subscription_ID, lineItem.Member_ID, lineItem.Location));
            }
            catch (Exception e)
            {
                _log4net.Error(e.Message);
                return StatusCode(500);
            }

        }
        //Invoked by subscription microservice for to check pending refill status
        [HttpGet("getPendingStatus")]
        public IActionResult getduerefillstatus(int subscription_id)
        {
            try
            {
                _refillProvider = new RefillProvider();
                return Ok(_refillProvider.getduerefillstatus(subscription_id));
            }
            catch(Exception e)
            {
                _log4net.Error(e.Message);
                return StatusCode(500);
            }
        }

    }
}
