using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SubscriptionMicroservice.Filters;
using SubscriptionMicroservice.Model;
using SubscriptionMicroservice.Provider;
using SubscriptionMicroservice.Token;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace SubscriptionMicroservice.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [MailOrderAuthorization]
    public class SubcriptionController : ControllerBase
    {
        ISubscriptionProvider _subscriptionProvider;
        string Token;

        public SubcriptionController(ISubscriptionProvider subscriptionProvider)
        {
            _subscriptionProvider = subscriptionProvider;
        }


        //Subscription Microservice Endpoint- subscrribe
        [HttpPost("Subscribe")]
        public IActionResult Subscribe(MemberPrescription prescriptiondetails)
        {
            try
            {   
                    _subscriptionProvider = new SubscriptionProvider();
                    return Ok(_subscriptionProvider.Subscribe(prescriptiondetails));
            }
            catch(Exception e)
            {
                throw new  Exception("subscription failed");
            }
        }

        //Subscription Microservice Endpoint - unsubscrribe
        [HttpPost("Unsubscribe")]
        public IActionResult Unsubscribe(int member_id, int subscription_id)
        {
            try
            {
                _subscriptionProvider = new SubscriptionProvider();
                return Ok(_subscriptionProvider.Unsubscribe(member_id, subscription_id));
            }
            catch(Exception e)
            {
                throw new Exception("UnSubscription Failed");
            }
           
        }


        //Invoked By Refill microservice - getting refill occurance
        [HttpGet("getFrequency")]
        public IActionResult GetRefillfrequnecyAsofdates(int subId)
        {
            try
            {
                    _subscriptionProvider = new SubscriptionProvider();
                    return Ok(_subscriptionProvider.GetRefillfrequnecyAsofdates(subId));
            }
            catch(Exception e)
            {
                throw new Exception("Get refill frequency failed");
            }
           
        }

    }
}
