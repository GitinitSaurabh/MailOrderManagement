using Microsoft.AspNetCore.Mvc;
using Moq;
using NUnit.Framework;
using RefillMicroservice.Controllers;
using RefillMicroservice.Model;
using RefillMicroservice.Provider;
using RefillMicroservice.Repository;
using System;
using System.Collections.Generic;

namespace RefillRepositoryTest
{
    public class Tests
    {
        string Token = "token";
     
        List<RefillOrder> refillList = new List<RefillOrder>()
        {
             new RefillOrder()
            {
                 RefillOrderId=1,
                Subscription_ID = 7,
                DrugID=1,
                RefillDate=new DateTime(2020,05,12),
                FromDate = new DateTime(2020, 05, 19),
                NextRefillDate=new DateTime(2020,10,08),
                Status="pending",
                Policy_ID = 1,
                Member_ID = 1,
                Location = "Mumbai"
            },
              new RefillOrder()
            {
                 RefillOrderId=1,
                Subscription_ID = 7,
                DrugID=1,
                RefillDate=new DateTime(2020,09,19),
                FromDate = new DateTime(2020, 05, 26),
                NextRefillDate=new DateTime(2020,10,08),
                Status="pending",
                Policy_ID = 1,
                Member_ID = 1,
                Location = "Mumbai"
            },
               new RefillOrder()
            {
                 RefillOrderId=1,
                Subscription_ID = 7,
                DrugID=1,
                RefillDate=new DateTime(2020,09,26),
                FromDate = new DateTime(2020, 05, 02),
                NextRefillDate=new DateTime(2020,10,08),
                Status="pending",
                Policy_ID = 1,
                Member_ID = 1,
                Location = "Mumbai"
            }, new RefillOrder()
            {
                 RefillOrderId=1,
                Subscription_ID = 7,
                DrugID=1,
                RefillDate=new DateTime(2020,09,02),
                FromDate = new DateTime(2020, 05, 09),
                NextRefillDate=new DateTime(2020,10,08),
                Status="pending",
                Policy_ID = 1,
                Member_ID = 1,
                Location = "Mumbai"
            }
        };
        RefillOrder re1 = new RefillOrder()
        {
            RefillOrderId = 1,
            Subscription_ID = 7,
            DrugID = 1,
            RefillDate = new DateTime(2020, 09, 12),
            FromDate = new DateTime(2020, 10, 08),
            NextRefillDate = new DateTime(2020, 05, 15),
            Status = "pending",
            Policy_ID = 1,
            Member_ID = 1,
            Location = "Mumbai"
        };

        RefillOrderLineItem lineItem = new RefillOrderLineItem()
        {
            Policy_ID = 1,
            Member_ID = 1,
            Subscription_ID = 7,
            Location = "Hyderabad"
        };
        
        [SetUp]
        public void Setup()
        {
        }

        [Test]
        public void TestLatestRefillOrderValid()
        {
            RefillRepository refill = new RefillRepository();
            int subId = 7;
            RefillOrder refillOrder = refill.latestRefillOrder(subId);
            Assert.AreEqual(1,refillOrder.RefillOrderId);
        }
        [Test]
        public void TestLatestRefillOrderInvalid()
        {
            RefillRepository refill = new RefillRepository();
            int subId = 7;
            RefillOrder refillOrder = refill.latestRefillOrder(subId);
            Assert.AreNotEqual(2,refillOrder.RefillOrderId);
        }
        [Test]
        public void GetRefillDueAsofdatesTestValid()
        {
                Mock<IRefillProvider> mock = new Mock<IRefillProvider>();
                mock.Setup(p => p.GetRefillDueAsofdates(7, new DateTime(2020, 05, 05))).Returns(refillList);

                RefillController obj = new RefillController(mock.Object);
                var res = obj.GetRefillDueAsofdate(7, Convert.ToDateTime("2020, 05, 05")) as OkObjectResult;
                Assert.AreEqual(200, res.StatusCode);
                      
        }

        [Test]
        public void GetRefillDueAsofdatesTestInvalid()
        {
            Mock<IRefillProvider> mock = new Mock<IRefillProvider>();
            mock.Setup(p => p.GetRefillDueAsofdates(7, new DateTime(2020, 05, 05))).Returns(refillList);

            RefillController obj = new RefillController(mock.Object);
            var res = obj.GetRefillDueAsofdate(7, Convert.ToDateTime("2020, 05, 05")) as OkObjectResult;
            Assert.AreNotEqual(500, res.StatusCode);
        }

         [Test]
        public void CalculateDuesTestValid()
        {
            RefillRepository refill = new RefillRepository();
            List<RefillOrder> list = new List<RefillOrder>();
            list = refill.CalculateDues("weekly",7, new DateTime(2020, 05, 15));
            
            Assert.AreEqual(new DateTime(2020, 05, 29), list[0].NextRefillDate);
        }

        [Test]
        public void CalculateDuesTestInvalid()
        {
            RefillRepository refill = new RefillRepository();
            List<RefillOrder> list = new List<RefillOrder>();
            list = refill.CalculateDues("weekly", 7, new DateTime(2020, 05, 15));
            Assert.AreNotEqual(new DateTime(2020, 05, 30), list[0].NextRefillDate);
        }

        [Test]
        public void requestAdhocRefillsTestValid()
        {
            Mock<IRefillProvider> mock = new Mock<IRefillProvider>();
            mock.Setup(p => p.requestAdhocRefill(lineItem.Policy_ID,lineItem.Subscription_ID,lineItem.Member_ID,lineItem.Location)).Returns(re1);

            RefillController obj = new RefillController(mock.Object);
            var res = obj.requestAdhocRefill(lineItem) as OkObjectResult;
            Assert.AreEqual(200, res.StatusCode);
        }

        [Test]
        public void requestAdhocRefillsTestInvalid()
        {
            Mock<IRefillProvider> mock = new Mock<IRefillProvider>();
            mock.Setup(p => p.requestAdhocRefill(lineItem.Policy_ID, lineItem.Subscription_ID, lineItem.Member_ID, lineItem.Location)).Returns(re1);

            RefillController obj = new RefillController(mock.Object);
            var res = obj.requestAdhocRefill(lineItem) as OkObjectResult;
            Assert.AreNotEqual(500, res.StatusCode);
        }

        [Test]
        public void getduerefillstatusTest()
        {
            RefillRepository refill = new RefillRepository();
            string status = refill.getduerefillstatus(6);
            Assert.AreEqual("Successful", status);
        }

        [Test]
        public void getduerefillstatusTestInvalid()
        {
            RefillRepository refill = new RefillRepository();
            string status = refill.getduerefillstatus(6);
            Assert.AreNotEqual("pending", status);
        }

    }
}