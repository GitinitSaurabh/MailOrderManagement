using Microsoft.AspNetCore.Mvc;
using Moq;
using NUnit.Framework;
using SubscriptionMicroservice.Controllers;
using SubscriptionMicroservice.Model;
using SubscriptionMicroservice.Provider;
using SubscriptionMicroservice.Repository;
using System;

namespace SubscriptionTest
{
    public class Tests
    {
        [SetUp]
        public void Setup()
        {
        }
        MemberSubscription M1 = new MemberSubscription()


        {
            MemberID = 1,
            SubscriptionDate = Convert.ToDateTime("01/01/2020"),

            PrescriptionID = 1,
            Drug_ID = 1,
            SubscriptionId = 7,
            RefillOccurrence = "weekly",
            Member_Location = "Mumbai",
            SubscriptionStatus = true


        };
        MemberPrescription T1 = new MemberPrescription()
        {
            PrescriptionId = 1,
            drugID = 1,
            MemberID = 5,
            InsuranceProvider = "MediBoddy",
            Insurance_Policy_Number = 5,
            // PrescriptionDate = Convert.ToDateTime("05/29/2020 5:50"),
            dosage = "daily",
            PrescriptionCourse = "FiveDays",
            Doctordetails = "MD"

        };

       

        [Test]
        public void SubscribeTestValid()
        {
            Mock<ISubscriptionProvider> acr = new Mock<ISubscriptionProvider>();
            acr.Setup(p => p.Subscribe(T1)).Returns("Your Subscription Added Successfully!");
            SubcriptionController contr = new SubcriptionController(acr.Object);
            var data = contr.Subscribe(T1) as OkObjectResult;
            Assert.AreEqual(200,data.StatusCode);

        }

       
        [Test]
        public void SubscribeTestInValid()
        {

            Mock<ISubscriptionProvider> mock = new Mock<ISubscriptionProvider>();
            mock.Setup(p => p.Subscribe(T1)).Returns("Sorry! Subscription Not Possible Due To Unavailable drug.");

            SubcriptionController obj = new SubcriptionController(mock.Object);
            var res = obj.Subscribe(T1) as OkObjectResult;
            Assert.AreNotEqual(res,"Unavailable");

        }

        [Test]
        public void UnsubscribeTestValid()
        {
            string str = "Unsubscription Done. Thank You!";
            Mock<ISubscriptionProvider> acr = new Mock<ISubscriptionProvider>();
            acr.Setup(p => p.Subscribe(T1)).Returns(str);
            SubcriptionController contr = new SubcriptionController(acr.Object);
            var data = contr.Subscribe(T1) as OkObjectResult;
            Assert.AreEqual(200,data.StatusCode);

        }


        [Test]
        public void UnsubscribeTestInValid()
        {

            string str = "Unsubscription Done. Thank You!";
            Mock<ISubscriptionProvider> acr = new Mock<ISubscriptionProvider>();
            acr.Setup(p => p.Subscribe(T1)).Returns(str);
            SubcriptionController contr = new SubcriptionController(acr.Object);
            var data = contr.Subscribe(T1) as OkObjectResult;
            Assert.AreNotEqual(data,"successful");

        }
        //[Test]
        //public void RefillFrequencyTestValid()
        //{
           
        //    Mock<ISubscriptionProvider> acr = new Mock<ISubscriptionProvider>();
        //    acr.Setup(p => p.Subscribe(T1)).Returns(Mock.Object);
        //    SubcriptionController contr = new SubcriptionController(acr.Object);
        //    var data = contr.Subscribe(T1) as OkObjectResult;
        //    Assert.AreEqual(data, null);

        //}


        //[Test]
        //public void RefillFrequencyTestInValid()
        //{

            
        //    Mock<ISubscriptionProvider> acr = new Mock<ISubscriptionProvider>();
        //    acr.Setup(p => p.Subscribe(T1)).Returns(str);
        //    SubcriptionController contr = new SubcriptionController(acr.Object);
        //    var data = contr.Subscribe(T1) as OkObjectResult;
        //    Assert.AreNotEqual(data, "successful");

        //}




    }

}

