using DrugApi.Controllers;
using DrugApi.Model;
using DrugApi.Provider;
using DrugApi.Repository;
using Microsoft.AspNetCore.Mvc;
using Moq;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace DrugApi_Test
{
    class UnitTestForControllers
    {
        Drugs d = new Drugs()

        {
            Drug_Id = 1,
            Drug_Name = "Paracetamol",
            Manufacturer = "sai",
            Manufactured_Date = new DateTime(2021, 05, 25),
            Expiry_Date = new DateTime(2022, 05, 25),
            UnitsPackage = 100,
            Cost = 500,
            Quantity = 100

        };

        DrugLocation dl = new DrugLocation();
        [SetUp]
        public void Setup()
        {
            DrugLocation dl = new DrugLocation()
            {
                Drug_Id = 1,
                Drug_Name = "Paracetamol",
                Location_Name = "Hyderabad",
                Available_Stock = 100
            };
        }

        [Test]

        public void TestDrugByIdValid()
        {
            Mock<providerclass> mock = new Mock<providerclass>();
            mock.Setup(p => p.GetdrugDetail(1)).Returns(d);
            DrugController con = new DrugController(mock.Object);
            var data = con.Get(1) as OkObjectResult;
            Assert.AreEqual(200, data.StatusCode);
        }

       [Test]
        public void TestDrugByIdInValid()
        {
            Mock<providerclass> mock = new Mock<providerclass>();
            mock.Setup(p => p.GetdrugDetail(1)).Returns(d);
            DrugController con = new DrugController(mock.Object);
            var data = con.Get(1) as OkObjectResult;
            Assert.AreNotEqual(500, data.StatusCode);
        }


        [Test]
        public void TestDrugByIDandLocationValid()
        {
            var mock = new Mock<providerclass>();
            mock.Setup(p => p.GetDispatchableStocks(1, "Delhi")).Returns(dl);
            DrugController con = new DrugController(mock.Object);
            var data = con.getDrugs(1, "Delhi") as OkObjectResult;
            Assert.AreEqual(200, data.StatusCode);

        }

        [Test]
        public void TestDrugByIDandLocationInValid()
        {
            var mock = new Mock<providerclass>();
            mock.Setup(p => p.GetDispatchableStocks(1, "Delhi")).Returns(dl);
            DrugController con = new DrugController(mock.Object);
            var data = con.getDrugs(1, "Delhi") as OkObjectResult;
            Assert.AreNotEqual(500, data.StatusCode);
        }

    }
}
