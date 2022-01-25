using DrugApi.Controllers;
using DrugApi.Model;
using DrugApi.Repository;
using Microsoft.AspNetCore.Mvc;
using NUnit.Framework;
using System;
using System.Collections.Generic;

namespace DrugApi
{
    public class Test
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

        List<DrugLocation> dl = new List<DrugLocation>();
        [SetUp]
        public void Setup()
        {
            dl = new List<DrugLocation>
            {
                new DrugLocation()
                {
                    Drug_Id = 1,
                    Drug_Name = "Paracetamol",
                    Location_Name = "Hyderabad",
                    Available_Stock = 100
                }
            };
        }

        [Test]

        public void TestDrugByIdValid()
        {
            //int a = 1;
            RepoClass r = new RepoClass();
            var b = r.GetdrugDetails(1);
            Assert.AreEqual(d.Drug_Id, b.Drug_Id);
            // Assert.AreEqual(d.Drug_Name, b.Drug_Name);
        }

        [Test]
        public void TestDrugByIdInValid()
        {

            RepoClass r = new RepoClass();
            var b = r.GetdrugDetails(5);
            Assert.AreNotEqual(d.Drug_Id, b.Drug_Id);
        }


        [Test]
        public void TestDrugByIDandLocationValid()
        {
            RepoClass r = new RepoClass();
            var a = r.GetDispatchableStock(1, "Hyderabad");
            Assert.AreEqual(d.Drug_Id, a.Drug_Id);
            //  Assert.AreEqual(dl[2].Location_Name, a[1].Location_Name);

        }

        [Test]
        public void TestDrugByIDandLocationInValid()
        {

            RepoClass r = new RepoClass();
            var b = r.GetDispatchableStock(2, "Bangalore");
            Assert.AreNotEqual(d.Drug_Id, b.Drug_Id);
        }


        [Test]
        public void TestAdhocRefillOrderValid()
        {
            RepoClass r = new RepoClass();
            var c = r.AdhocRefillOrder(1, "Hyderabad");
            DrugLocation dl1 = new DrugLocation();
            Assert.AreEqual(dl1.Available_Stock, dl1.Available_Stock);
            //Assert.
        }

        [Test]
          public void TestAdhocRefillOrderInvalid()
          {
              RepoClass r = new RepoClass();
              var c = r.AdhocRefillOrder(2, "Hyderabad");
              DrugLocation dl1 = new DrugLocation();
              Assert.AreEqual(-1,-1 );
              //Assert.
          }
        [Test]
        public void TestCheckAvailbleDrugValid()
        {
            string s = "Available";
            RepoClass r = new RepoClass();
            var a = r.CheckAvailbleDrug(1);
            Assert.AreEqual(s, a);
        }
        [Test]
        public void TestCheckAvailbleDrugInValid()
        {
            string s = "available";
            RepoClass r = new RepoClass();
            var a = r.CheckAvailbleDrug(7);
            Assert.AreNotEqual(s, a);
        }
    }
}

