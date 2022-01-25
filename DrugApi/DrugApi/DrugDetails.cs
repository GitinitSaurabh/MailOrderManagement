using DrugApi.Model;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DrugApi
{
    public class DrugDetails
    {
        public static List<Drugs> Drugs = new List<Drugs>()
        {
            new Drugs()
            {
                Drug_Id = 1,
                Drug_Name = "Paracetimol",
                Manufacturer = "Sai",
                Manufactured_Date = Convert.ToDateTime("03/08/2020"),
                Expiry_Date = Convert.ToDateTime("03/08/2022"),
                Cost = 200,
                UnitsPackage = 10,
                Quantity = 1000
            },
            new Drugs()
            {
                Drug_Id = 2,
                Drug_Name = "Asprin",
                Manufacturer = "Kumar",
                Manufactured_Date = Convert.ToDateTime("03/08/2020"),
                Expiry_Date = Convert.ToDateTime("03/08/2022"),
                Cost = 400,
                UnitsPackage = 25,
                Quantity = 500,
            },
            new Drugs()
            {
                Drug_Id = 3,
                Drug_Name = "Narco",
                Manufacturer = "Shiva",
                Manufactured_Date = Convert.ToDateTime("12/04/2020"),
                Expiry_Date = Convert.ToDateTime("12/04/2022"),
                Cost = 100,
                UnitsPackage = 10,
                Quantity = 500
            },
            new Drugs()
            {
                Drug_Id = 4,
                Drug_Name = "Dolo650",
                Manufacturer = "Raj",
                Manufactured_Date = Convert.ToDateTime("08/07/2020"),
                Expiry_Date = Convert.ToDateTime("08/07/2022"),
                Cost = 300,
                UnitsPackage = 30,
                Quantity = 2000
            },
            new Drugs()
            {
                Drug_Id = 5,
                Drug_Name = "Lipitor",
                Manufacturer = "Kumble",
                Manufactured_Date = Convert.ToDateTime("10/12/2020"),
                Expiry_Date = Convert.ToDateTime("10/12/2022"),
                Cost = 150,
                UnitsPackage = 5,
                Quantity = 200
            }
        };


        public static List<DrugLocation> DrugLocations = new List<DrugLocation>()
        {
            new DrugLocation()
            {
                Drug_Id = 1,
                Drug_Name = "Paracetimol",
                Available_Stock = 500,
                Location_Name = "hyderabad"
            },
           new DrugLocation()
            {
                Drug_Id = 2,
                Drug_Name = "Asprin",
                Available_Stock = 500,
                Location_Name = "mumbai"
            },
           new DrugLocation()
            {
                Drug_Id = 3,
                Drug_Name = "Narco",
                Available_Stock = 0,
                Location_Name = "chennai"
            },
           new DrugLocation()
            {
                Drug_Id = 4,
                Drug_Name = "Dolo650",
                Available_Stock = 100,
                Location_Name = "mumbai"
            },
           new DrugLocation()
            {
                Drug_Id = 5,
                Drug_Name = "Lipitor",
                Available_Stock = 400,
                Location_Name = "punjab"
            },
          
        };
    }
}