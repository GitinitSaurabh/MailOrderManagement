using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace DrugApi.Model
{
    public class Drugs
    {


        //Drug_ID | Output: Drug Details like ID, Name,

        //Manufacturer, Manufactured Date, Expiry Date, Quantity available across loc.etc..)
      //  [Required]
        public int Drug_Id { get; set; }

        public string Drug_Name { get; set; }
        public string Manufacturer { get; set; }
        public DateTime Manufactured_Date { get; set; }
        public DateTime Expiry_Date { get; set; }
        public int UnitsPackage { get; set; }
        public int Cost { get; set; }
        public int Quantity { get; set; }
        public string Location_Name { get; set; }



    }
}
