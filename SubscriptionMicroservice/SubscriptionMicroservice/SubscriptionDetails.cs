using SubscriptionMicroservice.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SubscriptionMicroservice
{
    public class SubscriptionDetails
    {
        public static List<MemberSubscription> ls = new List<MemberSubscription>()
        {
            new MemberSubscription()
            {
                MemberID = 1,
                SubscriptionDate = Convert.ToDateTime("01/01/2020"),
                PrescriptionID = 1,
                Drug_ID=1,
                SubscriptionId=7,
                RefillOccurrence="weekly",
                Member_Location="Mumbai",
                SubscriptionStatus = true
            },
            new MemberSubscription()
            {
                Drug_ID=2,
                SubscriptionId=8,
                RefillOccurrence="monthly",
                Member_Location="Mumbai",
                SubscriptionStatus = true
            },
            new MemberSubscription()
            {
                Drug_ID=2,
                SubscriptionId=9,
                RefillOccurrence="monthly",
                Member_Location="Nashik",
                SubscriptionStatus = true
            },
            new MemberSubscription()
            {
                Drug_ID=3,
                SubscriptionId=6,
                RefillOccurrence="weekly",
                Member_Location="Chennai",
                SubscriptionStatus = true
            },
            new MemberSubscription()
            {
                Drug_ID=4,
                SubscriptionId=5,
                RefillOccurrence="weekly",
                Member_Location="Chennai",
                SubscriptionStatus = true
            }

        };
        public static List<MemberPrescription> pre = new List<MemberPrescription>()
        {
            new MemberPrescription()
            {
                PrescriptionId = 1,
                drugID=1,
                MemberID=1,
                InsuranceProvider="MediBoddy",
                Insurance_Policy_Number = 1,
                //PrescriptionDate = Convert.ToDateTime("08/23/2020 5:50"),
                dosage = "daily",
                PrescriptionCourse = "TwoWeeks",
                Doctordetails = "MBBS"
            },
            new MemberPrescription()
            {
                PrescriptionId = 2,
                drugID=1,
                MemberID=2,
                InsuranceProvider="MediWell",
                Insurance_Policy_Number = 2,
                //PrescriptionDate = Convert.ToDateTime("01/29/2021 5:50"),
                dosage = "daily",
                PrescriptionCourse = "ThreeWeeks",
                Doctordetails = "MD"

            },
            new MemberPrescription()
            {
                PrescriptionId = 3,
                drugID=2,
                MemberID=3,
                InsuranceProvider="MediBoddy",
                Insurance_Policy_Number = 3,
                //PrescriptionDate = Convert.ToDateTime("12/01/2015 5:50"),
                dosage = "daily",
                PrescriptionCourse = "OneWeeks",
                Doctordetails = "MBBS"

            },
            new MemberPrescription()
            {
                PrescriptionId = 4,
                drugID=2,
                MemberID=4,
                InsuranceProvider="MediWell",
                Insurance_Policy_Number = 4,
                //PrescriptionDate = Convert.ToDateTime("08/12/2015 5:50"),
                dosage = "daily",
                PrescriptionCourse = "ThreeDays",
                Doctordetails = "MBBS"

            },
            new MemberPrescription()
            {
                PrescriptionId = 5,
                drugID=4,
                MemberID=5,
                InsuranceProvider="MediBoddy",
                Insurance_Policy_Number = 5,
               // PrescriptionDate = Convert.ToDateTime("05/29/2020 5:50"),
                dosage = "daily",
                PrescriptionCourse = "FiveDays",
                Doctordetails = "MD"

            }
        };

    }
}
