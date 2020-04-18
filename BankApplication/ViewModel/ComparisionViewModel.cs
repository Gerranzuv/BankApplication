using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace BankApplication.ViewModel
{
    public class ComparisionViewModel
    {
        public string Id { get; set; }

        [Display(Name = "Email")]
        public string Email { get; set; }

        [Display(Name = "ID")]
        public string UserId { get; set; }

        [Display(Name = "PN")]
        public string PN { get; set; }

        [Display(Name = "Fingerprint Image")]
        public string MainImage { get; set; }

        [Display(Name = "Share1 Image")]
        public string Sahre1Image { get; set; }

        [Display(Name = "Share2 Image")]
        public string Sahre2Image { get; set; }
        [Display(Name = "Name")]
        public string Name { get; set; }

        [Display(Name = "First Name")]
        public string FirstName { get; set; }

        [Display(Name = "Last Name")]
        public string LastName { get; set; }

        [Display(Name = "Phone Number")]
        public string PhoneNumber { get; set; }

        [Display(Name = "UserName")]
        public string UserName { get; set; }

        [Display(Name = "Share1 new Image")]
        public string Sahre1NewImage { get; set; }

        [Display(Name = "Share2 New Image")]
        public string Sahre2NewImage { get; set; }

        [Display(Name = "Fingerprint New Image")]
        public string NewMainImage { get; set; }

        public bool share1Matched { get; set; }
        public bool share2Matched { get; set; }

        public bool passwordMatched { get; set; }

        public bool processSuccesfful { get; set; }
    }
}