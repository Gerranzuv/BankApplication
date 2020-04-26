using System;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using BankApplication.Models;
using System.IO;
using BankApplication.Extra;
using Microsoft.AspNet.Identity.EntityFramework;
using BankApplication.ViewModel;

namespace BankApplication.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private ApplicationSignInManager _signInManager;
        private ApplicationUserManager _userManager;
        private ApplicationDbContext db = new ApplicationDbContext();
        public AccountController()
        {
        }

        public AccountController(ApplicationUserManager userManager, ApplicationSignInManager signInManager )
        {
            UserManager = userManager;
            SignInManager = signInManager;
        }

        public ApplicationSignInManager SignInManager
        {
            get
            {
                return _signInManager ?? HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            }
            private set 
            { 
                _signInManager = value; 
            }
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        //
        // GET: /Account/Login
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        [AllowAnonymous]
        public ActionResult AdminLogin(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel model, string returnUrl, HttpPostedFileBase upload)
        {
            if (upload == null)
            {
                TempData["errMessage"] = "Please upload fingerprint photo!";
                return View(model);
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }
            Random random = new Random();
            String stamp =  random.Next(1000).ToString();

            //Save the uploaded photo in temp folder
            string path = Path.Combine(Server.MapPath("~/Temp"), stamp + upload.FileName);
            upload.SaveAs(path);
            
            //Generate the two shares
            VisualCryptographyLibrary.processing(path, "Temp/" + stamp);
            
            ComparisionViewModel res = new ComparisionViewModel();
            res.Sahre1NewImage = stamp + VisualCryptographyLibrary.SHARE_1_NAME;
            res.Sahre2NewImage = stamp + VisualCryptographyLibrary.SHARE_2_NAME;
            res.TempShare1 = stamp + VisualCryptographyLibrary.TEMP_SHARE_1_NAME;
            res.TempShare2 = stamp + VisualCryptographyLibrary.TEMP_SHARE_2_NAME;
            var result = await SignInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, shouldLockout: false);
            if (result.Equals(SignInStatus.Success)) {
                res.passwordMatched = true;
                //var userManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(new ApplicationDbContext()));

                var user = db.Users.Where(a => a.Email.Equals(model.Email)).FirstOrDefault();
                res.Sahre1Image = user.Sahre1Image;
                res.Sahre2Image = user.Sahre2Image;
                
                res.share1Matched = VisualCryptographyLibrary.comparTwoPhotos(user.Sahre1Image, res.Sahre1NewImage);
                res.share2Matched = VisualCryptographyLibrary.comparTwoPhotos(user.Sahre2Image, res.Sahre2NewImage);
                res.processSuccesfful = res.share1Matched&&res.share1Matched&&res.passwordMatched;
                res.Sahre1Image = user.TempShare1;
                res.Sahre2Image = user.TempShare2;
                if (!res.processSuccesfful)
                {
                    AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
                }
            }
            else {
                res.passwordMatched = false;
                res.Sahre1Image = "Dummy.png";
                res.Sahre2Image = "Dummy.png";
                res.share1Matched = false;
                res.share2Matched = false;
                res.processSuccesfful = false;
            }
            TempData["campare"] = res;
            return RedirectToAction("Comparision");

        }

        //
        // GET: /Account/Comparision
        [AllowAnonymous]
        public ActionResult Comparision(ComparisionViewModel model)
        {
            ComparisionViewModel temp =(ComparisionViewModel) TempData["campare"];
            return View(temp);
        }


        // POST: /Account/AdminLogin
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> AdminLogin(LoginViewModel model, string returnUrl)
        {
            

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var result = await SignInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, shouldLockout: false);
            

            if (result.Equals(SignInStatus.Success)) {
                var user = db.Users.Where(a => a.Email.Equals(model.Email)).FirstOrDefault();
                var userManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(new ApplicationDbContext()));
                if (!userManager.IsInRole(user.Id,"Admin"))
                {
                    ModelState.AddModelError("", "This page is only for admins!");
                    AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
                    return View(model);
                }
                return RedirectToAction("UserList");
            }
            else
            {
                ModelState.AddModelError("", "Invalid login attempt.");
                return View(model);
            }


            
        }
        //
        // GET: /Account/VerifyCode
        [AllowAnonymous]
        public async Task<ActionResult> VerifyCode(string provider, string returnUrl, bool rememberMe)
        {
            // Require that the user has already logged in via username/password or external login
            if (!await SignInManager.HasBeenVerifiedAsync())
            {
                return View("Error");
            }
            return View(new VerifyCodeViewModel { Provider = provider, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/VerifyCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyCode(VerifyCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // The following code protects for brute force attacks against the two factor codes. 
            // If a user enters incorrect codes for a specified amount of time then the user account 
            // will be locked out for a specified amount of time. 
            // You can configure the account lockout settings in IdentityConfig
            var result = await SignInManager.TwoFactorSignInAsync(model.Provider, model.Code, isPersistent:  model.RememberMe, rememberBrowser: model.RememberBrowser);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(model.ReturnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Invalid code.");
                    return View(model);
            }
        }

        //
        // GET: /Account/Register
        [AllowAnonymous]
        public ActionResult Register()
        {
            return View();
        }

        //
        // POST: /Account/Register
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(RegisterViewModel model, HttpPostedFileBase upload)
        {
            if (upload == null)
            {
                TempData["errMessage"] = "Please upload fingerprint photo!";
                return View(model);
            }
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser {  Email = model.Email };
                user.UserId = model.UserId;
                user.FirstName = model.FirstName;
                user.Email = model.Email;
                user.LastName = model.LastName;
                user.UserName = model.UserName;
                user.PhoneNumber = model.PhoneNumber;
                Random random = new Random();
                String stamp = random.Next(1000).ToString();
                string path = Path.Combine(Server.MapPath("~/Images"),stamp+ model.PhoneNumber+upload.FileName.Substring(upload.FileName.Length-4));
                upload.SaveAs(path);
                user.MainImage = stamp+model.PhoneNumber+ upload.FileName.Substring(upload.FileName.Length - 4);
                
                VisualCryptographyLibrary.processing(path, "Images/"+ stamp);
                user.Sahre1Image = stamp + VisualCryptographyLibrary.SHARE_1_NAME;
                user.Sahre2Image = stamp + VisualCryptographyLibrary.SHARE_2_NAME;
                user.TempShare1 = stamp + VisualCryptographyLibrary.TEMP_SHARE_1_NAME;
                user.TempShare2 = stamp + VisualCryptographyLibrary.TEMP_SHARE_2_NAME;
                var result = await UserManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    await SignInManager.SignInAsync(user, isPersistent:false, rememberBrowser:false);

                    // For more information on how to enable account confirmation and password reset please visit https://go.microsoft.com/fwlink/?LinkID=320771
                    // Send an email with this link
                    // string code = await UserManager.GenerateEmailConfirmationTokenAsync(user.Id);
                    // var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
                    // await UserManager.SendEmailAsync(user.Id, "Confirm your account", "Please confirm your account by clicking <a href=\"" + callbackUrl + "\">here</a>");

                    //return RedirectToAction("Index", "Home");
                    return RedirectToAction("Profile");
                }
                AddErrors(result);
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/CreateNewUser
        [Authorize(Roles ="Admin")]
        public ActionResult CreateNewUser()
        {
            return View();
        }


        // POST: /Account/CreateNewUser
        [HttpPost]
        [Authorize(Roles = "Admin")]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> CreateNewUser(RegisterViewModel model, HttpPostedFileBase upload)
        {
            if (upload == null)
            {
                TempData["errMessage"] = "Please upload fingerprint photo!";
                return View(model);
            }
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { Email = model.Email };
                user.UserId = model.UserId;
                user.FirstName = model.FirstName;
                user.Email = model.Email;
                user.LastName = model.LastName;
                user.UserName = model.UserName;
                user.PhoneNumber = model.PhoneNumber;
                Random random = new Random();
                String stamp = random.Next(1000).ToString();
                string path = Path.Combine(Server.MapPath("~/Images"), stamp + model.PhoneNumber + upload.FileName.Substring(upload.FileName.Length - 4));
                upload.SaveAs(path);
                user.MainImage = stamp + model.PhoneNumber + upload.FileName.Substring(upload.FileName.Length - 4);

                VisualCryptographyLibrary.processing(path, "Images/" + stamp);
                user.Sahre1Image = stamp + VisualCryptographyLibrary.SHARE_1_NAME;
                user.Sahre2Image = stamp + VisualCryptographyLibrary.SHARE_2_NAME;
                user.TempShare1 = stamp + VisualCryptographyLibrary.TEMP_SHARE_1_NAME;
                user.TempShare2 = stamp + VisualCryptographyLibrary.TEMP_SHARE_2_NAME;
                var result = await UserManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    //await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);

                    // For more information on how to enable account confirmation and password reset please visit https://go.microsoft.com/fwlink/?LinkID=320771
                    // Send an email with this link
                    // string code = await UserManager.GenerateEmailConfirmationTokenAsync(user.Id);
                    // var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
                    // await UserManager.SendEmailAsync(user.Id, "Confirm your account", "Please confirm your account by clicking <a href=\"" + callbackUrl + "\">here</a>");

                    //return RedirectToAction("Index", "Home");
                    return RedirectToAction("Profile",new { id=user.Id});
                }
                AddErrors(result);
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/ConfirmEmail
        [AllowAnonymous]
        public async Task<ActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return View("Error");
            }
            var result = await UserManager.ConfirmEmailAsync(userId, code);
            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }

        //
        // GET: /Account/ForgotPassword
        [AllowAnonymous]
        public ActionResult ForgotPassword()
        {
            return View();
        }

        //
        // POST: /Account/ForgotPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await UserManager.FindByNameAsync(model.Email);
                if (user == null || !(await UserManager.IsEmailConfirmedAsync(user.Id)))
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    return View("ForgotPasswordConfirmation");
                }

                // For more information on how to enable account confirmation and password reset please visit https://go.microsoft.com/fwlink/?LinkID=320771
                // Send an email with this link
                // string code = await UserManager.GeneratePasswordResetTokenAsync(user.Id);
                // var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);		
                // await UserManager.SendEmailAsync(user.Id, "Reset Password", "Please reset your password by clicking <a href=\"" + callbackUrl + "\">here</a>");
                // return RedirectToAction("ForgotPasswordConfirmation", "Account");
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/ForgotPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        //
        // GET: /Account/ResetPassword
        [AllowAnonymous]
        public ActionResult ResetPassword(string code)
        {
            return code == null ? View("Error") : View();
        }

        //
        // POST: /Account/ResetPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await UserManager.FindByNameAsync(model.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            var result = await UserManager.ResetPasswordAsync(user.Id, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            AddErrors(result);
            return View();
        }

        //
        // GET: /Account/ResetPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        //
        // POST: /Account/ExternalLogin
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider, string returnUrl)
        {
            // Request a redirect to the external login provider
            return new ChallengeResult(provider, Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl }));
        }

        //
        // GET: /Account/SendCode
        [AllowAnonymous]
        public async Task<ActionResult> SendCode(string returnUrl, bool rememberMe)
        {
            var userId = await SignInManager.GetVerifiedUserIdAsync();
            if (userId == null)
            {
                return View("Error");
            }
            var userFactors = await UserManager.GetValidTwoFactorProvidersAsync(userId);
            var factorOptions = userFactors.Select(purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();
            return View(new SendCodeViewModel { Providers = factorOptions, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/SendCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SendCode(SendCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            // Generate the token and send it
            if (!await SignInManager.SendTwoFactorCodeAsync(model.SelectedProvider))
            {
                return View("Error");
            }
            return RedirectToAction("VerifyCode", new { Provider = model.SelectedProvider, ReturnUrl = model.ReturnUrl, RememberMe = model.RememberMe });
        }

        //
        // GET: /Account/ExternalLoginCallback
        [AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();
            if (loginInfo == null)
            {
                return RedirectToAction("Login");
            }

            // Sign in the user with this external login provider if the user already has a login
            var result = await SignInManager.ExternalSignInAsync(loginInfo, isPersistent: false);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(returnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.RequiresVerification:
                    return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = false });
                case SignInStatus.Failure:
                default:
                    // If the user does not have an account, then prompt the user to create an account
                    ViewBag.ReturnUrl = returnUrl;
                    ViewBag.LoginProvider = loginInfo.Login.LoginProvider;
                    return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = loginInfo.Email });
            }
        }

        //
        // POST: /Account/ExternalLoginConfirmation
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl)
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Manage");
            }

            if (ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await AuthenticationManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return View("ExternalLoginFailure");
                }
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await UserManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await UserManager.AddLoginAsync(user.Id, info.Login);
                    if (result.Succeeded)
                    {
                        await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                        return RedirectToLocal(returnUrl);
                    }
                }
                AddErrors(result);
            }

            ViewBag.ReturnUrl = returnUrl;
            return View(model);
        }

        //
        // POST: /Account/LogOff
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            return RedirectToAction("Index", "Home");
        }

        //
        // GET: /Account/ExternalLoginFailure
        [AllowAnonymous]
        public ActionResult ExternalLoginFailure()
        {
            return View();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_userManager != null)
                {
                    _userManager.Dispose();
                    _userManager = null;
                }

                if (_signInManager != null)
                {
                    _signInManager.Dispose();
                    _signInManager = null;
                }
            }


            
            base.Dispose(disposing);
        }
        public ActionResult UserList()
        {
            var users = db.Users.OrderBy(a=>a.FirstName).ToList();
            return View(users);
        }

        #region Helpers
        // Used for XSRF protection when adding external logins
        private const string XsrfKey = "XsrfId";

        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        internal class ChallengeResult : HttpUnauthorizedResult
        {
            public ChallengeResult(string provider, string redirectUri)
                : this(provider, redirectUri, null)
            {
            }

            public ChallengeResult(string provider, string redirectUri, string userId)
            {
                LoginProvider = provider;
                RedirectUri = redirectUri;
                UserId = userId;
            }

            public string LoginProvider { get; set; }
            public string RedirectUri { get; set; }
            public string UserId { get; set; }

            public override void ExecuteResult(ControllerContext context)
            {
                var properties = new AuthenticationProperties { RedirectUri = RedirectUri };
                if (UserId != null)
                {
                    properties.Dictionary[XsrfKey] = UserId;
                }
                context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
            }
        }
        #endregion

        public ActionResult Profile( string id="")
        {
            string userId;
            if (id.Equals(""))
                userId = User.Identity.GetUserId();
            else
                userId = id;
            ApplicationUser user = db.Users.Find(userId);
            var model = new UserViewModel
            {
                Id = user.Id,
                UserId = user.UserId,
                Email = user.Email,
                MainImage = user.MainImage,
                Sahre1Image = user.TempShare1,
                Sahre2Image = user.TempShare2,
                PN = user.PN,
                Name = user.UserName,
                FirstName = user.FirstName,
                LastName=user.LastName,
                PhoneNumber=user.PhoneNumber,
                UserName=user.UserName

            };
            return View(model);
        }

        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login2(LoginViewModel model, string returnUrl, HttpPostedFileBase upload)
        {
            if (upload == null)
            {
                TempData["errMessage"] = "Please upload fingerprint photo!";
                return View(model);
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }
            Random random = new Random();
            String stamp = random.Next(1000).ToString();

            //Save the uploaded photo in temp folder
            string path = Path.Combine(Server.MapPath("~/Temp"), stamp + upload.FileName);
            upload.SaveAs(path);

            //Generate the two shares
            VisualCryptographyLibrary.processing(path, "Temp/" + stamp);

            ComparisionViewModel res = new ComparisionViewModel();
            res.Sahre1NewImage = stamp + VisualCryptographyLibrary.SHARE_1_NAME;
            res.Sahre2NewImage = stamp + VisualCryptographyLibrary.SHARE_2_NAME;
            res.TempShare1 = stamp + VisualCryptographyLibrary.TEMP_SHARE_1_NAME;
            res.TempShare2 = stamp + VisualCryptographyLibrary.TEMP_SHARE_2_NAME;
            VisualCryptographyLibrary.saveFinalImage();
            var result = await SignInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, shouldLockout: false);
            if (result.Equals(SignInStatus.Success))
            {
                res.passwordMatched = true;
                //var userManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(new ApplicationDbContext()));

                var user = db.Users.Where(a => a.Email.Equals(model.Email)).FirstOrDefault();
                res.Sahre1Image = user.Sahre1Image;
                res.Sahre2Image = user.Sahre2Image;

                res.share1Matched = VisualCryptographyLibrary.comparTwoPhotos(user.Sahre1Image, res.Sahre1NewImage);
                res.share2Matched = VisualCryptographyLibrary.comparTwoPhotos(user.Sahre2Image, res.Sahre2NewImage);
                res.processSuccesfful = res.share1Matched && res.share1Matched && res.passwordMatched;
                res.Sahre1Image = user.TempShare1;
                res.Sahre2Image = user.TempShare2;
                if (!res.processSuccesfful)
                {
                    AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
                }
            }
            else
            {
                res.passwordMatched = false;
                res.Sahre1Image = "Dummy.png";
                res.Sahre2Image = "Dummy.png";
                res.share1Matched = false;
                res.share2Matched = false;
                res.processSuccesfful = false;
            }
            TempData["campare"] = res;
            return RedirectToAction("Comparision");

        }

        //
        // GET: /Account/Login
        [AllowAnonymous]
        public ActionResult Login2(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }
    }
}