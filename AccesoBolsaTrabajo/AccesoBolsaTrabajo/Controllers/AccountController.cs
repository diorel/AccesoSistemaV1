using System;
using System.Data;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security;
using AccesoBolsaTrabajo.Models;
using System.Configuration;
using Newtonsoft.Json.Linq;
using Owin.Security.Providers.Orcid.Message;

namespace AccesoBolsaTrabajo.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        public AccountController()
            : this(new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(new ApplicationDbContext())))
        {
        }

        public AccountController(UserManager<ApplicationUser> userManager)
        {
            UserManager = userManager;
        }

        public UserManager<ApplicationUser> UserManager { get; private set; }

        //
        // GET: /Account/Login
        [HttpGet]
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }


        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel model, string returnUrl)
        {
            if (ModelState.IsValid)
            {
                var user = await UserManager.FindAsync(model.Email, model.Password); if (user != null)
                {
                    if (user.EmailConfirmed == true)
                    {
                        await SignInAsync(user, model.RememberMe); return RedirectToLocal(returnUrl);
                    }
                    else
                    {
                        ModelState.AddModelError("", "Confirm Email Address.");
                    }
                }
                else
                {
                    ModelState.AddModelError("", "Invalid username or password.");
                }
            }
            // If we got this far, something failed, redisplay form
            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public ActionResult ForgotPassword(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }




        


        //[AllowAnonymous]
        //[HttpPost]
        //public ActionResult ResetPassword(ResetPasswordModel model)
        //{
        //    string emailAddress = WebSecurity.GetEmail(model.UserName);
        //    if (!string.IsNullOrEmpty(emailAddress))
        //    {
        //        string confirmationToken =
        //            WebSecurity.GeneratePasswordResetToken(model.UserName);
        //        dynamic email = new Email("ChngPasswordEmail");
        //        email.To = emailAddress;
        //        email.UserName = model.UserName;
        //        email.ConfirmationToken = confirmationToken;
        //        email.Send();

        //        return RedirectToAction("ResetPwStepTwo");
        //    }

        //    return RedirectToAction("InvalidUserName");
        //}








        // **************+++login telefono
        //
        // GET: /Account/Login
        [HttpGet]
        [AllowAnonymous]
        public ActionResult LoginTelefono(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }


        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> LoginTelefono(LoginViewModel model, string returnUrl)
        {
            if (ModelState.IsValid)
            {
                var user = await UserManager.FindAsync(model.Email, model.Password); if (user != null)
                {
                    if (user.EmailConfirmed == true)
                    {
                        await SignInAsync(user, model.RememberMe); return RedirectToLocal(returnUrl);
                    }
                    else
                    {
                        ModelState.AddModelError("", "Confirm Email Address.");
                    }
                }
                else
                {
                    ModelState.AddModelError("", "Invalid username or password.");
                }
            }
            // If we got this far, something failed, redisplay form
            return View(model);
        }


        //
        // GET: /Account/Register
        [AllowAnonymous]
        public ActionResult PreguntasFrecuentes()
        {
            return View();
        }


        //
        // GET: /Account/Register
        [HttpGet]
        [AllowAnonymous]
        public ActionResult ReportarProblema()
        {
            //return View();
            return PartialView("_ReportarProblemaPartial");
        }




        // Este método envia la informacion para Autorizar el token rdca19
        [HttpPost]
        public ActionResult ReportarProblema(string Email, string Commentary)
        {
            JObject data = new JObject();
            data["Respuesta"] = true;

            using (DAMSAUserEmail7Entities1 bd = new DAMSAUserEmail7Entities1())
            {
                try
                {
                    var Cosulata = bd.usp_InsertarProblema(Email, Commentary);
                }
                catch
                {
                    data["Respuesta"] = false;
                }
            }
            return RedirectToAction("Index", "Home");
        }
           
    //
    // GET: /Account/Register
    [AllowAnonymous]
    public ActionResult Register()
    {
        return View();
    }

    //
    // POST: /Account/Register +++++++++++++++++++++++++++ aqui se envia la confirmacion del correo
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<ActionResult> Register(RegisterViewModel model)
    {
        if (string.IsNullOrWhiteSpace(model.Email) && string.IsNullOrWhiteSpace(model.PhoneNumber))
        {
            ModelState.AddModelError("", "Nopuedes dejar los dos campos vacios inresa telecono o correo");

        }
        else
        {


            if (ModelState.IsValid)
            {
                //var Correo = from[""];
                //var correo = Convert.ToInt32(model.Email);





                if (string.IsNullOrWhiteSpace(model.Email))
                {
                    var user1 = new ApplicationUser { UserName = model.PhoneNumber, PhoneNumber = model.PhoneNumber };
                    var result1 = await UserManager.CreateAsync(user1, model.Password);
                    if (result1.Succeeded)
                    {

                        // Generar el token y enviarlo
                        //var code = await UserManager.GenerateChangePhoneNumberTokenAsync(User.Identity.GetUserId(), model.PhoneNumber);
                        var code = 5485;
                        if (UserManager.SmsService != null)
                        {
                            var message = new IdentityMessage
                            {
                                Destination = model.PhoneNumber,
                                Body = "Su código de seguridad es: " + code
                            };
                            await UserManager.SmsService.SendAsync(message);
                        }

                        return RedirectToAction("VerifyPhone", "Account");

                        //return RedirectToAction("VerifyPhoneNumber", new { PhoneNumber = model.PhoneNumber });



                        //return RedirectToAction("Confirm", "Account", new { Email = user.Email });
                        //return RedirectToAction("RegistrarNumero", "Account");


                    }


                }
                else
                {

                    var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                    user.Email = model.Email;
                    user.PhoneNumber = model.PhoneNumber;

                    user.EmailConfirmed = true;
                    var result = await UserManager.CreateAsync(user, model.Password);
                    if (result.Succeeded)
                    {
                        System.Net.Mail.MailMessage m = new System.Net.Mail.MailMessage(
                              new System.Net.Mail.MailAddress("diorelx@gamail.com", "DAMSA Registro"),
                              new System.Net.Mail.MailAddress(user.Email));
                        m.Subject = "Confirmación  Email";
                        m.Body = string.Format("Para {0}<BR/>Gracias por su registro, por favor haga clic en el siguiente enlace para completar su registro: <a href=\"{1}\" title=\"User Email Confirm\">{1}</a>", user.UserName, Url.Action("ConfirmEmail", "Account", new { Token = user.Id, Email = user.Email }, Request.Url.Scheme));
                        m.IsBodyHtml = true;
                        System.Net.Mail.SmtpClient smtp = new System.Net.Mail.SmtpClient(ConfigurationManager.AppSettings["SmtpGmail"]);
                        smtp.Credentials = new System.Net.NetworkCredential(ConfigurationManager.AppSettings["UserGmail"], ConfigurationManager.AppSettings["PassGmail"]);
                        //smtp.Credentials = new System.Net.NetworkCredential("diorelx@gmail.com", "diorelyon19");
                        smtp.EnableSsl = true;
                        smtp.Send(m);
                        return RedirectToAction("Confirm", "Account", new { Email = user.Email });
                    }
                    //else
                    //{ 
                    //AddErrors(result);
                    //}
                }
            }
        }
        // If we got this far, something failed, redisplay form
        //return RedirectToAction("VerifyPhoneNumber2", "Account");
        return View(model);

        //return RedirectToAction("AddPhoneNumber", "Account");

    }

    [HttpGet]
    [AllowAnonymous]
    public ActionResult VerifyPhone()
    {
        string code = "5544";
        ViewBag.Code = code;
        return View();
    }



    [HttpPost]
    public ActionResult VerifyPhone(RegisterViewModel model)
    {

        var user = new ApplicationUser { PhoneNumberConfirmed = model.PhoneNumberConfirmed };

        user.PhoneNumberConfirmed = true;

        return RedirectToAction("Index", "Home");

    }


    ////
    //// POST: /Manage/VerifyPhoneNumber
    //[HttpPost]
    //[ValidateAntiForgeryToken]
    //public async Task<ActionResult> VerifyPhone(VerifyPhoneNumberViewModel model)
    //{
    //    if (!ModelState.IsValid)
    //    {
    //        return View(model);
    //    }
    //    var result = await UserManager.ChangePhoneNumberAsync(User.Identity.GetUserId(), model.PhoneNumber, model.Code);
    //    if (result.Succeeded)
    //    {
    //        var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
    //        if (user != null)
    //        {
    //            await SignInAsync(user, isPersistent: false);
    //        }
    //        return RedirectToAction("Index", new { Message = ManageMessageId.AddPhoneSuccess });
    //    }
    //    // If we got this far, something failed, redisplay form
    //    ModelState.AddModelError("", "Failed to verify phone");
    //    return View(model);
    //}




    [AllowAnonymous]
    public ActionResult Confirm(string Email)
    {
        ViewBag.Email = Email;
        return View();
    }
    // GET: /Account/ConfirmEmail
    [AllowAnonymous]
    public async Task<ActionResult> ConfirmEmail(string Token, string Email)
    {
        ApplicationUser user = this.UserManager.FindById(Token);
        if (user != null)
        {
            if (user.Email == Email)
            {
                user.EmailConfirmed = true;
                await UserManager.UpdateAsync(user);
                await SignInAsync(user, isPersistent: false);
                return RedirectToAction("Index", "Home", new { EmailConfirmed = user.Email });
            }
            else
            {
                return RedirectToAction("Confirm", "Account", new { Email = user.Email });
            }
        }
        else
        {
            return RedirectToAction("Confirm", "Account", new { Email = "" });
        }

    }

    //
    // POST: /Account/Disassociate
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<ActionResult> Disassociate(string loginProvider, string providerKey)
    {
        ManageMessageId? message = null;
        IdentityResult result = await UserManager.RemoveLoginAsync(User.Identity.GetUserId(), new UserLoginInfo(loginProvider, providerKey));
        if (result.Succeeded)
        {
            message = ManageMessageId.RemoveLoginSuccess;
        }
        else
        {
            message = ManageMessageId.Error;
        }
        return RedirectToAction("Manage", new { Message = message });
    }

    //
    // GET: /Account/Manage
    public ActionResult Manage(ManageMessageId? message)
    {
        ViewBag.StatusMessage =
            message == ManageMessageId.ChangePasswordSuccess ? "Your password has been changed."
            : message == ManageMessageId.SetPasswordSuccess ? "Your password has been set."
            : message == ManageMessageId.RemoveLoginSuccess ? "The external login was removed."
            : message == ManageMessageId.Error ? "An error has occurred."
            : "";
        ViewBag.HasLocalPassword = HasPassword();
        ViewBag.ReturnUrl = Url.Action("Manage");
        return View();
    }

    //
    // POST: /Account/Manage
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<ActionResult> Manage(ManageUserViewModel model)
    {
        bool hasPassword = HasPassword();
        ViewBag.HasLocalPassword = hasPassword;
        ViewBag.ReturnUrl = Url.Action("Manage");
        if (hasPassword)
        {
            if (ModelState.IsValid)
            {
                IdentityResult result = await UserManager.ChangePasswordAsync(User.Identity.GetUserId(), model.OldPassword, model.NewPassword);
                if (result.Succeeded)
                {
                    return RedirectToAction("Manage", new { Message = ManageMessageId.ChangePasswordSuccess });
                }
                else
                {
                    AddErrors(result);
                }
            }
        }
        else
        {
            // User does not have a password so remove any validation errors caused by a missing OldPassword field
            ModelState state = ModelState["OldPassword"];
            if (state != null)
            {
                state.Errors.Clear();
            }

            if (ModelState.IsValid)
            {
                IdentityResult result = await UserManager.AddPasswordAsync(User.Identity.GetUserId(), model.NewPassword);
                if (result.Succeeded)
                {
                    return RedirectToAction("Manage", new { Message = ManageMessageId.SetPasswordSuccess });
                }
                else
                {
                    AddErrors(result);
                }
            }
        }

        // If we got this far, something failed, redisplay form
        return View(model);
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
        var user = await UserManager.FindAsync(loginInfo.Login);
        if (user != null)
        {
            await SignInAsync(user, isPersistent: false);
            return RedirectToLocal(returnUrl);
        }
        else
        {
            // If the user does not have an account, then prompt the user to create an account RDCA1
            ViewBag.ReturnUrl = returnUrl;
            ViewBag.LoginProvider = loginInfo.Login.LoginProvider;
            ViewBag.EmailUser = loginInfo.Email;
            // aqui se agregara la paete del cogigo de confirmacion externa ************ RDCA2


            return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = loginInfo.Email });

        }
    }

    //
    // POST: /Account/LinkLogin
    [HttpPost]
    [ValidateAntiForgeryToken]
    public ActionResult LinkLogin(string provider)
    {
        // Request a redirect to the external login provider to link a login for the current user
        return new ChallengeResult(provider, Url.Action("LinkLoginCallback", "Account"), User.Identity.GetUserId());
    }

    //
    // GET: /Account/LinkLoginCallback
    public async Task<ActionResult> LinkLoginCallback()
    {
        var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync(XsrfKey, User.Identity.GetUserId());
        if (loginInfo == null)
        {
            return RedirectToAction("Manage", new { Message = ManageMessageId.Error });
        }
        var result = await UserManager.AddLoginAsync(User.Identity.GetUserId(), loginInfo.Login);
        if (result.Succeeded)
        {
            return RedirectToAction("Manage");
        }
        return RedirectToAction("Manage", new { Message = ManageMessageId.Error });
    }

    // ++++++++++++++++++++++++++++++++++++++++++++ aqui se confirma el correo de linquedin 
    // POST: /Account/ExternalLoginConfirmation
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<ActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl)
    {
        if (User.Identity.IsAuthenticated)
        {
            return RedirectToAction("Manage");
        }

        if (ModelState.IsValid)
        {
            // Get the information about the user from the external login provider
            var info = await AuthenticationManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return View("ExternalLoginFailure");
            }
            var user = new ApplicationUser() { UserName = model.Email, Email = model.Email };
            var result = await UserManager.CreateAsync(user);
            if (result.Succeeded)
            {
                result = await UserManager.AddLoginAsync(user.Id, info.Login);
                if (result.Succeeded)
                {
                    await SignInAsync(user, isPersistent: false);
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
        AuthenticationManager.SignOut();
        return RedirectToAction("Index", "Home");
    }

    //
    // GET: /Account/ExternalLoginFailure
    [AllowAnonymous]
    public ActionResult ExternalLoginFailure()
    {
        return View();
    }

    [ChildActionOnly]
    public ActionResult RemoveAccountList()
    {
        var linkedAccounts = UserManager.GetLogins(User.Identity.GetUserId());
        ViewBag.ShowRemoveButton = HasPassword() || linkedAccounts.Count > 1;
        return (ActionResult)PartialView("_RemoveAccountPartial", linkedAccounts);
    }

    //protected override void Dispose(bool disposing)
    //{
    //    if (disposing && UserManager != null)
    //    {
    //        UserManager.Dispose();
    //        UserManager = null;
    //    }
    //    base.Dispose(disposing);
    //}

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

        public object WebSecurity { get; private set; }

        private async Task SignInAsync(ApplicationUser user, bool isPersistent)
    {
        AuthenticationManager.SignOut(DefaultAuthenticationTypes.ExternalCookie);
        var identity = await UserManager.CreateIdentityAsync(user, DefaultAuthenticationTypes.ApplicationCookie);
        AuthenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = isPersistent }, identity);
    }

    private void AddErrors(IdentityResult result)
    {
        foreach (var error in result.Errors)
        {
            ModelState.AddModelError("", error);
        }
    }

    private bool HasPassword()
    {
        var user = UserManager.FindById(User.Identity.GetUserId());
        if (user != null)
        {
            return user.PasswordHash != null;
        }
        return false;
    }

    public enum ManageMessageId
    {
        ChangePasswordSuccess,
        SetPasswordSuccess,
        RemoveLoginSuccess,
        Error,
        AddPhoneSuccess
    }

    private ActionResult RedirectToLocal(string returnUrl)
    {
        if (Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }
        else
        {
            return RedirectToAction("Index", "Home");
        }
    }

    private async Task<string> SendEmailConfirmationTokenAsync(string userID, string subject)
    {
        string code = await UserManager.GenerateEmailConfirmationTokenAsync(userID);
        var callbackUrl = Url.Action("ConfirmEmail", "Account",
           new { userId = userID, code = code }, protocol: Request.Url.Scheme);
        await UserManager.SendEmailAsync(userID, subject,
           "Please confirm your account by clicking <a href=\"" + callbackUrl + "\">here</a>");

        return callbackUrl;
    }



    private class ChallengeResult : HttpUnauthorizedResult
    {
        public ChallengeResult(string provider, string redirectUri) : this(provider, redirectUri, null)
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
            var properties = new AuthenticationProperties() { RedirectUri = RedirectUri };
            if (UserId != null)
            {
                properties.Dictionary[XsrfKey] = UserId;
            }
            context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
        }
    }
    #endregion
}
}