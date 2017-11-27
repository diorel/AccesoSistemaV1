using AccesoBolsaTrabajo.Models;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace AccesoBolsaTrabajo.Controllers
{
    public class HomeController : Controller
    {
        // GET: Home
        [HttpGet]
        public ActionResult Cargar()
        {
            return View();
        }

        //Este método carga los detalles  del token
        [HttpPost]
        public ActionResult Cargar(string Email, string Commentary)
        {
            JObject data = new JObject();
            data["Respuesta"] = true;

            using (DAMSAUserEmail7Entities1 bd = new DAMSAUserEmail7Entities1())
            {
                try
                {
                    var Cosulata = bd.usp_InsertarProblema(Email, Commentary);
                    ViewBag.Message = "error message";

                }
                catch
                {
                    data["Respuesta"] = false;
                }
            }
            return RedirectToAction("PreguntasFrecuentes", "Account");

        }

    }
}