using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace AccesoBolsaTrabajo.Controllers
{
    public class ReportarController : Controller
    {
        // GET: Reportar
        public ActionResult Index()
        {
            return View();
        }

        // GET: Reportar/Details/5
        public ActionResult Details(int id)
        {
            return View();
        }

        // GET: Reportar/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: Reportar/Create
        [HttpPost]
        public ActionResult Create(FormCollection collection)
        {
            try
            {
                // TODO: Add insert logic here

                return RedirectToAction("Index");
            }
            catch
            {
                return View();
            }
        }

        // GET: Reportar/Edit/5
        public ActionResult Edit(int id)
        {
            return View();
        }

        // POST: Reportar/Edit/5
        [HttpPost]
        public ActionResult Edit(int id, FormCollection collection)
        {
            try
            {
                // TODO: Add update logic here

                return RedirectToAction("Index");
            }
            catch
            {
                return View();
            }
        }

        // GET: Reportar/Delete/5
        public ActionResult Delete(int id)
        {
            return View();
        }

        // POST: Reportar/Delete/5
        [HttpPost]
        public ActionResult Delete(int id, FormCollection collection)
        {
            try
            {
                // TODO: Add delete logic here

                return RedirectToAction("Index");
            }
            catch
            {
                return View();
            }
        }
    }
}
