using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Mvc;
using AccesoBolsaTrabajo.Models;

namespace AccesoBolsaTrabajo.Views.Account
{
    public class ReportarProblemasController : Controller
    {
        private DAMSAUserEmail7Entities1 db = new DAMSAUserEmail7Entities1();

        // GET: ReportarProblemas
        public ActionResult Index()
        {
            return View(db.ReportarProblema.ToList());
        }

        // GET: ReportarProblemas/Details/5
        public ActionResult Details(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            ReportarProblema reportarProblema = db.ReportarProblema.Find(id);
            if (reportarProblema == null)
            {
                return HttpNotFound();
            }
            return View(reportarProblema);
        }

        // GET: ReportarProblemas/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: ReportarProblemas/Create
        // Para protegerse de ataques de publicación excesiva, habilite las propiedades específicas a las que desea enlazarse. Para obtener 
        // más información vea http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create([Bind(Include = "IdReportarProblema,CorreoTelefono,Descripcion")] ReportarProblema reportarProblema)
        {
            if (ModelState.IsValid)
            {
                db.ReportarProblema.Add(reportarProblema);
                db.SaveChanges();
                return RedirectToAction("Index");
            }

            return View(reportarProblema);
        }

        // GET: ReportarProblemas/Edit/5
        public ActionResult Edit(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            ReportarProblema reportarProblema = db.ReportarProblema.Find(id);
            if (reportarProblema == null)
            {
                return HttpNotFound();
            }
            return View(reportarProblema);
        }

        // POST: ReportarProblemas/Edit/5
        // Para protegerse de ataques de publicación excesiva, habilite las propiedades específicas a las que desea enlazarse. Para obtener 
        // más información vea http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit([Bind(Include = "IdReportarProblema,CorreoTelefono,Descripcion")] ReportarProblema reportarProblema)
        {
            if (ModelState.IsValid)
            {
                db.Entry(reportarProblema).State = EntityState.Modified;
                db.SaveChanges();
                return RedirectToAction("Index");
            }
            return View(reportarProblema);
        }

        // GET: ReportarProblemas/Delete/5
        public ActionResult Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            ReportarProblema reportarProblema = db.ReportarProblema.Find(id);
            if (reportarProblema == null)
            {
                return HttpNotFound();
            }
            return View(reportarProblema);
        }

        // POST: ReportarProblemas/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public ActionResult DeleteConfirmed(int id)
        {
            ReportarProblema reportarProblema = db.ReportarProblema.Find(id);
            db.ReportarProblema.Remove(reportarProblema);
            db.SaveChanges();
            return RedirectToAction("Index");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
