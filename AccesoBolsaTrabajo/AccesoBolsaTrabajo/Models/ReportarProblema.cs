//------------------------------------------------------------------------------
// <auto-generated>
//     Este código se generó a partir de una plantilla.
//
//     Los cambios manuales en este archivo pueden causar un comportamiento inesperado de la aplicación.
//     Los cambios manuales en este archivo se sobrescribirán si se regenera el código.
// </auto-generated>
//------------------------------------------------------------------------------

namespace AccesoBolsaTrabajo.Models
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;

    public partial class ReportarProblema
    {
        public int IdReportarProblema { get; set; }

        [Required]
        [EmailAddress]
        public string CorreoTelefono { get; set; }
        [Required]
        public string Descripcion { get; set; }
    }
}