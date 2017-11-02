using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace AccesoBolsaTrabajo.Models.Validaciones
{
    public class CorreoVacioAttribute : ValidationAttribute
    {
     

        protected override ValidationResult IsValid(object value, ValidationContext validationContext)
        {
            var correo = (ExternalLoginConfirmationViewModel)validationContext.ObjectInstance;

            if (string.IsNullOrWhiteSpace(correo.Email))
            {
                if (value == null || string.IsNullOrEmpty(value.ToString()))
                {
                    // opss
                    return new ValidationResult(validationContext.DisplayName + "El campo de telenono es requerido XD");
                }
               
            }


               //OK
                return ValidationResult.Success;
        }



    }
}