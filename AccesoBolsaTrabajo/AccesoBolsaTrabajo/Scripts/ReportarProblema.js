

function Reportarproblema() {

    $.ajax({
        dataType: "html",
        url: "/AccesoBolsaTrabajo/Account/ReportarProblema",
        data: {
        },
        success: function (resultado) {
            $("#miCancelar").click();
            $("#Cancelarpartial").html(resultado);
        }
    });
}