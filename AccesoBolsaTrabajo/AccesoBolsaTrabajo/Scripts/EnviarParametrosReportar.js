function GuardarProblema() {

    alert("entro a la funcion del boton");
    //document.getElementById("btn").disabled = true;

    var Email = $("#email").val();
    var Commentary = $("#commentary").val();

    $.ajax({
        type: "POST",
        url: "/AccesoBolsaTrabajo/Account/ReportarProblema",
        dataType: "json",
        data: {
            Email: Email,
            Commentary: Commentary,
        },
        success: function (resultado) {
            alert("entro a la funcion del boton2");

            if (resultado == "") {
                //$("#Alerta").css("display","visible");

                alert("red");
            }

            $("#ContenedorToken").text(resultado);
        }, error: function (e) { alert(e) }
    });
}
