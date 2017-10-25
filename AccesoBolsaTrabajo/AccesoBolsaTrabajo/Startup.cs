using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(AccesoBolsaTrabajo.Startup))]
namespace AccesoBolsaTrabajo
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
