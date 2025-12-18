using Biblioteca.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace BaseSystem.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class CatalogoController : ControllerBase
    {
        private readonly GeneralServices _GeneralServices;

        public CatalogoController(GeneralServices generalServices)
        {
            _GeneralServices = generalServices;
        }

        [Authorize(Roles = "Propietario,Visitante")] // Ambos roles pueden ejecutar este endpoint
        [HttpGet("ObtenerCatalogos")]
        public async Task<IActionResult> GetProductos(string data)
        {
            string? emailFromToken = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(emailFromToken))
            {
                return Unauthorized("No hay email en el token"); // No hay email en el token
            }

            // Verificar el rol real del usuario en la base de datos
            var rolReal = await _GeneralServices.ObtenerData("uspObtenerRoleFromTokenCsv", emailFromToken);
            if (rolReal == null)
            {
                return Unauthorized(); // Usuario no encontrado 401
            }

            // Validar que el rol sea uno de los permitidos
            if (rolReal != "Propietario" && rolReal != "Visitante")
            {
                return Forbid(); // Acceso denegado 403
            }

            var response = await _GeneralServices.ObtenerData("uspGetCatalogosCsv", data);
            if (response == null)
                return NotFound(); // 404

            return Ok(response); // 200
        }

        [Authorize(Roles = "Propietario")] // Ambos roles pueden ejecutar este endpoint
        [HttpGet("CreateCatalogos")]
        public async Task<IActionResult> CreateCatalogo(string data)
        {
            string? emailFromToken = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(emailFromToken))
            {
                return Unauthorized("No hay email en el token"); // No hay email en el token
            }

            // Verificar el rol real del usuario en la base de datos
            var rolReal = await _GeneralServices.ObtenerData("uspObtenerRoleFromTokenCsv", emailFromToken);
            if (rolReal == null)
            {
                return Unauthorized(); // Usuario no encontrado 401
            }

            // Validar que el rol sea uno de los permitidos
            if (rolReal != "Propietario")
            {
                return Forbid(); // Acceso denegado 403
            }

            var response = await _GeneralServices.ObtenerData("uspCreateCatalogoCsv", data);
            if (response == null)
                return NotFound(); // 404

            return Ok(response); // 200
        }


        [Authorize(Roles = "Propietario")] // Ambos roles pueden ejecutar este endpoint
        [HttpGet("DeleteCatalogos")]
        public async Task<IActionResult> DeleteCatalogo(string data)
        {
            string? emailFromToken = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(emailFromToken))
            {
                return Unauthorized("No hay email en el token"); // No hay email en el token
            }

            // Verificar el rol real del usuario en la base de datos
            var rolReal = await _GeneralServices.ObtenerData("uspObtenerRoleFromTokenCsv", emailFromToken);
            if (rolReal == null)
            {
                return Unauthorized(); // Usuario no encontrado 401
            }

            // Validar que el rol sea uno de los permitidos
            if (rolReal != "Propietario")
            {
                return Forbid(); // Acceso denegado 403
            }

            var response = await _GeneralServices.ObtenerData("uspDeleteCatalogoCsv", data);
            if (response == null)
                return NotFound(); // 404

            return Ok(response); // 200
        }




    }
}
