using Biblioteca.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace BaseSystem.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ProductosController : ControllerBase
    {
        private readonly GeneralServices _GeneralServices;

        public ProductosController(GeneralServices generalServices)
        {
            _GeneralServices = generalServices;
        }

        [Authorize(Roles = "Propietario,Visitante")] // Ambos roles pueden ejecutar este endpoint
        [HttpGet("ObtenerProductos")]
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

            var response = await _GeneralServices.ObtenerData("uspGetProductosCsv", data);
            if (response == null)
                return NotFound(); // 404

            return Ok(response); // 200
        }

        [Authorize(Roles = "Propietario")] // Ambos roles pueden ejecutar este endpoint
        [HttpGet("CreateProductos")]
        public async Task<IActionResult> CreateProductos(string data)
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

            var response = await _GeneralServices.ObtenerData("uspCreateProductoCsv", data);
            if (response == null)
                return NotFound(); // 404

            return Ok(response); // 200
        }

        [Authorize(Roles = "Propietario")] // Ambos roles pueden ejecutar este endpoint
        [HttpGet("DeleteProductos")]
        public async Task<IActionResult> DeleteProductos(string data)
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

            var response = await _GeneralServices.ObtenerData("uspDeleteProductoCsv", data);
            if (response == null)
                return NotFound(); // 404

            return Ok(response); // 200
        }

    }
}
