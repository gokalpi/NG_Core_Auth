using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using NG_Core_Auth.Data;
using NG_Core_Auth.Models;
using System.Linq;
using System.Threading.Tasks;

namespace NG_Core_Auth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ProductController : ControllerBase
    {
        private readonly ApplicationDbContext _db;

        public ProductController(ApplicationDbContext db)
        {
            _db = db;
        }

        // GET: api/Product/GetProducts
        [HttpGet("[action]")]
        [Authorize(Policy = "RequireLoggedIn")]
        public IActionResult GetProducts()
        {
            return Ok(_db.Products.ToList());
        }

        // GET: api/Product/GetProduct/5
        [HttpGet("[action]/{id}")]
        [Authorize(Policy = "RequireLoggedIn")]
        public async Task<ActionResult<ProductModel>> GetProduct(int id)
        {
            var model = await _db.Products.FindAsync(id);

            if (model == null)
            {
                return NotFound();
            }

            return model;
        }

        // PUT: api/Product/UpdateProduct/5
        [HttpPut("[action]/{id}")]
        [Authorize(Policy = "RequiredAdministratorRole")]
        public async Task<IActionResult> UpdateProduct(int id, [FromBody] ProductModel model)
        {
            if (id != model.ProductId)
            {
                return BadRequest();
            }

            _db.Entry(model).State = EntityState.Modified;

            try
            {
                await _db.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!ProductExists(id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return Ok(new JsonResult("The Product with id " + id + " is updated"));
        }

        // POST: api/Product/AddProduct
        [HttpPost("[action]")]
        [Authorize(Policy = "RequiredAdministratorRole")]
        public async Task<ActionResult<ProductModel>> AddProduct(ProductModel model)
        {
            _db.Products.Add(model);
            await _db.SaveChangesAsync();

            return CreatedAtAction("GetProduct", new { id = model.ProductId }, model);
        }

        // DELETE: api/Product/DeleteProduct/5
        [HttpPut("[action]/{id}")]
        [Authorize(Policy = "RequiredAdministratorRole")]
        public async Task<ActionResult<ProductModel>> DeleteProduct(int id)
        {
            var productModel = await _db.Products.FindAsync(id);
            if (productModel == null)
            {
                return NotFound();
            }

            _db.Products.Remove(productModel);
            await _db.SaveChangesAsync();

            return Ok(new JsonResult("The Product with id " + id + " is deleted"));
        }

        private bool ProductExists(int id)
        {
            return _db.Products.Any(e => e.ProductId == id);
        }
    }
}