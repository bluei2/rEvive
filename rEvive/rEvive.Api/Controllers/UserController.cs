using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using rEvive.Api.Models;

namespace rEvive.Api
{
    [ApiController]
    [Route("[controller]")]
    public class UserController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ILogger<UserController> _logger;

        public UserController(UserManager<IdentityUser> userManager, 
            SignInManager<IdentityUser> signInManager, 
            ILogger<UserController> logger){
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> RegisterAsync(UserModel model){
            if (ModelState.IsValid){
                var user = new IdentityUser{
                    UserName = model.Email, Email = model.Email, EmailConfirmed = true
                };

                var result = await _userManager.CreateAsync(user, model.Password);
                if (result.Succeeded){
                    _logger.LogInformation("User created a new account with password.");
                }
                foreach (var error in result.Errors){
                    ModelState.AddModelError(string.Empty, error.Description);
                }

                return Ok();
            }
            else{
                return BadRequest();
            }
        }
        [HttpPost("Login")]
        public async Task<IActionResult> LoginAsync(UserModel model, string returnUrl = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");

            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, true, lockoutOnFailure: false);
                if (result.Succeeded)
                {
                    _logger.LogInformation("User logged in.");
                    return LocalRedirect(returnUrl);
                }
                if (result.IsLockedOut)
                {
                    _logger.LogWarning("User account locked out.");
                    return RedirectToPage("./Lockout");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return BadRequest();
                }
            }

            // If we got this far, something failed, redisplay form
            return BadRequest();
        }
    }
}