using AuthLogin.API.Entities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Mail;
using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity.Data;
using AuthLogin.API.Context;

namespace AuthLogin.API.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class AuthController : ControllerBase
	{
		private readonly UserManager<ApplicationUser> _userManager;
		private readonly SignInManager<ApplicationUser> _signInManager;
		private readonly ApplicationDbContext _applicationDbContext;

		public AuthController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
		{
			_userManager = userManager;
			_signInManager = signInManager;
		}

		[HttpPost("register")]
		public async Task<IActionResult> Register([FromBody] AuthLogin.API.Model.RegisterRequest model)
		{
			if (model == null)
			{
				return BadRequest("Invalid registration request");
			}

			var user = new ApplicationUser
			{
				Email = model.Email,
				UserName = model.UserName
			};

			var result = await _userManager.CreateAsync(user, model.Password);
			if (result.Succeeded)
			{
				return Ok(new { Message = "User registered successfully" });
			}

			return BadRequest(result.Errors);
		}

		[HttpPost("login")]
		public async Task<IActionResult> Login([FromBody] LoginRequest model)
		{
			if (string.IsNullOrWhiteSpace(model.Email) || string.IsNullOrWhiteSpace(model.Password))
			{
				return BadRequest("Email and Password is required.");
			}

			var user = await _userManager.FindByEmailAsync(model.Email);
			if (user == null)
			{
				return Unauthorized(new { message = "Kullanıcı adı ya da şifre yanlış" });
			}

			if (user.AccountLockoutEndTime.HasValue && user.AccountLockoutEndTime.Value > DateTime.UtcNow)
			{
				return BadRequest(new { message = "Hesabınız kilitli, lütfen daha sonra tekrar deneyin" });
			}

			var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);
			if (!result.Succeeded)
			{
				user.FailedLoginAttempts += 1;

				if (user.FailedLoginAttempts >= 3)
				{
					user.AccountLockoutEndTime = DateTime.UtcNow.AddMinutes(15);
					await _userManager.UpdateAsync(user);
					return BadRequest(new { message = "Hesabınız 15 dakika boyunca kilitlenmiştir" });
				}

				await _userManager.UpdateAsync(user);
				return Unauthorized(new { message = "Kullanıcı adı ya da şifre yanlış" });
			}

			user.FailedLoginAttempts = 0;
			user.LastLoginTime = DateTime.UtcNow;
			await _userManager.UpdateAsync(user);

			// OTP oluştur ve gönder
			var otp = GenerateOtp();
			await SendOtpEmail(user.Email, otp);

			// İki faktörlü kimlik doğrulamasını etkinleştir
			user.IsTwoFactorEnabled = true;
			// OTP'yi kullanıcı nesnesinde sakla
			user.TwoFactorOtp = otp; // Bu özelliği ApplicationUser'a eklemelisiniz
			await _userManager.UpdateAsync(user);

			return Ok(new { Message = "OTP e-postanıza gönderildi", Email = user.Email });
		}

		[HttpPost("verify-otp")]
		public async Task<IActionResult> VerifyOtp([FromBody] VerifyOtpRequest model)
		{
			var user = await _userManager.FindByEmailAsync(model.Email);
			if (user == null || !user.IsTwoFactorEnabled)
			{
				return Unauthorized(new { message = "Kullanıcı bulunamadı veya iki faktörlü kimlik doğrulaması etkin değil" });
			}

			// OTP'yi kontrol et
			if (model.Otp == user.TwoFactorOtp) // user.TwoFactorOtp, kullanıcının en son OTP'sidir
			{
				user.IsTwoFactorEnabled = false; // 2FA'yi devre dışı bırak
				await _userManager.UpdateAsync(user);

				var token = GenerateJwtToken(user);
				return Ok(new { Token = token });
			}

			return Unauthorized(new { message = "Geçersiz OTP" });
		}

		private string GenerateOtp()
		{
			Random random = new Random();
			return random.Next(100000, 999999).ToString(); // 6 haneli rastgele OTP
		}

		private async Task SendOtpEmail(string email, string otp)
		{
			// E-posta gönderme işlemi
			var fromAddress = new MailAddress("your-email@example.com", "Your Name");
			var toAddress = new MailAddress(email);
			const string fromPassword = "your-email-password"; // E-posta şifreniz
			const string subject = "Your OTP Code";
			string body = $"Your OTP code is: {otp}";

			var smtp = new SmtpClient
			{
				Host = "smtp.example.com", // SMTP sunucunuz
				Port = 587, // SMTP port numarası
				EnableSsl = true,
				DeliveryMethod = SmtpDeliveryMethod.Network,
				UseDefaultCredentials = false,
				Credentials = new NetworkCredential(fromAddress.Address, fromPassword)
			};

			using (var message = new MailMessage(fromAddress, toAddress)
			{
				Subject = subject,
				Body = body
			})
			{
				await smtp.SendMailAsync(message);
			}
		}

		private string GenerateJwtToken(ApplicationUser user)
		{
			var claims = new[]
			{
			new Claim(JwtRegisteredClaimNames.Sub, user.Email),
			new Claim(JwtRegisteredClaimNames.Jti, user.Id),
		};

			var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("YOUR_SECRET_KEY"));
			var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

			var token = new JwtSecurityToken(
				issuer: "YOUR_ISSUER",
				audience: "YOUR_AUDIENCE",
				claims: claims,
				expires: DateTime.Now.AddMinutes(60),
				signingCredentials: creds);

			return new JwtSecurityTokenHandler().WriteToken(token);
		}
	}

	public class LoginRequest
	{
		public string Email { get; set; }
		public string Password { get; set; }
	}

	public class VerifyOtpRequest
	{
		public string Email { get; set; }
		public string Otp { get; set; }
	}
}
