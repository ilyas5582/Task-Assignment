using System.ComponentModel.DataAnnotations;

namespace Login_Registration_NetCoreWebApi.Authentication
{
    public class RegisterModel
    {
        [Required]
        public string? UserName { get; set; }
        [Required]
        public string? Email { get; set; }
        [Required]
        public string? Password { get; set; }

        [Required]
        public string? UserRole { get; set;}
    }
}
