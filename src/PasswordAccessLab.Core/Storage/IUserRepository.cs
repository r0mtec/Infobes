using PasswordAccessLab.Core.Models;

namespace PasswordAccessLab.Core.Storage;

public interface IUserRepository
{
    UserDatabase Load();
    void Save(UserDatabase data);
}
