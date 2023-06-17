from django.db import models
from django.contrib.auth.models import BaseUserManager,AbstractBaseUser

#  Custom User Manager
class UserManager(BaseUserManager):
  def create_user(self, email, name, tc, password=None, password2=None):
      """
      Creates and saves a User with the given email, name, tc and password.
      """
      if not email:
          raise ValueError('User must have an email address')

      user = self.model(
          email=self.normalize_email(email),
          name=name,
          tc=tc,
      )

      user.set_password(password)
      user.save(using=self._db)
      return user

  def create_superuser(self, email, name, tc, password=None):
      """
      Creates and saves a superuser with the given email, name, tc and password.
      """
      user = self.create_user(
          email,
          password=password,
          name=name,
          tc=tc,
      )
      user.is_admin = True
      user.save(using=self._db)
      return user

#  Custom User Model
class User(AbstractBaseUser):
  
  email = models.EmailField(
      verbose_name='Email',
      max_length=255,
      unique=True,
  )
  name = models.CharField(max_length=200)
  tc = models.BooleanField()
  is_active = models.BooleanField(default=True)
  is_admin = models.BooleanField(default=False)
  created_at = models.DateTimeField(auto_now_add=True)
  updated_at = models.DateTimeField(auto_now=True)

  objects = UserManager()

  USERNAME_FIELD = 'email'
  REQUIRED_FIELDS = ['name', 'tc']

  def __str__(self):
      return self.email

  def has_perm(self, perm, obj=None):
      "Does the user have a specific permission?"
      # Simplest possible answer: Yes, always
      return self.is_admin

  def has_module_perms(self, app_label):
      "Does the user have permissions to view the app `app_label`?"
      # Simplest possible answer: Yes, always
      return True

  @property
  def is_staff(self):
      "Is the user a member of staff?"
      # Simplest possible answer: All admins are staff
      return self.is_admin
# lets us explicitly set upload path and filename
def upload_to(instance, filename):
    return 'images/{filename}'.format(filename=filename)

class camira(models.Model):
    ip = models.CharField(
        max_length=80, blank=False, null=False) 
    name = models.CharField(
        max_length=80, blank=False, null=False)   
    password = models.CharField(
        max_length=80, blank=False, null=False)  
class MyModel(models.Model):
    cameria_id = models.ForeignKey(
        camira, on_delete=models.CASCADE, related_name="listings")
    alarm = models.CharField(
        max_length=80, blank=False, null=False)
    
    image_url = models.ImageField(upload_to='my_picter', blank=True, null=True)
    alrm_at = models.DateTimeField(auto_now_add=True)

class Reservation(models.Model):
    camira = models.ForeignKey(camira, related_name='reservation', on_delete=models.CASCADE )
    movie = models.ForeignKey(User, related_name='reservation', on_delete=models.CASCADE )
class alarm(models.Model):
    cameria = models.ForeignKey(
        camira, on_delete=models.CASCADE, related_name="listigs",default=1)
    alarmat = models.CharField(
        max_length=80, blank=False, null=False)
    
    image_ur = models.ImageField(upload_to='my_picter', blank=True, null=True)
    alrm_in = models.DateTimeField(auto_now_add=True)

