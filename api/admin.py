from django.contrib import admin
from django.contrib import messages
from api.models import User,MyModel,camira,Reservation,alarm
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin 
# Register your models here.
class UserModelAdmin(BaseUserAdmin):
  # The fields to be used in displaying the User model.
  # These override the definitions on the base UserModelAdmin
  # that reference specific fields on auth.User.
  list_display = ('id', 'email', 'name', 'tc', 'is_admin')
  list_filter = ('is_admin',)
  fieldsets = (
      ('User Credentials', {'fields': ('email', 'password')}),
      ('Personal info', {'fields': ('name', 'tc')}),
      ('Permissions', {'fields': ('is_admin',)}),
  )
  # add_fieldsets is not a standard ModelAdmin attribute. UserModelAdmin
  # overrides get_fieldsets to use this attribute when creating a user.
  add_fieldsets = (
      (None, {
          'classes': ('wide',),
          'fields': ('email', 'name', 'tc', 'password1', 'password2'),
      }),
  )
  search_fields = ('email',)
  ordering = ('email', 'id')
  filter_horizontal = ()
def make_active(modeladmin, request, queryset):
        queryset.update(is_active = 1)
        messages.success(request, "Selected Record(s) Marked as Active Successfully !!")
  
def make_inactive(modeladmin, request, queryset):
        queryset.update(is_active = 0)
        messages.success(request, "Selected Record(s) Marked as Inactive Successfully !!")
  
        admin.site.add_action(make_active, "Make Active")
        admin.site.add_action(make_inactive, "Make Inactive")
  
def has_delete_permission(self, request, obj = None):
        return False

# Now register the new UserModelAdmin...
admin.site.register(User, UserModelAdmin)
admin.site.register(MyModel)
admin.site.register(camira)
admin.site.register(Reservation)
admin.site.register(alarm)
