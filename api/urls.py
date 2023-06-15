
from django.urls import path,include
from api.views import Alarm,history,MyModelDetail,UserRegistrationView,UserView,UserLoginView,UserProfileView,camiraView,UserChangePasswordView,SendPasswordResetEmailView,UserPasswordResetView,index
from django.conf import settings  
from django.conf.urls.static import static  
urlpatterns = [
    path('register/', UserRegistrationView.as_view(),name='register'),
    path('login/', UserLoginView.as_view(),name='login'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('changepassword/', UserChangePasswordView.as_view(), name='changepassword'),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
    path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset-password'),
    path('cameria/', camiraView.as_view(), name='profile'),
    path('index/', index, name='index'),
   # path('video/', video_feed, name='video_feed'),
    path('user/', UserView.as_view()),
    path('alarm/', Alarm.as_view()),
    path('history/', history.as_view()),
    path('editProfile/', UserProfileView.as_view(), name='profile'),
    path('mymodel/<int:id>/', MyModelDetail.as_view()),

    
    
    
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
