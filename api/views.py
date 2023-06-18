from django.http import StreamingHttpResponse
from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework import status,generics
from rest_framework.views import APIView
from api.serializers import alarmsaSerilazer,MyModelSerializer,alarmSerilazer,SendPasswordResetEmailSerializer,UserChangePasswordSerializer, UserLoginSerializer, UserPasswordResetSerializer, UserProfileSerializer, UserRegistrationSerializer,camerSerilazer
from django.contrib.auth import authenticate
from api.renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
import jwt, datetime
from rest_framework.decorators import api_view
from .models import User,MyModel,alarm
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import os
import requests
import uuid


from rest_framework.exceptions import AuthenticationFailed




def get_tokens_for_user(user):
  refresh = RefreshToken.for_user(user)
  return {
      'refresh': str(refresh),
      'access': str(refresh.access_token),
  }
def isLogin(request):
  token = request.META.get('HTTP_AUTHORIZATION')
  if not token:
    raise AuthenticationFailed({'success':False,'message':'Authentication credentials were not provided.'})
  try:
    payload = jwt.decode(token, 'secret', algorithms=['HS256'])

  except jwt.ExpiredSignatureError:
    raise AuthenticationFailed({'success':False,'message':'Token Is Expired'})

  except jwt.exceptions.DecodeError:
    raise AuthenticationFailed({'success':False,'message':'Invalid token'})

  user = User.objects.filter(id=payload['id']).first()
  if not user:
    raise AuthenticationFailed({'success':False,'message':'User Account not found!'})

  return user

class UserRegistrationView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, format=None):
    serializer = UserRegistrationSerializer(data=request.data)
    if serializer.is_valid(raise_exception=True):
      user=serializer.save()
      token = get_tokens_for_user(user)
      return Response({'token':token, 'msg':'Registration Successful'}, status=status.HTTP_201_CREATED)
    #serializer.is_valid(raise_exception=True)
    #user = serializer.save()
    #token = get_tokens_for_user(user)
    return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
class UserLoginView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, format=None):
    serializer = UserLoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    email = serializer.data.get('email')
    password = serializer.data.get('password')
    user = authenticate(email=email, password=password)
    if user is not None:
      token = get_tokens_for_user(user)

      return Response({'token':token, 'msg':'Login Success'}, status=status.HTTP_200_OK)
    else:
      return Response({'errors':{'non_field_errors':['Email or Password is not Valid']}}, status=status.HTTP_404_NOT_FOUND)

class UserChangePasswordView(APIView):
  renderer_classes = [UserRenderer]
  permission_classes = [IsAuthenticated]
  def post(self, request, format=None):
    serializer = UserChangePasswordSerializer(data=request.data, context={'user':request.user})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Changed Successfully'}, status=status.HTTP_200_OK)

class UserProfileView(APIView):
  renderer_classes = [UserRenderer]
  permission_classes = [IsAuthenticated]
  
  def get(self, request, format=None):
    token = request.COOKIES.get('jwt')
    serializer = UserProfileSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)  
  def put(self,request,format=None):
    user=isLogin(request)
    serializer= UserProfileSerializer(user,data=request.data)
    if serializer.is_valid(raise_exception=True):
        pharmacy = serializer.save()
        return Response({'message':'profile updated Successfully',"success":True}, status=status.HTTP_201_CREATED)
    # print(serializer.errors)
    return Response({'success':False,'message':serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
def index(request):
    return render(request,'index.html')  

class SendPasswordResetEmailView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, format=None):
    serializer = SendPasswordResetEmailSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)

class UserPasswordResetView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, uid, token, format=None):
    serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)



class camiraView(APIView):
  renderer_classes = [UserRenderer]
  permission_classes = [IsAuthenticated]
  def get(self, request, format=None):
    serializer = camerSerilazer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)  


class UserView(APIView):
     renderer_classes = [UserRenderer]
     permission_classes = [IsAuthenticated]
     def get(self, request, format=None):
         serializer = UserProfileSerializer(request.user)
         return Response(serializer.data, status=status.HTTP_200_OK)

class Alarm(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def get(self, request, format=None):
        serializers = UserProfileSerializer(request.user)
        userd = alarm.objects.last()
       
        serializer =alarmSerilazer(userd)
        return Response(serializer.data, status=status.HTTP_200_OK)

   
class history(APIView):
       renderer_classes = [UserRenderer]
       permission_classes = [IsAuthenticated]
       def get(self, request):
        
        
           userd = alarm.objects.all().order_by('-id')[:5]
       
           serializer =alarmSerilazer(userd, many=True)
           return Response(serializer.data)
  
class MyModelDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserProfileSerializer

    def put(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
@api_view(['POST'])
def MyAPIView(request):
  

    if request.method == 'POST':
        serializer = MyModelSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)

        return Response(serializer.errors, status=400)


from rest_framework import generics


class ImageUploadView(generics.CreateAPIView):
    serializer_class = MyModelSerializer
@csrf_exempt
def upload(request):
    if request.method == 'POST':
        # get the image file from the request
        image_file = request.FILES.get('image', None)
        if not image_file:
            return JsonResponse({'error': 'Image file not found'}, status=400)

        # generate a unique file name for the image
        file_name = str(uuid.uuid4()) + os.path.splitext(image_file.name)[1]

        # save the image to disk on the server
        with open(os.path.join('path', 'to', 'upload', 'directory', file_name), 'wb') as f:
            for chunk in image_file.chunks():
                f.write(chunk)

        # save the data to the database along with the URL of the uploaded image
        my_model = MyModel(cameria_id_id=request.POST.get('id_cam'),alarm=request.POST.get('alarm'), image_url= 'https://apica-camapi.up.railway.app/api/user/photos' + file_name)
        my_model.save()

        return JsonResponse({'id': my_model.id}, status=201)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)      
      
class uploadealarm(APIView):
  
  def post(self, request, format=None):
    
    serializer = alarmsaSerilazer(data=request.data)
    if serializer.is_valid(raise_exception=True):
      
      user=serializer.save()
      return Response("succsesse", status=status.HTTP_201_CREATED)
    return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

