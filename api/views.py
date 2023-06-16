from django.http import StreamingHttpResponse
from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status,generics
from rest_framework.views import APIView
from api.serializers import alarmSerilazer,SendPasswordResetEmailSerializer,UserChangePasswordSerializer, UserLoginSerializer, UserPasswordResetSerializer, UserProfileSerializer, UserRegistrationSerializer,camerSerilazer
from django.contrib.auth import authenticate
from api.renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
import jwt, datetime
from ultralytics import YOLO
from .models import User,MyModel
import torch

from rest_framework.exceptions import AuthenticationFailed
#yolo v5 related import
"""import yolov5,torch
from yolov5.utils.general import (check_img_size, non_max_suppression, 
                                  check_imshow, xyxy2xywh, increment_path)
from yolov5.utils.torch_utils import select_device, time_sync
from yolov5.utils.plots import Annotator, colors
from deep_sort.utils.parser import get_config
from deep_sort.deep_sort import DeepSort"""


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
#loade modeal
#model = yolov5.load('yolov5s.pt')
#model = yolov5.load('yolov5s.pt')
model =  YOLO("weights/best.pt")


# Get names and colors
names = false
hide_labels=False
hide_conf = False

def stream():
    cap = cv2.VideoCapture(0)
    model.conf = 0.25
    model.iou = 0.5
   # model.classes = [0,64,39]
    while True:
        ret, frame = cap.read()
        if not ret:
            print("Error: failed to capture image")
            break

        results = model(frame, augment=True)
        # proccess
        annotator = Annotator(frame, line_width=2, pil=not ascii) 
        det = results.pred[0]
        if det is not None and len(det):  
            for *xyxy, conf, cls in reversed(det):
                c = int(cls)  # integer class
                label = None if hide_labels else (names[c] if hide_conf else f'{names[c]} {conf:.2f}')
                annotator.box_label(xyxy, label, color=colors(c, True)) 

        im0 = annotator.result() 
       
        image_bytes = cv2.imencode('.jpg', im0)[1].tobytes()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + image_bytes + b'\r\n')  


def video_feed(request):
    return StreamingHttpResponse(stream(), content_type='multipart/x-mixed-replace; boundary=frame')
"""  
import cv2
from django.shortcuts import render

def live_feed(request):
    # Open the camera
    cap = cv2.VideoCapture(0)

    while True:
        # Capture frame-by-frame
        ret, frame = cap.read()

        # Convert the frame to JPEG format
        ret, jpeg = cv2.imencode('.jpg', frame)

        # Render the frame to a Django template
        return render(request, 'index.html', {'image': jpeg.tobytes()})
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
        userd = MyModel.objects.last()
       
        serializer =alarmSerilazer(userd)
        return Response(serializer.data, status=status.HTTP_200_OK)

   
class history(APIView):
       renderer_classes = [UserRenderer]
       permission_classes = [IsAuthenticated]
       def get(self, request):
        
        
           userd = MyModel.objects.all().order_by('-id')[:5]
       
           serializer =alarmSerilazer(userd, many=True)
           return Response(serializer.data)
  
class MyModelDetail(generics.RetrieveUpdateAPIView):
    queryset = User.objects.all()
    serializer_class = UserProfileSerializer
    lookup_field = 'id'

    def put(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)

        if serializer.is_valid():
            self.perform_update(serializer)

            return Response(serializer.data)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def perform_update(self, serializer):
        serializer.save()
model = torch.hub.load('ultralytics/yolov5', 'yolov5s', pretrained=True)

@api_view(['POST'])
def detect_objects(request):
    # Define a generator function to process each frame of the video
    def process_frames(video):
        while True:
            # Read the next frame from the video
            ret, frame = video.read()
            if not ret:
                break
            
            # Convert the frame to a PyTorch tensor
            frame_tensor = torch.from_numpy(frame.transpose(2, 0, 1)).float() / 255.0
            
            # Pass the frame through the YOLO model
            results = model(frame_tensor.unsqueeze(0))[0]
            
            # Parse the output of the YOLO model
            for obj in results:
                # Extract the object label and bounding box coordinates
                label = obj['label']
                bbox = obj['box']
                x1, y1, x2, y2 = bbox.tolist()
                
                # Draw the bounding box on the original frame
                cv2.rectangle(frame, (x1, y1), (x2, y2), (0, 255, 0), 2)
                cv2.putText(frame, label, (x1, y1 - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 2)
            
            # Encode the processed frame as a JPEG image and yield it
            _, jpeg = cv2.imencode('.jpg', frame)
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + jpeg.tobytes() + b'\r\n')
    
    # Read the input video file
    file = request.FILES['file']
    video = cv2.VideoCapture(file)
    
    # Return a streaming HTTP response with the processed frames
    return StreamingHttpResponse(process_frames(video), content_type='multipart/x-mixed-replace; boundary=frame')

def index(request):
    return render(request, 'index.html')
