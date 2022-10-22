from django.shortcuts import render
from django.http import HttpResponse
from django.shortcuts import render

# Create your views here.

def index(request):
    # return HttpResponse("index")
    return render(request, 'index/index.html')

def home(request):
    # return HttpResponse("home")
    return render(request, 'home/index.html')

def login(request):
    # return HttpResponse("login")
    return render(request, 'login/index.html')