from smtplib import SMTPException

from django.conf.global_settings import SECRET_KEY
from django.contrib.sites.shortcuts import get_current_site
import jwt
from django.core.exceptions import ObjectDoesNotExist
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth.models import User, auth
from django.contrib import messages
from django.core.mail import EmailMessage, send_mail
from django.template.loader import render_to_string
from django.urls import reverse


def index(request):
    return render(request, 'index.html')

def login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = auth.authenticate(username=username, password=password)
        if user is not None:
            auth.login(request, user)
            return render(request, 'chatindex.html')
        else:
            messages.info(request, "invalid user")
            return redirect('login')
    else:
        return render(request, 'login.html')

def register(request, ):
    if request.method == 'POST':
        username = request.POST['username']
        password1 = request.POST['password1']
        password2 = request.POST['password2']
        email = request.POST['email']
        if password1 == password2 and password1 != '':
            if User.objects.filter(username=username).exists():
                messages.info(request, 'User name is already taken')
            elif User.objects.filter(email=email).exists():
                messages.info(request, 'Email is already registered')
            else:
                try:
                    user = User.objects.create_user(username=username, password=password1, email=email)
                except ObjectDoesNotExist as e:
                    print(e)
                payload = {'username': user.username,'email': user.email}
                key = jwt.encode(payload, SECRET_KEY, algorithm="HS256").decode('utf-8')
                mail_subject = 'Link to activate the account'
                mail_message = render_to_string('activate.html', {'user': user.username,'domain': get_current_site(request).domain,'token': key,})
                recipient_email = ['krndileep@gmail.com']
                email = EmailMessage(mail_subject, mail_message, to=[recipient_email])
                email.send()
                return HttpResponse("Check your mail for activate")
        else:
            messages.info(request, 'Passwords doesnt matching')
            return render(request, 'register.html')
    return render(request, 'register.html')


def activate(request, token):
    user_details = jwt.decode(token, SECRET_KEY)
    user_name = user_details['username']
    try:
        user = User.objects.get(username=user_name)
    except ObjectDoesNotExist as e:
        print(e)
    if user is not None:
        user.is_active = True
        user.save()
        return redirect('login')
    else:
        return redirect('register')


def verify(request, token):
    user_details = jwt.decode(token, SECRET_KEY)
    user_name = user_details['username']
    try:
        user = User.objects.get(username=user_name)
    except ObjectDoesNotExist as e:
        print(e)
    if user is not None:
        return redirect(reverse('resetpassword', args=[token]))
    else:
        messages.info("Invalid user")
        return redirect('register')
    return render(request, "resetpassword.html")


def reset_password(request, token):
    if request.method == 'POST':
        password1 = request.POST['password1']
        password2 = request.POST['password2']
        if password1 == password2:
            user_details = jwt.decode(token, SECRET_KEY)
            username = user_details['username']
            user = User.objects.get(username=username)
            user.set_password(password1)
            user.save()
            return redirect('index')
        else:
            print("Passwords doesn't match")
    return render(request, 'resetpassword.html')


def sendmail(request):
    if request.method == 'POST':
        emailid = request.POST["email"]
        try:
            user = User.objects.get(email=emailid)
            if user is not None:
                payload = {'username': user.username, 'email': user.email}
                key = jwt.encode(payload, SECRET_KEY, algorithm="HS256").decode('utf-8')
                mail_subject = 'Link to activate the account'
                mail_message = render_to_string('verify.html',
                                                {'user': user.username, 'domain': get_current_site(request).domain,
                                                 'u_token': key, })
                email = EmailMessage(mail_subject, mail_message, to=[emailid])
                email.send()
                return HttpResponse("Check your mail to reset your password")
            else:
                messages.info(request, 'Invalid Email id.. Try Once again')
                return render(request, "register.html")
        except TypeError as e:
            print(e)
    else:
        return render(request, "resetmail.html")

def logout(request):
    auth.logout(request)
    return redirect('/')
