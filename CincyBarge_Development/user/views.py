from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from .forms import CreateUserForm

# Create your views here.

def register(request):
    if request.method == "POST":
        form = UserCreationForm(CreateUserForm.POST)
        if form.is_valid():
            form.save()
            return redirect('user-login')
    else:
        form = CreateUserForm()
    context = {
        'form': form,
    }
    return render(request, 'user/register.html', context)

def profile(request):
    return render(request, 'user/profile.html')

def staff_page(request):
    staff_users = User.objects.filter(is_staff=True).order_by('date_joined')

    return render(request, 'your_template_name.html', {'users': staff_users})


