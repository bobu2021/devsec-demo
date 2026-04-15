from django.contrib.auth.models import Group, User
from django.test import Client, TestCase
from django.urls import reverse

from .models import Profile


class RegistrationTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.url = reverse("philemon_mutabazi:register")

    def test_register_success(self):
        response = self.client.post(
            self.url,
            {
                "username": "newuser",
                "email": "new@example.com",
                "password1": "StrongPass123!",
                "password2": "StrongPass123!",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(User.objects.filter(username="newuser").exists())

    def test_register_rejects_duplicate_email(self):
        User.objects.create_user(username="existing", email="dup@example.com", password="StrongPass123!")
        response = self.client.post(
            self.url,
            {
                "username": "other",
                "email": "dup@example.com",
                "password1": "StrongPass123!",
                "password2": "StrongPass123!",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "A user with this email already exists.")


class LoginLogoutTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="tester", password="StrongPass123!")

    def test_login_success(self):
        response = self.client.post(
            reverse("philemon_mutabazi:login"),
            {
                "username": "tester",
                "password": "StrongPass123!",
            },
        )
        self.assertEqual(response.status_code, 302)

    def test_logout_requires_post(self):
        self.client.login(username="tester", password="StrongPass123!")
        response = self.client.get(reverse("philemon_mutabazi:logout"))
        self.assertEqual(response.status_code, 200)
        response = self.client.post(reverse("philemon_mutabazi:logout"))
        self.assertEqual(response.status_code, 302)


class AccessControlTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="authuser", password="StrongPass123!")

    def test_dashboard_requires_login(self):
        response = self.client.get(reverse("philemon_mutabazi:dashboard"))
        self.assertEqual(response.status_code, 302)

    def test_profile_requires_login(self):
        response = self.client.get(reverse("philemon_mutabazi:profile"))
        self.assertEqual(response.status_code, 302)

    def test_dashboard_allows_authenticated_user(self):
        self.client.login(username="authuser", password="StrongPass123!")
        response = self.client.get(reverse("philemon_mutabazi:dashboard"))
        self.assertEqual(response.status_code, 200)


class PasswordAndProfileTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="profileuser",
            email="profile@example.com",
            password="StrongPass123!",
        )
        self.client.login(username="profileuser", password="StrongPass123!")
        self.profile_url = reverse("philemon_mutabazi:profile_detail", kwargs={"username": "profileuser"})

    def test_password_change(self):
        response = self.client.post(
            reverse("philemon_mutabazi:password_change"),
            {
                "old_password": "StrongPass123!",
                "new_password1": "UpdatedPass123!",
                "new_password2": "UpdatedPass123!",
            },
        )
        self.assertEqual(response.status_code, 302)

    def test_profile_detail_allows_owner_to_view(self):
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "profileuser")

    def test_profile_update(self):
        response = self.client.post(
            self.profile_url,
            {
                "username": "profileuser",
                "email": "updated@example.com",
                "bio": "Updated bio",
                "date_of_birth": "1999-01-15",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "updated@example.com")
        self.assertTrue(Profile.objects.filter(user=self.user).exists())

    def test_profile_update_denies_cross_user_access(self):
        other_user = User.objects.create_user(
            username="otheruser",
            email="other@example.com",
            password="StrongPass123!",
        )
        response = self.client.post(
            reverse("philemon_mutabazi:profile_detail", kwargs={"username": other_user.username}),
            {
                "username": other_user.username,
                "email": "attempted-change@example.com",
                "bio": "Attempted change",
                "date_of_birth": "1998-12-31",
            },
        )
        self.assertEqual(response.status_code, 404)
        other_user.refresh_from_db()
        self.assertEqual(other_user.email, "other@example.com")


class RoleBasedAccessTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.privileged_url = reverse("philemon_mutabazi:privileged_dashboard")
        self.normal_user = User.objects.create_user(
            username="normal",
            password="StrongPass123!",
        )
        self.staff_user = User.objects.create_user(
            username="staffuser",
            password="StrongPass123!",
            is_staff=True,
        )
        self.instructor_user = User.objects.create_user(
            username="instructor",
            password="StrongPass123!",
        )
        instructors = Group.objects.create(name="instructors")
        self.instructor_user.groups.add(instructors)

    def test_privileged_route_redirects_anonymous_user_to_login(self):
        response = self.client.get(self.privileged_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("philemon_mutabazi:login"), response.url)

    def test_privileged_route_denies_normal_authenticated_user(self):
        self.client.login(username="normal", password="StrongPass123!")
        response = self.client.get(self.privileged_url)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("philemon_mutabazi:dashboard"))

    def test_privileged_route_allows_staff_user(self):
        self.client.login(username="staffuser", password="StrongPass123!")
        response = self.client.get(self.privileged_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Privileged Area")

    def test_privileged_route_allows_instructor_group_user(self):
        self.client.login(username="instructor", password="StrongPass123!")
        response = self.client.get(self.privileged_url)
        self.assertEqual(response.status_code, 200)

    def test_privileged_user_cannot_view_other_user_profile(self):
        self.client.login(username="staffuser", password="StrongPass123!")
        response = self.client.get(
            reverse("philemon_mutabazi:profile_detail", kwargs={"username": "normal"}),
        )
        self.assertEqual(response.status_code, 404)

    def test_privileged_user_cannot_modify_other_user_profile(self):
        self.client.login(username="staffuser", password="StrongPass123!")
        response = self.client.post(
            reverse("philemon_mutabazi:profile_detail", kwargs={"username": "normal"}),
            {
                "username": "normal",
                "email": "hijack@example.com",
                "bio": "hijacked",
                "date_of_birth": "2000-01-01",
            },
        )
        self.assertEqual(response.status_code, 404)
        self.normal_user.refresh_from_db()
        self.assertNotEqual(self.normal_user.email, "hijack@example.com")

    def test_template_hides_privileged_link_for_normal_user(self):
        self.client.login(username="normal", password="StrongPass123!")
        response = self.client.get(reverse("philemon_mutabazi:dashboard"))
        self.assertNotContains(response, "Privileged Area")

    def test_template_shows_privileged_link_for_staff_user(self):
        self.client.login(username="staffuser", password="StrongPass123!")
        response = self.client.get(reverse("philemon_mutabazi:dashboard"))
        self.assertContains(response, "Privileged Area")
