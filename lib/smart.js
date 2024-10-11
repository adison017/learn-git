function togglePassword() {
    const passwordInput = document.getElementById("password");
    const eyeIcon = document.getElementById("eye-icon");

    if (passwordInput.type === "password") {
        passwordInput.type = "text";
        eyeIcon.classList.remove("fa-eye"); // เปลี่ยนไอคอนเป็นเปิด
        eyeIcon.classList.add("fa-eye-slash");
    } else {
        passwordInput.type = "password";
        eyeIcon.classList.remove("fa-eye-slash"); // เปลี่ยนไอคอนเป็นปิด
        eyeIcon.classList.add("fa-eye");
    }
}
function confirmLogout() {
    if (confirm("คุณแน่ใจว่าต้องการออกจากระบบ?")) {
        window.location.href = "/logout"; // เปลี่ยนเส้นทางไปที่ /logout
    }
}