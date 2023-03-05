<?php
// Import the PHPMailer library
require_once "phpmailer/PHPMailer.php";
require_once "phpmailer/SMTP.php";
require_once "phpmailer/Exception.php";

// Check if the sign-up form was submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Get the form data
    $username = $_POST["username"];
    $email = $_POST["email"];
    $password = $_POST["password"];

    // Validate the form data (omitted for brevity)

    // Send the email using PHPMailer
    $mail = new PHPMailer\PHPMailer\PHPMailer(true);
    $mail->SMTPDebug = 0;
    $mail->isSMTP();
    $mail->Host = 'smtp.gmail.com';
    $mail->SMTPAuth = true;
    $mail->Username = 'your-email@gmail.com';
    $mail->Password = 'your-password';
    $mail->SMTPSecure = 'tls';
    $mail->Port = 587;

    $mail->setFrom('your-email@gmail.com', 'Your Name');
    $mail->addAddress($email, $username);

    $mail->isHTML(true);
    $mail->Subject = 'Welcome to My Website';
    $mail->Body = 'Thank you for signing up!';

    if ($mail->send()) {
        // Email sent successfully
        echo "Email sent successfully!";
    } else {
        // Email sending failed
        echo "Email sending failed.";
    }
}