<?php
defined('BASEPATH') or exit('No direct script access allowed');
class Api extends CI_Controller
{

    public function __construct()
    {
        parent::__construct();
        $this->load->model(['Api_model']);
    }

    public function uniqueId()
    {
        $str = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNIPQRSTUVWXYZ';
        $nstr = str_shuffle($str);
        $unique_id = substr($nstr, 0, 10);
        return $unique_id;
    }

    //----------------------------- Upload single file-----------------------------
    public function doUploadImage($path, $file_name)
    {
        $config = array(
            'upload_path' => $path,
            'allowed_types' => "jpeg|jpg|png|pdf",
            'file_name' => rand(11111, 99999),
            'max_size' => "5120",
        );
        $this->load->library('upload', $config);
        $this->upload->initialize($config);
        if ($this->upload->do_upload($file_name)) {
            $data = $this->upload->data();
            return $data['file_name'];
        } else {
            return $this->upload->display_errors();
        }
    }

    //----------------------------- Upload multiple files-------------------------------------------
    public function upload_files($path, $file_name)
    {
        $this->output->set_content_type('application/json');
        $files = $_FILES[$file_name];
        $config = array(
            'upload_path' => $path,
            'allowed_types' => 'jpeg|jpg|gif|png|pdf',
            'overwrite' => 1,
        );
        $this->load->library('upload', $config);
        $images = array();
        $i = 0;
        foreach ($files['name'] as $key => $image) {
            $_FILES['images[]']['name'] = $files['name'][$key];
            $_FILES['images[]']['type'] = $files['type'][$key];
            $_FILES['images[]']['tmp_name'] = $files['tmp_name'][$key];
            $_FILES['images[]']['error'] = $files['error'][$key];
            $_FILES['images[]']['size'] = $files['size'][$key];

            $title = rand('1111', '9999');
            $image = explode('.', $image);
            $count = count($image);
            $extension = $image[$count - 1];
            $fileName = $title . '.' . $extension;
            $images[$i] = $fileName;
            $config['file_name'] = $fileName;
            $this->upload->initialize($config);

            if ($this->upload->do_upload('images[]')) {
                $this->upload->data();
            } else {
                return $this->upload->display_errors();
            }
            $i++;
        }
        return $images;
    }

    public function genrateToken()
    {
        $token = openssl_random_pseudo_bytes(16);
        $token = bin2hex($token);
        return $token;
    }

    public function sendMail($data)
    {
        $this->load->library('email');
        $to = $data['email'];
        $subject = $data['subject'];
        $message = $data['message'];
        $header = "from:ambuj.deisgnoweb@gmail.com \r\n";
        $header .= "MIME-Version: 1.0\r\n";
        $header .= "Content-type: text/html\r\n";
        $retval = mail($to, $subject, $message, $header);
        return true;
    }

    public function doSignup()
    {
        $this->output->set_content_type('application/json');
        $this->form_validation->set_rules('name', ' Name ', 'required');
        $this->form_validation->set_rules('email', ' Email ID ', 'required');
        $this->form_validation->set_rules('country_code', ' Country Code ', 'required');
        $this->form_validation->set_rules('phone', ' Phone Number ', 'required');
        $this->form_validation->set_rules('zip_code', ' Zip Code ', 'required');
        $this->form_validation->set_rules('password', ' Password', 'required');
        $this->form_validation->set_rules('confirm_password', 'Confirm Password', 'required|matches[password]');
        if ($this->form_validation->run() === FALSE) {
            $this->output->set_output(json_encode(['result' => 0, 'errors' => $this->form_validation->error_array()]));
            return FALSE;
        }
        $checkMail = $this->Api_model->checkEmail($this->input->post('email'));
        if (!empty($checkMail)) {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Email Id Already Exist.']));
            return FALSE;
        }
        $result = $this->Api_model->doSignup();
        if ($result) {
            // Token insert
            $this->Api_model->insertToken($result['user_id'], $this->uniqueId());
            $response = $this->Api_model->getUserByUserId($result['user_id']);
            if (!empty($response)) {
                $response['image_url'] = !empty($response['image']) ? base_url('uploads/users/') . $response['image_url'] : '';
            }
            // $this->sendVerificationMail($result['user_id']);
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Registered Succesfully. Verification mail has been sent on your email ID.', 'data' => $response]));
            return FALSE;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Registration Failed.!!!']));
            return FALSE;
        }
    }

    public function sendVerificationMail($user_id)
    {
        $user = $this->Api_model->getUserByUserId($user_id);
        $userEmail = $user['email'];
        $fromEmail = 'support@hoof_boot.com';
        $subject = 'Email Verification | Hoof-Boot';
        $htmlContent = "<h3>Hi " . $user['name'] . ",</h3>";
        $htmlContent .= "Welcome To Hoof-Boot !!<br />";
        $htmlContent .= "Please click the link below to verify your email.<br />";
        $user_id = $user['user_id'];
        $htmlContent .= "<a href=" . base_url("Api/verifyemail/" . substr(uniqid(), 0, 10) . $user_id . substr(uniqid(), 0, 10)) . ">Click For verification</a>";
        $mail_data['subject']=$subject;
        $mail_data['message']=$htmlContent;
        $mail_data['email']=$userEmail;
        $result = $this->sendMail($mail_data);
        if ($result) {
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Email Sent to your Registered Email Id', 'url' => base_url('service-provider/badges')]));
            return true;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Something Went Wrong.']));
            return False;
        }
    }

    public function sendOtp()
    {
        $this->output->set_content_type('application/json');
        $this->form_validation->set_rules('email', 'Email ', 'required|valid_email');
        if ($this->form_validation->run() === false) {
            $this->output->set_output(json_encode(['result' => 0, 'msg' => $this->form_validation->error_array()]));
            return false;
        }
        $email = $this->input->post('email');
        $is_email = $this->Api_model->getUserByEmail($email);
        if (empty($is_email)) {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Email is not present in our database.']));
            return false;
        }
        $otp = mt_rand(1111, 9999);
        $result = $this->Api_model->sendOtp($otp, $is_email['patient_id']);
        if ($result) {
            // for mail
            $mail['subject'] = 'Otp For Login!';
            $mail['message'] = 'Your Otp Is' . $otp;
            $mail['email'] = $is_email['email'];
            $this->sendMail($mail);
            $result = $this->Api_model->getUserByUserId($is_email['user_id']);
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Otp Send Successfully', 'data' => $result]));
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Failed to send otp.']));
        }
    }

    public function otpVerification()
    {
        $this->output->set_content_type('application/json');
        $user_id = $this->input->post('user_id');
        $otp = $this->input->post('otp');
        if (empty($user_id)) {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'User ID is Required!!.']));
            return false;
        }
        if (empty($otp)) {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Otp Required.']));
            return false;
        }
        $current_time = date('Y-m-d h:i');
        $result = $this->Api_model->verifyOtp($otp, $user_id);
        if ($result) {
            /*if (strtotime($result['otp_expiry']) < strtotime($current_time)) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Otp Expired. Please Request New Otp']));
                return false;
            }*/
            $this->Api_model->updateVerifyStatus($user_id);
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Otp Verified Successfully.', 'data' => $result]));
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Invaid Otp.']));
        }
    }

    public function updateProfile()
    {
        $this->output->set_content_type('application/json');
        $user_token = $this->input->get_request_header('token');
        $user_data = $this->Api_model->getUserByToken($user_token);
        if (empty($user_data)) {
            header('HTTP/1.1 402 User already logged in on a different device', true, 402);
            $this->output->set_output(json_encode(['result' => -2, 'msg' => 'User already logged in on a different device']));
            return FALSE;
        }
        $user_id = $user_data['user_id'];
        if (!empty($_FILES['image_url']['name'])) {
            $path = "uploads/users";
            $file_name = "image_url";
            $profile_image = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Profile Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        } else {
            $user = $this->Api_model->getUserByUserId($user_id);
            $profile_image = $user['image_url'];
        }
        $result = $this->Api_model->updateProfile($user_id, $profile_image);
        if ($result) {
            $result = $this->Api_model->getUserByUserId($user_id);
            $result['image_url'] = !empty($result['image_url']) ? base_url('uploads/users/' . $result['image_url']) : "";
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Profile updated successfully', 'data' => $result]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Failed to Update', 'data' => NULL]));
            return false;
        }
    }

    public function doLogin()
    {
        $this->output->set_content_type('application/json');
        $email = $this->input->post('email');
        $checkemail = $this->Api_model->emailVerify($email);
        if (!empty($checkemail)) {
            if ($checkemail['is_verify'] == 'no') {
                $this->sendVerificationMail($checkemail['user_id']);
                header('HTTP/1.1 402 User Account has not been verified yet.', true, 402);
                $this->output->set_output(json_encode(['result' => -2, 'msg' => 'We have resend verification link to your email id. Please check your mail.']));
                return false;
            }
            if ($checkemail['status'] == 'Deleted') {
                header('HTTP/1.1 402 User Account has been deleted.', true, 402);
                $this->output->set_output(json_encode(['result' => -2, 'msg' => 'Your Account has been deleted.']));
                return false;
            }
            if ($checkemail['status'] == 'Blocked') {
                header('HTTP/1.1 402 User Account Is Blocked.', true, 402);
                $this->output->set_output(json_encode(['result' => -2, 'msg' => 'Your Account Is Blocked.']));
                return false;
            }
            if ($checkemail['status'] == 'Inactive') {
                header('HTTP/1.1 402 User Account Is Inactive.', true, 402);
                $this->output->set_output(json_encode(['result' => -2, 'msg' => 'Your Account Is Inactive.']));
                return false;
            }
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Email does not exist']));
            return false;
        }
        $results = $this->Api_model->doLogin();
        if ($results) {
            if ($results['is_verify'] == 'no') {
                $this->output->set_output(json_encode(['result' => 3, 'msg' => 'Please Verfiy yourself', 'data' => $results]));
                return false;
            }
            $this->Api_model->updateToken($results['user_id'], $this->genrateToken());
            $result = $this->Api_model->getUserByUserId($results['user_id']);
            if (!empty($result['image_url'])) {
                $result['image_url'] = base_url('uploads/users/' . $result['image_url']);
            } else {
                $result['image_url'] = null;
            }
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Login Successfully', 'data' => $result]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Email id or password is incorrect.', 'data' => null]));
            return false;
        }
    }

    public function getCategories()
    {
        $this->output->set_content_type('application/json');
        $category_id = $this->input->post('category_id');
        $result = $this->Api_model->getCategories();
       // $result['category_detail'] = $this->Api_model->getCategoryDetail($category_id);
        if ($result) {
            if(!empty($result)){
                $i=0;
                foreach($result as $row){
                    $result[$i]['image_url']=base_url('uploads/categories/').$row['image_url'];
                    $result[$i]['banner_image']=base_url('uploads/categories/banner/').$row['banner_image'];
                    $i++;
                }
            }
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Categories fetched Successfully.', 'data' => $result]));
        } else {
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'No Record Found!!','data' => null]));
        }
    }

    public function getPages()
    {
        $this->output->set_content_type('application/json');
        $page = $this->input->post('page');
        if (empty($page)) {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Page Name Required!!.']));
            return false;
        }
        $result = $this->Api_model->getPages($page);
        if (!empty($result)) {
            if ($result['page_name'] == 'helpsupport') {
                $result['page_name'] = "Help & Support";
            }
            if ($result['page_name'] == 'termsconditions') {
                $result['page_name'] = "Terms and Conditions";
            }
            if ($result['page_name'] == 'privacypolicy') {
                $result['page_name'] = "Privacy Policy";
            }
            $str = ["&nbsp;", "&#39;"];
            $rplc = [" ", "'"];
            $description = str_replace($str, $rplc,($result['description']));
            $result['description'] = $description;
        }
        if ($result) {
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Pages Data', 'data' => $result]));
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'No Record Found!!']));
        }
    }

    // for forgot password
    public function forgotPassword()
    {
        $this->output->set_content_type('application/json');
        $email = $this->input->post('email');
        if (empty($email)) {
            $this->output->set_output(json_encode(['result' => 0, 'msg' => 'Email is Required!!!.', 'data' => null]));
            return false;
        }
        $mail_exist = $this->Api_model->emailVerify($email);
        if ($mail_exist) {
            // $otp = mt_rand(1111, 9999);
            $otp = 1234;
            // for mail
            $mail['subject'] = 'Otp For Forgot Password!';
            $mail['message'] = 'Your Otp Is' . $otp;
            $mail['email'] = $mail_exist['email'];
            // $this->sendMail($mail);
            $result = $this->Api_model->sendOtp($otp, $mail_exist['user_id']);
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Otp Sent on your mail.', 'data' => ['user_id' => $mail_exist['user_id'], 'email' => $mail_exist['email'], 'otp' => $otp]]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'User does not exist.', 'data' => null]));
            return false;
        }
    }

    public function changePassword()
    {
        $this->output->set_content_type('application/json');
        $user_token = $this->input->get_request_header('token');
        $user_data = $this->Api_model->getUserByToken($user_token);
        if (empty($user_data)) {
            header('HTTP/1.1 402 User already logged in on a different device', true, 402);
            $this->output->set_output(json_encode(['result' => -2, 'msg' => 'User already logged in on a different device']));
            return false;
        }
        $user_id = $user_data['user_id'];
        $old_pass = $this->input->post('old_password');
        $new_pass = $this->input->post('new_password');
        $c_pass = $this->input->post('confirm_password');
        $checkold = $this->Api_model->checkoldpassword($old_pass, $user_id);
        if ($checkold) {
            if ($old_pass == $new_pass) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'New and Old Password should not be same.']));
            } else {
                if ($new_pass == $c_pass) {
                    $result = $this->Api_model->changePassword($user_id, $old_pass, $new_pass);
                    if ($result) {
                        $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Password changed successfully']));
                    } else {
                        $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Password Update Failed']));
                    }
                } else {
                    $this->output->set_output(json_encode(['result' => -1, 'msg' => 'New and Confirm password did not match.']));
                }
            }
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Old password is Incorrect.']));
        }
    }

    public function resetPassword()
    {
        $this->output->set_content_type('application/json');
        $user_id = $this->input->post('user_id');
        $new_pass = $this->input->post('new_password');
        $c_pass = $this->input->post('confirm_password');
        if ($new_pass != $c_pass) {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Password should be same.']));
        } else {
            if ($new_pass == $c_pass) {
                $result = $this->Api_model->resetPassword($user_id, $new_pass);
                if ($result) {
                    $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Password reset successfully']));
                } else {
                    $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Password Update Failed']));
                }
            } else {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'New and Confirm password did not match.']));
            }
        }
    }

    public function viewProfile()
    {
        $this->output->set_content_type('application/json');
        $user_token = $this->input->get_request_header('token');
        $user_data = $this->Api_model->getUserByToken($user_token);
        if (empty($user_data)) {
            header('HTTP/1.1 402 User already logged in on a different device', true, 402);
            $this->output->set_output(json_encode(['result' => -2, 'msg' => 'User already logged in on a different device']));
            return false;
        }
        $user_id = $user_data['user_id'];
        $result = $this->Api_model->viewProfile($user_id);
        if ($result) {
            $response = $this->Api_model->getUserByUserId($user_id);
            $response['image_url']=base_url('uploads/users/') . $response['image_url'];
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Profile fetched Successfully !!', 'data' => $response]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Falied to view', 'data' => NULL]));
            return false;
        }
    }

    public function faqs()
    {
        $this->output->set_content_type('application/json');
        $result = $this->Api_model->getFaq();
        if ($result) {
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'faqs Data Fetched Successfully', 'data' => $result]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'failed To Fetch', 'data' => null]));
            return false;
        }
    }

    public function getNotification()
    {
        $this->output->set_content_type('application/json');
        $patient_token = $this->input->get_request_header('token');
        $patient_data = $this->Api_model->getUserByToken($patient_token);
        if (empty($patient_data)) {
            header('HTTP/1.1 402 User already logged in on a different device', true, 402);
            $this->output->set_output(json_encode(['result' => -2, 'msg' => 'User already logged in on a different device']));
            return false;
        }
        $patient_id = $patient_data['patient_id'];
        $result = $this->Api_model->getNotification($patient_id);
        $i = 0;
        foreach ($result as $row) {
            $result[$i]['notification_date_time'] = changeDateFormat($row['created_at']);
            $i++;
        }

        if ($result) {
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Patient History', 'data' => $result]));
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'No record Found !!.']));
        }
    }

    public function emailChange()
    {
        $this->output->set_content_type('application/json');
        $user_token = $this->input->get_request_header('token');
        $user_data = $this->Api_model->getUserByToken($user_token);
        if (empty($user_data)) {
            header('HTTP/1.1 402 User already logged in on a different device', true, 402);
            $this->output->set_output(json_encode(['result' => -2, 'msg' => 'User already logged in on a different device']));
            return FALSE;
        }
        $email = $this->input->post('email');
        if (empty($email)) {
            $this->output->set_output(json_encode(['result' => 0, 'msg' => 'Email is Required!!!.', 'data' => null]));
            return false;
        }
        $mail_exist = $this->Api_model->emailVerify($email);
        if (!$mail_exist) {
            $otp = mt_rand(1111, 9999);
            // for mail
            $mail['subject'] = 'Otp For Email Change!';
            $mail['message'] = 'Your Otp Is ' . $otp;
            $mail['email'] = $email;
            // $this->sendMail($mail);
            $result = $this->Api_model->sendEmailOtp($otp, $email);
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Otp Sent on your mail.', 'data' => $result]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'User Already exist.', 'data' => null]));
            return false;
        }
    }

    public function sendEmailOtp()
    {
        $this->output->set_content_type('application/json');
        $this->form_validation->set_rules('email', 'Email ', 'required|valid_email');
        if ($this->form_validation->run() === false) {
            $this->output->set_output(json_encode(['result' => 0, 'msg' => $this->form_validation->error_array()]));
            return false;
        }
        $email = $this->input->post('email');
        $patient_id = $this->input->post('patient_id');
        if (empty($email)) {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Email is required.']));
            return false;
        }
        $otp = mt_rand(1111, 9999);
        $result = $this->Api_model->sendEmailOtp($otp, $patient_id);
        if ($result) {
            // for mail
            $mail['subject'] = 'Otp For Email!';
            $mail['message'] = 'Your Otp Is' . $otp;
            $mail['email'] = $email;
            //$this->sendMail($mail);
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Otp Send Successfully', 'data' => $result]));
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Failed to send otp.']));
        }
    }

    public function updatePassword()
    {
        $this->output->set_content_type('application/json');
        $patient_id = $this->input->post('patient_id');
        $new_pass = $this->input->post('new_password');
        $c_pass = $this->input->post('confirm_password');
        if ($new_pass == $c_pass) {
            $result = $this->Api_model->updatePassword($patient_id, $new_pass);
            if ($result) {
                $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Password Update successfully']));
            } else {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Password Update Failed']));
            }
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'New and Confirm password did not match.']));
        }
    }

    public function setToken()
    {
        $this->output->set_content_type('application/json');
        $patient_id = $this->input->post('patient_id');
        $token_id = $this->input->post('firebase_token');
        $device_type = $this->input->post('device_type');
        $check = $this->Api_model->checkTokenid($token_id, $patient_id);
        if ($check) {
            $this->output->set_output(json_encode(['result' => 0, 'msg' => 'Token Already Exists', 'data' => NULL]));
            return false;
        } else {
            $this->Api_model->deleteToken($patient_id);
            $result = $this->Api_model->updatefToken($patient_id, $token_id, $device_type);
            if ($result) {
                $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Token Id Updated']));
                return false;
            } else {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Fail To Update Token Id', 'data' => NULL]));
                return false;
            }
        }
    }

    public function removeProfile()
    {
        $this->output->set_content_type('application/json');
        $patient_token = $this->input->get_request_header('token');
        $patient_data = $this->Api_model->getUserByToken($patient_token);
        if (empty($patient_data)) {
            header('HTTP/1.1 402 User already logged in on a different device', true, 402);
            $this->output->set_output(json_encode(['result' => -2, 'msg' => 'User already logged in on a different device']));
            return false;
        }
        $patient_id = $patient_data['patient_id'];
        $result = $this->Api_model->removeProfile($patient_id);
        if ($result) {
            $response = $this->Api_model->getPatientByID($patient_id);
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Profile Removed Successfully !!', 'data' => $response]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Falied to Remove', 'data' => NULL]));
            return false;
        }
    }

    public function verifyemail($user_id)
    {
        $user_id = decryptId($user_id);
        $data['result'] = $this->Api_model->verifyemail($user_id);
        $data['title'] = 'Verify Email';
        $this->load->view('admin/verifyemail', $data);
    }

    /// ambuj
    public function getProducts()
    {
        $this->output->set_content_type('application/json');
        $category_id = $this->input->post('category_id');
        $result = $this->Api_model->getProductsBycategoryid($category_id);
        if ($result) {
            if (!empty($result)) {
                $i = 0;
                foreach ($result as  $row) {
                    $result[$i]['thumbnail_image'] = base_url('uploads/product/thumbnail/') . $row['thumbnail_image'];
                    $i++;
                }
            }
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Products fetched Successfully.', 'data' => $result]));
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'No Record Found!!']));
        }
    }

    public function getProductDetails()
    {
        $this->output->set_content_type('application/json');
        $this->form_validation->set_rules('product_id', 'Product Id ', 'required');
        if ($this->form_validation->run() === false) {
            $vaidation = $this->form_validation->error_array();
            if (!empty($vaidation)) {
                foreach ($vaidation as $valid) {
                    $this->output->set_output(json_encode(['result' => 0, 'msg' => $valid]));
                    return false;
                }
            }
        }
        $pid = $this->input->post('product_id');
        $result = $this->Api_model->getProductDetail($pid);
        $images = $this->Api_model->getProductImagesByPID($pid);
        if ($result) {
            if (!empty($result)) {
                $result['thumbnail_image'] = base_url('uploads/product/thumbnail/') . $result['thumbnail_image'];
                $result['currency'] = '€';
                $i = 0;
                foreach ($images as $img) {
                    $images[$i]['image_name'] = base_url('uploads/product/') . $img['image_name'];
                    $i++;
                }
                $count=count($images);
                if(!empty($result)){
                    $images[$count]['product_image_id']=0;
                    $images[$count]['image_name']=$result['thumbnail_image'];
                    
                }
                
                $result['product_images'] = $images;
                $result['similar_product'] = $this->Api_model->getSimilarproduct($pid, $result['category_id']);
                if (!empty($result['similar_product'])) {
                    $j = 0;
                    foreach ($result['similar_product'] as $simg) {
                        $result['similar_product'][$j]['thumbnail_image'] = base_url('uploads/product/thumbnail/') . $simg['thumbnail_image'];
                        $j++;
                    }
                }
            }
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Products fetched Successfully.', 'data' => $result]));
        } else {
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'No Record Found!!','data'=>NULL]));
        }
    }

    public function productSearch(){
        $this->output->set_content_type('application/json');
        $cid = $this->input->post('category_id');
        $keyword = $this->input->post('keyword');
        $result = $this->Api_model->getProductSearch($keyword, $cid);
        if (!empty($result)) {
            $i = 0;
            foreach ($result as  $row) {
                $result[$i]['thumbnail_image'] = base_url('uploads/product/thumbnail/') . $row['thumbnail_image'];
                 $result[$i]['product_description'] = strip_tags($row['product_description']);
                $i++;
            }
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Products fetched Successfully.', 'data' => $result]));
        } else {
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'No Record Found!!', 'data'=> NULL]));
        }
    }

    // public function information()
    // {
    //     $this->output->set_content_type('application/json');
    //     $this->form_validation->set_rules('name', 'Name', 'required');
    //     $this->form_validation->set_rules('email', 'Email', 'required');
    //     $this->form_validation->set_rules('zipcode', 'Zip code', 'required');
    //     $this->form_validation->set_rules('delivery_period', 'Delivery Period', 'required');
    //     $this->form_validation->set_rules('specify', 'Specify', 'required');
    //     if ($this->form_validation->run() === false) {
    //         $vaidation = $this->form_validation->error_array();
    //         if (!empty($vaidation)) {
    //             foreach ($vaidation as $valid) {
    //                 $this->output->set_output(json_encode(['result' => 0, 'msg' => $valid]));
    //                 return false;
    //             }
    //         }
    //     }
    //     $step = $this->input->post('step');
    //     $unique_id = $this->input->post('main_unique_id');
    //     $user_id=$this->input->post('user_id');
    //     $product_id=$this->input->post('product_id');
    //     $main_unique_id_data=$this->Api_model->checkMainUnique_id($unique_id);
    //     if(empty($product_id)){
    //         $product_id=0;
    //     }
    //     if (empty($main_unique_id_data)) {
    //         // user for connect the table together
    //         $main_unique_id = $this->uniqueId();
    //         $data = array(
    //             'main_unique_id'    => $main_unique_id,
    //             'user_id'           =>$user_id,
    //             'name'              => $this->input->post('name'),
    //             'email'             => $this->input->post('email'),
    //             'zipcode'           => $this->input->post('zipcode'),
    //             'delivery_period'   => $this->input->post('delivery_period'),
    //             'specify'           => $this->input->post('specify'),
    //             'product_id'        =>  $product_id,
    //             'steps'             => 'information',
    //             'hourse_image'      => NULL,
    //             'status'            => 'Active',
    //             'is_complete'       => 'no',
    //             'date_added'        => date('Y-m-d H:i:s'),
    //         );
    //         $result = $this->Api_model->information($data);
    //     } else {
    //         $data = array(
    //             'user_id'           =>$user_id,
    //             'name'              => $this->input->post('name'),
    //             'email'             => $this->input->post('email'),
    //             'zipcode'           => $this->input->post('zipcode'),
    //             'delivery_period'   => $this->input->post('delivery_period'),
    //             'specify'           => $this->input->post('specify'),
    //             'product_id'        =>  $product_id,
    //             'steps'             => 'information',
    //         );
    //         $result = $this->Api_model->updateInformation($data, $unique_id);
    //     }
    //     if ($result) {
    //         $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Information page added.', 'data' => $result]));
    //         return false;
    //     } else {
    //         $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Opps Try Again Lator!!.']));
    //         return false;
    //     }
    // }
    public function information()
    {
        $this->output->set_content_type('application/json');
        $this->form_validation->set_rules('name', 'Name', 'required');
        $this->form_validation->set_rules('email', 'Email', 'required');
        $this->form_validation->set_rules('zipcode', 'Zip code', 'required');
        $this->form_validation->set_rules('delivery_period', 'Delivery Period', 'required');
        $this->form_validation->set_rules('specify', 'Specify', 'required');
        $this->form_validation->set_rules('form_opening_type', 'form opening type', 'required');
        if ($this->form_validation->run() === false) {
            $vaidation = $this->form_validation->error_array();
            if (!empty($vaidation)) {
                foreach ($vaidation as $valid) {
                    $this->output->set_output(json_encode(['result' => 0, 'msg' => $valid]));
                    return false;
                }
            }
        }
        $step = $this->input->post('step');
        $unique_id = $this->input->post('main_unique_id');
        $user_id=$this->input->post('user_id');
        $product_id=$this->input->post('product_id');
        $main_unique_id_data=$this->Api_model->checkMainUnique_id($unique_id);
        $form_open=$this->input->post('form_opening_type');
        if(empty($product_id)){
            $product_id=0;
        }
        if (empty($main_unique_id_data)) {
            // user for connect the table together
            $main_unique_id = $this->uniqueId();
            $data = array(
                'main_unique_id'    => $main_unique_id,
                'user_id'           =>$user_id,
                'name'              => $this->input->post('name'),
                'email'             => $this->input->post('email'),
                'zipcode'           => $this->input->post('zipcode'),
                'delivery_period'   => $this->input->post('delivery_period'),
                'specify'           => $this->input->post('specify'),
                'product_id'        =>  $product_id,
                'steps'             => 'information',
                'hourse_image'      => NULL,
                'status'            => 'Active',
                'is_complete'       => 'no',
                'date_added'        => date('Y-m-d H:i:s'),
                'form_open'         => $form_open
            );
            $result = $this->Api_model->information($data);
        } else {
            $data = array(
                'user_id'           =>$user_id,
                'name'              => $this->input->post('name'),
                'email'             => $this->input->post('email'),
                'zipcode'           => $this->input->post('zipcode'),
                'delivery_period'   => $this->input->post('delivery_period'),
                'specify'           => $this->input->post('specify'),
                'product_id'        =>  $product_id,
                'steps'             => 'information',
                'form_open'         => $form_open
            );
            $result = $this->Api_model->updateInformation($data, $unique_id);
        }
        if ($result) {
            if($form_open == "other_products"){
                $this->Api_model->updateStatus($main_unique_id, ['steps' => 'others']);
                $this->Api_model->updateStatus($main_unique_id, ['is_complete' => 'yes']);
                $result=$this->Api_model->getInformation($main_unique_id);
            }
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Information page added.', 'data' => $result]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Opps Try Again Lator!!.']));
            return false;
        }
    }
    public function additionalinformation()
    {
        $this->output->set_content_type('application/json');
        $this->form_validation->set_rules('main_unique_id', 'Main Unique id', 'required');
        $this->form_validation->set_rules('purpose', 'Purpose of Boot', 'required');
        $this->form_validation->set_rules('other_information', 'Other Information', 'required');
        $this->form_validation->set_rules('duration', 'Duration in hours', 'required');
        $this->form_validation->set_rules('preferred_hoof_model', 'Preferred Hoof Model', 'required');
        if ($this->form_validation->run() === false) {
            $vaidation = $this->form_validation->error_array();
            if (!empty($vaidation)) {
                foreach ($vaidation as $valid) {
                    $this->output->set_output(json_encode(['result' => 0, 'msg' => $valid]));
                    return false;
                }
            }
        }
        $step = $this->input->post('step');
        $unique_id = $this->input->post('main_unique_id');
        $main_unique_id_data=$this->Api_model->checkMainUniqueAdditnal($unique_id);
        //dd($main_unique_id_data); die;
        // REMOVE NEW DESIGNS
        // $images = [];
        // if (!empty($_FILES['image_url']['name'][0])) {
        //     $path = "uploads/bootmodel/";
        //     $file_name = "image_url";
        //     $images = $this->upload_files($path, $file_name);
        //     if ($this->upload->display_errors()) {
        //         $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Bootmodel Image :' . strip_tags($this->upload->display_errors())]));
        //         $this->session->unset_userdata('error');
        //         return FALSE;
        //     }
        // }

        if (empty($main_unique_id_data)) {
            // user for connect the table together
            $data = array(
                'main_unique_id'        => $unique_id,
                'purpose_of_boots'      => $this->input->post('purpose'),
                'other_information'     => $this->input->post('other_information'),
                'duration'              => $this->input->post('duration'),
                'main_unique_id'        => $this->input->post('main_unique_id'),
                'preferred_hoof_model'  => $this->input->post('preferred_hoof_model'),
                'status'                => 'Active',
            );
            $result = $this->Api_model->additionalinformation($data);
            // if (!empty($images)) {
            //     foreach ($images as $img) {
            //         $imgdata = array(
            //             'image_url'         => $img,
            //             'main_unique_id'    => $unique_id,
            //             'status'            => 'Active'
            //         );
            //         $this->Api_model->additionalinformationImages($imgdata);
            //     }
            // }
            $this->Api_model->updateStatus($unique_id, ['steps' => 'additinal_info']);
        } else {
            $data = array(
                'purpose_of_boots'                => $this->input->post('purpose'),
                'other_information'      => $this->input->post('other_information'),
                'duration'               => $this->input->post('duration'),
                'preferred_hoof_model'  => $this->input->post('preferred_hoof_model'),
                'main_unique_id'         => $this->input->post('main_unique_id'),
                'status'                 => 'Active',
            );
            $result = $this->Api_model->updateadditionalinformation($data, $unique_id);
            // $this->Api_model->delteadditionalinformationImages($unique_id);
            // if (!empty($images)) {
            //     foreach ($images as $img) {
            //         $imgdata = array(
            //             'image_url'         => $img,
            //             'main_unique_id'    => $unique_id,
            //             'status'            => 'Active'
            //         );
            //         $this->Api_model->additionalinformationImages($imgdata);
            //     }
            // }
        }
        if ($result) {
            
            //$result['steps'] = 'additinal_info';
            // $bootimages = $this->Api_model->getImagesByMainid($unique_id);
            // if (!empty($bootimages)) {
            //     $i = 0;
            //     foreach ($bootimages as $bimg) {
            //         $bootimages[$i]['image_url'] = base_url('uploads/bootmodel/') . $bimg['image_url'];
            //     }
            // }
            // $result['images'] = $bootimages;
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Additinal Information page added.', 'data' => $result]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Opps Try Again Lator!!.']));
            return false;
        }
    }

    // public function measurement()
    // {
    //     $this->output->set_content_type('application/json');
    //     $this->form_validation->set_rules('main_unique_id', 'Main Unique id', 'required');
    //     $this->form_validation->set_rules('front_right_leg_width', 'Front Right Leg Width(cm)', 'required');
    //     $this->form_validation->set_rules('front_right_leg_length', 'Front Right Leg Lenght(cm)', 'required');
    //     $this->form_validation->set_rules('front_left_leg_width', 'Front Left Leg Width(cm)', 'required');
    //     $this->form_validation->set_rules('front_left_leg_length', 'Front Left Leg Lenght(cm)', 'required');
    //     $this->form_validation->set_rules('rear_right_leg_width', 'Rear Right Leg Width(cm)', 'required');
    //     $this->form_validation->set_rules('rear_right_leg_length', 'Rear Right Leg Lenght(cm)', 'required');
    //     $this->form_validation->set_rules('rear_left_leg_width', 'Rear Left Leg Width(cm)', 'required');
    //     $this->form_validation->set_rules('rear_left_leg_length', 'Rear Left Leg Lenght(cm)', 'required');

    //     if ($this->form_validation->run() === false) {
    //         $vaidation = $this->form_validation->error_array();
    //         if (!empty($vaidation)) {
    //             foreach ($vaidation as $valid) {
    //                 $this->output->set_output(json_encode(['result' => 0, 'msg' => $valid]));
    //                 return false;
    //             }
    //         }
    //     }
    //     $step = $this->input->post('step');
    //     $unique_id = $this->input->post('main_unique_id');
    //     // for update back btn
    //     $main_unique_id_data=$this->Api_model->checkMainUniquemeasurement($unique_id);

    //     $front_right_old_image = $this->Api_model->getMeasurement('front_right_leg', $unique_id);
    //     $front_left_old_image = $this->Api_model->getMeasurement('front_left_leg', $unique_id);
    //     $rear_right_old_image = $this->Api_model->getMeasurement('rear_right_leg', $unique_id);
    //     $rear_left_old_image = $this->Api_model->getMeasurement('rear_left_leg', $unique_id);

    //     if (!empty($front_right_old_image)) {
    //         $front_right_leg_image_front_view = $front_right_old_image['front_view'];
    //         $front_right_leg_image_side_view = $front_right_old_image['side_view'];
    //         $front_right_leg_image_hoof_sole = $front_right_old_image['hoof_sole'];
    //         $front_right_leg_image_measuring_tape = $front_right_old_image['measuring_tape'];
    //     } else {
    //         $front_right_leg_image_front_view = NULL;
    //         $front_right_leg_image_side_view = NULL;
    //         $front_right_leg_image_hoof_sole = NUll;
    //         $front_right_leg_image_measuring_tape = null;
    //     }
    //     if (!empty($front_left_old_image)) {
    //         $front_left_leg_image_front_view = $front_left_old_image['front_view'];
    //         $front_left_leg_image_side_view = $front_left_old_image['side_view'];
    //         $front_left_leg_image_hoof_sole = $front_left_old_image['hoof_sole'];
    //         $front_left_leg_image_measuring_tape = $front_left_old_image['measuring_tape'];
    //     } else {
    //         $front_left_leg_image_front_view = NULL;
    //         $front_left_leg_image_side_view = NULL;
    //         $front_left_leg_image_hoof_sole = NUll;
    //         $front_left_leg_image_measuring_tape = null;
    //     }
    //     if (!empty($rear_right_old_image)) {
    //         $rear_right_leg_image_front_view = $rear_right_old_image['front_view'];
    //         $rear_right_leg_image_side_view = $rear_right_old_image['side_view'];
    //         $rear_right_leg_image_hoof_sole = $rear_right_old_image['hoof_sole'];
    //         $rear_right_leg_image_measuring_tape = $rear_right_old_image['measuring_tape'];
    //     } else {
    //         $rear_right_leg_image_front_view = NULL;
    //         $rear_right_leg_image_side_view = NULL;
    //         $rear_right_leg_image_hoof_sole = NUll;
    //         $rear_right_leg_image_measuring_tape = null;
    //     }
    //     if (!empty($rear_left_old_image)) {
    //         $rear_left_leg_image_front_view = $rear_left_old_image['front_view'];
    //         $rear_left_leg_image_side_view = $rear_left_old_image['side_view'];
    //         $rear_left_leg_image_hoof_sole = $rear_left_old_image['hoof_sole'];
    //         $rear_left_leg_image_measuring_tape = $rear_left_old_image['measuring_tape'];
    //     } else {
    //         $rear_left_leg_image_front_view = NULL;
    //         $rear_left_leg_image_side_view = NULL;
    //         $rear_left_leg_image_hoof_sole = NUll;
    //         $rear_left_leg_image_measuring_tape = null;
    //     }

    //     //------------------------------------------FRONT RIGHT-------------------------------------------------------
    //     if (!empty($_FILES['front_right_front_view_image']['name'])) {
    //         $path = "uploads/measurementimages/";
    //         $file_name = "front_right_front_view_image";
    //         $front_right_leg_image_front_view = $this->doUploadImage($path, $file_name);
    //         if ($this->upload->display_errors()) {
    //             $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
    //             $this->session->unset_userdata('error');
    //             return FALSE;
    //         }
    //     }

    //     if (!empty($_FILES['front_right_side_view_image']['name'])) {
    //         $path = "uploads/measurementimages/";
    //         $file_name = "front_right_side_view_image";
    //         $front_right_leg_image_side_view = $this->doUploadImage($path, $file_name);
    //         if ($this->upload->display_errors()) {
    //             $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
    //             $this->session->unset_userdata('error');
    //             return FALSE;
    //         }
    //     }

    //     if (!empty($_FILES['front_right_hoof_sole_image']['name'])) {
    //         $path = "uploads/measurementimages/";
    //         $file_name = "front_right_hoof_sole_image";
    //         $front_right_leg_image_hoof_sole = $this->doUploadImage($path, $file_name);
    //         if ($this->upload->display_errors()) {
    //             $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
    //             $this->session->unset_userdata('error');
    //             return FALSE;
    //         }
    //     }

    //     if (!empty($_FILES['front_right_measuring_tape_image']['name'])) {
    //         $path = "uploads/measurementimages/";
    //         $file_name = "front_right_measuring_tape_image";
    //         $front_right_leg_image_measuring_tape = $this->doUploadImage($path, $file_name);
    //         if ($this->upload->display_errors()) {
    //             $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
    //             $this->session->unset_userdata('error');
    //             return FALSE;
    //         }
    //     }

    //     //---------------------------------------Left Right---------------------------------------------------------------
    //     if (!empty($_FILES['front_left_front_view_image']['name'])) {
    //         $path = "uploads/measurementimages/";
    //         $file_name = "front_left_front_view_image";
    //         $front_left_leg_image_front_view = $this->doUploadImage($path, $file_name);
    //         if ($this->upload->display_errors()) {
    //             $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
    //             $this->session->unset_userdata('error');
    //             return FALSE;
    //         }
    //     }

    //     if (!empty($_FILES['front_left_side_view_image']['name'])) {
    //         $path = "uploads/measurementimages/";
    //         $file_name = "front_left_side_view_image";
    //         $front_left_leg_image_side_view = $this->doUploadImage($path, $file_name);
    //         if ($this->upload->display_errors()) {
    //             $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
    //             $this->session->unset_userdata('error');
    //             return FALSE;
    //         }
    //     }

    //     if (!empty($_FILES['front_left_hoof_sole_image']['name'])) {
    //         $path = "uploads/measurementimages/";
    //         $file_name = "front_left_hoof_sole_image";
    //         $front_left_leg_image_hoof_sole = $this->doUploadImage($path, $file_name);
    //         if ($this->upload->display_errors()) {
    //             $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
    //             $this->session->unset_userdata('error');
    //             return FALSE;
    //         }
    //     }

    //     if (!empty($_FILES['front_left_measuring_tape_image']['name'])) {
    //         $path = "uploads/measurementimages/";
    //         $file_name = "front_left_measuring_tape_image";
    //         $front_left_leg_image_measuring_tape = $this->doUploadImage($path, $file_name);
    //         if ($this->upload->display_errors()) {
    //             $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
    //             $this->session->unset_userdata('error');
    //             return FALSE;
    //         }
    //     }

    //     //---------------------------------------Rear left---------------------------------------------------------------
    //     if (!empty($_FILES['rear_left_front_view_image']['name'])) {
    //         $path = "uploads/measurementimages/";
    //         $file_name = "rear_left_front_view_image";
    //         $rear_left_leg_image_front_view = $this->doUploadImage($path, $file_name);
    //         if ($this->upload->display_errors()) {
    //             $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
    //             $this->session->unset_userdata('error');
    //             return FALSE;
    //         }
    //     }

    //     if (!empty($_FILES['rear_left_side_view_image']['name'])) {
    //         $path = "uploads/measurementimages/";
    //         $file_name = "rear_left_side_view_image";
    //         $rear_left_leg_image_side_view = $this->doUploadImage($path, $file_name);
    //         if ($this->upload->display_errors()) {
    //             $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
    //             $this->session->unset_userdata('error');
    //             return FALSE;
    //         }
    //     }

    //     if (!empty($_FILES['rear_left_hoof_sole_image']['name'])) {
    //         $path = "uploads/measurementimages/";
    //         $file_name = "rear_left_hoof_sole_image";
    //         $rear_left_leg_image_hoof_sole = $this->doUploadImage($path, $file_name);
    //         if ($this->upload->display_errors()) {
    //             $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
    //             $this->session->unset_userdata('error');
    //             return FALSE;
    //         }
    //     }

    //     if (!empty($_FILES['rear_left_measuring_tape_image']['name'])) {
    //         $path = "uploads/measurementimages/";
    //         $file_name = "rear_left_measuring_tape_image";
    //         $rear_left_leg_image_measuring_tape = $this->doUploadImage($path, $file_name);
    //         if ($this->upload->display_errors()) {
    //             $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
    //             $this->session->unset_userdata('error');
    //             return FALSE;
    //         }
    //     }

    //     //------------------------------------------Rear RIGHT-------------------------------------------------------
    //     if (!empty($_FILES['rear_right_front_view_image']['name'])) {
    //         $path = "uploads/measurementimages/";
    //         $file_name = "rear_right_front_view_image";
    //         $rear_right_leg_image_front_view = $this->doUploadImage($path, $file_name);
    //         if ($this->upload->display_errors()) {
    //             $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
    //             $this->session->unset_userdata('error');
    //             return FALSE;
    //         }
    //     }

    //     if (!empty($_FILES['rear_right_side_view_image']['name'])) {
    //         $path = "uploads/measurementimages/";
    //         $file_name = "rear_right_side_view_image";
    //         $rear_right_leg_image_side_view = $this->doUploadImage($path, $file_name);
    //         if ($this->upload->display_errors()) {
    //             $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
    //             $this->session->unset_userdata('error');
    //             return FALSE;
    //         }
    //     }

    //     if (!empty($_FILES['rear_right_hoof_sole_image']['name'])) {
    //         $path = "uploads/measurementimages/";
    //         $file_name = "rear_right_hoof_sole_image";
    //         $rear_right_leg_image_hoof_sole = $this->doUploadImage($path, $file_name);
    //         if ($this->upload->display_errors()) {
    //             $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
    //             $this->session->unset_userdata('error');
    //             return FALSE;
    //         }
    //     }

    //     if (!empty($_FILES['rear_right_measuring_tape_image']['name'])) {
    //         $path = "uploads/measurementimages/";
    //         $file_name = "rear_right_measuring_tape_image";
    //         $rear_right_leg_image_measuring_tape = $this->doUploadImage($path, $file_name);
    //         if ($this->upload->display_errors()) {
    //             $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
    //             $this->session->unset_userdata('error');
    //             return FALSE;
    //         }
    //     }

    //     if (empty($main_unique_id_data)) {

    //         // user for connect the table together
    //         $front_right_leg = array(
    //             'main_unique_id'        => $unique_id,
    //             'width'                 => $this->input->post('front_right_leg_width'),
    //             'lenght'                => $this->input->post('front_right_leg_length'),
    //             'front_view'            =>$front_right_leg_image_front_view,
    //             'side_view'             =>$front_right_leg_image_side_view,
    //             'hoof_sole'             =>$front_right_leg_image_hoof_sole,
    //             'measuring_tape'        =>$front_right_leg_image_measuring_tape,
    //             'type'                  => 'front_right_leg',
    //             'status'                => 'Active',
    //         );
    //         $front_left_leg = array(
    //             'main_unique_id'        => $unique_id,
    //             'width'                 => $this->input->post('front_left_leg_width'),
    //             'lenght'                => $this->input->post('front_left_leg_length'),
    //             'front_view'            =>$front_left_leg_image_front_view,
    //             'side_view'             =>$front_left_leg_image_side_view,
    //             'hoof_sole'             =>$front_left_leg_image_hoof_sole,
    //             'measuring_tape'        =>$front_left_leg_image_measuring_tape,
    //             'type'                  => 'front_left_leg',
    //             'status'                => 'Active',
    //         );
    //         $rear_right_leg = array(
    //             'main_unique_id'        => $unique_id,
    //             'width'                 => $this->input->post('rear_right_leg_width'),
    //             'lenght'                => $this->input->post('rear_right_leg_length'),
    //             'front_view'            =>$rear_right_leg_image_front_view,
    //             'side_view'             =>$rear_right_leg_image_side_view,
    //             'hoof_sole'             =>$rear_right_leg_image_hoof_sole,
    //             'measuring_tape'        =>$rear_right_leg_image_measuring_tape,
    //             'type'                  => 'rear_right_leg',
    //             'status'                => 'Active',
    //         );
    //         $rear_left_leg = array(
    //             'main_unique_id'        => $unique_id,
    //             'width'                 => $this->input->post('rear_left_leg_width'),
    //             'lenght'                => $this->input->post('rear_left_leg_length'),
    //             'front_view'            =>$rear_left_leg_image_front_view,
    //             'side_view'             =>$rear_left_leg_image_side_view,
    //             'hoof_sole'             =>$rear_left_leg_image_hoof_sole,
    //             'measuring_tape'        =>$rear_left_leg_image_measuring_tape,
    //             'type'                  => 'rear_left_leg',
    //             'status'                => 'Active',
    //         );
    //         $this->Api_model->measurement($front_right_leg);
    //         $this->Api_model->measurement($front_left_leg);
    //         $this->Api_model->measurement($rear_right_leg);
    //         $this->Api_model->measurement($rear_left_leg);
    //         $this->Api_model->updateStatus($unique_id, ['steps' => 'measurement']);
    //     } else {
    //         $front_right_leg = array(
    //             'width'                 => $this->input->post('front_right_leg_width'),
    //             'lenght'                => $this->input->post('front_right_leg_length'),
    //             'front_view'            =>$front_right_leg_image_front_view,
    //             'side_view'             =>$front_right_leg_image_side_view,
    //             'hoof_sole'             =>$front_right_leg_image_hoof_sole,
    //             'measuring_tape'        =>$front_right_leg_image_measuring_tape,
    //         );
    //         $front_left_leg = array(
    //             'width'                 => $this->input->post('front_left_leg_width'),
    //             'lenght'                => $this->input->post('front_left_leg_length'),
    //             'front_view'            =>$front_left_leg_image_front_view,
    //             'side_view'             =>$front_left_leg_image_side_view,
    //             'hoof_sole'             =>$front_left_leg_image_hoof_sole,
    //             'measuring_tape'        =>$front_left_leg_image_measuring_tape,
    //         );
    //         $rear_right_leg = array(
    //             'width'                 => $this->input->post('rear_right_leg_width'),
    //             'lenght'                => $this->input->post('rear_right_leg_length'),
    //             'front_view'            =>$rear_right_leg_image_front_view,
    //             'side_view'             =>$rear_right_leg_image_side_view,
    //             'hoof_sole'             =>$rear_right_leg_image_hoof_sole,
    //             'measuring_tape'        =>$rear_right_leg_image_measuring_tape,
    //         );
    //         $rear_left_leg = array(
    //             'width'                 => $this->input->post('rear_left_leg_width'),
    //             'lenght'                => $this->input->post('rear_left_leg_length'),
    //             'front_view'            =>$rear_left_leg_image_front_view,
    //             'side_view'             =>$rear_left_leg_image_side_view,
    //             'hoof_sole'             =>$rear_left_leg_image_hoof_sole,
    //             'measuring_tape'        =>$rear_left_leg_image_measuring_tape,
    //         );

    //         $this->Api_model->updateMeasurement($front_right_leg, 'front_right_leg', $unique_id);
    //         $this->Api_model->updateMeasurement($front_left_leg, 'front_left_leg', $unique_id);
    //         $this->Api_model->updateMeasurement($rear_right_leg, 'rear_right_leg', $unique_id);
    //         $this->Api_model->updateMeasurement($rear_left_leg, 'rear_left_leg', $unique_id);
    //     }
    //     if ($result = true) {
    //         $results = $this->Api_model->getMeasurements($unique_id);
    //         if (!empty($results)) {
    //             $i = 0;
    //             foreach ($results as $key=>$row) {
    //                 $results[$i]['front_view'] = base_url('uploads/measurementimages/' . $row['front_view']);
    //                 $results[$i]['side_view'] = base_url('uploads/measurementimages/' . $row['side_view']);
    //                 $results[$i]['hoof_sole'] = base_url('uploads/measurementimages/' . $row['hoof_sole']);
    //                 $results[$i]['measuring_tape'] = base_url('uploads/measurementimages/' . $row['measuring_tape']);
    //                 $i++;
    //             }
    //         }
    //         $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Measurement Information.', 'steps' => 'measurement', 'data' => $results]));
    //         return false;
    //     } else {
    //         $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Opps Try Again Lator!!.']));
    //         return false;
    //     }
    // }
    
    public function measurement()
    {
        $this->output->set_content_type('application/json');
        $this->form_validation->set_rules('main_unique_id', 'Main Unique id', 'required');
        // $this->form_validation->set_rules('front_right_leg_width', 'Front Right Leg Width(cm)', 'required');
        // $this->form_validation->set_rules('front_right_leg_length', 'Front Right Leg Lenght(cm)', 'required');
        // $this->form_validation->set_rules('front_left_leg_width', 'Front Left Leg Width(cm)', 'required');
        // $this->form_validation->set_rules('front_left_leg_length', 'Front Left Leg Lenght(cm)', 'required');
        // $this->form_validation->set_rules('rear_right_leg_width', 'Rear Right Leg Width(cm)', 'required');
        // $this->form_validation->set_rules('rear_right_leg_length', 'Rear Right Leg Lenght(cm)', 'required');
        // $this->form_validation->set_rules('rear_left_leg_width', 'Rear Left Leg Width(cm)', 'required');
        // $this->form_validation->set_rules('rear_left_leg_length', 'Rear Left Leg Lenght(cm)', 'required');

        if ($this->form_validation->run() === false) {
            $vaidation = $this->form_validation->error_array();
            if (!empty($vaidation)) {
                foreach ($vaidation as $valid) {
                    $this->output->set_output(json_encode(['result' => 0, 'msg' => $valid]));
                    return false;
                }
            }
        }
        $step = $this->input->post('step');
        $unique_id = $this->input->post('main_unique_id');
        // for update back btn
        $main_unique_id_data=$this->Api_model->checkMainUniquemeasurement($unique_id);

        $front_right_old_image = $this->Api_model->getMeasurement('front_right_leg', $unique_id);
        $front_left_old_image = $this->Api_model->getMeasurement('front_left_leg', $unique_id);
        $rear_right_old_image = $this->Api_model->getMeasurement('rear_right_leg', $unique_id);
        $rear_left_old_image = $this->Api_model->getMeasurement('rear_left_leg', $unique_id);

        if (!empty($front_right_old_image)) {
            $front_right_leg_image_front_view = $front_right_old_image['front_view'];
            $front_right_leg_image_side_view = $front_right_old_image['side_view'];
            $front_right_leg_image_hoof_sole = $front_right_old_image['hoof_sole'];
            $front_right_leg_image_hoof_sole_second = $front_right_old_image['hoof_sole_second'];
            // $front_right_leg_image_measuring_tape = $front_right_old_image['measuring_tape'];
        } else {
            $front_right_leg_image_front_view = NULL;
            $front_right_leg_image_side_view = NULL;
            $front_right_leg_image_hoof_sole = NUll;
            $front_right_leg_image_hoof_sole_second = NUll;
            // $front_right_leg_image_measuring_tape = null;
        }
        if (!empty($front_left_old_image)) {
            $front_left_leg_image_front_view = $front_left_old_image['front_view'];
            $front_left_leg_image_side_view = $front_left_old_image['side_view'];
            $front_left_leg_image_hoof_sole = $front_left_old_image['hoof_sole'];
            $front_left_leg_image_hoof_sole_second = $front_left_old_image['hoof_sole_second'];
            // $front_left_leg_image_measuring_tape = $front_left_old_image['measuring_tape'];
        } else {
            $front_left_leg_image_front_view = NULL;
            $front_left_leg_image_side_view = NULL;
            $front_left_leg_image_hoof_sole = NUll;
            $front_left_leg_image_hoof_sole_second = NUll;
            // $front_left_leg_image_measuring_tape = null;
        }
        if (!empty($rear_right_old_image)) {
            $rear_right_leg_image_front_view = $rear_right_old_image['front_view'];
            $rear_right_leg_image_side_view = $rear_right_old_image['side_view'];
            $rear_right_leg_image_hoof_sole = $rear_right_old_image['hoof_sole'];
            $rear_right_leg_image_hoof_sole_second = $rear_right_old_image['hoof_sole_second'];
            // $rear_right_leg_image_measuring_tape = $rear_right_old_image['measuring_tape'];
        } else {
            $rear_right_leg_image_front_view = NULL;
            $rear_right_leg_image_side_view = NULL;
            $rear_right_leg_image_hoof_sole = NUll;
            $rear_right_leg_image_hoof_sole_second = NUll;
            // $rear_right_leg_image_measuring_tape = null;
        }
        if (!empty($rear_left_old_image)) {
            $rear_left_leg_image_front_view = $rear_left_old_image['front_view'];
            $rear_left_leg_image_side_view = $rear_left_old_image['side_view'];
            $rear_left_leg_image_hoof_sole = $rear_left_old_image['hoof_sole'];
            $rear_left_leg_image_hoof_sole_second = $rear_left_old_image['hoof_sole_second'];
            // $rear_left_leg_image_measuring_tape = $rear_left_old_image['measuring_tape'];
        } else {
            $rear_left_leg_image_front_view = NULL;
            $rear_left_leg_image_side_view = NULL;
            $rear_left_leg_image_hoof_sole = NUll;
            $rear_left_leg_image_hoof_sole_second = NUll;
            // $rear_left_leg_image_measuring_tape = null;
        }

        //------------------------------------------FRONT RIGHT-------------------------------------------------------
        if (!empty($_FILES['front_right_front_view_image']['name'])) {
            $path = "uploads/measurementimages/";
            $file_name = "front_right_front_view_image";
            $front_right_leg_image_front_view = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        if (!empty($_FILES['front_right_side_view_image']['name'])) {
            $path = "uploads/measurementimages/";
            $file_name = "front_right_side_view_image";
            $front_right_leg_image_side_view = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        if (!empty($_FILES['front_right_hoof_sole_image']['name'])) {
            $path = "uploads/measurementimages/";
            $file_name = "front_right_hoof_sole_image";
            $front_right_leg_image_hoof_sole = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        if (!empty($_FILES['front_right_hoof_sole_second_image']['name'])) {
            $path = "uploads/measurementimages/";
            $file_name = "front_right_hoof_sole_second_image";
            $front_right_leg_image_hoof_sole_second = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        // if (!empty($_FILES['front_right_measuring_tape_image']['name'])) {
        //     $path = "uploads/measurementimages/";
        //     $file_name = "front_right_measuring_tape_image";
        //     $front_right_leg_image_measuring_tape = $this->doUploadImage($path, $file_name);
        //     if ($this->upload->display_errors()) {
        //         $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
        //         $this->session->unset_userdata('error');
        //         return FALSE;
        //     }
        // }

        //---------------------------------------Left Right---------------------------------------------------------------
        if (!empty($_FILES['front_left_front_view_image']['name'])) {
            $path = "uploads/measurementimages/";
            $file_name = "front_left_front_view_image";
            $front_left_leg_image_front_view = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        if (!empty($_FILES['front_left_side_view_image']['name'])) {
            $path = "uploads/measurementimages/";
            $file_name = "front_left_side_view_image";
            $front_left_leg_image_side_view = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        if (!empty($_FILES['front_left_hoof_sole_image']['name'])) {
            $path = "uploads/measurementimages/";
            $file_name = "front_left_hoof_sole_image";
            $front_left_leg_image_hoof_sole = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        if (!empty($_FILES['front_left_hoof_sole_second_image']['name'])) {
            $path = "uploads/measurementimages/";
            $file_name = "front_left_hoof_sole_second_image";
            $front_left_leg_image_hoof_sole_second = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        // if (!empty($_FILES['front_left_measuring_tape_image']['name'])) {
        //     $path = "uploads/measurementimages/";
        //     $file_name = "front_left_measuring_tape_image";
        //     $front_left_leg_image_measuring_tape = $this->doUploadImage($path, $file_name);
        //     if ($this->upload->display_errors()) {
        //         $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
        //         $this->session->unset_userdata('error');
        //         return FALSE;
        //     }
        // }

        //---------------------------------------Rear left---------------------------------------------------------------
        if (!empty($_FILES['rear_left_front_view_image']['name'])) {
            $path = "uploads/measurementimages/";
            $file_name = "rear_left_front_view_image";
            $rear_left_leg_image_front_view = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        if (!empty($_FILES['rear_left_side_view_image']['name'])) {
            $path = "uploads/measurementimages/";
            $file_name = "rear_left_side_view_image";
            $rear_left_leg_image_side_view = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        if (!empty($_FILES['rear_left_hoof_sole_image']['name'])) {
            $path = "uploads/measurementimages/";
            $file_name = "rear_left_hoof_sole_image";
            $rear_left_leg_image_hoof_sole = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        if (!empty($_FILES['rear_left_hoof_sole_second_image']['name'])) {
            $path = "uploads/measurementimages/";
            $file_name = "rear_left_hoof_sole_second_image";
            $rear_left_leg_image_hoof_sole_second = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        // if (!empty($_FILES['rear_left_measuring_tape_image']['name'])) {
        //     $path = "uploads/measurementimages/";
        //     $file_name = "rear_left_measuring_tape_image";
        //     $rear_left_leg_image_measuring_tape = $this->doUploadImage($path, $file_name);
        //     if ($this->upload->display_errors()) {
        //         $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
        //         $this->session->unset_userdata('error');
        //         return FALSE;
        //     }
        // }

        //------------------------------------------Rear RIGHT-------------------------------------------------------
        if (!empty($_FILES['rear_right_front_view_image']['name'])) {
            $path = "uploads/measurementimages/";
            $file_name = "rear_right_front_view_image";
            $rear_right_leg_image_front_view = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        if (!empty($_FILES['rear_right_side_view_image']['name'])) {
            $path = "uploads/measurementimages/";
            $file_name = "rear_right_side_view_image";
            $rear_right_leg_image_side_view = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        if (!empty($_FILES['rear_right_hoof_sole_image']['name'])) {
            $path = "uploads/measurementimages/";
            $file_name = "rear_right_hoof_sole_image";
            $rear_right_leg_image_hoof_sole = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        if (!empty($_FILES['rear_right_hoof_sole_second_image']['name'])) {
            $path = "uploads/measurementimages/";
            $file_name = "rear_right_hoof_sole_second_image";
            $rear_right_leg_image_hoof_sole_second = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        // if (!empty($_FILES['rear_right_measuring_tape_image']['name'])) {
        //     $path = "uploads/measurementimages/";
        //     $file_name = "rear_right_measuring_tape_image";
        //     $rear_right_leg_image_measuring_tape = $this->doUploadImage($path, $file_name);
        //     if ($this->upload->display_errors()) {
        //         $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
        //         $this->session->unset_userdata('error');
        //         return FALSE;
        //     }
        // }

        if (empty($main_unique_id_data)) {

            // user for connect the table together
            $front_right_leg = array(
                'main_unique_id'        => $unique_id,
                'width'                 => $this->input->post('front_right_leg_width'),
                'lenght'                => $this->input->post('front_right_leg_length'),
                'front_view'            =>$front_right_leg_image_front_view,
                'side_view'             =>$front_right_leg_image_side_view,
                'hoof_sole'             =>$front_right_leg_image_hoof_sole,
                'hoof_sole_second'      =>$front_right_leg_image_hoof_sole_second,
                // 'measuring_tape'        =>$front_right_leg_image_measuring_tape,
                'type'                  => 'front_right_leg',
                'status'                => 'Active',
            );
            $front_left_leg = array(
                'main_unique_id'        => $unique_id,
                'width'                 => $this->input->post('front_left_leg_width'),
                'lenght'                => $this->input->post('front_left_leg_length'),
                'front_view'            =>$front_left_leg_image_front_view,
                'side_view'             =>$front_left_leg_image_side_view,
                'hoof_sole'             =>$front_left_leg_image_hoof_sole,
                'hoof_sole_second'      =>$front_left_leg_image_hoof_sole_second,
                // 'measuring_tape'        =>$front_left_leg_image_measuring_tape,
                'type'                  => 'front_left_leg',
                'status'                => 'Active',
            );
            $rear_right_leg = array(
                'main_unique_id'        => $unique_id,
                'width'                 => $this->input->post('rear_right_leg_width'),
                'lenght'                => $this->input->post('rear_right_leg_length'),
                'front_view'            =>$rear_right_leg_image_front_view,
                'side_view'             =>$rear_right_leg_image_side_view,
                'hoof_sole'             =>$rear_right_leg_image_hoof_sole,
                'hoof_sole_second'      =>$rear_right_leg_image_hoof_sole_second,
                // 'measuring_tape'        =>$rear_right_leg_image_measuring_tape,
                'type'                  => 'rear_right_leg',
                'status'                => 'Active',
            );
            $rear_left_leg = array(
                'main_unique_id'        => $unique_id,
                'width'                 => $this->input->post('rear_left_leg_width'),
                'lenght'                => $this->input->post('rear_left_leg_length'),
                'front_view'            =>$rear_left_leg_image_front_view,
                'side_view'             =>$rear_left_leg_image_side_view,
                'hoof_sole'             =>$rear_left_leg_image_hoof_sole,
                'hoof_sole_second'      =>$rear_left_leg_image_hoof_sole_second,
                // 'measuring_tape'        =>$rear_left_leg_image_measuring_tape,
                'type'                  => 'rear_left_leg',
                'status'                => 'Active',
            );
            $this->Api_model->measurement($front_right_leg);
            $this->Api_model->measurement($front_left_leg);
            $this->Api_model->measurement($rear_right_leg);
            $this->Api_model->measurement($rear_left_leg);
            $this->Api_model->updateStatus($unique_id, ['steps' => 'measurement']);
        } else {
            $front_right_leg = array(
                'width'                 => $this->input->post('front_right_leg_width'),
                'lenght'                => $this->input->post('front_right_leg_length'),
                'front_view'            =>$front_right_leg_image_front_view,
                'side_view'             =>$front_right_leg_image_side_view,
                'hoof_sole'             =>$front_right_leg_image_hoof_sole,
                'hoof_sole_second'      =>$front_right_leg_image_hoof_sole_second,
                // 'measuring_tape'        =>$front_right_leg_image_measuring_tape,
            );
            $front_left_leg = array(
                'width'                 => $this->input->post('front_left_leg_width'),
                'lenght'                => $this->input->post('front_left_leg_length'),
                'front_view'            =>$front_left_leg_image_front_view,
                'side_view'             =>$front_left_leg_image_side_view,
                'hoof_sole'             =>$front_left_leg_image_hoof_sole,
                'hoof_sole_second'      =>$front_left_leg_image_hoof_sole_second,
                // 'measuring_tape'        =>$front_left_leg_image_measuring_tape,
            );
            $rear_right_leg = array(
                'width'                 => $this->input->post('rear_right_leg_width'),
                'lenght'                => $this->input->post('rear_right_leg_length'),
                'front_view'            =>$rear_right_leg_image_front_view,
                'side_view'             =>$rear_right_leg_image_side_view,
                'hoof_sole'             =>$rear_right_leg_image_hoof_sole,
                'hoof_sole_second'      =>$rear_right_leg_image_hoof_sole_second,
                // 'measuring_tape'        =>$rear_right_leg_image_measuring_tape,
            );
            $rear_left_leg = array(
                'width'                 => $this->input->post('rear_left_leg_width'),
                'lenght'                => $this->input->post('rear_left_leg_length'),
                'front_view'            =>$rear_left_leg_image_front_view,
                'side_view'             =>$rear_left_leg_image_side_view,
                'hoof_sole'             =>$rear_left_leg_image_hoof_sole,
                'hoof_sole_second'      =>$rear_left_leg_image_hoof_sole_second,
                // 'measuring_tape'        =>$rear_left_leg_image_measuring_tape,
            );

            $this->Api_model->updateMeasurement($front_right_leg, 'front_right_leg', $unique_id);
            $this->Api_model->updateMeasurement($front_left_leg, 'front_left_leg', $unique_id);
            $this->Api_model->updateMeasurement($rear_right_leg, 'rear_right_leg', $unique_id);
            $this->Api_model->updateMeasurement($rear_left_leg, 'rear_left_leg', $unique_id);
        }
        if ($result = true) {
            $results = $this->Api_model->getMeasurements($unique_id);
            $tempids=[];
            if (!empty($results)) {
                $i = 0;
                foreach ($results as $key=>$row) {
                    if(!empty($row['width']) && !empty($row['lenght'])){
                        $results[$i]['front_view'] = !empty($row['front_view'])?base_url('uploads/measurementimages/' . $row['front_view']):null;
                        $results[$i]['side_view'] = !empty($row['side_view'])?base_url('uploads/measurementimages/' . $row['side_view']):null;
                        $results[$i]['hoof_sole'] = !empty($row['hoof_sole'])?base_url('uploads/measurementimages/' . $row['hoof_sole']):null;
                        $results[$i]['hoof_sole_second'] = !empty($row['hoof_sole_second'])?base_url('uploads/measurementimages/' . $row['hoof_sole_second']):null;
                        // $results[$i]['measuring_tape'] = base_url('uploads/measurementimages/' . $row['measuring_tape']);
                    }else{
                        unset($results[$key]);
                    }
                    $i++;
                }
                
            }
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Measurement Information.', 'steps' => 'measurement', 'data' => $results]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Oops! Something went wrong.Please try again later.']));
            return false;
        }
    }

    public function legImagesUpload()
    {
        $this->output->set_content_type('application/json');
        $this->form_validation->set_rules('main_unique_id', 'Main Unique id', 'required');
        if ($this->form_validation->run() === false) {
            $vaidation = $this->form_validation->error_array();
            if (!empty($vaidation)) {
                foreach ($vaidation as $valid) {
                    $this->output->set_output(json_encode(['result' => 0, 'msg' => $valid]));
                    return false;
                }
            }
        }

        $step = $this->input->post('step');
        $unique_id = $this->input->post('main_unique_id');
        // for update back btn

        $front_right_old_image = $this->Api_model->getLegImage('front_right_hoof', $unique_id);
        $front_left_old_image = $this->Api_model->getLegImage('front_left_hoof', $unique_id);
        $rear_right_old_image = $this->Api_model->getLegImage('rear_right_hoof', $unique_id);
        $rear_left_old_image = $this->Api_model->getLegImage('rear_left_hoof', $unique_id);

        if (!empty($front_right_old_image)) {
            $front_right_hoof_side = $front_right_old_image['side_view'];
            $front_right_hoof_sole = $front_right_old_image['sole_view'];
            $front_right_hoof_front = $front_right_old_image['front_view'];
        } else {
            $front_right_hoof_side = NULL;
            $front_right_hoof_sole = NULL;
            $front_right_hoof_front = NULL;
        }

        if (!empty($front_left_old_image)) {
            $front_left_hoof_side = $front_left_old_image['side_view'];
            $front_left_hoof_sole = $front_left_old_image['sole_view'];
            $front_left_hoof_front = $front_left_old_image['front_view'];
        } else {
            $front_left_hoof_side = NULL;
            $front_left_hoof_sole = NULL;
            $front_left_hoof_front = NULL;
        }
        if (!empty($rear_right_old_image)) {
            $rear_right_hoof_sole = $rear_right_old_image['sole_view'];
            $rear_right_hoof_side = $rear_right_old_image['side_view'];
            $rear_right_hoof_front = $rear_right_old_image['front_view'];
        } else {
            $rear_right_hoof_side = NULL;
            $rear_right_hoof_sole = NULL;
            $rear_right_hoof_front = NULL;
        }
        if (!empty($rear_left_old_image)) {
            $rear_left_hoof_side = $rear_left_old_image['side_view'];
            $rear_left_hoof_sole = $rear_left_old_image['sole_view'];
            $rear_left_hoof_front = $rear_left_old_image['front_view'];
        } else {
            $rear_left_hoof_side = NULL;
            $rear_left_hoof_sole = NULL;
            $rear_left_hoof_front = NULL;
        }


        if (!empty($_FILES['front_right_hoof_side']['name'])) {
            $path = "uploads/legimages/side/";
            $file_name = "front_right_hoof_side";
            $front_right_hoof_side = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        if (!empty($_FILES['front_right_hoof_sole']['name'])) {
            $path = "uploads/legimages/sole/";
            $file_name = "front_right_hoof_sole";
            $front_right_hoof_sole = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        if (!empty($_FILES['front_right_hoof_front']['name'])) {
            $path = "uploads/legimages/front/";
            $file_name = "front_right_hoof_front";
            $front_right_hoof_front = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        if (!empty($_FILES['front_left_hoof_side']['name'])) {
            $path = "uploads/legimages/side/";
            $file_name = "front_left_hoof_side";
            $front_left_hoof_side = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        if (!empty($_FILES['front_left_hoof_sole']['name'])) {
            $path = "uploads/legimages/sole/";
            $file_name = "front_left_hoof_sole";
            $front_left_hoof_sole = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        if (!empty($_FILES['front_left_hoof_front']['name'])) {
            $path = "uploads/legimages/front/";
            $file_name = "front_left_hoof_front";
            $front_left_hoof_front = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        if (!empty($_FILES['rear_right_hoof_side']['name'])) {
            $path = "uploads/legimages/side/";
            $file_name = "rear_right_hoof_side";
            $rear_right_hoof_side = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        if (!empty($_FILES['rear_right_hoof_sole']['name'])) {
            $path = "uploads/legimages/sole/";
            $file_name = "rear_right_hoof_sole";
            $rear_right_hoof_sole = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }
        if (!empty($_FILES['rear_right_hoof_front']['name'])) {
            $path = "uploads/legimages/front/";
            $file_name = "rear_right_hoof_front";
            $rear_right_hoof_front = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        if (!empty($_FILES['rear_left_hoof_side']['name'])) {
            $path = "uploads/legimages/side/";
            $file_name = "rear_left_hoof_side";
            $rear_left_hoof_side = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        if (!empty($_FILES['rear_left_hoof_sole']['name'])) {
            $path = "uploads/legimages/sole/";
            $file_name = "rear_left_hoof_sole";
            $rear_left_hoof_sole = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        if (!empty($_FILES['rear_left_hoof_front']['name'])) {
            $path = "uploads/legimages/front/";
            $file_name = "rear_left_hoof_front";
            $rear_left_hoof_front = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }

        if (empty($step)) {
            $front_right_hoof = array(
                'main_unique_id' => $unique_id,
                'side_view'      => $front_right_hoof_side,
                'front_view'     => $front_right_hoof_front,
                'sole_view'      => $front_right_hoof_sole,
                'type'           => 'front_right_hoof',
                'status'         => 'Active'
            );
            $front_left_hoof = array(
                'main_unique_id' => $unique_id,
                'side_view'      => $front_left_hoof_side,
                'front_view'     => $front_left_hoof_front,
                'sole_view'      => $front_left_hoof_sole,
                'type'           => 'front_left_hoof',
                'status'         => 'Active'
            );
            $rear_right_hoof = array(
                'main_unique_id' => $unique_id,
                'side_view'      => $rear_right_hoof_side,
                'front_view'     => $rear_right_hoof_front,
                'sole_view'      => $rear_right_hoof_sole,
                'type'           => 'rear_right_hoof',
                'status'         => 'Active'
            );
            $rear_left_hoof = array(
                'main_unique_id' => $unique_id,
                'side_view'      => $rear_left_hoof_side,
                'front_view'     => $rear_left_hoof_front,
                'sole_view'      => $rear_left_hoof_sole,
                'type'           => 'rear_left_hoof',
                'status'         => 'Active'
            );

            $this->Api_model->legImagesUpload($front_right_hoof);
            $this->Api_model->legImagesUpload($front_left_hoof);
            $this->Api_model->legImagesUpload($rear_right_hoof);
            $this->Api_model->legImagesUpload($rear_left_hoof);
            $this->Api_model->updateStatus($unique_id, ['steps' => 'leg_image']);
        } else {
            $front_right_hoof = array(
                'side_view'      => $front_right_hoof_side,
                'front_view'     => $front_right_hoof_front,
                'sole_view'      => $front_right_hoof_sole,
            );
            $front_left_hoof = array(
                'side_view'      => $front_left_hoof_side,
                'front_view'     => $front_left_hoof_front,
                'sole_view'      => $front_left_hoof_sole,
            );
            $rear_right_hoof = array(
                'side_view'      => $rear_right_hoof_side,
                'front_view'     => $rear_right_hoof_front,
                'sole_view'      => $rear_right_hoof_sole,
            );
            $rear_left_hoof = array(
                'side_view'      => $rear_left_hoof_side,
                'front_view'     => $rear_left_hoof_front,
                'sole_view'      => $rear_left_hoof_sole,
            );

            $this->Api_model->updatelegImages($front_right_hoof, 'front_right_hoof', $unique_id);
            $this->Api_model->updatelegImages($front_left_hoof, 'front', $unique_id);
            $this->Api_model->updatelegImages($rear_right_hoof, 'rear_right_hoof', $unique_id);
            $this->Api_model->updatelegImages($rear_left_hoof, 'rear_left_hoof', $unique_id);
        }
        if ($result = true) {
            $results = $this->Api_model->getLegImages($unique_id);
            if (!empty($results)) {
                $i = 0;
                foreach ($results as $img) {
                    $results[$i]['side_view'] = base_url('uploads/legimages/side/') . $img['side_view'];
                    $results[$i]['front_view'] = base_url('uploads/legimages/front/') . $img['front_view'];
                    $results[$i]['sole_view'] = base_url('uploads/legimages/sole/') . $img['sole_view'];
                    $i++;
                }
            }
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Leg Images Updates.', 'steps' => 'leg_image', 'data' => $results]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Opps Try Again Lator!!.']));
            return false;
        }
    }

    public function hourseImage()
    {
        $this->output->set_content_type('application/json');
        $this->form_validation->set_rules('main_unique_id', 'Main Unique id', 'required');
        if ($this->form_validation->run() === false) {
            $vaidation = $this->form_validation->error_array();
            if (!empty($vaidation)) {
                foreach ($vaidation as $valid) {
                    $this->output->set_output(json_encode(['result' => 0, 'msg' => $valid]));
                    return false;
                }
            }
        }

        $step = $this->input->post('step');
        $unique_id = $this->input->post('main_unique_id');
        // for update back btn
        $hourseoldimages = $this->Api_model->getInformation($unique_id);

        if (!empty($hourseoldimages)) {
            $hourse_image = $hourseoldimages['hourse_image'];
        } else {
           $hourse_image=Null;
        }
        if (!empty($_FILES['hourse_image']['name'])) {
            $path = "uploads/hourse_image";
            $file_name = "hourse_image";
            $hourse_image = $this->doUploadImage($path, $file_name);
            if ($this->upload->display_errors()) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Image :' . strip_tags($this->upload->display_errors())]));
                $this->session->unset_userdata('error');
                return FALSE;
            }
        }
        $this->Api_model->updateStatus($unique_id,['hourse_image'=>$hourse_image]);
        $this->Api_model->updateStatus($unique_id, ['steps' => 'hourse_image']);
        $this->Api_model->updateStatus($unique_id, ['is_complete' => 'yes']);
        if ($result = true) {
            $results = $this->Api_model->getInformation($unique_id);
            if (!empty($results['hourse_image'])) {
                    $results['hourse_image'] = base_url('uploads/hourse_image/') . $results['hourse_image'];
            }
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Hourse Images Updates.', 'steps' => 'hourse_image', 'data' => $results]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Opps Try Again Lator!!.']));
            return false;
        }
    }

    public function booking(){
        $this->output->set_content_type('application/json');
        $user_token = $this->input->get_request_header('token');
        $user_data = $this->Api_model->getUserByToken($user_token);
        if (empty($user_data)) {
            header('HTTP/1.1 402 User already logged in on a different device', true, 402);
            $this->output->set_output(json_encode(['result' => -2, 'msg' => 'User already logged in on a different device']));
            return FALSE;
        }
        $user_id = $user_data['user_id'];
        $slot_date = date('Y-m-d',strtotime($this->input->post('slot_date')));
        $slot_time=date('H:i',strtotime($this->input->post('slot_time')));
        //Date string
        $date_string = $this->input->post('slot_date');
        $time_string=$this->input->post('slot_time');
        //Creating a DateTime object
        $date_time_Obj = date_create($date_string.' '.$time_string);
        //formatting the date to print it
        $final_date = date_format($date_time_Obj, "Y-m-d H:i");
        $startdates=[];
        $enddates=[];
        $date=$this->Api_model->getEventByDate($slot_date);
        if(!empty($date)){
            foreach($date as $row){
                $startdates[]=$row['start'];
                $enddates[]=$row['end'];
            }
            if(!empty($startdates)){
                $i=0;
                foreach($startdates as $row){
                    if(date('Y-m-d H:i',strtotime($row)) <= date('Y-m-d H:i',strtotime($final_date)) && date('Y-m-d H:i',strtotime($enddates[$i])) >= date('Y-m-d H:i',strtotime($final_date))){
                        $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Booking not availbale for ' .$final_date, 'data' => NULL]));
                        return false;
                    }
                    $i++;
                }
            }
        }
        $data=array(
            'booking_unique_id'=>'HOURSE'.$this->uniqueId(),
            'order_number'     => 'order'.$this->uniqueId(),
            'user_id'  => $user_id,
            'email'  =>$this->input->post('email'),
            'name' => $this->input->post('name'),
            'country_code' => $this->input->post('country_code'),
            'phone' => $this->input->post('phone'),
            'slot_date'=> date('Y-m-d',strtotime($this->input->post('slot_date'))),
            'slot_timing'=> date('H:i',strtotime($this->input->post('slot_time'))),
        );
        $result = $this->Api_model->booking($data);
        if ($result) {
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Booking data', 'data' => $result]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Failed to booking', 'data' => NULL]));
            return false;
        }
    }
    public function homeapi(){
        $this->output->set_content_type('application/json');
        // $result['categories'] = $this->Api_model->getCategories();
         $result['content']=$this->Api_model->getHomepageContent();
          $result['content']['description']=strip_tags($result['content']['description']);
         $result['featured_product']=$this->Api_model->getProductsBycategoryid();
        if ($result) {
            $result['banner']=array(
            'banner_image'=>base_url('uploads/homepage/homepagebanner.png'),
            'title1'=>'Geben Sie uns Ihre',
            'title2'=>'Bedarf!',
            );
            // if(!empty($result['categories'])){
            //     $i=0;
            //     foreach($result['categories'] as $row){
            //         $result['categories'][$i]['image_url']=base_url('uploads/categories/').$row['image_url'];
            //          $result['categories'][$i]['banner_image']=base_url('uploads/categories/banner/').$row['banner_image'];
            //         $i++;
            //     }
            // }
            if(!empty($result['featured_product'])){
                $j = 0;
                foreach ($result['featured_product'] as  $row) {
                    $result['featured_product'][$j]['thumbnail_image'] = base_url('uploads/product/thumbnail/') . $row['thumbnail_image'];
                    $result['featured_product'][$j]['product_description'] = strip_tags($row['product_description']);
                    $j++;
                }
            }
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Home Api Data Successfully.', 'data' => $result]));
        } else {
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'No Record Found!!','data'=>NULL]));
        }
    }
    
    public function socialLogin(){
        $this->output->set_content_type('application/json');
        $social_type = $this->input->post('source');
        $name = $this->input->post('name');
        $email = $this->input->post('email');
        $social_id = $this->input->post('social_id');
        $device_type=$this->input->post('device_type');
        $token = $this->genrateToken();
        $checkmail = $this->Api_model->checkSocialUserData($email);
        $userdata = $this->Api_model->checkSocialUserData($email);
        if(empty($checkmail)){
            $insert_social_data = $this->Api_model->insertSocialUserData($social_type, $email,$social_id,$name);
            $this->Api_model->insertToken($insert_social_data, $this->genrateToken(),$device_type);
        }else{
            if($checkmail['status'] == 'Blocked'){
                $this->output->set_output(json_encode(['result' => 1, 'msg' =>'Your account has been blocked.' , 'data' => NULL,]));
                return FALSE;
            }else{
                $update_social_data = $this->Api_model->updateSocialUserData($social_type, $email,$social_id,$name);
                 $this->Api_model->updateToken($userdata['user_id'], $this->genrateToken(),$device_type);
            }
        }
        $userdata = $this->Api_model->checkSocialUserData($email);
        $result = $this->Api_model->getUserByUserId($userdata['user_id']);
        if (!empty($userdata['image_url'])) {
            $userdata['image_url'] = base_url('uploads/users/' . $userdata['image_url']);
        } else {
            $userdata['image_url'] = null;
        }
       
        if($result){
             $this->output->set_output(json_encode(['result' => 1, 'msg' =>'Logged In Successfully.' , 'data' => $result]));
            return FALSE;
        }else{
             $this->output->set_output(json_encode(['result' => -1, 'msg' =>'Not Authentication !!.' , 'data' => []]));
            return FALSE;
        }
       
    }
    
    /*
    |--------------------------------------------------------------------------
    | Stripe Payement Gateway Integration
    |--------------------------------------------------------------------------
    */
    
    // public function token()
    // {
    //     $this->output->set_content_type('application/json');
    //     $card_number=$this->input->post('card_no');
    //     $expire_month=$this->input->post('expire_month');
    //     $expire_year=$this->input->post('expire_year');
    //     $cvc=$this->input->post('cvc');
    //     require_once('application/libraries/stripe-php/init.php');
    //     \Stripe\Stripe::setApiKey($this->config->item('stripe_secret'));
    //     $stripe = new \Stripe\StripeClient(
    //         $this->config->item('stripe_secret')
    //     );


    //     $result = $stripe->tokens->create([
    //         'card' => [
    //             'number' => $card_number,
    //             'exp_month' => $expire_month,
    //             'exp_year' => $expire_year,
    //             'cvc' => $cvc,
    //         ],
    //     ]);

    //     if ($result) {
    //         $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Token Creted Successfully', 'data' => $result]));
    //         return FALSE;
    //     } else {
    //         $this->output->set_output(json_encode(['result' => -1, 'msg' => 'No Vehicle found', 'data' => NULL]));
    //         return FALSE;
    //     }
    // }
    
    public function token()
    {
        $this->output->set_content_type('application/json');
        $card_number=$this->input->post('card_no');
        $expire_month=$this->input->post('expire_month');
        $expire_year=$this->input->post('expire_year');
        $cvc=$this->input->post('cvc');
        require_once('application/libraries/stripe-php/init.php');
        \Stripe\Stripe::setApiKey($this->config->item('stripe_secret'));
        $stripe = new \Stripe\StripeClient(
            $this->config->item('stripe_secret')
        );


        $result = $stripe->tokens->create([
            'card' => [
                'number' => $card_number,
                'exp_month' => $expire_month,
                'exp_year' => $expire_year,
                'cvc' => $cvc,
            ],
        ]);

        if ($result) {
             $last_four_digit=@$result->card->last4;
             $brand_name=@$result->card->brand;
             $booking_unique_id=$this->input->post('booking_id');
             $this->Api_model->updatebookingConfirmation($booking_unique_id,['last_four_digit' => $last_four_digit,'card_brand_name' => $brand_name]);
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Token Creted Successfully', 'data' => $result]));
            return FALSE;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'No Vehicle found', 'data' => NULL]));
            return FALSE;
        }
    }

    public function stripe_keys()
    {
        $this->output->set_content_type('application/json');
        $user_token = $this->input->get_request_header('token');
        $user_data = $this->Api_model->getUserByToken($user_token);

        if (empty($user_data)) {
            header('HTTP/1.1 402 User already logged in on a different device', true, 402);
            $this->output->set_output(json_encode(['result' => -2, 'msg' => 'User already logged in on a different device']));
            return FALSE;
        }
        $result['stripe_key'] = $this->config->item('stripe_key');
        $result['stripe_secret'] = $this->config->item('stripe_secret');

        if ($result) {
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Stripe Keys', 'data' => $result]));
            return FALSE;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'No Location found', 'data' => NULL]));
            return FALSE;
        }
    }



    public function cardList()
    {
        $this->output->set_content_type('application/json');
        $user_token = $this->input->get_request_header('token');
        $user_data = $this->Api_model->getUserByToken($user_token);

        if (empty($user_data)) {
            header('HTTP/1.1 402 User already logged in on a different device', true, 402);
            $this->output->set_output(json_encode(['result' => -2, 'msg' => 'User already logged in on a different device']));
            return FALSE;
        }
        require_once('application/libraries/stripe-php/init.php');
        \Stripe\Stripe::setApiKey($this->config->item('stripe_secret'));
        $stripe = new \Stripe\StripeClient(
            $this->config->item('stripe_secret')
        );

        $result = $stripe->customers->allSources(
            $user_data['stripe_customer_id'],
            ['object' => 'card', 'limit' => 10]
        );

        if ($result) {
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Card Listing', 'data' => $result]));
            return FALSE;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'No Data found', 'data' => NULL]));
            return FALSE;
        }
    }

    public function deleteCard()
    {
        $this->output->set_content_type('application/json');
        $user_token = $this->input->get_request_header('token');
        $user_data = $this->Api_model->getUserByToken($user_token);

        if (empty($user_data)) {
            header('HTTP/1.1 402 User already logged in on a different device', true, 402);
            $this->output->set_output(json_encode(['result' => -2, 'msg' => 'User already logged in on a different device']));
            return FALSE;
        }
        $card_id = $this->input->post('card_id');
        if (empty($card_id)) {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Please Send Card Id']));
            return FALSE;
        }
        require_once('application/libraries/stripe-php/init.php');
        \Stripe\Stripe::setApiKey($this->config->item('stripe_secret'));
        $token = $this->input->post('stripe_token');
        $stripe = new \Stripe\StripeClient(
            $this->config->item('stripe_secret')
        );

        $result = $stripe->customers->deleteSource(
            $user_data['stripe_customer_id'],
            $card_id,
            []
        );

        if ($result) {
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Card Delete Successfull']));
            return FALSE;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Something went wrong']));
            return FALSE;
        }
    }

    public function stripe()
    {
        try {
            $this->output->set_content_type('application/json');
            $user_token = $this->input->get_request_header('token');
            $user_data = $this->Api_model->getUserByToken($user_token);

            if (empty($user_data)) {
                header('HTTP/1.1 402 User already logged in on a different device', true, 402);
                $this->output->set_output(json_encode(['result' => -2, 'msg' => 'User already logged in on a different device']));
                return FALSE;
            }

            $booking_unique_id = $this->input->post('booking_unique_id');
            $token = $this->input->post('stripe_token');
            $card_id = $this->input->post('card_id');


            $result = $this->Api_model->getBookingByUniqueID($booking_unique_id);
            $price = 5 * 100;


            require_once('application/libraries/stripe-php/init.php');
            \Stripe\Stripe::setApiKey($this->config->item('stripe_secret'));

            $stripe = new \Stripe\StripeClient(
                $this->config->item('stripe_secret')
            );

            if (!empty($token)) {

                $tokenDetail = $stripe->tokens->retrieve(
                    $token,
                    []
                );

                $charge = \Stripe\Charge::create([
                    "amount" => $price,
                    "currency" => "usd",
                    "source" => $token,
                    "description" => "Test payment"
                ]);
                $chargeJson = $charge->jsonSerialize();
                $txn_id = $chargeJson['balance_transaction'];

                if ($chargeJson) {
                    if ($this->input->post('save_status') == '1') {

                        // $check_card = $this->Api_model->stripeCard($user_data['id'],$tokenDetail['card']['id']);
                        // if(empty($check_card)){
                        // $this->Api_model->addStripeCard($user_data['id'],$tokenDetail['card']['id']);
                        $source = 'tok_' . strtolower($tokenDetail['card']['brand']);

                        $card = $stripe->customers->createSource(
                            $user_data['stripe_customer_id'],
                            [
                                'source' => $source,
                            ]
                        );
                    }
                    $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Transaction Succeeded', 'booking_id' => $booking_unique_id, 'txn_id' => $txn_id]));
                    $this->Api_model->bookingConfirmation($booking_unique_id, 'success',$txn_id,$price,$card_id);
                    return false;
                } else {
                    $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Your Card is Declined']));
                    return false;
                }
            } elseif (!empty($card_id)) {

                $charge = \Stripe\Charge::create([
                    'currency' => 'USD',
                    'amount' => $price,
                    // converting dollars to cents
                    // 'description' => $description, //it may be blank
                    'customer' => $user_data['stripe_customer_id'],
                    'card' => $card_id,
                ]);
                $chargeJson = $charge->jsonSerialize();
                $txn_id = $chargeJson['balance_transaction'];
                if ($chargeJson) {
                    $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Transaction Succeeded', 'booking_id' => $booking_unique_id, 'txn_id' => $txn_id]));
                    $this->Api_model->bookingConfirmation($booking_unique_id, 'success',$txn_id,$price);
                    return false;
                } else {
                    $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Your Card is Declined']));
                    return false;
                }
            } else {

                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Please Provide Token/Card_id']));
                return false;
            }
        } catch (\Stripe\Exception\CardException $e) {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Message is:' . $e->getError()->message, 'booking_id' => NULL]));
            return false;
        } catch (\Stripe\Exception\TokenException $e) {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Token is in use']));
            return false;
        } catch (\Stripe\Exception\RateLimitException $e) {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Too many requests made to the API too quickly', 'booking_id' => NULL]));
            return false;
        } catch (\Stripe\Exception\InvalidRequestException $e) {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Invalid parameters were supplied to Stripes API', 'booking_id' => NULL]));
            return false;
        } catch (\Stripe\Exception\AuthenticationException $e) {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Authentication with Stripe API failed', 'booking_id' => NULL]));
            return false;
        } catch (\Stripe\Exception\ApiConnectionException $e) {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Network communication with Stripe failed', 'booking_id' => NULL]));
            return false;
        } catch (\Stripe\Exception\ApiErrorException $e) {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Display a very generic error to the user, and maybe send yourself an email', 'booking_id' => NULL]));
            return false;
        } catch (Exception $e) {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Something else happened, completely unrelated to Stripe', 'booking_id' => NULL]));
            return false;
        }
    }
    
    public function paymentHistory(){
        $this->output->set_content_type('application/json');
        $booking_id = $this->input->post('booking_id');
        $result = $this->Api_model->getPaymentDetailByBookingId($booking_id);
        if ($result) {
            $result['payment_date']=date('d M,Y',strtotime($result['payment_date']));
            $this->output->set_output(json_encode(['result' => 1, 'data' => $result]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'data' => NULL]));
            return false;
        }
    }
    
    public function bookingHistory(){
        $this->output->set_content_type('application/json');
        $user_token = $this->input->get_request_header('token');
            $user_data = $this->Api_model->getUserByToken($user_token);

            if (empty($user_data)) {
                header('HTTP/1.1 402 User already logged in on a different device', true, 402);
                $this->output->set_output(json_encode(['result' => -2, 'msg' => 'User already logged in on a different device']));
                return FALSE;
            }
        $user_id =$user_data['user_id'];
        $result = $this->Api_model->getBookingHistory($user_id);
        if ($result) {
            $i=0;
            foreach($result as $row){
                $result[$i]['title']="Zahlungsbeleg".' '.$row['booking_id'];
                $result[$i]['content']="Die Zahlung für „Beratungsbuchung“ wurde durchgeführt ".$row['payment_status'];
                $i++;
            }
            $this->output->set_output(json_encode(['result' => 1, "msg" =>"Zahlungsverlaufsdaten gefunden!!",'data' => $result]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, "msg" =>"Keine Daten gefunden !!" ,'data' => NULL]));
            return false;
        }
    }
    
    public function optionListGerman(){
        $this->output->set_content_type('application/json');
        $type = $this->input->post('type');
        if($type  === 'delivery_period'){
            $result = array(
                'sofort', 'innerhalb_von_8_tagen', 'innerhalb_von_3_monaten', 'hufe_nur_andeuten'
            );
        }else{
            $result = array(
                'nur_vorderhufe', 'alles_für_die_hufe'
            );
        }
        if ($result) {
            $this->output->set_output(json_encode(['result' => 1,'msg' => 'Options List', 'data' => $result]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'data' => NULL]));
            return false;
        }
    }
    
     public function deleteAccount(){
        $this->output->set_content_type('application/json');
        $user_id = $this->input->post('user_id');
        $result = $this->Api_model->deleteAccount($user_id);
        if ($result) {
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Account deleted successfully.', 'data' => $result]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Something went wrong', 'data' => NULL]));
            return false;
        }
    }
    
    
    
}
