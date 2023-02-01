<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Welcome extends CI_Controller {

	public function __construct(){
		parent::__construct();
		$this->load->model(['admin/admin_model']);
	}

	public function index(){
		if(!empty($this->session->userdata('admin_id'))){
			redirect('admin/dashboard');
		}
		$data['title'] = 'Admin Login';
		$data['admin_detail']=$this->admin_model->getAdminDetail(1);
		$this->load->view('admin/login', $data);
	}
}