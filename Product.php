<?php 
defined("BASEPATH") or exit ("No direct script access allowed");

class Product extends CI_Controller{
	
	public function __construct(){
		parent::__construct();
		$this->load->model(['admin/admin_model','admin/product_model']);
	}

	public function loadview($loadview, $data=null){
		$this->load->view('admin/common/header',$data);
		$this->load->view('admin/'.$loadview);
		$this->load->view('admin/common/footer');
	}

	public function dashboard_loadview($loadview,$data=NULL){
		$admin_id=$this->session->userdata('admin_id');
        $admin['unseen_notification_count'] = $this->admin_model->getAdminUnseenNotification();
        $admin['notification'] = $this->admin_model->getAdminNotification();
        $i = 0;
        foreach ($admin['notification'] as $key => $value) {
            $user_image = $this->admin_model->getUserImage($value['user_id']);
            $admin['notification'][$i]['time'] = convertToHoursMinsSec(date('Y-m-d H:i:s', strtotime($value['created_at'])));
            if(!empty($user_image['image_url'])){
                $admin['notification'][$i]['image_url'] = base_url('uploads/profilePic/'.$user_image['image_url']);
            }else{
                $admin['notification'][$i]['image_url'] = base_url('assets/admin/no_image_avail.png');
            }
            $i++;
        }
		$data['admin_detail']=$this->admin_model->getAdminDetail($admin_id);
		$this->load->view('admin/common/header',$data);
		$this->load->view('admin/common/sidebar',$data);
		$this->load->view('admin/'.$loadview);
		$this->load->view('admin/common/footer');
    }

    private  function is_login(){
		$admin_id=$this->session->userdata('admin_id');
		if(empty($admin_id)){
			redirect('admin');
		}else{
			return $admin_id;
		}
    }

    //----------------------------- Upload single file-----------------------------

	public function doUploadImage($path,$file_name) {
        $config = array(
            'upload_path'   => $path,
            'allowed_types' => "jpeg|jpg|png|ico",
            'file_name'     => rand(11111, 99999),
            'max_size'      => "5072"
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

    //----------------------------- Upload multiple files-----------------------------

    public function upload_files($path,$file_name){
        $this->output->set_content_type('application/json');
        $files = $_FILES[$file_name];
        $config = array(
            'upload_path'   => $path,
            'allowed_types' => 'jpeg|jpg|gif|png|pdf',
            'overwrite'     => 1,                       
        );
        $this->load->library('upload', $config);
        $images = array();
        $i=0;
        foreach ($files['name'] as $key => $image) {
            $_FILES['images[]']['name']= $files['name'][$key];
            $_FILES['images[]']['type']= $files['type'][$key];
            $_FILES['images[]']['tmp_name']= $files['tmp_name'][$key];
            $_FILES['images[]']['error']= $files['error'][$key];
            $_FILES['images[]']['size']= $files['size'][$key];

            $title = rand('1111','9999');
            $image = explode('.',$image);
            $count = count($image);
            $extension = $image[$count-1];
            $fileName = $title .'.'. $extension;
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

    
    function change_status($id,$status,$table,$unique_id,$status_variable){
        $this->output->set_content_type('application/json');
        change_status($id,$status,$table,$unique_id,$status_variable);
        if($status == 'Deleted'){
            $msg = ucwords(str_replace('_', ' ', $table)).' deleted successfully.';
        }else{
            $msg = ucwords(str_replace('_', ' ', $table)).' status change to '.strtolower($status).' successfully.';
        }
        if($status_variable=='is_featured'){
            $msg='Featured Status changed Successfully';
        }
        $this->output->set_output(json_encode(['result' => 1,'msg'=> $msg]));
        return FALSE;
    }


    public function products(){
        $admin_id = $this->is_login();
        $data['title'] = 'Products';
        $data['basic_datatable'] = '1';
        $data['product'] = $this->product_model->getAllProducts();
        $this->dashboard_loadview('products/product',$data);
    }

    public function productDetail($id){
        $admin_id = $this->is_login();
        $data['title'] = 'Product Details';
        $id=decryptionID($id);
        $data['basic_datatable']='1';
        $data['product_detail'] = $this->product_model->getProductDetail($id);
        $data['images']=$this->product_model->getProductImagesByPID($id);
        $this->dashboard_loadview('products/product_detail',$data);
    }

    public function addProduct($pid=null){
        $admin_id = $this->is_login();
        $data['product_category']=$this->admin_model->getAllCategories();
        $data['product_type'] = $this->config->item('product_type');
        if(!empty($pid)){
            $pid=decryptionID($pid);
            $data['title'] = 'Edit Product';
            $data['product_detail'] = $this->product_model->getProductDetail($pid);
            $data['images']=$this->product_model->getProductImagesByPID($pid);
            
        }else{
            $data['title'] = 'Add Product';
        }
        $this->dashboard_loadview('products/add_product',$data);
    }

    public function doAddProduct(){
        $this->output->set_content_type('application/json');
        $this->form_validation->set_rules('product_name', 'Product Name', 'required');
        $this->form_validation->set_rules('product_price', 'Product Price', 'required');
        $this->form_validation->set_rules('product_category_id', 'Product Category', 'required');
        $this->form_validation->set_rules('product_type', 'Product Type', 'required');
        $this->form_validation->set_rules('product_description', 'Product Description', 'required');
        $this->form_validation->set_rules('link', 'Product Link', 'required');
        if ($this->form_validation->run() === FALSE) {
            $this->output->set_output(json_encode(['result' => 0, 'errors' => $this->form_validation->error_array()]));
            return FALSE;
        }
        if(empty($_FILES['thumbnail_image']['name'])){
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Please Select a Thumbnail Image.!!!']));
            return FALSE;
        }
        
		$thumbnailpath='uploads/product/thumbnail/';
		$thumbnail_image=$this->doUploadImage($thumbnailpath, 'thumbnail_image');

        if(empty($_FILES['product_images']['name'][0])){
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Please Select a Product Image.!!!']));
            return FALSE;
        }

        $productpath='uploads/product/';
		$productimage=$this->upload_files($productpath, 'product_images');

		if($this->upload->display_errors()){
			$this->output->set_output(json_encode(['result' => -1, 'msg' => $this->upload->display_errors()]));
            return FALSE;
		}
        $result = $this->product_model->addProduct($thumbnail_image);
        if($result){
            if(!empty($productimage)){
                foreach($productimage as $img){
                    $this->product_model->insertProductImage($result,$img);
                }
            }
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Product added Successfully.','url'=> base_url('admin/product')]));
            return false;
        }else{
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Something went wrong.']));
            return false;
        }
    }

    public function editProduct($pid){
        $this->output->set_content_type('application/json');
        $admin_id=$this->is_login();
        $pid=decryptionID($pid);
        $this->form_validation->set_rules('product_name', 'Product Name', 'required');
        $this->form_validation->set_rules('product_price', 'Product Price', 'required');
        $this->form_validation->set_rules('product_category_id', 'Product Category', 'required');
        $this->form_validation->set_rules('product_type', 'Product Type', 'required');
        $this->form_validation->set_rules('product_description', 'Product Description', 'required');
        $this->form_validation->set_rules('link', 'Product Link', 'required');
        if ($this->form_validation->run() === FALSE) {
            $this->output->set_output(json_encode(['result' => 0, 'errors' => $this->form_validation->error_array()]));
            return FALSE;
        }
        $productdata=$this->product_model->getProductDetail($pid);
        $thumbnail_image='';
        if(!empty($_FILES['thumbnail_image']['name'])){
            $thumbnailpath='uploads/product/thumbnail/';
		    $thumbnail_image=$this->doUploadImage($thumbnailpath, 'thumbnail_image');
            if($this->upload->display_errors()){
                $this->output->set_output(json_encode(['result' => -1, 'msg' => $this->upload->display_errors()]));
                return FALSE;
            }
        }else{
            if(!empty($productdata)){
                $thumbnail_image=$productdata['thumbnail_image'];
            }
        }
        
        if(!empty($_FILES['product_images']['name'][0])){
            $productpath='uploads/product/';
		    $productimage=$this->upload_files($productpath, 'product_images');
            if($this->upload->display_errors()){
                $this->output->set_output(json_encode(['result' => -1, 'msg' => $this->upload->display_errors()]));
                return FALSE;
            }
            if(!empty($productimage)){
                foreach($productimage as $img){
                    $this->product_model->insertProductImage($pid,$img);
                }
            }
        }

        
        $result=$this->product_model->update_product($pid,$thumbnail_image);
        if ($result=true) {
            $this->output->set_output(json_encode(['result' => 1, 'url' => base_url('admin/product'), 'msg' => 'Products Updated successfully.']));
            return FALSE;
        }else{
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'OOPs Something went wrong']));
            return FALSE;
        }
    }
    public function deleteimage(){
        $this->output->set_content_type('application/json');
        $img_id=$this->input->post('image_id');
        $result=$this->product_model->deletProductImage($img_id);
        $pid=$this->input->post('product_id');
        $data['images']=$this->product_model->getProductImagesByPID($pid);   
        $htmlwrapper=$this->load->view('admin/products/imagewrapper',$data,true);
        return $this->output->set_output(json_encode(['result' => 1, 'url' =>'', 'msg' => 'Image Deleted successfully','htmlwrapper'=>$htmlwrapper ]));
    }
    
  
}
?>