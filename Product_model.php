<?php 
defined("BASEPATH") or exit ("No direct script access allowed");

class Product_model extends CI_Model{
	
	public function __construct(){
		parent::__construct();
	}
    public function getAllProducts(){
        $this->db->select('*');
        $this->db->from('products');
        $this->db->order_by('product_id','DESC');
        $this->db->where('status !=','Deleted');
        $query=$this->db->get();
        return $query->result_array();
    }

    public function getProductDetail($pid){
        $query = $this->db->get_where('products', ['product_id' => $pid,'status !='=>'Deleted']);
        return $query->row_array();
    }

    public function addProduct($image_url){
        $data = array(
            'product_name'          => $this->input->post('product_name'),
            'product_description'   => $this->input->post('product_description'),
            'product_price'         => $this->input->post('product_price'),
            'product_category_id'   => $this->input->post('product_category_id'),
            'product_type'          => $this->input->post('product_type'),
            'link'                  => $this->input->post('link'),
            'thumbnail_image'       => $image_url,
            'status'                => 'Active',
            'added_date'            =>date('Y-m-d H:i:s'),
            'updated_date'           =>date('Y-m-d H:i:s'),

        );
        $this->db->insert('products',$data);
        return $this->db->insert_id();
    }

    public function update_product($id, $image_url){
        $data = array(
            'product_name'          => $this->input->post('product_name'),
            'product_description'   => $this->input->post('product_description'),
            'product_price'         => $this->input->post('product_price'),
            'product_category_id'   => $this->input->post('product_category_id'),
            'product_type'          => $this->input->post('product_type'),
            'link'                  => $this->input->post('link'),
            'thumbnail_image'       => $image_url,
        );
        $this->db->update('products',$data, ['product_id' => $id]);
        return true;
    }

    public function insertProductImage($product_id,$image_url){
        $data = array(
            'product_id'            => $product_id,
            'image_name'            => $image_url,
            'status'                => 'Active',
        );
        $this->db->insert('product_images',$data);
        return $this->db->insert_id();
    }

    public function getProductImagesByPID($pid){
        $this->db->select('*');
        $this->db->from('product_images');
        $this->db->where('product_id',$pid);
        $this->db->where('status !=','Deleted');
        $query=$this->db->get();
        return $query->result_array();
    }

    public function deletProductImage($imgid){
        $this->db->where('product_image_id',$imgid);
        $this->db->delete('product_images');
        return true;
    }
    
}
?>