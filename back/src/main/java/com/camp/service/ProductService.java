package com.camp.service;

import org.springframework.transaction.annotation.Transactional;

import com.camp.dto.PageRequestDTO;
import com.camp.dto.PageResponseDTO;
import com.camp.dto.ProductDTO;

@Transactional
public interface ProductService {
    PageResponseDTO<ProductDTO> getList(PageRequestDTO pageRequestDTO, String pname);

    Long register(ProductDTO productDTO);
    ProductDTO get(Long pno);
    void modify(ProductDTO productDTO);
    void remove(Long pno);
    public void updateTotalReviews(Long pno);

    public String getProductInfo(String productName);
}
