package com.camp.service;


import com.camp.dto.PageRequestDTO;
import com.camp.dto.PageResponseDTO;
import com.camp.dto.ProductReviewDTO;

public interface ProductReviewService {

    Long register(ProductReviewDTO productReviewDTO);

    ProductReviewDTO read(Long prno);

    void modify(ProductReviewDTO productReviewDTO);

    void  remove(Long prno);

    PageResponseDTO<ProductReviewDTO> getListOfBoard(Long pno, PageRequestDTO pageRequestDTO);

}
