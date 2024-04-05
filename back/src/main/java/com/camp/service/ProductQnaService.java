package com.camp.service;

import com.camp.dto.PageRequestDTO;
import com.camp.dto.PageResponseDTO;
import com.camp.dto.ProductQnaDTO;
import com.camp.dto.ProductQnaReplyDTO;

public interface ProductQnaService {
    // 새로운 상품 Q&A를 등록하고, 등록된 Q&A의 식별자를 반환합니다.
    Long register(ProductQnaDTO productQnaDTO);

    // 지정된 식별자(qno)를 가진 상품 Q&A를 조회합니다.
    ProductQnaDTO get(Long qno);

    // 상품 Q&A 정보를 수정합니다.
    void modify(ProductQnaDTO productQnaDTO);

    // 지정된 식별자(qnaId)를 가진 상품 Q&A를 삭제합니다.
    void remove(Long qnaId);

    // 특정 상품(pno)에 대한 Q&A 목록을 페이지네이션과 함께 조회합니다.
    PageResponseDTO<ProductQnaDTO> getQnaList(Long pno, PageRequestDTO pageRequestDTO);

}
