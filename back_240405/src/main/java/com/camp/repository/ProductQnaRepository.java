package com.camp.repository;

import com.camp.domain.ProductQna;
import org.springframework.data.domain.Page; // 수정됨
import org.springframework.data.domain.Pageable; // 수정됨
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface ProductQnaRepository extends JpaRepository<ProductQna, Long> {

    // 질문과 답변을 함께 조회하는 메서드
    @Query("SELECT q FROM ProductQna q LEFT JOIN FETCH q.replies WHERE q.qno = :qno")
    ProductQna findQnaWithReplies(Long qno);

    // 미답변 질문 조회
    List<ProductQna> findByAnsweredFalse();

    // 특정 상품의 질문 조회 (페이지네이션 없음)
    List<ProductQna> findByProductPno(Long pno);

    // 특정 상품의 질문을 페이지네이션과 함께 조회
    Page<ProductQna> findByProductPno(Long pno, Pageable pageable);
}
