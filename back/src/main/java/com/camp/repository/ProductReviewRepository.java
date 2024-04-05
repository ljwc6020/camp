package com.camp.repository;

import com.camp.domain.Product;
import com.camp.domain.ProductReview;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface ProductReviewRepository extends JpaRepository<ProductReview, Long> {

    @Query("select pr, pri from ProductReview pr left join pr.reviewImageList pri where pr.product.pno = :pno order by pr.prno asc")
    Page<Object[]> listOfBoard(@Param("pno") Long pno, Pageable pageable);
    void deleteByProductPno(Long pno);

    @EntityGraph(attributePaths = "reviewImageList")
    @Query("select pr from ProductReview pr where pr.prno = :prno")
    Optional<ProductReview> selectOne(@Param("prno") Long prno);


    // prno 를 이용하여 pno 를 알아오는 쿼리문
    @Query("SELECT pr.product.pno FROM ProductReview pr WHERE pr.prno = :prno")
    Optional<Long> findPnoByPrno(@Param("prno") Long prno);

}