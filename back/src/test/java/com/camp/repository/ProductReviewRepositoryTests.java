package com.camp.repository;


import com.camp.domain.*;
import jakarta.transaction.Transactional;
import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.test.annotation.Commit;
import org.springframework.test.annotation.Rollback;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@SpringBootTest
@Log4j2
public class ProductReviewRepositoryTests {

    @Autowired
    private ProductReviewRepository productReviewRepository;

    @Autowired
    private ProductRepository productRepository;


    @Test
    public void testReviewInsert() {

        //실제DB에 있는 pno
        Long pno = 5L;

        // 존재하는 Product 조회
        Product product = productRepository.findById(pno).orElseThrow(() -> new RuntimeException("Product not found"));

        ProductReview review = ProductReview.builder()
                .product(product)
                .reviewText("리뷰 이미지 테스트")
                .reviewer("reviewer")
                .build();

        review.addImageString("test01.jpg");

        productReviewRepository.save(review);
    }

    @Transactional
    @Test    // left join 처리되고 Product와 ProductImage가 배열로 만들어진다.
    public void testList() {


        Long pno = 13L;

        //org.springframework.data.domain 패키지
        Pageable pageable = PageRequest.of(0, 10, Sort.by("prno").descending());

        Page<Object[]> result = productReviewRepository.listOfBoard(pno,pageable);

        //java.util
        result.getContent().forEach(arr -> log.info(Arrays.toString(arr)));

    }

    @Test
    @Transactional
    @Commit
    public  void testRemoveAll(){

        Long pno = 5L;

        productReviewRepository.deleteByProductPno(pno);

    }


    @Test
    public void testUpdate(){// 상품의 설명이나 가격변동, 이미지 3개도 변경

        Long prno = 3L;

        ProductReview review = productReviewRepository.selectOne(prno).get();


        review.changeText("이미지 수정 테스트");

        // 컬렉션 초기화
        review.clearList();

        // 새로운 이미지 추가
        review.addImageString(UUID.randomUUID().toString()+"_"+"NEWIMAGE2.jpg");

        productReviewRepository.save(review);

    }

}