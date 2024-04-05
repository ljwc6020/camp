package com.camp.service;

import com.camp.dto.ProductReviewDTO;
import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
@Log4j2
public class ProductReviewServiceTests {

    @Autowired
    private ProductReviewService productReviewService;

    @Test
    public void testRegister(){

        ProductReviewDTO reviewDTO = ProductReviewDTO.builder()
                .reviewText("ReviewDTO Text")
                .reviewer("reviewer")
                .pno(5L)
                .build();

        log.info(productReviewService.register(reviewDTO));

    }
}