package com.camp.domain;

import jakarta.persistence.Embeddable;
import lombok.*;

@Embeddable
@Getter
@ToString
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ProductReviewImage { // 이미지마다 번호를 지정하고 상품 목록을 출력할때 ord값이 0번인 이미지들만 대표이미지로 출력하고자 하는 목적.

    private String fileName;

    private int ord;
    public void setOrd(int ord){
        this.ord = ord;
    }

}