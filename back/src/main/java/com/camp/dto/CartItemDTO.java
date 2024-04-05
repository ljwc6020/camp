package com.camp.dto;

import lombok.Data;

@Data
// Lombok 라이브러리를 사용하여 클래스에 대한 getter, setter, toString, equals, hashCode 메서드를 자동으로 생성.
public class CartItemDTO {

    private String email;
    // 사용자의 이메일 주소. 장바구니 아이템을 사용자 계정에 연결하는 데 사용됩니다.

    private Long pno;
    // 상품 번호. 이 필드는 장바구니에 추가할 특정 상품을 식별합니다.

    private int qty;
    // 수량. 장바구니에 담긴 해당 상품의 수량을 나타냅니다.

    private Long cino;
    // 카트 아이템 번호. 장바구니 아이템을 식별하는 고유한 ID입니다.
}
