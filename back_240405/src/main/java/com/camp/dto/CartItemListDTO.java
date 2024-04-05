
package com.camp.dto; // 패키지 선언, com.mallapi.dto 패키지에 속함을 나타냄

import lombok.Builder; // Lombok 라이브러리의 Builder 어노테이션을 가져옴
import lombok.Data; // Lombok 라이브러리의 Data 어노테이션을 가져옴
import lombok.NoArgsConstructor; // Lombok 라이브러리의 NoArgsConstructor 어노테이션을 가져옴

@Data // Lombok: 클래스에 대한 getter, setter, toString 등의 메서드 자동 생성
@Builder // Lombok: 객체 생성 시 빌더 패턴을 사용할 수 있게 해주는 어노테이션
@NoArgsConstructor // Lombok: 파라미터가 없는 기본 생성자를 자동으로 생성
public class CartItemListDTO { // 쇼핑카트 아이템 리스트를 위한 DTO(Data Transfer Object) 클래스 선언

    private Long cino; // 카트 아이템 고유 번호
    private int qty; // 상품 수량
    private Long pno; // 상품 번호
    private String pname; // 상품 이름
    private int price; // 상품 가격
    private String imageFile; // 상품 이미지 파일 경로 또는 URL

    // 모든 필드를 초기화하는 생성자
    public CartItemListDTO(Long cino, int qty, Long pno, String pname, int price, String imageFile){
        this.cino = cino; // 카트 아이템 고유 번호 초기화
        this.qty = qty; // 상품 수량 초기화
        this.pno = pno; // 상품 번호 초기화
        this.pname = pname; // 상품 이름 초기화
        this.price = price; // 상품 가격 초기화
        this.imageFile = imageFile; // 상품 이미지 파일 경로 또는 URL 초기화
    }

}
