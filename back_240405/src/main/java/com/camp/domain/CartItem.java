package com.camp.domain;

import jakarta.persistence.*;
import lombok.*;

@Entity
// 이 클래스를 JPA 엔티티로 선언. 클래스 인스턴스는 데이터베이스의 tbl_cart_item 테이블에 매핑됩니다.
@AllArgsConstructor
// Lombok 라이브러리를 사용하여 모든 필드를 인자로 받는 생성자를 자동으로 생성.
@NoArgsConstructor
// Lombok 라이브러리를 사용하여 기본 생성자를 자동으로 생성.
@Getter
// Lombok 라이브러리를 사용하여 모든 필드에 대한 getter 메소드를 자동으로 생성.
@Builder
// Lombok 라이브러리를 사용하여 빌더 패턴을 적용.
@ToString(exclude="cart")
// Lombok 라이브러리를 사용하여 toString() 메서드를 자동으로 생성. 'cart' 필드는 출력에서 제외.
@Table(name = "tbl_cart_item", indexes = {
        @Index(columnList = "cart_cno", name = "idx_cartitem_cart"),
        @Index(columnList = "product_pno, cart_cno", name="idx_cartitem_pno_cart")
})
// 이 엔티티가 매핑될 데이터베이스 테이블의 이름과 인덱스를 지정.
public class CartItem {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    // 기본 키를 나타내며, 데이터베이스가 자동으로 ID를 생성하도록 설정.
    private Long cino; // 카트 아이템 번호.

    @ManyToOne
    // 다대일 관계를 나타냄. 한 상품(Product)은 여러 카트 아이템에 속할 수 있음.
    @JoinColumn(name = "product_pno")
    private Product product; // 연결된 상품.

    @ManyToOne
    // 다대일 관계를 나타냄. 한 카트(Cart)는 여러 카트 아이템을 가질 수 있음.
    @JoinColumn(name = "cart_cno")
    private Cart cart; // 연결된 카트.

    private int qty; // 해당 아이템의 수량.

    public void changeQty(int qty){
        // 수량 변경 메소드. 주어진 수량으로 아이템의 수량을 업데이트.
        this.qty = qty;
    }
}
