package com.camp.domain;

import jakarta.persistence.*;
import lombok.*;



@Entity // 이 클래스가 JPA 엔티티임을 나타냄. 클래스의 인스턴스는 데이터베이스 테이블에 매핑됨.
@Builder // Lombok의 Builder 패턴 자동 생성. 객체 생성 시 빌더 패턴을 사용할 수 있게 함.
@AllArgsConstructor // 모든 필드 값을 인자로 받는 생성자를 자동 생성.
@NoArgsConstructor // 기본 생성자를 자동 생성.
@Getter // 모든 필드에 대한 getter 메서드를 자동 생성.
@ToString(exclude = "owner") // 객체를 문자열로 표현하는 toString() 메서드 자동 생성. owner 필드는 제외.
@Table(
        name = "tbl_cart", // 이 엔티티가 매핑될 데이터베이스 테이블의 이름을 지정.
        indexes = {@Index(name="idx_cart_email", columnList = "member_owner")} // member_owner 칼럼에 대한 인덱스 생성.
)
public class Cart {

    @Id // 이 필드가 테이블의 기본 키 역할을 함을 나타냄.
    @GeneratedValue(strategy = GenerationType.IDENTITY) // 데이터베이스가 키 값을 자동으로 생성하도록 함.
    private Long cno;

    @OneToOne // OneToOne 관계를 나타냄. 한 명의 회원이 하나의 장바구니를 가짐.
    @JoinColumn(name="member_owner") // owner 필드가 member_owner 칼럼과 매핑됨을 나타냄.
    private User owner; // 장바구니의 소유자. Member 클래스는 사용자 정의 클래스여야 함.

}
