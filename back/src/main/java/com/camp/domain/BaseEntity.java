package com.camp.domain;


import jakarta.persistence.Column;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
import lombok.Getter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@MappedSuperclass  //공통속성 처리
//모든 하위 엔티티 클래스에서 해당 {} 안의 클래스를 공통적으로 사용할 수 있다.
@EntityListeners(value = {AuditingEntityListener.class})  //데이터베이스에 추가되거나 버깅될 때 자동으로 시간 값을 지정할 수 있다.
@Getter
abstract class BaseEntity {

    @CreatedDate
    @Column(name = "regdate", updatable = false)
    private LocalDateTime regDate;

    @LastModifiedDate
    @Column(name =" moddate")
    private LocalDateTime modDate;
}
