package com.camp.domain;

import static com.querydsl.core.types.PathMetadataFactory.*;

import com.querydsl.core.types.dsl.*;

import com.querydsl.core.types.PathMetadata;
import javax.annotation.processing.Generated;
import com.querydsl.core.types.Path;
import com.querydsl.core.types.dsl.PathInits;


/**
 * QProductQna is a Querydsl query type for ProductQna
 */
@Generated("com.querydsl.codegen.DefaultEntitySerializer")
public class QProductQna extends EntityPathBase<ProductQna> {

    private static final long serialVersionUID = 1282318047L;

    private static final PathInits INITS = PathInits.DIRECT2;

    public static final QProductQna productQna = new QProductQna("productQna");

    public final StringPath answer = createString("answer");

    public final BooleanPath answered = createBoolean("answered");

    public final DateTimePath<java.time.LocalDateTime> answeredAt = createDateTime("answeredAt", java.time.LocalDateTime.class);

    public final DateTimePath<java.time.LocalDateTime> askedAt = createDateTime("askedAt", java.time.LocalDateTime.class);

    public final StringPath authorName = createString("authorName");

    public final QProduct product;

    public final NumberPath<Long> qno = createNumber("qno", Long.class);

    public final StringPath question = createString("question");

    public final ListPath<ProductQnaReply, QProductQnaReply> replies = this.<ProductQnaReply, QProductQnaReply>createList("replies", ProductQnaReply.class, QProductQnaReply.class, PathInits.DIRECT2);

    public QProductQna(String variable) {
        this(ProductQna.class, forVariable(variable), INITS);
    }

    public QProductQna(Path<? extends ProductQna> path) {
        this(path.getType(), path.getMetadata(), PathInits.getFor(path.getMetadata(), INITS));
    }

    public QProductQna(PathMetadata metadata) {
        this(metadata, PathInits.getFor(metadata, INITS));
    }

    public QProductQna(PathMetadata metadata, PathInits inits) {
        this(ProductQna.class, metadata, inits);
    }

    public QProductQna(Class<? extends ProductQna> type, PathMetadata metadata, PathInits inits) {
        super(type, metadata, inits);
        this.product = inits.isInitialized("product") ? new QProduct(forProperty("product")) : null;
    }

}

