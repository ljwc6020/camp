package com.camp.domain;

import static com.querydsl.core.types.PathMetadataFactory.*;

import com.querydsl.core.types.dsl.*;

import com.querydsl.core.types.PathMetadata;
import javax.annotation.processing.Generated;
import com.querydsl.core.types.Path;
import com.querydsl.core.types.dsl.PathInits;


/**
 * QProductQnaReply is a Querydsl query type for ProductQnaReply
 */
@Generated("com.querydsl.codegen.DefaultEntitySerializer")
public class QProductQnaReply extends EntityPathBase<ProductQnaReply> {

    private static final long serialVersionUID = 1732245323L;

    private static final PathInits INITS = PathInits.DIRECT2;

    public static final QProductQnaReply productQnaReply = new QProductQnaReply("productQnaReply");

    public final StringPath authorName = createString("authorName");

    public final QProductQna parentQna;

    public final DateTimePath<java.time.LocalDateTime> repliedAt = createDateTime("repliedAt", java.time.LocalDateTime.class);

    public final StringPath replyContent = createString("replyContent");

    public final NumberPath<Long> replyId = createNumber("replyId", Long.class);

    public QProductQnaReply(String variable) {
        this(ProductQnaReply.class, forVariable(variable), INITS);
    }

    public QProductQnaReply(Path<? extends ProductQnaReply> path) {
        this(path.getType(), path.getMetadata(), PathInits.getFor(path.getMetadata(), INITS));
    }

    public QProductQnaReply(PathMetadata metadata) {
        this(metadata, PathInits.getFor(metadata, INITS));
    }

    public QProductQnaReply(PathMetadata metadata, PathInits inits) {
        this(ProductQnaReply.class, metadata, inits);
    }

    public QProductQnaReply(Class<? extends ProductQnaReply> type, PathMetadata metadata, PathInits inits) {
        super(type, metadata, inits);
        this.parentQna = inits.isInitialized("parentQna") ? new QProductQna(forProperty("parentQna"), inits.get("parentQna")) : null;
    }

}

