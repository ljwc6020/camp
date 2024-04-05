package com.camp.domain;

import static com.querydsl.core.types.PathMetadataFactory.*;

import com.querydsl.core.types.dsl.*;

import com.querydsl.core.types.PathMetadata;
import javax.annotation.processing.Generated;
import com.querydsl.core.types.Path;


/**
 * QNoticeBoardImage is a Querydsl query type for NoticeBoardImage
 */
@Generated("com.querydsl.codegen.DefaultEmbeddableSerializer")
public class QNoticeBoardImage extends BeanPath<NoticeBoardImage> {

    private static final long serialVersionUID = 1693155319L;

    public static final QNoticeBoardImage noticeBoardImage = new QNoticeBoardImage("noticeBoardImage");

    public final StringPath fileName = createString("fileName");

    public final NumberPath<Integer> ord = createNumber("ord", Integer.class);

    public QNoticeBoardImage(String variable) {
        super(NoticeBoardImage.class, forVariable(variable));
    }

    public QNoticeBoardImage(Path<? extends NoticeBoardImage> path) {
        super(path.getType(), path.getMetadata());
    }

    public QNoticeBoardImage(PathMetadata metadata) {
        super(NoticeBoardImage.class, metadata);
    }

}

