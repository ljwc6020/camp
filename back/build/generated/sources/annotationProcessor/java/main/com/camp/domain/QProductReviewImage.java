package com.camp.domain;

import static com.querydsl.core.types.PathMetadataFactory.*;

import com.querydsl.core.types.dsl.*;

import com.querydsl.core.types.PathMetadata;
import javax.annotation.processing.Generated;
import com.querydsl.core.types.Path;


/**
 * QProductReviewImage is a Querydsl query type for ProductReviewImage
 */
@Generated("com.querydsl.codegen.DefaultEmbeddableSerializer")
public class QProductReviewImage extends BeanPath<ProductReviewImage> {

    private static final long serialVersionUID = -739027234L;

    public static final QProductReviewImage productReviewImage = new QProductReviewImage("productReviewImage");

    public final StringPath fileName = createString("fileName");

    public final NumberPath<Integer> ord = createNumber("ord", Integer.class);

    public QProductReviewImage(String variable) {
        super(ProductReviewImage.class, forVariable(variable));
    }

    public QProductReviewImage(Path<? extends ProductReviewImage> path) {
        super(path.getType(), path.getMetadata());
    }

    public QProductReviewImage(PathMetadata metadata) {
        super(ProductReviewImage.class, metadata);
    }

}

