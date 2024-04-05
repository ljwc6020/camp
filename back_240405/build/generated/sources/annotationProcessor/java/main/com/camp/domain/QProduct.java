package com.camp.domain;

import static com.querydsl.core.types.PathMetadataFactory.*;

import com.querydsl.core.types.dsl.*;

import com.querydsl.core.types.PathMetadata;
import javax.annotation.processing.Generated;
import com.querydsl.core.types.Path;
import com.querydsl.core.types.dsl.PathInits;


/**
 * QProduct is a Querydsl query type for Product
 */
@Generated("com.querydsl.codegen.DefaultEntitySerializer")
public class QProduct extends EntityPathBase<Product> {

    private static final long serialVersionUID = 1822207173L;

    public static final QProduct product = new QProduct("product");

    public final BooleanPath delFlag = createBoolean("delFlag");

    public final ListPath<ProductImage, QProductImage> imageList = this.<ProductImage, QProductImage>createList("imageList", ProductImage.class, QProductImage.class, PathInits.DIRECT2);

    public final StringPath pdesc = createString("pdesc");

    public final StringPath pname = createString("pname");

    public final NumberPath<Long> pno = createNumber("pno", Long.class);

    public final NumberPath<Integer> price = createNumber("price", Integer.class);

    public final ListPath<ProductQna, QProductQna> productQna = this.<ProductQna, QProductQna>createList("productQna", ProductQna.class, QProductQna.class, PathInits.DIRECT2);

    public final ListPath<ProductReview, QProductReview> reviews = this.<ProductReview, QProductReview>createList("reviews", ProductReview.class, QProductReview.class, PathInits.DIRECT2);

    public final NumberPath<Integer> totalQna = createNumber("totalQna", Integer.class);

    public final NumberPath<Integer> totalReviews = createNumber("totalReviews", Integer.class);

    public QProduct(String variable) {
        super(Product.class, forVariable(variable));
    }

    public QProduct(Path<? extends Product> path) {
        super(path.getType(), path.getMetadata());
    }

    public QProduct(PathMetadata metadata) {
        super(Product.class, metadata);
    }

}

